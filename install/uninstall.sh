#!/usr/bin/env bash
# uninstall.sh — remove the FixControl cluster agent, leaving nothing behind.
#
# "Nothing behind" is a claim, so this script ends by PROVING it: a
# cluster-wide sweep for anything carrying `app.kubernetes.io/part-of=
# fixcontrol-agent`, for the cluster-scoped policy objects, and for leftover
# `fc-test-*` sandbox namespaces. If the sweep finds anything, the script fails
# and names it.
#
# It removes by LABEL, not from the render, so an install whose values.env has
# been lost is still fully removable — which is exactly the situation an
# operator is in when they most want this script.
#
# What it deliberately does NOT do:
#   · Revoke the agent on the FixControl side. Deleting the pod stops the
#     cluster from acting; it does not stop the credential from being valid.
#     Run ./revoke-agent.sh (or the FixControl UI) as well — the order is in
#     the README's "Uninstall" section, and revoking FIRST is the safe one.
#   · Delete a namespace this installer did not create. It checks the
#     `fixcontrol.ai/created-by` annotation and leaves anything else alone.
#
# Usage:
#   ./uninstall.sh                 # remove; keep any namespace we did not create
#   ./uninstall.sh --values x.env  # read namespaces from a specific values file
#   ./uninstall.sh --keep-secrets  # leave the Secrets (ESO/Vault owns them)
#   ./uninstall.sh --yes           # no confirmation prompt
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES="$HERE/values.env"
ASSUME_YES=0
KEEP_SECRETS=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --values) VALUES="$2"; shift 2 ;;
    --values=*) VALUES="${1#*=}"; shift ;;
    --yes|-y) ASSUME_YES=1; shift ;;
    --keep-secrets) KEEP_SECRETS=1; shift ;;
    -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

LABEL="app.kubernetes.io/part-of=fixcontrol-agent"
# Both selectors are swept. `part-of` marks the package; `managed-by` marks
# what THIS installer wrote, including the content-hashed ConfigMap
# generators whose names change with every configuration edit and can
# therefore not be removed by name.
MANAGED="app.kubernetes.io/managed-by=fixcontrol-install"

if [[ -f "$VALUES" ]]; then
  set -a; . "$VALUES"; set +a
else
  echo "note: $VALUES not found — falling back to label-only removal." >&2
fi
: "${FC_AGENT_NAMESPACE:=fixcontrol-agent}"
: "${FC_TEST_RUNNER_NAMESPACE:=fc-test-runner}"
: "${FC_ALLOWED_NAMESPACES:=}"; : "${FC_ROLLOUT_NAMESPACES:=}"

step() { echo; echo "==> $*"; }
note() { echo "       $*"; }

echo "This will remove the FixControl agent install from context:"
echo "    $(kubectl config current-context)"
echo "  agent namespace       : $FC_AGENT_NAMESPACE"
echo "  test-runner namespace : $FC_TEST_RUNNER_NAMESPACE"
echo "  rollout RBAC in       : ${FC_ROLLOUT_NAMESPACES:-${FC_ALLOWED_NAMESPACES:-<unknown>}}"
if [[ "$ASSUME_YES" != "1" ]]; then
  read -r -p "Proceed? [y/N] " a
  [[ "$a" == "y" || "$a" == "Y" ]] || { echo "aborted"; exit 1; }
fi

# ── 1. Workloads first, so nothing is mid-operation while RBAC disappears ──
step "Stopping workloads"
kubectl -n "$FC_AGENT_NAMESPACE" delete deploy fc-agent --ignore-not-found --wait=true 2>/dev/null
kubectl -n "$FC_TEST_RUNNER_NAMESPACE" delete deploy fc-test-runner --ignore-not-found --wait=true 2>/dev/null

# ── 2. Ephemeral sandbox namespaces ────────────────────────────────────────
# The runner deletes its own run namespace in a `finally`, and the TTL sweeper
# reclaims anything a SIGKILL left behind — but the sweeper is the process we
# just stopped, so anything still standing is now ours to remove.
step "Reclaiming sandbox namespaces"
mapfile -t sandboxes < <(kubectl get ns -l fixcontrol.sandbox=1 -o name 2>/dev/null || true)
if [[ ${#sandboxes[@]} -gt 0 ]]; then
  note "found ${#sandboxes[@]}: ${sandboxes[*]}"
  kubectl delete "${sandboxes[@]}" --wait=true 2>/dev/null
else
  note "none"
fi

# ── 3. Namespaced objects, by label ────────────────────────────────────────
step "Removing namespaced objects"
NS_LIST="$FC_AGENT_NAMESPACE $FC_TEST_RUNNER_NAMESPACE"
IFS=, read -r -a _rns <<< "${FC_ROLLOUT_NAMESPACES:-$FC_ALLOWED_NAMESPACES}"
for n in "${_rns[@]}"; do
  n="$(echo "$n" | tr -d '[:space:]')"; [[ -n "$n" ]] && NS_LIST="$NS_LIST $n"
done
KINDS="deploy,svc,cm,role,rolebinding,serviceaccount,networkpolicy"
[[ "$KEEP_SECRETS" == "1" ]] || KINDS="$KINDS,secret"
for n in $NS_LIST; do
  kubectl get ns "$n" >/dev/null 2>&1 || continue
  for sel in "$LABEL" "$MANAGED"; do
    out="$(kubectl -n "$n" delete "$KINDS" -l "$sel" --ignore-not-found 2>&1 | grep -v '^No resources' || true)"
    [[ -n "$out" ]] && note "$n: $(echo "$out" | tr '\n' ' ')"
  done
done
# The Secrets install.sh creates carry the managed-by label rather than being
# part of the kustomize render; remove them by that label too.
if [[ "$KEEP_SECRETS" != "1" ]]; then
  for n in "$FC_AGENT_NAMESPACE" "$FC_TEST_RUNNER_NAMESPACE"; do
    kubectl get ns "$n" >/dev/null 2>&1 || continue
    kubectl -n "$n" delete secret -l app.kubernetes.io/managed-by=fixcontrol-install \
      --ignore-not-found >/dev/null 2>&1
  done
fi

# ── 4. Cluster-scoped objects ──────────────────────────────────────────────
step "Removing cluster-scoped objects"
kubectl delete clusterrole,clusterrolebinding -l "$LABEL" --ignore-not-found 2>&1 | grep -v '^No resources' || true
kubectl delete validatingadmissionpolicybinding fc-test-runner-namespace-scope --ignore-not-found 2>/dev/null
kubectl delete validatingadmissionpolicy        fc-test-runner-namespace-scope --ignore-not-found 2>/dev/null

# ── 5. Namespaces WE created ───────────────────────────────────────────────
step "Removing namespaces this installer created"
for n in "$FC_AGENT_NAMESPACE" "$FC_TEST_RUNNER_NAMESPACE"; do
  kubectl get ns "$n" >/dev/null 2>&1 || continue
  owner="$(kubectl get ns "$n" -o jsonpath='{.metadata.annotations.fixcontrol\.ai/created-by}' 2>/dev/null || true)"
  part="$(kubectl get ns "$n" -o jsonpath='{.metadata.labels.app\.kubernetes\.io/part-of}' 2>/dev/null || true)"
  if [[ "$owner" == "fixcontrol-install" || "$part" == "fixcontrol-agent" ]]; then
    kubectl delete ns "$n" --wait=true
    note "deleted namespace $n"
  else
    note "kept namespace $n — not created by this installer"
  fi
done

# ── 6. Local render ────────────────────────────────────────────────────────
rm -rf "$HERE/.render"
note "removed $HERE/.render"

# ── 7. PROVE it is clean ───────────────────────────────────────────────────
step "Sweep — anything left?"
LEFT=0
report() { echo "LEFT  $*" >&2; LEFT=$((LEFT+1)); }

# Every namespaced kind the package can create, across every namespace.
for k in deployments services configmaps secrets serviceaccounts roles rolebindings networkpolicies; do
  for sel in "$LABEL" "$MANAGED"; do
    found="$(kubectl get "$k" -A -l "$sel" --no-headers 2>/dev/null | grep -v '^$' || true)"
    [[ -n "$found" ]] && { report "$k ($sel):"; echo "$found" >&2; }
  done
done
found="$(kubectl get clusterroles,clusterrolebindings -l "$LABEL" --no-headers 2>/dev/null | grep -v '^$' || true)"
[[ -n "$found" ]] && { report "cluster-scoped RBAC:"; echo "$found" >&2; }
found="$(kubectl get validatingadmissionpolicies,validatingadmissionpolicybindings \
          --no-headers 2>/dev/null | grep fc-test-runner || true)"
[[ -n "$found" ]] && { report "admission policy:"; echo "$found" >&2; }
found="$(kubectl get ns -l fixcontrol.sandbox=1 --no-headers 2>/dev/null | grep -v '^$' || true)"
[[ -n "$found" ]] && { report "sandbox namespaces:"; echo "$found" >&2; }
found="$(kubectl get ns --no-headers 2>/dev/null | awk '{print $1}' | grep -E '^fc-test-' || true)"
[[ -n "$found" ]] && { report "fc-test-* namespaces:"; echo "$found" >&2; }
# The nonce ledgers are the two objects most likely to be missed: they are
# ConfigMaps whose names are pinned by RBAC resourceNames, so they never carry
# a generator hash and never move.
for pair in "$FC_AGENT_NAMESPACE fc-agent-nonces" "$FC_TEST_RUNNER_NAMESPACE fc-test-runner-nonces"; do
  set -- $pair
  kubectl -n "$1" get cm "$2" >/dev/null 2>&1 && report "nonce ConfigMap $1/$2 still exists"
done

echo
if [[ "$LEFT" -eq 0 ]]; then
  echo "clean — nothing carrying $LABEL, no fc-test-* namespace, no nonce ledger remains."
  echo
  echo "REMEMBER: the FixControl-side credential is still valid. Revoke it:"
  echo "    ./revoke-agent.sh            (or /settings/devops in FixControl)"
  exit 0
fi
echo "$LEFT leftover group(s) — see above." >&2
exit 1
