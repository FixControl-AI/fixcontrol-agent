#!/usr/bin/env bash
# verify.sh — prove the install is what the values file asked for, against the
# LIVE cluster. Run automatically at the end of install.sh, and safe to run at
# any time afterwards (it is entirely read-only apart from `--dry-run=server`
# admission probes, which write nothing).
#
# What it checks, and why each check is here rather than "obviously fine":
#   1. The pods run the DIGEST the values file names — not a tag that resolved
#      to it once. A drifted image is the failure that looks like nothing.
#   2. fc-test-runner's RUNNER_IMAGE self-reference equals its own image. They
#      are two fields that must agree, so they will eventually disagree.
#   3. The RBAC negatives from the plan's acceptance criterion 5, asked of the
#      API server rather than read off a manifest.
#   4. The agent's egress policy names destinations and never 0.0.0.0/0.
#   5. The admission policy actually REFUSES, tested by making the API server
#      refuse — not by checking the object exists.
#   6. The signing-key pin is live in the process, read from its startup log.
#
# Exit 0 on pass, 1 on any failure. Every failure prints what was expected.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES="$HERE/values.env"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --values) VALUES="$2"; shift 2 ;;
    --values=*) VALUES="${1#*=}"; shift ;;
    -h|--help) sed -n '2,25p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[[ -f "$VALUES" ]] || { echo "values file not found: $VALUES" >&2; exit 2; }
set -a; . "$VALUES"; set +a

: "${FC_AGENT_NAMESPACE:=fixcontrol-agent}"; : "${FC_TEST_RUNNER_NAMESPACE:=fc-test-runner}"
: "${FC_INSTALL_AGENT:=1}"; : "${FC_INSTALL_TEST_RUNNER:=1}"
: "${FC_APPLY_ADMISSION_POLICY:=1}"; : "${FC_ARGO_LOCAL_API:=0}"
: "${FC_ALLOWED_NAMESPACES:=}"; : "${FC_ROLLOUT_NAMESPACES:=}"
: "${FC_SIGNING_PUBLIC_KEYS:=}"

FAILURES=0
ok()   { echo "ok    $*"; }
bad()  { echo "FAIL  $*" >&2; FAILURES=$((FAILURES+1)); }
skip() { echo "skip  $*"; }
sec()  { echo; echo "── $* ──"; }

# ── 1. Workloads, on the pinned digest ─────────────────────────────────────
check_workload() {  # check_workload <ns> <deploy> <container> <expected-image>
  local ns="$1" dep="$2" ctr="$3" want="$4" ready running live
  ready="$(kubectl -n "$ns" get deploy "$dep" -o jsonpath='{.status.readyReplicas}' 2>/dev/null || true)"
  [[ "${ready:-0}" -ge 1 ]] && ok "$ns/$dep has $ready ready replica(s)" \
    || { bad "$ns/$dep has no ready replica"; return; }

  running="$(kubectl -n "$ns" get pods -l app="$dep" \
      -o jsonpath='{.items[0].status.phase}' 2>/dev/null || true)"
  [[ "$running" == "Running" ]] && ok "$ns/$dep pod is Running" || bad "$ns/$dep pod phase=$running"

  # The SPEC reference — what we asked the kubelet for.
  live="$(kubectl -n "$ns" get deploy "$dep" \
      -o jsonpath="{.spec.template.spec.containers[?(@.name=='$ctr')].image}")"
  if [[ "$live" == "$want" ]]; then
    ok "$ns/$dep image reference is the pinned one ($live)"
  else
    bad "$ns/$dep image is '$live', values.env asks for '$want'"
  fi

  # The RESOLVED reference — what the kubelet actually pulled. This is the
  # check that catches a tag whose meaning changed under a running pod.
  local imageid
  imageid="$(kubectl -n "$ns" get pods -l app="$dep" \
      -o jsonpath="{.items[0].status.containerStatuses[?(@.name=='$ctr')].imageID}" 2>/dev/null || true)"
  if [[ "$want" == *"@sha256:"* ]]; then
    if [[ "$imageid" == *"${want##*@}"* ]]; then
      ok "$ns/$dep RUNS the pinned digest (${want##*@sha256:} …)"
    else
      bad "$ns/$dep runs imageID '$imageid', which does not contain the pinned digest ${want##*@}"
    fi
  else
    skip "$ns/$dep image is a tag, not a digest — running imageID: $imageid"
  fi
}

if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  sec "fc-agent workload"
  check_workload "$FC_AGENT_NAMESPACE" fc-agent fc-agent "$FC_AGENT_IMAGE"
fi
if [[ "$FC_INSTALL_TEST_RUNNER" == "1" ]]; then
  sec "fc-test-runner workload"
  check_workload "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner test-runner "$FC_TEST_RUNNER_IMAGE"
  # 2. The self-reference the runner hands to the Job's fetch/sentinel
  #    containers must be the same bytes it runs itself.
  cm="$(kubectl -n "$FC_TEST_RUNNER_NAMESPACE" get deploy fc-test-runner \
        -o jsonpath='{.spec.template.spec.containers[0].envFrom[?(@.configMapRef)].configMapRef.name}' | tr ' ' '\n' | grep config || true)"
  runner_image="$(kubectl -n "$FC_TEST_RUNNER_NAMESPACE" get cm "$cm" \
        -o jsonpath='{.data.RUNNER_IMAGE}' 2>/dev/null || true)"
  [[ "$runner_image" == "$FC_TEST_RUNNER_IMAGE" ]] \
    && ok "RUNNER_IMAGE self-reference matches the running image" \
    || bad "RUNNER_IMAGE='$runner_image' but the container runs '$FC_TEST_RUNNER_IMAGE'"

  # 3. The runner-side checkout lane, if the customer opted into it. Both
  #    objects are theirs and both mounts are optional, so their ABSENCE is a
  #    complete install and is reported as a skip. What must not happen quietly
  #    is a repo map that exists while the pod cannot see it: that install
  #    refuses every git-remote run and looks, from FixControl, like a runner
  #    that never advertised the capability.
  if kubectl -n "$FC_TEST_RUNNER_NAMESPACE" get cm fc-test-runner-repos >/dev/null 2>&1; then
    mounted="$(kubectl -n "$FC_TEST_RUNNER_NAMESPACE" get deploy fc-test-runner \
        -o jsonpath='{.spec.template.spec.volumes[?(@.configMap.name=="fc-test-runner-repos")].name}' 2>/dev/null || true)"
    [[ -n "$mounted" ]] \
      && ok "repo-key ConfigMap fc-test-runner-repos is mounted (runner-side checkout enabled)" \
      || bad "ConfigMap fc-test-runner-repos exists but the Deployment does not mount it —
       every git-remote workspace would be refused not_allowlisted"
    kubectl -n "$FC_TEST_RUNNER_NAMESPACE" get secret fc-test-runner-git >/dev/null 2>&1 \
      && ok "git credential Secret fc-test-runner-git is present" \
      || skip "no fc-test-runner-git Secret — unauthenticated remotes only"
    echo "      NOTE the ephemeral fc-test-* namespaces must reach your git host;"
    echo "      this Deployment's own egress policy deliberately does not open it."
  else
    skip "no fc-test-runner-repos ConfigMap — channel-tar workspaces only (the default)"
  fi
fi

# ── 3. RBAC, asked of the API server ───────────────────────────────────────
# NOTE the `--subresource=` spelling below rather than `resource/subresource`.
# `kubectl auth can-i get pods/log` does NOT ask about the log subresource: the
# argument is TYPE[.VERSION][.GROUP][/NAME], so that reads "get the pod named
# log" and answers from the `pods` rule. This check passed for the wrong reason
# until `pods: get` was removed and it started failing on a grant that was
# present and correct (kind rig, 2026-08-23). Anything that must ask about a
# subresource has to use the flag.
cani() {  # cani <expect yes|no> <sa-namespace> <sa> <verb> <resource> [flags…]
  local expect="$1" sans="$2" sa="$3"; shift 3
  local answer
  answer="$(kubectl auth can-i "$@" --as="system:serviceaccount:${sans}:${sa}" 2>/dev/null || true)"
  answer="${answer%%$'\n'*}"
  if [[ "$answer" == "$expect" ]]; then
    ok "$sa: '$*' → $answer"
  else
    bad "$sa: '$*' → $answer (expected $expect)"
  fi
}

if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  sec "fc-rollout-controller RBAC (plan §Identities and RBAC)"
  rns="${FC_ROLLOUT_NAMESPACES:-$FC_ALLOWED_NAMESPACES}"
  first_ns="$(echo "$rns" | cut -d, -f1 | tr -d '[:space:]')"
  # Is Argo Rollouts even installed? `kubectl auth can-i` answers `no` for a
  # resource the API server cannot resolve, so on a cluster without the CRD
  # EVERY rollouts check "passes" its negative and fails its positive — the
  # positives read as an RBAC defect and the negatives are a false comfort.
  # A CI/CD-gate-only install (FC_PROMOTE_MODE=none) is exactly that cluster,
  # so the absence is reported once, plainly, instead of six times as a lie.
  if kubectl get crd rollouts.argoproj.io >/dev/null 2>&1; then
    HAS_ROLLOUTS=1
  else
    HAS_ROLLOUTS=0
    skip "Argo Rollouts CRD is not installed in this cluster — every
      rollouts.argoproj.io check below would answer 'no' because the resource
      cannot be resolved, not because RBAC denied it. Install Argo Rollouts to
      make these checks meaningful."
  fi
  # Positives — what the agent must be able to do.
  if [[ "$HAS_ROLLOUTS" == "1" ]]; then
    cani yes "$FC_AGENT_NAMESPACE" fc-rollout-controller get  rollouts.argoproj.io -n "$first_ns"
    # `list` is granted only while events are on: install.sh narrows the Role
    # to `get` at FC_EVENTS_ENABLED=0 because nothing LISTs the collection any
    # more. Asserting `yes` unconditionally made a CORRECT events-off install
    # fail its own verify (private-network rig, 2026-08-23).
    if [[ "${FC_EVENTS_ENABLED:-1}" == "1" ]]; then
      cani yes "$FC_AGENT_NAMESPACE" fc-rollout-controller list rollouts.argoproj.io -n "$first_ns"
    else
      cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller list rollouts.argoproj.io -n "$first_ns"
    fi
  fi
  cani yes "$FC_AGENT_NAMESPACE" fc-rollout-controller get  configmaps/fc-agent-nonces -n "$FC_AGENT_NAMESPACE"
  # Negatives — the plan's explicit denials, plus the two grants this package
  # removed. A regression that restores them fails here.
  cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller create namespaces
  cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller get    secrets -n "$first_ns"
  cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller list   secrets -n kube-system
  cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller create deployments.apps -n "$first_ns"
  cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller list   configmaps -n "$FC_AGENT_NAMESPACE"
  if [[ "$HAS_ROLLOUTS" == "1" ]]; then
    cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller create rollouts.argoproj.io --subresource=promote -n "$first_ns"
    if [[ "$FC_ARGO_LOCAL_API" == "1" ]]; then
      cani yes "$FC_AGENT_NAMESPACE" fc-rollout-controller patch rollouts.argoproj.io --subresource=status -n "$first_ns"
    else
      cani no  "$FC_AGENT_NAMESPACE" fc-rollout-controller patch rollouts.argoproj.io --subresource=status -n "$first_ns"
    fi
  fi
fi

if [[ "$FC_INSTALL_TEST_RUNNER" == "1" ]]; then
  sec "fc-test-runner RBAC"
  cani yes "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create namespaces
  cani yes "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create secrets -n fc-test-probe
  cani yes "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner get    pods --subresource=log -n fc-test-probe
  # The load-bearing negative: the component that runs customer test code must
  # not be able to promote a rollout.
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner get    rollouts.argoproj.io -n "${FC_ALLOWED_NAMESPACES%%,*}"
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create rollouts.argoproj.io --subresource=promote -n "${FC_ALLOWED_NAMESPACES%%,*}"
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner get    secrets -n kube-system
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner list   secrets -n kube-system
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create clusterrolebindings.rbac.authorization.k8s.io
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner get    nodes
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create customresourcedefinitions.apiextensions.k8s.io
  # Grants this package removed — a restored one is a finding, not an upgrade.
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create statefulsets.apps -n fc-test-probe
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner create configmaps -n fc-test-probe
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner list   events -n fc-test-probe
  cani no  "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner get    pods -n fc-test-probe
fi

# ── 4. NetworkPolicy ───────────────────────────────────────────────────────
if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  sec "fc-agent egress policy"
  pol="$(kubectl -n "$FC_AGENT_NAMESPACE" get netpol fc-agent-egress -o json 2>/dev/null || true)"
  if [[ -z "$pol" ]]; then
    bad "NetworkPolicy fc-agent-egress is missing"
  else
    if grep -q '0.0.0.0/0' <<<"$pol"; then
      bad "fc-agent-egress contains 0.0.0.0/0 — this pod holds three credentials; name every destination"
    else
      ok "fc-agent-egress contains no 0.0.0.0/0"
    fi
    n="$(python3 -c 'import json,sys; print(len(json.load(sys.stdin)["spec"]["egress"]))' <<<"$pol")"
    ok "fc-agent-egress has $n egress rule(s)"
    ing="$(python3 -c 'import json,sys; print("Ingress" in (json.load(sys.stdin)["spec"].get("policyTypes") or []))' <<<"$pol")"
    [[ "$ing" == "False" ]] && ok "fc-agent-egress declares no Ingress rules (the agent has no listener)" \
                            || bad "fc-agent-egress declares Ingress — the agent must have no inbound surface"
  fi
  if kubectl -n "$FC_AGENT_NAMESPACE" get svc -l app=fc-agent 2>/dev/null | grep -q fc-agent; then
    bad "a Service exists for fc-agent — the outbound-only promise does not survive one"
  else
    ok "no Service for fc-agent (inbound requirement: none)"
  fi
fi

# ── 5. The admission policy, proven by making it refuse ────────────────────
if [[ "$FC_INSTALL_TEST_RUNNER" == "1" && "$FC_APPLY_ADMISSION_POLICY" == "1" ]]; then
  sec "ValidatingAdmissionPolicy enforcement"
  if ! kubectl get validatingadmissionpolicy fc-test-runner-namespace-scope >/dev/null 2>&1; then
    skip "policy not installed (older cluster, or FC_APPLY_ADMISSION_POLICY was 0 at install time)"
  else
    ok "policy fc-test-runner-namespace-scope exists"
    sa="system:serviceaccount:${FC_TEST_RUNNER_NAMESPACE}:fc-test-runner"
    # Must be REFUSED: a namespace outside the fc-test-* prefix.
    if kubectl create ns fc-not-a-sandbox --as="$sa" --dry-run=server >/dev/null 2>&1; then
      bad "the runner identity was allowed to create 'fc-not-a-sandbox' — the policy is not enforcing"
    else
      ok "refused: runner cannot create a namespace outside fc-test-*"
    fi
    # Must be REFUSED: a Secret in a namespace that is not a sandbox.
    if kubectl -n default create secret generic vap-probe --from-literal=a=b \
         --as="$sa" --dry-run=server >/dev/null 2>&1; then
      bad "the runner identity was allowed to write a Secret into 'default'"
    else
      ok "refused: runner cannot write outside an fc-test-* namespace"
    fi
    # Must be REFUSED: deleting its own namespace, which satisfies the prefix.
    if kubectl delete ns "$FC_TEST_RUNNER_NAMESPACE" --as="$sa" --dry-run=server >/dev/null 2>&1; then
      bad "the runner identity was allowed to delete its own namespace"
    else
      ok "refused: runner cannot delete its own namespace"
    fi
    # Must be ALLOWED: a correctly labelled sandbox namespace.
    if kubectl create -f - --as="$sa" --dry-run=server >/dev/null 2>&1 <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: fc-test-vapprobe
  labels: { fixcontrol.sandbox: "1", fixcontrol.expires: "1" }
EOF
    then ok "allowed: a labelled fc-test-* sandbox namespace"
    else bad "the policy refuses a legitimate sandbox namespace — it is too strict"
    fi
    # Must be REFUSED: an fc-test-* namespace without the sweeper's labels.
    if kubectl create ns fc-test-unlabelled --as="$sa" --dry-run=server >/dev/null 2>&1; then
      bad "an unlabelled fc-test-* namespace was allowed — it would leak past the TTL sweeper"
    else
      ok "refused: an fc-test-* namespace without fixcontrol.sandbox/expires labels"
    fi
    # Must be ALLOWED: the runner's own workload writes INSIDE a sandbox
    # namespace. This is the check that would have caught the policy bug where
    # the namespace-name rule lacked its resource guard and refused every
    # Deployment whose name did not start with fc-test- (found live 2026-08-23:
    # a service named `cache` was denied inside its own sandbox). A server
    # dry-run needs the namespace to exist, so this probe makes ONE real,
    # labelled, immediately-deleted namespace — the only write verify performs.
    vapns="fc-test-vapprobe-$$"
    if kubectl create -f - --as="$sa" >/dev/null 2>&1 <<EOF2
apiVersion: v1
kind: Namespace
metadata:
  name: ${vapns}
  labels: { fixcontrol.sandbox: "1", fixcontrol.expires: "1" }
EOF2
    then
      if kubectl -n "$vapns" create deployment cache --image=redis:7-alpine \
           --as="$sa" --dry-run=server >/dev/null 2>&1; then
        ok "allowed: a Deployment named 'cache' inside an fc-test-* namespace"
      else
        bad "the policy refuses the runner's own workloads inside a sandbox namespace — it is too strict"
      fi
      kubectl delete ns "$vapns" --wait=false >/dev/null 2>&1 || true
    else
      skip "could not create the probe namespace ${vapns} — in-namespace allow check skipped"
    fi
  fi
fi

# ── 6. The pin, live in the process ────────────────────────────────────────
if [[ "$FC_INSTALL_AGENT" == "1" ]]; then
  sec "signing-key pin and liveness"
  startup="$(kubectl -n "$FC_AGENT_NAMESPACE" logs deploy/fc-agent --tail=200 2>/dev/null \
             | grep '"event":"startup"' | tail -1 || true)"
  if [[ -z "$startup" ]]; then
    bad "no startup log line from fc-agent"
  else
    pins="$(python3 -c 'import json,sys; print(",".join(json.loads(sys.stdin.read()).get("signing_key_pins") or []))' <<<"$startup" 2>/dev/null || true)"
    if [[ -n "$FC_SIGNING_PUBLIC_KEYS" ]]; then
      [[ -n "$pins" ]] && ok "agent reports signing_key_pins=[$pins] — cross-check against \`agent-signing-key list\`" \
                       || bad "a pin is configured but the agent reports none"
    else
      [[ -z "$pins" ]] && skip "no pin configured — LEGACY shared-secret verification (README Step 16)" \
                       || ok "agent reports signing_key_pins=[$pins]"
    fi
  fi
  # /healthz binds loopback on purpose, so ask from inside the pod.
  if kubectl -n "$FC_AGENT_NAMESPACE" exec deploy/fc-agent -- python3 -c \
      'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8080/healthz",timeout=5).status==200 else 1)' \
      >/dev/null 2>&1; then
    ok "agent /healthz is 200 — it has completed at least one successful FixControl poll"
  else
    bad "agent /healthz is not 200 — it has not reached FixControl (503 until the first good poll)"
  fi
fi

echo
if [[ "$FAILURES" -eq 0 ]]; then
  echo "all checks passed"
  exit 0
fi
echo "$FAILURES check(s) failed" >&2
exit 1
