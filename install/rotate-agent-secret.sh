#!/usr/bin/env bash
# rotate-agent-secret.sh — replace the agent's FixControl credential.
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ THE HONEST VERSION OF "NO DOWNTIME".                                     ║
# ╚══════════════════════════════════════════════════════════════════════════╝
# There is a gap, and pretending otherwise would make an operator plan badly.
#
# FixControl's `rotateAgentSecret` mints a new secret and the OLD ONE STOPS
# VERIFYING THE MOMENT IT COMMITS (src/server/integrations/devops/agent/store.ts
# — the docblock says so in as many words). The agent reads its secret from an
# environment variable, so it cannot pick up the new one without a restart. So
# between "FixControl rotated" and "the new pod is up" the agent's polls are
# rejected. On this deployment that window is the time a single-replica
# `Recreate` rollout takes: seconds.
#
# What makes those seconds safe is not speed, it is the operation model:
#
#   · An operation the agent never claims stays `registered` until `expiresAt`
#     (minutes). The next successful poll picks it up. Nothing is lost.
#   · Nothing double-executes: the nonce ledger is a ConfigMap that survives
#     the restart, and the single-use envelope is single-use across processes.
#   · A gate whose operation is still unclaimed shows as "cluster agent
#     unreachable" rather than silently succeeding — degradation is visible
#     (invariant 9).
#
# So the promise is: **no operation is lost and none is executed twice.** Plan a
# maintenance moment anyway if a governed deployment is mid-flight; do not plan
# an outage.
#
# ORDER MATTERS, and this is the only correct one:
#
#   1. FixControl side: rotate. You get the new secret ONCE.
#   2. Cluster side:    write it into the Secret.       ← this script, step 1
#   3. Cluster side:    restart the agent.              ← this script, step 2
#   4. Cluster side:    confirm it is polling again.    ← this script, step 3
#
# Doing 3 before 2 restarts the agent onto the OLD secret and burns the window
# for nothing. Doing 2 before 1 writes a secret FixControl has not minted.
#
# Usage:
#   ./rotate-agent-secret.sh                  # prompts for the new secret (not echoed)
#   ./rotate-agent-secret.sh --from-file p    # read it from a file
#   ./rotate-agent-secret.sh --test-runner    # rotate fc-test-runner's credential instead
#
# The new secret is never passed on a command line and never written to
# values.env by this script. If you keep values.env as the source of truth,
# update FC_AGENT_SECRET there yourself afterwards — otherwise the next
# `install.sh` will write the OLD secret back.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES="$HERE/values.env"
FROM_FILE=""
TARGET=agent

while [[ $# -gt 0 ]]; do
  case "$1" in
    --values) VALUES="$2"; shift 2 ;;
    --values=*) VALUES="${1#*=}"; shift ;;
    --from-file) FROM_FILE="$2"; shift 2 ;;
    --from-file=*) FROM_FILE="${1#*=}"; shift ;;
    --test-runner) TARGET=test-runner; shift ;;
    -h|--help) sed -n '2,50p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$VALUES" ]] && { set -a; . "$VALUES"; set +a; }
: "${FC_AGENT_NAMESPACE:=fixcontrol-agent}"
: "${FC_TEST_RUNNER_NAMESPACE:=fc-test-runner}"

if [[ "$TARGET" == "agent" ]]; then
  NS="$FC_AGENT_NAMESPACE"; SECRET=fc-agent; KEY=agent-secret; DEPLOY=fc-agent
else
  NS="$FC_TEST_RUNNER_NAMESPACE"; SECRET=fc-test-runner; KEY=FIXCONTROL_AGENT_SECRET; DEPLOY=fc-test-runner
fi

cat <<EOF

Rotating the FixControl credential for $NS/$DEPLOY.

Step 0 (FixControl side) must already be done. If it is not, stop now:
  · /settings/devops → the agent → Rotate secret, or
  · the platform operator's rotateAgentSecret call.
The old secret stopped verifying the moment that committed, so the agent is
already failing its polls. Everything below closes that window.

EOF

if [[ -n "$FROM_FILE" ]]; then
  [[ -r "$FROM_FILE" ]] || { echo "cannot read $FROM_FILE" >&2; exit 1; }
  NEW="$(cat "$FROM_FILE")"
else
  read -rs -p "Paste the new agent secret (not echoed): " NEW; echo
fi
[[ -n "$NEW" ]] || { echo "empty secret — aborted" >&2; exit 1; }

TMP="$(mktemp -d)"; chmod 700 "$TMP"
trap 'rm -rf "$TMP"' EXIT
printf '%s' "$NEW" > "$TMP/$KEY"; chmod 600 "$TMP/$KEY"
unset NEW

echo "==> 1/3  writing $NS/$SECRET key '$KEY'"
# A strategic-merge patch on the one key, so every other key in the Secret —
# the repo PAT, the webhook secret, the CI credentials — is untouched. A
# `create --dry-run | apply` would replace the whole object and silently drop
# anything values.env no longer knows about.
kubectl -n "$NS" patch secret "$SECRET" --type merge \
  -p "{\"data\":{\"$KEY\":\"$(base64 -w0 < "$TMP/$KEY")\"}}" >/dev/null
echo "         done"

echo "==> 2/3  restarting $NS/$DEPLOY"
kubectl -n "$NS" rollout restart "deploy/$DEPLOY" >/dev/null
kubectl -n "$NS" rollout status "deploy/$DEPLOY" --timeout=180s

echo "==> 3/3  confirming it is polling again"
if [[ "$TARGET" == "agent" ]]; then
  probe='import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8080/healthz",timeout=5).status==200 else 1)'
  for i in $(seq 1 12); do
    if kubectl -n "$NS" exec "deploy/$DEPLOY" -- python3 -c "$probe" >/dev/null 2>&1; then
      echo "         /healthz is 200 — the new secret verifies."
      break
    fi
    [[ "$i" == "12" ]] && {
      echo "         /healthz never reached 200." >&2
      echo "         The agent returns 503 until its FIRST successful poll, so this means the" >&2
      echo "         new secret is not the one FixControl minted, or FixControl is unreachable." >&2
      kubectl -n "$NS" logs "deploy/$DEPLOY" --tail=20 >&2
      exit 1
    }
    sleep 5
  done
else
  kubectl -n "$NS" wait --for=condition=Available "deploy/$DEPLOY" --timeout=120s >/dev/null
  echo "         deployment available; check /settings/devops for a fresh last-seen."
fi

cat <<EOF

Rotation complete.

Two follow-ups, both easy to forget:
  · If values.env holds FC_AGENT_SECRET, update it — otherwise the next
    ./install.sh writes the OLD secret back over this one.
  · Confirm the agent's last-seen is moving in FixControl (/settings/devops).
    An agent that restarted but cannot authenticate looks Running here and dead
    there.
EOF
