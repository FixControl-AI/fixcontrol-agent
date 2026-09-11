#!/usr/bin/env bash
# revoke-agent.sh — stop this cluster from acting on FixControl's behalf, now.
#
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║ Revocation has TWO halves, and only one of them lives in this cluster.   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
#   FixControl side (authoritative)  — `revokeAgent(tenant, agentId)`. A soft
#     revoke: the row is kept so operations keep a resolvable claimer and the
#     audit trail stays intact, but `getAgentForAuth` refuses the identity from
#     the NEXT REQUEST ON. It is idempotent. There is no "un-revoke": a cluster
#     that must come back needs a new registration.
#     Do it at  /settings/devops → the agent → Revoke.
#
#   Cluster side (this script)       — scale the workloads to zero. Every
#     credential stays where it is, so nothing is lost; the pods simply stop
#     asking. Use it when you need the cluster to go quiet in seconds and the
#     FixControl-side action needs an owner who is not you.
#
# WHICH ORDER. If you suspect the CREDENTIAL is compromised, revoke on the
# FixControl side FIRST — scaling pods to zero does nothing about a secret that
# has already left the cluster. If you are decommissioning a healthy cluster,
# either order works; stopping the pods first avoids a burst of failed polls in
# the FixControl logs.
#
# WHAT THE CUSTOMER SEES afterwards, so nobody debugs a working refusal:
#   · The agent pod keeps running and keeps polling. Its polls get an
#     authentication failure, /healthz stays 503 after the next cycle, and its
#     log fills with outbound 4xx lines. It does NOT crash-loop — a revoked
#     agent that crash-looped would look like an outage instead of a decision.
#   · In FixControl the agent's connectivity health goes stale and any gate
#     needing it reports "cluster agent unreachable". Operations already
#     registered stay `registered` until `expiresAt` and then expire — they are
#     never executed by a revoked agent, and never silently dropped.
#   · Nothing already committed is rolled back. A revocation stops future
#     authority; it is not an undo.
#
# Usage:
#   ./revoke-agent.sh              # scale both workloads to 0
#   ./revoke-agent.sh --resume     # scale them back to 1
#   ./revoke-agent.sh --purge      # ALSO delete the credential Secrets
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VALUES="$HERE/values.env"
MODE=stop

while [[ $# -gt 0 ]]; do
  case "$1" in
    --values) VALUES="$2"; shift 2 ;;
    --values=*) VALUES="${1#*=}"; shift ;;
    --resume) MODE=resume; shift ;;
    --purge)  MODE=purge;  shift ;;
    -h|--help) sed -n '2,45p' "${BASH_SOURCE[0]}"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -f "$VALUES" ]] && { set -a; . "$VALUES"; set +a; }
: "${FC_AGENT_NAMESPACE:=fixcontrol-agent}"
: "${FC_TEST_RUNNER_NAMESPACE:=fc-test-runner}"

scale() {  # scale <ns> <deploy> <n>
  kubectl -n "$1" get deploy "$2" >/dev/null 2>&1 || { echo "       $1/$2 not present"; return 0; }
  kubectl -n "$1" scale "deploy/$2" --replicas="$3" >/dev/null
  echo "       $1/$2 → replicas=$3"
}

case "$MODE" in
  stop)
    echo "==> Stopping the cluster side"
    scale "$FC_AGENT_NAMESPACE" fc-agent 0
    scale "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner 0
    cat <<EOF

The cluster is quiet. It is NOT revoked.

Now do the authoritative half in FixControl:
    /settings/devops → the agent → Revoke
Until that happens the credential in this cluster's Secrets is still valid, and
anyone holding a copy of it can act as this cluster.

To bring it back:  ./revoke-agent.sh --resume
EOF
    ;;
  resume)
    echo "==> Resuming"
    scale "$FC_AGENT_NAMESPACE" fc-agent 1
    scale "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner 1
    echo
    echo "If the agent was revoked on the FixControl side, it will come up and fail"
    echo "its polls — a revocation cannot be undone from here. Register a new agent"
    echo "and run ./install.sh with the new FC_AGENT_ID / FC_AGENT_SECRET."
    ;;
  purge)
    echo "==> Stopping and destroying the credentials"
    scale "$FC_AGENT_NAMESPACE" fc-agent 0
    scale "$FC_TEST_RUNNER_NAMESPACE" fc-test-runner 0
    kubectl -n "$FC_AGENT_NAMESPACE" delete secret fc-agent fc-agent-ci --ignore-not-found
    kubectl -n "$FC_TEST_RUNNER_NAMESPACE" delete secret fc-test-runner --ignore-not-found
    cat <<EOF

Credentials removed from the cluster. The pods will not start again without
them (a Deployment whose secretKeyRef is missing stays Pending, which is the
right failure).

This still does NOT revoke anything on the FixControl side. Do that too.
EOF
    ;;
esac
