# fc-agent — outbound-only FixControl agent (Phase 2a).
#
# Dials OUT to FixControl, re-authorizes every signed operation locally, and
# executes against the PRIVATE Kubernetes/Argo API over ClusterIP. Nothing in
# this image listens on a routable address: the health/metrics server binds
# loopback by default and the manifest ships no Service.
#
# Supply-chain stance (Tier 1):
#   - Runtime is python:3.12-slim pinned by the SAME digest as
#     docker/git-promote-bot/Dockerfile. Keeping the two in lockstep means one
#     base bump is one review, not two divergent bases in one namespace.
#   - NOT distroless, and the reason is `git`: the DEFAULT promotion profile
#     (PROMOTE_MODE=git) writes a promotion marker commit to the manifests
#     repo, and distroless ships no git binary. That is the same trade-off
#     docker/git-promote-bot/Dockerfile already makes. Customers who run
#     PROMOTE_MODE=receiver exclusively can rebuild FROM the distroless base
#     used by docker/signer/Dockerfile and drop the apt layer entirely.
#   - The only apt packages are `git` and `ca-certificates`. No curl, no wget,
#     no compiler — nothing downloads at runtime, so there is nothing to
#     SHA-verify here (unlike the receiver/bot images, which fetch kubectl).
#   - No pip. The agent and fc_agent_common are stdlib-only by design: the
#     whole trust boundary is two readable files with no transitive deps.
#
# Build:
#   docker build -t fc-agent:1.0.0 -f docker/agent/Dockerfile .
#
# Local run (kind dev, host FixControl on 172.17.0.1:3000):
#   docker run --rm \
#     -e FIXCONTROL_URL=http://172.17.0.1:3000 \
#     -e ALLOW_INSECURE_FIXCONTROL_URL=1 \
#     -e FIXCONTROL_AGENT_ID=agt_dev -e FIXCONTROL_AGENT_SECRET=... \
#     -e FIXCONTROL_CLUSTER_ID=cl_dev -e FIXCONTROL_TENANT=t_dev \
#     -e ALLOWED_NAMESPACES=argo-demo -e ALLOWED_ROLLOUTS='*' \
#     -e DRY_RUN=1 \
#     fc-agent:1.0.0
#
# In-cluster: see manifests/fc-agent.yaml.

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

RUN useradd --create-home --shell /usr/sbin/nologin --uid 1001 fc
USER fc
WORKDIR /home/fc

# Defaults that make the SAFE posture the default one: GitOps promotion,
# local Argo API off, loopback-only metrics. Everything else comes from the
# customer-owned ConfigMap; credentials come from the Secret.
ENV AGENT_NAME=fc-agent \
    AGENT_CAPABILITIES=rollout.promote,rollout.abort,rollout.status \
    POLL_SECONDS=10 \
    CLOCK_SKEW_SECONDS=300 \
    PROMOTE_MODE=git \
    GIT_PROMOTE_BRANCH=main \
    ARGO_LOCAL_API=0 \
    EVENTS_ENABLED=1 \
    METRICS_HOST=127.0.0.1 \
    METRICS_PORT=8080 \
    AGENT_WORK_DIR=/tmp/fc-agent \
    DRY_RUN=

# fc_ed25519 first: fc_agent_common imports it at module scope. Verify-only,
# stdlib-only, no pip resolver in this image on purpose.
COPY --chown=fc:fc bin/fc_ed25519.py      /home/fc/fc_ed25519.py
COPY --chown=fc:fc bin/fc_agent_common.py /home/fc/fc_agent_common.py
COPY --chown=fc:fc bin/agent.py           /home/fc/agent.py

ENTRYPOINT ["python3", "-u", "/home/fc/agent.py"]
