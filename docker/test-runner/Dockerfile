# fc-test-runner — in-cluster executor for FixControl sandbox environments
# (Phase 2b of docs/PLAN-multi-container-sandbox-environments.md, delivered
# over the outbound channel of docs/PLAN-fc-agent-outbound-connectivity.md).
#
# Build:
#   docker build -t fc-test-runner:1.1.0 -f docker/test-runner/Dockerfile .
#
# Supply-chain stance:
#   - Runtime is python:3.12-slim pinned by the SAME digest as
#     docker/agent/Dockerfile and docker/git-promote-bot/Dockerfile. One base
#     across the glue family means one CVE sweep, one bump, one re-publish — a
#     second digest is a second thing to forget.
#   - NOT distroless, and the reason is `git`. The runner-side checkout lane
#     (`workspaceRef.kind: "git-remote"`, P0 of
#     docs/PLAN-strict-source-residency.md) has this image clone the CUSTOMER's
#     own repository at an exact commit so the source tree never transits
#     FixControl Cloud — and distroless ships no git binary. That is the same
#     trade-off docker/agent/Dockerfile and docker/git-promote-bot/Dockerfile
#     already make, and it is why this file moved off
#     gcr.io/distroless/python3-debian12. An install that uses only
#     `channel-tar` workspaces can rebuild FROM the distroless base used by
#     docker/signer/Dockerfile and drop the apt layer entirely: nothing outside
#     `--checkout-workspace` executes a subprocess.
#   - The only apt packages are `git` and `ca-certificates`. No curl, no wget,
#     no compiler — nothing downloads at build time beyond apt itself, so there
#     is nothing to SHA-verify here (unlike the receiver/bot images, which
#     fetch kubectl).
#   - No pip. The runner and fc_agent_common are stdlib-only by design: the
#     whole trust boundary is three readable files with no transitive deps.
#
# The image is ALSO the workload the Job runs. It runs itself with
# `--fetch-workspace <operationId>`   (download → verify sha256 → unpack),
# `--checkout-workspace <operationId>` (clone → checkout the exact commit →
#                                       verify HEAD → verify + apply the patch),
# and `--sentinel` (exit 0 so the pod can Succeed once every step
# initContainer passed). One image, one digest to pin, no busybox in the trust
# boundary.
#
# This image is NOT the toolchain image: customer plan steps run in
# TestRunSpec.image (node:20-bookworm and friends), never in here.
#
# In-cluster: see install/base/test-runner/fc-test-runner.yaml.

FROM python:3.12-slim@sha256:090ba77e2958f6af52a5341f788b50b032dd4ca28377d2893dcf1ecbdfdfe203

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends git ca-certificates; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/*

# The runner and the shared outbound/authorization module. `test-runner.py`
# inserts its own directory on sys.path, so `import fc_agent_common` resolves
# to the copy next to it — not to anything a workspace could shadow.
COPY bin/test-runner.py     /app/test-runner.py
COPY bin/fc_ed25519.py      /app/fc_ed25519.py
COPY bin/fc_agent_common.py /app/fc_agent_common.py

# The GIT_ASKPASS helper. It is the only path by which a git credential reaches
# `git`, which is what keeps that credential out of every URL, argv and log
# line — read the file, it is nine lines.
COPY bin/fc-git-askpass /usr/local/bin/fc-git-askpass

# World-readable, owned by root, never writable by the runtime uid: the process
# must be able to read its own code and nothing must be able to replace it.
RUN chmod 0555 /usr/local/bin/fc-git-askpass; \
    chmod 0444 /app/*.py; \
    chmod 0555 /app

# uid 65532 (distroless' `nonroot`), kept from this image's distroless
# ancestry so the pod specs that pin `runAsUser: 65532` — the Deployment, and
# the fetch/checkout/sentinel containers of every run Job — do not have to
# change. The passwd/group entries are the ones distroless ships, recreated
# here: `git` looks the current uid up (for `~` and for the identity it would
# use if it ever committed, which it does not), and an unknown uid turns that
# lookup into a warning nobody should have to diagnose.
RUN set -eux; \
    echo 'nonroot:x:65532:65532:nonroot:/home/nonroot:/usr/sbin/nologin' >> /etc/passwd; \
    echo 'nonroot:x:65532:' >> /etc/group; \
    install -d -o 65532 -g 65532 -m 0755 /home/nonroot

USER 65532:65532
WORKDIR /app

ENV LISTEN_PORT=8080 \
    POLL_SECONDS=5 \
    NAMESPACE_TTL_SECONDS=3600 \
    MAX_CONCURRENT_RUNS=1 \
    AGENT_CAPABILITIES=test.run,test.cancel \
    WORKSPACE_DIR=/workspace \
    REPO_KEYS_FILE=/etc/fc-test-runner/repos/repos.json \
    GIT_CREDENTIALS_DIR=/etc/fc-test-runner/git \
    GIT_ASKPASS_PATH=/usr/local/bin/fc-git-askpass \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080
ENTRYPOINT ["python3", "-u", "/app/test-runner.py"]
