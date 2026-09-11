"""
fc-test-runner — the in-cluster executor for FixControl sandbox environments.

Phase 2b of docs/PLAN-multi-container-sandbox-environments.md, delivered over
the outbound channel of docs/PLAN-fc-agent-outbound-connectivity.md. FixControl
never dials in: this process polls **out** to FixControl, receives a signed,
expiring, single-use `test.run` operation whose payload is a TestRunSpec (the
Phase 1 `SandboxEnvironmentSpec` plus run metadata), materialises that spec in
an ephemeral `fc-test-<runId>` namespace, runs the plan, and posts a signed
result back — outbound. The customer's Kubernetes API is never reachable from
FixControl and its address never leaves the cluster.

Trust model, unchanged from fc-receiver: signed request in, signed result out,
every cluster write performed by customer-operated code. FixControl gains no
kubectl write surface (integration-rules §6 / sandbox invariant 6).

────────────────────────────────────────────────────────────────────────────
What one `test.run` does
────────────────────────────────────────────────────────────────────────────
  1. verify_operation()               — the local second authorization pass
  2. sanitize the runId              — /^[a-z0-9][a-z0-9-]{0,40}$/i, else
                                        refused `not_allowlisted`
  2b. local authorization of the spec — the toolchain image AND every service
                                        image against ALLOWED_TOOLCHAIN_IMAGE_
                                        PREFIXES, and every plan step's argv[0]
                                        against ALLOWED_COMMANDS. All three are
                                        refused `not_allowlisted` before a
                                        single object exists. A signed
                                        operation proves WHO asked; these
                                        bound WHAT was asked for.
  2c. resolve the workspaceRef        — `channel-tar` (the cloud packs it) or
                                        `git-remote` (this cluster checks the
                                        repository out itself; see below)
  3. create namespace fc-test-<runId> — labelled sandbox/run/tenant/expires
  4. materialise every service        — Deployment (1 replica) + headless
                                        Service, in dependsOn order
  5. resolve every image → digest     — containerStatuses[].imageID
                                        (hard error when empty: invariant 7)
  6. wait readiness                   — native exec/tcp/http probes
  7. run the plan as ONE Job          — workspace fetch OR checkout
                                        initContainer, then one initContainer
                                        per required step, then a `--sentinel`
                                        main container
  8. collect + mask + truncate logs   — invariant 10
  9. finally: delete the namespace    — every outcome, exception included
 10. TTL sweeper each poll cycle      — restart-proof backstop, invariant 8

The evidence posted back is:

    { status, steps[], resolvedImages{service: digest}, namespace,
      provisionMs, teardown,
      failureKind?, services?[{name, readiness, digest?}],
      workspace?{kind, commitSha, patchApplied, patchDigest} }

`failureKind`, `services` and `workspace` are ADDITIVE
(docs/PLAN-validation-strategy.md §I gap 7; docs/PLAN-strict-source-residency.md
P0) and appear only when this process actually knows them — an absent key is
"no claim", which FixControl reads conservatively as an infrastructure failure
and never as a reason to change code. A FixControl that has never heard of any
of them ignores all three.

`workspace.commitSha` is the commit this cluster **observed** — the
`git rev-parse HEAD` the checkout container printed, parsed back out of its
log — never the commit the request asked for. FixControl refuses evidence whose
commitSha does not match its request, and that check is worth nothing if the
runner echoes the request back at it.

FixControl computes the environment spec hash and the plan fingerprint itself
(invariant 7 — a runner that recomputed them could not be an *independent*
witness of the topology it ran). This process never recomputes them.

────────────────────────────────────────────────────────────────────────────
Where the workspace comes from — `workspaceRef` is a union
────────────────────────────────────────────────────────────────────────────
    { kind: "channel-tar", digest, sizeBytes }        ← unchanged, the default
    { kind: "git-remote",  repoKey, commitSha, patch? }

**channel-tar** — FixControl packs the workspace (no `.git`, ≤32 MB) and the
`fetch` initContainer GETs it over the outbound channel, verifies sha256
against `digest` BEFORE unpacking, and extracts it. Byte-for-byte the shipped
path; nothing about it changed.

**git-remote** (P0 of docs/PLAN-strict-source-residency.md) — the source tree
never transits FixControl Cloud. The `checkout` initContainer clones from the
**customer's own** git remote and checks out `commitSha` detached, verifies
`git rev-parse HEAD` equals it byte-for-byte, and then — only when
`patch` is present — GETs a *patch archive* over the channel, verifies its
sha256 against `patch.digest` BEFORE unpacking, and applies it (deletes first,
then the declared writes) over the checkout.

The three properties that make this lane safe, in order of how loudly they
fail:

  · **The cloud never sends a URL or a credential.** `repoKey` is an opaque
    key; it is resolved against REPO_KEYS_FILE — a ConfigMap *you* own. A
    repoKey with no local mapping is REFUSED locally (`not_allowlisted`),
    never guessed. Same posture as ALLOWED_NAMESPACES in fc-agent: a
    FixControl-side bug cannot name a repository this cluster did not
    already authorize.
  · **A wrong commit is a refusal, not a retry.** The checkout container exits
    COMMIT_SHA_MISMATCH_EXIT when HEAD is not the requested commit, which this
    process maps to refused/`bad_signature` — exactly as it maps a workspace
    digest mismatch. Infrastructure failures keep their own exit codes.
  · **The git credential never leaves the checkout container.** It travels as
    one key of the per-run Secret, mounted by `secretKeyRef` on the checkout
    initContainer only, and reaches `git` through GIT_ASKPASS — never in a URL,
    never in argv (so never in `ps`), never in a log line, never in evidence.
    Step containers (customer code) and the sentinel never see it.

Advertisement is honest: the poll body carries `workspaceKinds`, and
`git-remote` appears in it only when a non-empty repo-key map is actually
mounted. Advertising a capability this runner could not fulfil is the failure
mode the negotiation exists to prevent.

────────────────────────────────────────────────────────────────────────────
Known v1 limitations — deliberate, reported, never silently green
────────────────────────────────────────────────────────────────────────────
  · **Optional steps are not executed.** Kubernetes initContainers stop the
    chain on any non-zero exit, so a `required: false` step that fails would
    abort the run — the opposite of "advisory". Language images have no
    guaranteed shell to wrap the exit code in, and wrapping customer commands
    in a runner-supplied shim is a widening of the execution surface this
    component is not allowed to make. v1 therefore runs ONLY required steps
    and reports every non-required step as `skipped` with the log line
    "optional step not executed by in-cluster runner v1". Honest, not green.
  · **Per-step timeouts are enforced run-wide.** A Job's
    `activeDeadlineSeconds` is the only timeout Kubernetes offers across an
    initContainer chain, so `plan.steps[].timeoutMs` is not individually
    enforced; `runTimeoutMs` is. The step that was running when the deadline
    hit is reported `timeout`.
  · **`limits.pids` is not enforceable in a pod spec** (PodPidsLimit is a
    kubelet-level setting, not a container field). memoryMb and cpus are.

────────────────────────────────────────────────────────────────────────────
Identity and RBAC
────────────────────────────────────────────────────────────────────────────
This process runs as the `fc-test-runner` ServiceAccount and holds
`test.run` + `test.cancel` only. It cannot touch `argoproj.io`, nodes, CRDs,
RBAC objects or impersonation — see install/base/test-runner/fc-test-runner.yaml, where the
absence of those rules is the enforcement and scripts/smoke-* assert it.
Compromising the component that by design executes customer test code must
never yield production rollout control (plan §Identities and RBAC).

The agent secret is mounted into the run namespace on the **workspace**
initContainer only — `fetch`, or `checkout` when that one needs to pull a patch
archive — never on a step container (customer code) and never on a service. The
customer's git credential travels the same single path and no further. Nothing
else FixControl-side crosses that boundary; a git-remote run with no patch
carries no FixControl credential into the run namespace at all.

────────────────────────────────────────────────────────────────────────────
Env (Secret `fc-test-runner`)
────────────────────────────────────────────────────────────────────────────
  FIXCONTROL_URL              e.g. https://api.fixcontrol.ai
  FIXCONTROL_AGENT_ID         this runner's registered agent id
  FIXCONTROL_AGENT_SECRET     the agent's outbound signing secret
  FIXCONTROL_CLUSTER_ID       the Cluster id registered in /settings/devops
  FIXCONTROL_TENANT           the tenant this agent is bound to

Env (ConfigMap `fc-test-runner-config`)
  FIXCONTROL_SIGNING_PUBLIC_KEYS
                              base64 Ed25519 public keys (comma/space
                              separated, max 2) this cluster trusts to
                              authorize operations. Set ⇒ only `alg: ed25519`
                              is accepted; unset ⇒ legacy shared-secret
                              verification. Same pin, same ConfigMap posture
                              and same fail-closed parse as fc-agent — the
                              runner redeems the SAME envelopes, so a fleet
                              that pins for one and not the other has a
                              component still trusting the old authority.
  AGENT_NAME                  display name, default fc-test-runner
  AGENT_CAPABILITIES          default "test.run,test.cancel"
  POLL_SECONDS                default 5
  NAMESPACE_TTL_SECONDS       default 3600
  MAX_CONCURRENT_RUNS         default 1
  MAX_SKEW_SECONDS            default 300
  ALLOWED_TOOLCHAIN_IMAGE_PREFIXES   csv, empty = any (customer-owned knob).
                              Applied to the toolchain image AND to every
                              environment.services[].image, with a
                              BOUNDARY-AWARE prefix match (`ghcr.io/acme` does
                              not admit `ghcr.io/acmeattacker/x`). Empty is
                              backward-compatible and logs a loud
                              `config.image_allowlist_open` warning at startup.
  ALLOWED_COMMANDS            csv of bare binary names a plan step may invoke;
                              empty/unset = the built-in default, which
                              reproduces the cloud's own closed command set.
                              A step whose argv[0] basename is not listed
                              REFUSES the operation (`not_allowlisted`) before
                              a namespace exists — the plan is never edited.
                              An operation-supplied `extraAllowedCommands`
                              grant is INTERSECTED with this list, so FixControl
                              can narrow it and has no spelling for widening it.
  RUNNER_IMAGE                self-reference for the fetch/sentinel containers
  SERVICE_START_BUDGET_MS     default 120000 (covers an image pull)
  ALLOW_INSECURE_FIXCONTROL_URL=1     opt into plaintext http:// (dev only)
  REPO_KEYS_FILE              default /etc/fc-test-runner/repos/repos.json —
                              the CUSTOMER-OWNED repoKey → clone-URL map that
                              makes `workspaceRef.kind: "git-remote"` possible.
                              Absent or empty ⇒ the runner does not advertise
                              `git-remote` and refuses every git-remote run.
  GIT_CREDENTIALS_DIR         default /etc/fc-test-runner/git — the
                              CUSTOMER-OWNED Secret mount whose file names are
                              the `credentialKey` values used in that map.

Mounts (both customer-owned, both `optional: true` — an install that never
uses the git-remote lane needs neither)
  ConfigMap fc-test-runner-repos → REPO_KEYS_FILE
  Secret    fc-test-runner-git   → GIT_CREDENTIALS_DIR

CLI
  (no flags)                  the outbound poll loop (the Deployment)
  --fetch-workspace <opId>    in-Job workspace fetch: GET the tar.gz, verify
                              sha256 against WORKSPACE_DIGEST BEFORE
                              unpacking, extract to WORKSPACE_DIR
  --checkout-workspace <opId> in-Job workspace CHECKOUT: clone GIT_REMOTE_URL,
                              check out GIT_COMMIT_SHA detached, verify
                              `git rev-parse HEAD` equals it, then — when
                              PATCH_DIGEST is set — GET the patch archive,
                              verify its sha256 BEFORE unpacking, and apply it
                              over the checkout in WORKSPACE_DIR
  --sentinel                  exit 0; the Job's main container, so the pod
                              terminates once every step initContainer passed
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tarfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO
from typing import Any

# The shared outbound/authorization module ships next to this file in the
# image (docker/test-runner/Dockerfile copies both into /app).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fc_agent_common as common  # noqa: E402

# ═══════════════════════════ Configuration ═══════════════════════════
#
# Read at import, validated in main(). Reading here (not lazily) keeps the
# process's configuration surface visible in one place; validating in main()
# keeps the module importable by the clusterless smoke.

URL = os.environ.get("FIXCONTROL_URL", "").rstrip("/")
AGENT_ID = os.environ.get("FIXCONTROL_AGENT_ID", "")
SECRET = os.environ.get("FIXCONTROL_AGENT_SECRET", "")
CLUSTER = os.environ.get("FIXCONTROL_CLUSTER_ID", "")
TENANT = os.environ.get("FIXCONTROL_TENANT", "")
# Check 3's trust anchor; a malformed value aborts rather than silently
# reverting to shared-secret verification. See fc_agent_common.
try:
    SIGNING_PUBLIC_KEYS = common.parse_signing_public_keys(
        os.environ.get("FIXCONTROL_SIGNING_PUBLIC_KEYS"))
except common.SigningKeyConfigError as _e:
    raise SystemExit(f"fc-test-runner: {_e}") from _e
AGENT_NAME = os.environ.get("AGENT_NAME", "fc-test-runner")
CAPABILITIES = tuple(
    c.strip() for c in os.environ.get("AGENT_CAPABILITIES", "test.run,test.cancel").split(",") if c.strip()
)
POLL = float(os.environ.get("POLL_SECONDS", "5"))
NAMESPACE_TTL_SECONDS = int(os.environ.get("NAMESPACE_TTL_SECONDS", "3600"))
MAX_CONCURRENT_RUNS = max(1, int(os.environ.get("MAX_CONCURRENT_RUNS", "1")))
MAX_SKEW_SECONDS = float(os.environ.get("MAX_SKEW_SECONDS", "300"))
ALLOWED_TOOLCHAIN_IMAGE_PREFIXES = tuple(
    p.strip() for p in os.environ.get("ALLOWED_TOOLCHAIN_IMAGE_PREFIXES", "").split(",") if p.strip()
)

# ── The runner-side command allowlist ──────────────────────────────────────
#
# Pinning FixControl's signing key means a compromised control plane cannot
# FORGE authority. It does not bound WHAT a validly signed plan asks this
# cluster to execute: without this set, `plan.steps[].cmd` travels verbatim
# into an initContainer command. This is the local half of that answer, and it
# has exactly the posture of ALLOWED_NAMESPACES in fc-agent — a list this
# cluster owns, checked before a namespace exists, refused rather than trimmed.
#
# The default is DERIVED from the cloud's own closed set — every deterministic
# plan step is built from literals in
# `fixcontrol/src/server/sandbox-runtime/plan/templates.ts ALLOWED_COMMANDS`,
# and that whole set is reproduced here so no shipped template can be refused
# by an upgrade. Three additions, each deliberate:
#
#   · `sh` / `bash` — the AI-discovery grant
#     (`environment-discovery/hypothesis-policy.ts DISCOVERY_SHELL_COMMANDS`),
#     which reaches this runner as ordinary plan steps because the wire
#     `TestRunSpec` has no grant field. They are admitted ONLY in the
#     `sh <workspace-script>.sh` shape the cloud compiles them in — `-c` and
#     every other flag are refused here exactly as `shell-grant.ts` refuses
#     them there (see `step_command_refusal`).
#   · `python3` / `pip3` — the concrete interpreter names the language images
#     actually ship; the cloud spells them `python` / `pip`.
#
# `git` is deliberately NOT here, even though the checkout lane runs it. That
# lane runs it in THIS image, from `--checkout-workspace`, never as a plan
# step, and no shipped template emits `git` as one — so admitting it by default
# would widen the plan surface for nobody. It is also the widest verb that
# could go in this list: `git -c alias.x='!…' x` is an arbitrary program. An
# operator whose repository genuinely needs git as a plan step adds it
# explicitly (ALLOWED_COMMANDS=…,git), which is the deliberate, written act
# this list exists to require.
#
# FixControl can NARROW this, never widen it: an operation that carries an
# `extraAllowedCommands` grant is INTERSECTED with this set
# (`effective_allowed_commands`), so a cloud-side bug cannot add a verb.
DEFAULT_ALLOWED_COMMANDS = frozenset({
    # Node
    "node", "npm", "pnpm", "yarn", "bun", "npx",
    # Python
    "python", "python3", "pip", "pip3", "pipenv", "poetry", "pytest", "mypy", "alembic",
    # PHP
    "composer", "php",
    # Go / Rust
    "go", "cargo",
    # Java / .NET
    "mvn", "gradle", "dotnet",
    # Ruby
    "bundle", "ruby", "rake",
    # C++ — CMake / Meson
    "cmake", "ctest", "meson", "ninja", "make",
    # WINDEV runner-agent CLI
    "wdcli",
    # The shell interpreters — admitted under the SHAPE rule above, never as
    # "run this program". `git` is deliberately absent; see the note above.
    "sh", "bash",
})


def parse_allowed_commands(raw: str | None) -> frozenset[str]:
    """`ALLOWED_COMMANDS` as csv, empty/unset ⇒ the built-in default.

    A value REPLACES the default rather than extending it: this knob is the
    customer's, and "my cluster runs exactly these verbs" must be spellable.
    Names are compared as basenames, so entries are bare binary names
    (`npm`, not `/usr/bin/npm`)."""
    names = {c.strip() for c in (raw or "").replace("\n", ",").split(",")}
    names = {n for n in names if n}
    return frozenset(names) if names else DEFAULT_ALLOWED_COMMANDS


ALLOWED_COMMANDS = parse_allowed_commands(os.environ.get("ALLOWED_COMMANDS"))
RUNNER_IMAGE = os.environ.get("RUNNER_IMAGE", "fc-test-runner:1.0.0")
# Build identifier reported on every poll. `/api/agent/poll` REQUIRES it
# (pollSchema: `version: z.string().max(100)`) and records it on the
# registration for fleet triage — omitting it makes every poll a 400 and the
# runner never receives a single operation.
#
# 1.1.0 is the build that can serve `workspaceRef.kind: "git-remote"`. The poll
# body's `workspaceKinds` is what a scheduler should actually route on — this
# is fleet triage, and a build number is not a capability — but the two moving
# together is what makes "which of my runners can do the strict lane?" a
# question the fleet view can answer.
RUNNER_VERSION = "1.1.0"
SERVICE_START_BUDGET_MS = int(os.environ.get("SERVICE_START_BUDGET_MS", "120000"))
LISTEN_PORT = int(os.environ.get("LISTEN_PORT", "8080"))
# This pod's own namespace — where the persisted nonce store lives. Set from
# the downward API in the Deployment; the default is the shipped namespace.
POD_NAMESPACE = os.environ.get("POD_NAMESPACE", "fc-test-runner")
NONCE_CONFIGMAP = os.environ.get("NONCE_CONFIGMAP", "fc-test-runner-nonces")

# The customer-owned half of the git-remote workspace lane. Neither path has to
# exist: an install that never runs a strict-residency test plan mounts
# neither, the runner then advertises only `channel-tar`, and every git-remote
# operation is refused locally. Read at USE time, not at import: both are
# projected volumes an operator can update without restarting the pod.
REPO_KEYS_FILE = os.environ.get("REPO_KEYS_FILE", "/etc/fc-test-runner/repos/repos.json")
GIT_CREDENTIALS_DIR = os.environ.get("GIT_CREDENTIALS_DIR", "/etc/fc-test-runner/git")

# Log tail cap, per step, before masking is applied and the result is posted
# (invariant 10 is masking; this is the size half of the same rule).
LOG_TRUNCATE_CHARS = 64_000
MASKED = "***"

# runId shape. Anything else is a refusal, never a sanitised guess: the
# namespace name is derived from it and a silent rewrite would make two
# different runs collide in one namespace.
RUN_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,40}$", re.IGNORECASE)

# The two interpreters the command allowlist admits under a SHAPE rule rather
# than by name alone, mirroring `sandbox-runtime/shell-grant.ts`: a shell is
# only ever "run this workspace script", never "run this inline program". The
# metacharacter set is that module's `SHELL_META` — the step containers run no
# shell, so a metacharacter in an argument is a literal token that would
# silently mis-execute rather than do what it looks like.
SHELL_INTERPRETERS = frozenset({"sh", "bash"})
SHELL_META_RE = re.compile(r"[|&;<>$`()\"'\\]|[\n\r]")

# Fase-1 parity: services run --cap-drop ALL plus this fixed minimal set. A
# bare ALL-drop breaks the official postgres/redis/mysql entrypoints, so the
# acceptance topology could never reach readiness (see the Status note at the
# top of PLAN-multi-container-sandbox-environments.md). Customer `cap_add:` is
# still refused upstream — this posture is FixControl's, never the repo's.
SERVICE_CAP_ADD = ["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"]

# The fetch initContainer exits with this code when the downloaded workspace
# does not hash to workspaceRef.digest. The runner maps it back to
# refused/bad_signature — a tampered workspace is an authenticity failure, not
# an infrastructure error. Both sides of this contract are pinned by the smoke.
# The checkout initContainer reuses it for a patch archive that does not hash to
# workspaceRef.patch.digest: same claim, same family, same refusal.
WORKSPACE_DIGEST_MISMATCH_EXIT = 65

# …and this one when the checkout's `git rev-parse HEAD` is not the commit the
# operation asked for. DISTINCT from 65 so the two authenticity failures stay
# distinguishable in the evidence, and distinct from every infrastructure exit
# so a wrong commit can never be retried into a green run: it is a REFUSED run.
COMMIT_SHA_MISMATCH_EXIT = 66

CREDS_SECRET_NAME = "fc-test-runner-creds"
JOB_NAME = "fc-test-plan"
FETCH_CONTAINER = "fetch"
CHECKOUT_CONTAINER = "checkout"
SENTINEL_CONTAINER = "sentinel"

# The workspaceRef union. `channel-tar` is the default for a payload that
# carries no `kind` at all — an older FixControl never sends one, and its runs
# must keep working byte-for-byte.
WORKSPACE_KIND_CHANNEL_TAR = "channel-tar"
WORKSPACE_KIND_GIT_REMOTE = "git-remote"

# The key of the git credential inside the per-run Secret, and the name of the
# env var it lands in on the checkout initContainer.
GIT_CREDENTIAL_KEY = "GIT_CREDENTIAL"
# GIT_ASKPASS helper shipped in the image (docker/test-runner/Dockerfile). It
# prints $FC_GIT_PASSWORD / $FC_GIT_USERNAME and nothing else, which is what
# keeps the credential out of every URL, argv and log line.
GIT_ASKPASS_PATH = os.environ.get("GIT_ASKPASS_PATH", "/usr/local/bin/fc-git-askpass")
# Default HTTPS username when the repo-key entry names none. Forges that
# authenticate by token ignore the username; the ones that do not (GitHub app
# tokens) want exactly this.
DEFAULT_GIT_USERNAME = "x-access-token"

COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")

# The patch archive's root manifest, and the log event the checkout container
# emits on success. The runner parses that event back out of the container's
# log to learn the commit it ACTUALLY checked out.
PATCH_MANIFEST_NAME = ".fc-patch-manifest.json"
CHECKOUT_EVENT = "workspace.checkout_complete"
OPTIONAL_STEP_LOG = "optional step not executed by in-cluster runner v1"
UNREACHED_STEP_LOG = "step not executed: an earlier required step did not pass"

# ── Failure classification (docs/PLAN-validation-strategy.md §I) ────────────
#
# The closed vocabulary FixControl reads back as `evidence.failureKind`. It is
# ADDITIVE: an older FixControl that has never heard of the field ignores it and
# behaves exactly as before, and this runner sets it only where it genuinely
# knows the cause — an absent kind is classified host-side as `infrastructure`,
# which never fabricates a code fix.
#
# Why the runner and not the host: only this process watched the pods. "the
# image would not pull", "the container crash-looped", "nothing could be
# scheduled" and "the probes never went green" all look identical from
# FixControl Cloud — a red environment — and the first three are facts about the
# cluster while the fourth may be a fact about the change. Reporting them apart
# is the difference between notifying an operator and rewriting someone's code.
KIND_TEST_FAILURE = "test_failure"
KIND_STARTUP_FAILURE = "startup_failure"
KIND_READINESS_TIMEOUT = "readiness_timeout"
KIND_IMAGE_PULL = "image_pull"
KIND_SCHEDULING = "scheduling"
KIND_INFRASTRUCTURE = "infrastructure"
KIND_CANCELLED = "cancelled"

# Container `state.waiting.reason` values, grouped by what they mean.
IMAGE_PULL_REASONS = frozenset({
    "ErrImagePull", "ImagePullBackOff", "ImageInspectError",
    "InvalidImageName", "RegistryUnavailable", "ErrImageNeverPull",
})
STARTUP_REASONS = frozenset({
    "CrashLoopBackOff", "RunContainerError", "CreateContainerError",
    "CreateContainerConfigError", "StartError", "PostStartHookError",
})

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


class SpecError(Exception):
    """A TestRunSpec FixControl should never have sent — refused, with a
    message that names the offending service. A configuration finding."""


class DigestError(Exception):
    """Image identity could not be resolved. Hard error: invariant 7 ("the
    evidence contract does not weaken by moving executors") cannot hold
    without a digest, so a run that cannot produce one must not pass."""


class WorkspaceRefError(Exception):
    """The workspaceRef cannot be honoured by THIS cluster — an unknown kind, a
    malformed commit id, or (the load-bearing one) a `repoKey` with no mapping
    in the customer-owned repo-key file. Refused `not_allowlisted`, exactly as
    an unlisted namespace is in fc-agent: local authorization is the point."""


class RepoConfigError(ValueError):
    """The customer-owned repo-key file is present but not usable. Fails the
    boot when it is already broken at startup (a misconfigured deploy should be
    loud), and degrades to "no git-remote lane" if it breaks later — a bad edit
    to a live ConfigMap must not crash-loop a runner that is mid-run."""


# ═══════════════════════════ Logging + metrics ═══════════════════════════

_METRICS_LOCK = threading.Lock()
_metrics: dict[str, Any] = {
    "fc_test_runner_runs_total": {},               # {outcome: n}
    "fc_test_runner_namespaces_reclaimed_total": 0,
    "fc_test_runner_operations_refused_total": {},  # {reason: n}
    "fc_test_runner_poll_failures_total": 0,
}


def log_event(level: str, event: str, **fields: object) -> None:
    """JSON-on-stdout structured log — same field discipline as signer.py so
    one SIEM rule covers the whole glue family."""
    line = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "event": event,
        "agent": AGENT_NAME,
        "cluster": CLUSTER or None,
        **{k: v for k, v in fields.items() if v is not None},
    }
    print(json.dumps({k: v for k, v in line.items() if v is not None}, separators=(",", ":")), flush=True)


def _metric_bump(key: str, sub: str | None = None, n: int | float = 1) -> None:
    with _METRICS_LOCK:
        if sub is None:
            _metrics[key] = _metrics[key] + n
        else:
            _metrics[key][sub] = _metrics[key].get(sub, 0) + n


def render_metrics() -> bytes:
    """Prometheus exposition (text/plain; version=0.0.4)."""
    lines: list[str] = []
    with _METRICS_LOCK:
        lines.append("# HELP fc_test_runner_runs_total Completed test runs by outcome.")
        lines.append("# TYPE fc_test_runner_runs_total counter")
        for outcome, n in sorted(_metrics["fc_test_runner_runs_total"].items()):
            lines.append(f'fc_test_runner_runs_total{{outcome="{outcome}"}} {n}')
        lines.append("# HELP fc_test_runner_namespaces_reclaimed_total Expired fc-test-* namespaces swept.")
        lines.append("# TYPE fc_test_runner_namespaces_reclaimed_total counter")
        lines.append(
            f'fc_test_runner_namespaces_reclaimed_total {_metrics["fc_test_runner_namespaces_reclaimed_total"]}'
        )
        lines.append("# HELP fc_test_runner_operations_refused_total Operations refused by reason code.")
        lines.append("# TYPE fc_test_runner_operations_refused_total counter")
        for reason, n in sorted(_metrics["fc_test_runner_operations_refused_total"].items()):
            lines.append(f'fc_test_runner_operations_refused_total{{reason="{reason}"}} {n}')
        lines.append("# HELP fc_test_runner_poll_failures_total Failed outbound poll cycles.")
        lines.append("# TYPE fc_test_runner_poll_failures_total counter")
        lines.append(f'fc_test_runner_poll_failures_total {_metrics["fc_test_runner_poll_failures_total"]}')
    body = ("\n".join(lines) + "\n").encode("utf-8")
    # The shared module keeps its own outbound/retry/DLQ/nonce-store counters.
    # Appending them means one scrape shows both halves of this process — an
    # outbound failure that never becomes a run failure is exactly the kind of
    # thing that must not be invisible (invariant 9).
    try:
        body += common.render_metrics()
    except Exception:  # noqa: BLE001 — /metrics must never be the thing that breaks
        pass
    return body


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802 — BaseHTTPRequestHandler's contract
        if self.path == "/healthz":
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")
            return
        if self.path == "/metrics":
            body = render_metrics()
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, fmt, *args):
        return  # structured events only


def start_health_server() -> None:
    srv = HTTPServer(("0.0.0.0", LISTEN_PORT), _HealthHandler)
    threading.Thread(target=srv.serve_forever, name="healthz", daemon=True).start()


# ═══════════════════════ Pure helpers (no IO, smoke-pinned) ═══════════════════════


def sanitize_run_id(run_id: str) -> str | None:
    """Return the lowercased runId when it matches the accepted shape, else
    None. The namespace name derives from this, so nothing is coerced: an
    unacceptable runId is refused with `not_allowlisted`."""
    if not isinstance(run_id, str):
        return None
    candidate = run_id.strip()
    if not RUN_ID_RE.match(candidate):
        return None
    return candidate.lower()


def namespace_for(run_id: str) -> str:
    return f"fc-test-{run_id}"


def label_value(value: str) -> str:
    """Kubernetes label values are [A-Za-z0-9._-]{0,63}. Tenant ids and run
    ids are ours, but a label rejected by the API server would fail the whole
    namespace create — so coerce defensively. Labels are attribution for the
    sweeper, never a tenancy control."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "-", str(value or ""))[:63]
    return cleaned.strip("-._") or "unknown"


def order_services(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """dependsOn topological order. Dangling and cyclic references raise —
    messages match the Phase 1 executor (environment/lifecycle.ts
    `orderServices`) so the same finding reads identically whichever executor
    produced it."""
    by_name = {s.get("name"): s for s in services}
    remaining = sorted(services, key=lambda s: str(s.get("name")))
    for s in remaining:
        for dep in s.get("dependsOn") or []:
            if dep not in by_name:
                raise SpecError(
                    f'environment: service "{s.get("name")}" depends on unknown service "{dep}"'
                )
    started: set[str] = set()
    ordered: list[dict[str, Any]] = []
    while len(ordered) < len(remaining):
        nxt = next(
            (s for s in remaining
             if s.get("name") not in started
             and all(d in started for d in (s.get("dependsOn") or []))),
            None,
        )
        if nxt is None:
            stuck = sorted(str(s.get("name")) for s in remaining if s.get("name") not in started)
            raise SpecError(f"environment: dependsOn cycle between services {', '.join(stuck)}")
        started.add(str(nxt.get("name")))
        ordered.append(nxt)
    return ordered


def probe_timing(timeout_ms: int) -> dict[str, int]:
    """Map the spec's single `timeoutMs` *budget* onto Kubernetes' periodic
    probe model.

    A ReadinessProbe in the spec says "this service has this long to become
    ready". A Kubernetes probe has no total budget — it has a period, a
    per-attempt timeout and a failure threshold. The mapping keeps the total
    equal to the budget:

        periodSeconds     = 2  (1 when the budget is under 4s)
        timeoutSeconds    = periodSeconds
        failureThreshold  = ceil(budget / periodSeconds)
        initialDelay      = 0   (the budget already covers startup)

    so the probe gives up after ~timeoutMs, and the runner's own readiness
    deadline (sum of budgets + a start budget covering image pulls) is the
    outer bound.
    """
    total = max(1, int(round((timeout_ms or 0) / 1000.0)))
    period = 2 if total >= 4 else 1
    failure = max(1, -(-total // period))  # ceil
    return {
        "initialDelaySeconds": 0,
        "periodSeconds": period,
        "timeoutSeconds": period,
        "successThreshold": 1,
        "failureThreshold": failure,
    }


def k8s_probe(readiness: dict[str, Any] | None) -> dict[str, Any] | None:
    """SandboxEnvironmentSpec ReadinessProbe → a native Kubernetes probe.

    Native probes, not runner-side polling: the kubelet already runs them next
    to the container, so a probe that passes is the *cluster's* judgement, not
    ours. Execution point per type mirrors the spec:

      exec → exec.command   (runs inside the service container)
      tcp  → tcpSocket      (`host` is dropped: the kubelet probes the pod it
                             owns, and a cross-pod host would probe the wrong
                             thing — the spec's host is the DNS name of this
                             very service)
      http → httpGet        (scheme/port/path parsed out of `url`; the host
                             component is dropped for the same reason)
    """
    if not readiness:
        return None
    kind = readiness.get("type")
    timing = probe_timing(int(readiness.get("timeoutMs") or 0))
    if kind == "exec":
        argv = [str(a) for a in (readiness.get("argv") or [])]
        if not argv:
            raise SpecError("environment: exec readiness probe has an empty argv")
        return {"exec": {"command": argv}, **timing}
    if kind == "tcp":
        port = int(readiness.get("port") or 0)
        if port <= 0:
            raise SpecError("environment: tcp readiness probe has no port")
        return {"tcpSocket": {"port": port}, **timing}
    if kind == "http":
        parsed = urllib.parse.urlsplit(str(readiness.get("url") or ""))
        if parsed.scheme not in ("http", "https"):
            raise SpecError("environment: http readiness probe needs an http(s) url")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        return {
            "httpGet": {
                "path": parsed.path or "/",
                "port": port,
                "scheme": parsed.scheme.upper(),
            },
            **timing,
        }
    raise SpecError(f"environment: unknown readiness probe type {kind!r}")


def resource_requirements(limits: dict[str, Any] | None, *, default_memory_mb: int,
                          default_cpus: float) -> dict[str, Any]:
    """ServiceLimits → pod resources. requests == limits so the scheduler
    reserves exactly what the run may consume (the aggregate budget FixControl
    validated is only real if the cluster honours it).

    `limits.pids` has no container-spec equivalent — PodPidsLimit is a kubelet
    setting — so it is not enforceable here and is deliberately dropped rather
    than silently pretended."""
    memory_mb = int((limits or {}).get("memoryMb") or default_memory_mb)
    cpus = float((limits or {}).get("cpus") or default_cpus)
    quantities = {"memory": f"{memory_mb}Mi", "cpu": f"{int(round(cpus * 1000))}m"}
    return {"limits": dict(quantities), "requests": dict(quantities)}


def namespace_manifest(run_id: str, tenant: str, expires_epoch: int) -> dict[str, Any]:
    """The ephemeral run namespace. `fixcontrol.expires` is what makes
    reclamation survive this process dying: any fc-test-runner, including a
    freshly restarted one, can read the label and sweep (invariant 8)."""
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": namespace_for(run_id),
            "labels": {
                "fixcontrol.sandbox": "1",
                "fixcontrol.run": label_value(run_id),
                "fixcontrol.tenant": label_value(tenant),
                "fixcontrol.expires": str(int(expires_epoch)),
                "app.kubernetes.io/part-of": "fixcontrol-k8s-glue",
            },
        },
    }


def _pod_security_context() -> dict[str, Any]:
    return {"seccompProfile": {"type": "RuntimeDefault"}}


def deployment_manifest(namespace: str, run_id: str, tenant: str,
                        service: dict[str, Any]) -> dict[str, Any]:
    """One SandboxServiceSpec → a 1-replica Deployment.

    Container posture: `capabilities.drop: [ALL]` plus SERVICE_CAP_ADD (Fase-1
    parity), `allowPrivilegeEscalation: false`, seccomp RuntimeDefault, no SA
    token. `runAsNonRoot` is deliberately NOT forced: the official database
    images start as root, chown their data dir and drop privileges themselves
    — forcing non-root here makes the plan's own acceptance topology
    unschedulable, which is exactly the Fase-1 finding.
    """
    name = str(service.get("name"))
    container: dict[str, Any] = {
        "name": name,
        "image": str(service.get("image")),
        "imagePullPolicy": "IfNotPresent",
        "env": [{"name": k, "value": str(v)} for k, v in sorted((service.get("env") or {}).items())],
        "resources": resource_requirements(service.get("limits"), default_memory_mb=512, default_cpus=1.0),
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "capabilities": {"drop": ["ALL"], "add": list(SERVICE_CAP_ADD)},
            "seccompProfile": {"type": "RuntimeDefault"},
        },
    }
    if service.get("entrypoint"):
        container["command"] = [str(a) for a in service["entrypoint"]]
    if service.get("command"):
        container["args"] = [str(a) for a in service["command"]]
    probe = k8s_probe(service.get("readiness"))
    if probe:
        container["readinessProbe"] = probe
    labels = {
        "fixcontrol.sandbox": "1",
        "fixcontrol.run": label_value(run_id),
        "fixcontrol.role": "service",
        "fixcontrol.service": label_value(name),
    }
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": {**labels, "fixcontrol.tenant": label_value(tenant)},
        },
        "spec": {
            "replicas": 1,
            "selector": {"matchLabels": {"fixcontrol.service": label_value(name)}},
            "template": {
                "metadata": {"labels": labels},
                "spec": {
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "restartPolicy": "Always",
                    "securityContext": _pod_security_context(),
                    "containers": [container],
                },
            },
        },
    }


def headless_service_manifest(namespace: str, run_id: str, service_name: str) -> dict[str, Any]:
    """A **headless** ClusterIP Service (`clusterIP: None`) per service.

    Why headless: a normal ClusterIP Service only forwards ports it was told
    about, and the spec does not carry a port list — readiness probes name at
    most one port, and plenty of services are talked to on ports no probe
    mentions (a worker's metrics port, a second listener). Headless makes DNS
    resolve `<name>.<ns>.svc` straight to the pod IP, so **every** port the
    container listens on is reachable without the runner having to know it, and
    no port knowledge has to be invented from the readiness probe. It also
    keeps the environment reachable only from inside the namespace: there is no
    virtual IP and no published host port anywhere in this manifest.
    """
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": service_name,
            "namespace": namespace,
            "labels": {"fixcontrol.sandbox": "1", "fixcontrol.run": label_value(run_id)},
        },
        "spec": {
            "clusterIP": "None",
            "selector": {"fixcontrol.service": label_value(service_name)},
            # A headless Service needs no port list to give DNS the pod IP.
            "ports": [],
        },
    }


def creds_secret_manifest(namespace: str, run_id: str, secret_value: str,
                          git_credential: str = "") -> dict[str, Any]:
    """The credentials this ONE run needs, scoped to its own namespace and
    mounted on the workspace initContainer only. It dies with the namespace.

    Two keys, each present only when the run actually needs it:

      FIXCONTROL_AGENT_SECRET — to GET the workspace tar (channel-tar) or the
        patch archive (git-remote WITH a patch). A git-remote run with no patch
        talks to FixControl not at all from inside the run namespace, and then
        this key is absent: the strictest lane leaves no FixControl credential
        anywhere near the customer's code.
      GIT_CREDENTIAL — the customer's own forge credential, when their repo-key
        entry names one. It reaches `git` through GIT_ASKPASS and therefore
        never appears in a remote URL, in argv or in a log line.

    Returns None when the run needs neither, so nothing is created for nothing.
    """
    data: dict[str, str] = {}
    if secret_value:
        data["FIXCONTROL_AGENT_SECRET"] = base64.b64encode(
            secret_value.encode("utf-8")).decode("ascii")
    if git_credential:
        data[GIT_CREDENTIAL_KEY] = base64.b64encode(
            git_credential.encode("utf-8")).decode("ascii")
    return {
        "apiVersion": "v1",
        "kind": "Secret",
        "type": "Opaque",
        "metadata": {
            "name": CREDS_SECRET_NAME,
            "namespace": namespace,
            "labels": {"fixcontrol.sandbox": "1", "fixcontrol.run": label_value(run_id)},
        },
        "data": data,
    }


def step_container_name(index: int, step: dict[str, Any]) -> str:
    """DNS-1123 label for one step's initContainer. Index-prefixed so ordering
    is readable in `kubectl describe` and two steps with the same name cannot
    collide."""
    slug = re.sub(r"[^a-z0-9]+", "-", str(step.get("name") or step.get("kind") or "step").lower())
    slug = slug.strip("-")[:40] or "step"
    return f"step-{index}-{slug}"


def job_manifest(namespace: str, run_id: str, spec: dict[str, Any], operation_id: str,
                 runner_image: str, resolved_workspace: dict[str, Any] | None = None,
                 ) -> tuple[dict[str, Any], list[tuple[str, dict[str, Any]]], list[dict[str, Any]]]:
    """Build the single test Job.

    Returns `(manifest, executed, skipped)` where `executed` binds each
    initContainer name to the step it runs and `skipped` carries the
    non-required steps this v1 does not execute (see the header).

    Shape: ONE workspace initContainer (runner image) → one initContainer per
    required step (the toolchain image, `[cmd] + args`, workingDir under
    /workspace) → a `--sentinel` main container that exits 0 so the pod can
    Succeed. The pod carries no ServiceAccount token, no host namespaces and no
    hostPath.

    The workspace initContainer is `fetch` (digest-verified tarball over the
    channel) or `checkout` (clone + verified detached checkout from the
    customer's own remote, then the verified patch archive), decided by
    `resolved_workspace["kind"]` — `resolve_workspace_ref()`'s output, never the
    raw payload. Absent, it is the channel-tar path, byte-for-byte unchanged.

    Whichever it is, it is the ONLY container in this pod that receives a
    credential of any kind. Step containers run customer code and get the
    workspace volume and nothing else.
    """
    plan = spec.get("plan") or {}
    steps = list(plan.get("steps") or [])
    # Re-asserted here and not only at the refusal site: this function is what
    # turns `plan.steps[].cmd` into an initContainer command, so the guard
    # belongs on the same side of that wall. A plan reaching here unvalidated is
    # a bug in this file, and it stops in this process rather than in a pod.
    validate_plan_commands(plan, spec.get("extraAllowedCommands"))
    step_env = spec.get("env") or {}
    resolved = resolved_workspace or resolve_workspace_ref(spec.get("workspaceRef") or {}, {})
    toolchain = str(spec.get("image") or "")
    run_timeout_ms = int(spec.get("runTimeoutMs") or 0)

    workspace_mount = {"name": "workspace", "mountPath": "/workspace"}
    hardened = {
        "allowPrivilegeEscalation": False,
        "capabilities": {"drop": ["ALL"]},
        "seccompProfile": {"type": "RuntimeDefault"},
    }
    agent_secret_env = {
        "name": "FIXCONTROL_AGENT_SECRET",
        "valueFrom": {"secretKeyRef": {"name": CREDS_SECRET_NAME,
                                       "key": "FIXCONTROL_AGENT_SECRET"}},
    }
    # The shared FCClient refuses a plaintext FIXCONTROL_URL on construction, so
    # the dev-rig opt-in has to travel with it — otherwise the workspace
    # container fails a run the runner itself was configured to allow. Absent in
    # production, where it must be.
    insecure_env = {"name": "ALLOW_INSECURE_FIXCONTROL_URL",
                    "value": os.environ.get("ALLOW_INSECURE_FIXCONTROL_URL", "")}
    volumes: list[dict[str, Any]] = [{"name": "workspace", "emptyDir": {}}]

    if resolved.get("kind") == WORKSPACE_KIND_GIT_REMOTE:
        needs_patch = bool(resolved.get("patchDigest"))
        checkout_env: list[dict[str, Any]] = [
            # No credential here and none anywhere else in this pod spec: the
            # URL is the customer's own, resolved from THEIR ConfigMap, and it
            # carries no userinfo by construction.
            {"name": "GIT_REMOTE_URL", "value": str(resolved.get("url") or "")},
            {"name": "GIT_COMMIT_SHA", "value": str(resolved.get("commitSha") or "")},
            {"name": "GIT_USERNAME", "value": str(resolved.get("username") or "")},
            {"name": "WORKSPACE_DIR", "value": "/workspace"},
            {"name": "PATCH_DIGEST", "value": str(resolved.get("patchDigest") or "")},
            {"name": "PATCH_SIZE_BYTES", "value": str(resolved.get("patchSizeBytes") or 0)},
        ]
        if needs_patch:
            # Only a run that must pull a patch archive gets a FixControl
            # credential inside the run namespace at all.
            checkout_env += [
                {"name": "FIXCONTROL_URL", "value": URL},
                {"name": "FIXCONTROL_AGENT_ID", "value": AGENT_ID},
                insecure_env,
                agent_secret_env,
            ]
        if resolved.get("credentialKey"):
            checkout_env.append({
                "name": GIT_CREDENTIAL_KEY,
                "valueFrom": {"secretKeyRef": {"name": CREDS_SECRET_NAME,
                                               "key": GIT_CREDENTIAL_KEY}},
            })
        # A private, memory-backed HOME for git: it wants somewhere to write
        # while the root filesystem stays read-only, and mounting it on this
        # container ONLY means no step container can read what git left behind.
        volumes.append({"name": "checkout-home",
                        "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}})
        checkout_env.append({"name": "HOME", "value": "/home/checkout"})
        workspace_container = {
            "name": CHECKOUT_CONTAINER,
            "image": runner_image,
            "imagePullPolicy": "IfNotPresent",
            "args": ["--checkout-workspace", operation_id],
            "env": checkout_env,
            "volumeMounts": [workspace_mount,
                             {"name": "checkout-home", "mountPath": "/home/checkout"}],
            "resources": resource_requirements(None, default_memory_mb=1024, default_cpus=1.0),
            "securityContext": {**hardened, "runAsNonRoot": True, "runAsUser": 65532,
                                "readOnlyRootFilesystem": True},
        }
    else:
        workspace_container = {
            "name": FETCH_CONTAINER,
            "image": runner_image,
            "imagePullPolicy": "IfNotPresent",
            "args": ["--fetch-workspace", operation_id],
            "env": [
                {"name": "FIXCONTROL_URL", "value": URL},
                {"name": "FIXCONTROL_AGENT_ID", "value": AGENT_ID},
                {"name": "WORKSPACE_DIGEST", "value": str(resolved.get("digest") or "")},
                {"name": "WORKSPACE_SIZE_BYTES", "value": str(resolved.get("sizeBytes") or 0)},
                {"name": "WORKSPACE_DIR", "value": "/workspace"},
                insecure_env,
                agent_secret_env,
            ],
            "volumeMounts": [workspace_mount],
            "resources": resource_requirements(None, default_memory_mb=512, default_cpus=0.5),
            "securityContext": {**hardened, "runAsNonRoot": True, "runAsUser": 65532,
                                "readOnlyRootFilesystem": True},
        }

    executed: list[tuple[str, dict[str, Any]]] = []
    skipped: list[dict[str, Any]] = []
    init_containers: list[dict[str, Any]] = [workspace_container]
    for i, step in enumerate(steps):
        if not step.get("required", True):
            # v1 limitation, reported honestly — see the module header.
            skipped.append(step)
            continue
        name = step_container_name(i, step)
        cwd = str(step.get("cwd") or "").strip("/")
        init_containers.append({
            "name": name,
            "image": toolchain,
            "imagePullPolicy": "IfNotPresent",
            "command": [str(step.get("cmd"))] + [str(a) for a in (step.get("args") or [])],
            "workingDir": f"/workspace/{cwd}" if cwd else "/workspace",
            "env": [{"name": k, "value": str(v)} for k, v in sorted(step_env.items())],
            "volumeMounts": [workspace_mount],
            "resources": resource_requirements(None, default_memory_mb=2048, default_cpus=1.0),
            "securityContext": dict(hardened),
        })
        executed.append((name, step))

    manifest = {
        "apiVersion": "batch/v1",
        "kind": "Job",
        "metadata": {
            "name": JOB_NAME,
            "namespace": namespace,
            "labels": {"fixcontrol.sandbox": "1", "fixcontrol.run": label_value(run_id),
                       "fixcontrol.role": "plan"},
        },
        "spec": {
            # One attempt only. A retried test run is a different run: it would
            # re-execute steps against a workspace the first attempt may have
            # mutated, and report a green that never happened in one pass.
            "backoffLimit": 0,
            # The only timeout Kubernetes offers across an initContainer chain
            # (see the header's per-step-timeout limitation).
            "activeDeadlineSeconds": max(1, -(-run_timeout_ms // 1000)),
            "template": {
                "metadata": {"labels": {"fixcontrol.sandbox": "1",
                                        "fixcontrol.run": label_value(run_id),
                                        "fixcontrol.role": "plan"}},
                "spec": {
                    "restartPolicy": "Never",
                    # Customer test code must never receive a cluster identity.
                    "automountServiceAccountToken": False,
                    "enableServiceLinks": False,
                    "securityContext": _pod_security_context(),
                    "volumes": volumes,
                    "initContainers": init_containers,
                    "containers": [{
                        "name": SENTINEL_CONTAINER,
                        "image": runner_image,
                        "imagePullPolicy": "IfNotPresent",
                        "args": ["--sentinel"],
                        "resources": resource_requirements(None, default_memory_mb=64, default_cpus=0.05),
                        "securityContext": {**hardened, "runAsNonRoot": True, "runAsUser": 65532,
                                            "readOnlyRootFilesystem": True},
                    }],
                },
            },
        },
    }
    return manifest, executed, skipped


def resolve_digest(image_id: str) -> str:
    """containerStatuses[].imageID → the image identity provenance binds to.

    Parity with the Phase 1 Docker executor, which stores `RepoDigests[0]`
    (`repo@sha256:…`) and falls back to the local image id. CRI runtimes spell
    the same thing differently:

        docker-pullable://ghcr.io/acme/api@sha256:ab…   (dockershim)
        docker.io/library/postgres@sha256:ab…           (containerd)
        sha256:ab…                                      (locally loaded image)

    Empty or digest-free is a hard error, not a null: invariant 7.
    """
    raw = (image_id or "").strip()
    for prefix in ("docker-pullable://", "docker://", "containerd://", "cri-o://"):
        if raw.startswith(prefix):
            raw = raw[len(prefix):]
            break
    if not raw or "sha256:" not in raw:
        raise DigestError(
            f"environment: could not resolve an image digest from imageID {image_id!r}"
        )
    return raw


def mask_log(text: str, mask_values: list[str] | None) -> str:
    """Replace every literal secret value with `***` BEFORE the log leaves the
    cluster (invariant 10). Longest first, so a value that contains another
    value cannot leave a fragment behind."""
    out = text or ""
    for value in sorted([v for v in (mask_values or []) if v], key=len, reverse=True):
        out = out.replace(value, MASKED)
    return out


def truncate_log(text: str) -> str:
    """Tail-cap at LOG_TRUNCATE_CHARS. The tail is kept: a failure's last
    output is the diagnostic, the build banner is not."""
    if len(text) <= LOG_TRUNCATE_CHARS:
        return text
    kept = text[-LOG_TRUNCATE_CHARS:]
    return f"[… truncated {len(text) - LOG_TRUNCATE_CHARS} chars …]\n{kept}"


def expired_namespaces(items: list[dict[str, Any]], now: float) -> list[str]:
    """TTL sweep selection: labelled sandbox namespaces whose
    `fixcontrol.expires` is in the past. A namespace already Terminating is
    left alone (deleting it again is a no-op that only produces noise), and an
    unparseable/absent expires label is left alone too — the sweeper reclaims
    what it can prove is expired, never what it merely does not recognise."""
    out: list[str] = []
    for ns in items or []:
        meta = ns.get("metadata") or {}
        labels = meta.get("labels") or {}
        if labels.get("fixcontrol.sandbox") != "1":
            continue
        if (ns.get("status") or {}).get("phase") == "Terminating":
            continue
        try:
            expires = int(labels.get("fixcontrol.expires"))
        except (TypeError, ValueError):
            continue
        if expires < now:
            out.append(str(meta.get("name")))
    return sorted(out)


def image_allowed(image: str, prefixes: "tuple[str, ...] | list[str]") -> bool:
    """Customer-owned image allowlist, applied to the toolchain image AND to
    every `environment.services[].image` — both are pulled and run in this
    cluster, so allowlisting one and not the other allowlists nothing.

    Empty list = any image, which is the documented default and stays that way
    for backward compatibility: FixControl already pins service images through
    its own SANDBOX_ENV_IMAGE_ALLOWLIST, and this knob exists so a platform team
    can *additionally* close the door on their own terms. An empty list is
    announced loudly at startup (`config.image_allowlist_open`) precisely
    because it is the permissive setting, unlike ALLOWED_NAMESPACES in fc-agent
    which allowlists nothing when empty.

    The match is BOUNDARY-AWARE, mirroring `imageMatchesAllowlist` in
    `src/server/environment-discovery/services.ts`: a prefix matches at a
    path/tag/digest boundary or exactly, so `ghcr.io/acme` covers
    `ghcr.io/acme`, `ghcr.io/acme/x` and `ghcr.io/acme:1` but NOT
    `ghcr.io/acmeattacker/x` — which a bare `startswith` waved straight through
    onto this cluster's kubelet.
    """
    if not prefixes:
        return True
    ref = str(image)
    for prefix in prefixes:
        if not prefix:
            continue
        if ref == prefix:
            return True
        if not ref.startswith(prefix):
            continue
        # A prefix that already ends on a boundary is satisfied by the
        # startswith; otherwise the next character of the image must be one.
        if prefix[-1] in ("/", ":", "@") or ref[len(prefix)] in ("/", ":", "@"):
            return True
    return False


def unallowed_service_images(services: "list[dict[str, Any]]",
                             prefixes: "tuple[str, ...] | list[str]") -> list[str]:
    """`name (image)` for every service image outside the allowlist. Separate
    from the toolchain check only so the refusal message can name which
    services are the problem — a spec with four services and one bad image is
    a two-character fix the operator should not have to hunt for."""
    return [f"{svc.get('name')} ({svc.get('image')})"
            for svc in (services or [])
            if not image_allowed(str(svc.get("image") or ""), prefixes)]


# ── The command allowlist (the local half of "what may run here") ──────────


def _contained_rel_path(rel: str) -> bool:
    """Workspace-relative containment, textual half — mirrors `containedRelPath`
    in `sandbox-runtime/shell-grant.ts`. The tree does not exist yet when a plan
    is validated, so this is a shape check only; the workspace volume is an
    emptyDir the step containers cannot escape anyway."""
    if not rel or rel.startswith("/") or rel.startswith("\\"):
        return False
    if re.match(r"^[A-Za-z]:", rel):
        return False
    return ".." not in re.split(r"[\\/]+", rel)


def effective_allowed_commands(
    extra: "list[str] | tuple[str, ...] | None",
) -> tuple[frozenset[str], list[str]]:
    """`(allowed, dropped)` for one operation.

    An operation may carry `extraAllowedCommands` (the cloud's AI-discovery
    grant). It is INTERSECTED with this cluster's list, never unioned: the
    control plane may narrow what runs here, and has no spelling for widening
    it. `dropped` is what the grant asked for and did not get — logged, so an
    operator sees a control plane reaching past the local list instead of
    wondering why a run was refused."""
    granted = {os.path.basename(str(c).strip().replace("\\", "/")) for c in (extra or [])}
    granted = {g for g in granted if g}
    return frozenset(ALLOWED_COMMANDS | (granted & ALLOWED_COMMANDS)), sorted(granted - ALLOWED_COMMANDS)


def step_command_refusal(step: dict[str, Any], allowed: "frozenset[str]") -> str | None:
    """Why this plan step may not run in this cluster, or None when it may.

    The check is on `argv[0]`'s BASENAME, so `/usr/local/bin/npm` and `npm` are
    the same verb and a path cannot smuggle one past the list. The message is
    the operator's, not FixControl's: it names the step, the command and the
    setting to change, because the fix is a ConfigMap edit or a conversation
    with FixControl — never a silently rewritten plan.
    """
    name = str(step.get("name") or step.get("kind") or "step")
    argv = [str(step.get("cmd") or "")] + [str(a) for a in (step.get("args") or [])]
    cmd = argv[0].strip()
    if not cmd:
        return f"step {name!r} carries no command"
    base = os.path.basename(cmd.replace("\\", "/"))
    if base not in allowed:
        return (f"step {name!r} runs {cmd!r}, which is not on this cluster's command "
                f"allowlist. Add it to ALLOWED_COMMANDS in the fc-test-runner-config "
                f"ConfigMap if this cluster should run it, or ask FixControl why the "
                f"plan asked for it. Allowed: {', '.join(sorted(allowed))}")
    if base in SHELL_INTERPRETERS:
        # Same rule as `shell-grant.ts`: a shell is "run this workspace script",
        # never an inline program. `sh -c "curl … | sh"` is refused here even
        # though `sh` is allowlisted.
        script = argv[1] if len(argv) > 1 else ""
        if not script or script.startswith("-"):
            return (f"step {name!r} runs {base!r} with no workspace script; "
                    f"{base!r} is honoured only as \"{base} <workspace-script>.sh\", and "
                    f"flags such as \"-c\" are refused — an inline shell program is not "
                    f"repository evidence")
        if not script.lower().endswith(".sh") or not _contained_rel_path(script):
            return (f"step {name!r} runs {base} {script!r}: the script must be a "
                    f"workspace-relative *.sh path with no \"..\" segments")
        # argv[1:] — the script path itself included, exactly as shell-grant.ts
        # scans it.
        offending = [a for a in argv[1:] if SHELL_META_RE.search(a)]
        if offending:
            return (f"step {name!r} passes shell metacharacters to {base}: "
                    f"{', '.join(repr(a) for a in offending)} — the step container runs no "
                    f"shell, so these would be literal tokens, not the program they look like")
    return None


def validate_plan_commands(plan: dict[str, Any],
                           extra: "list[str] | tuple[str, ...] | None" = None) -> None:
    """Refuse the whole plan when any step names a command this cluster does not
    allow. Raises `SpecError`, which `execute_test_run` posts back as
    refused/`not_allowlisted` BEFORE the run namespace exists.

    Every step is checked, including the `required: false` ones this v1 does
    not execute: a plan is refused for what it asks for, and a plan carrying a
    step this cluster would not run is a finding whether or not the initContainer
    chain would have reached it."""
    allowed, dropped = effective_allowed_commands(extra)
    if dropped:
        # Never fatal on its own — the grant is narrowed to nothing and the run
        # continues under the local list — but never silent either.
        log_event("warn", "plan.extra_commands_dropped", commands=dropped,
                  message="the operation asked for commands outside this cluster's "
                          "ALLOWED_COMMANDS; the local list is the ceiling")
    for step in (plan or {}).get("steps") or []:
        why = step_command_refusal(step, allowed)
        if why:
            raise SpecError(f"plan: {why}")


# ── The git-remote workspace lane (docs/PLAN-strict-source-residency.md P0) ──


def parse_repo_keys(text: str) -> dict[str, dict[str, str]]:
    """The customer-owned `repoKey → clone URL` map, validated.

    Two accepted spellings, because the common case should not need a nested
    object and the credentialed case must not be squeezed into a string:

        { "acme-api": "https://git.internal.example/acme/api.git" }
        { "acme-api": { "url": "…", "credentialKey": "acme-ci",
                        "username": "fixcontrol-ci", "insecure": false } }

    Rules, all fail-closed:
      · https:// only, unless the entry says `"insecure": true` — a token sent
        over plaintext http is a leaked token, and this file is the only place
        anyone could opt into that, deliberately and in writing.
      · `credentialKey` is a bare file name: it is joined onto
        GIT_CREDENTIALS_DIR, so a path separator in it would read an arbitrary
        file out of the pod.
      · An entry that does not validate fails the WHOLE file. A map that
        silently dropped its broken half would advertise a lane it cannot serve
        for the repositories that matter most to whoever wrote the broken half.
    """
    try:
        raw = json.loads(text or "{}")
    except ValueError as e:
        raise RepoConfigError(f"repo-key file is not valid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise RepoConfigError("repo-key file must be a JSON object of repoKey → entry")
    out: dict[str, dict[str, str]] = {}
    for key, value in raw.items():
        if not isinstance(key, str) or not key.strip():
            raise RepoConfigError("repo-key file has an empty repoKey")
        entry = {"url": value} if isinstance(value, str) else value
        if not isinstance(entry, dict):
            raise RepoConfigError(f"repoKey {key!r}: entry must be a URL string or an object")
        url = str(entry.get("url") or "").strip()
        if not url:
            raise RepoConfigError(f"repoKey {key!r}: no url")
        insecure = bool(entry.get("insecure"))
        if url.startswith("http://"):
            if not insecure:
                raise RepoConfigError(
                    f"repoKey {key!r}: plaintext http:// remote without \"insecure\": true — "
                    f"a credential sent over http is a disclosed credential")
        elif not url.startswith("https://"):
            raise RepoConfigError(
                f"repoKey {key!r}: url must be https:// (or http:// with \"insecure\": true). "
                f"ssh:// remotes are not served by this runner — see the module header.")
        credential_key = str(entry.get("credentialKey") or "").strip()
        if credential_key and (os.sep in credential_key or credential_key in (".", "..")
                               or credential_key.startswith(".")):
            raise RepoConfigError(
                f"repoKey {key!r}: credentialKey {credential_key!r} must be a bare Secret key")
        resolved: dict[str, str] = {"url": url}
        if credential_key:
            resolved["credentialKey"] = credential_key
        username = str(entry.get("username") or "").strip()
        if username:
            resolved["username"] = username
        out[key.strip()] = resolved
    return out


_repo_keys_error_logged = ""


def load_repo_keys(path: str | None = None) -> dict[str, dict[str, str]]:
    """Read + parse REPO_KEYS_FILE. An absent file is "this install does not use
    the git-remote lane" and is completely normal; an unreadable or invalid one
    is logged once per distinct error and treated as empty, which refuses every
    git-remote operation rather than guessing a URL."""
    global _repo_keys_error_logged
    target = path or REPO_KEYS_FILE
    try:
        with open(target, "r", encoding="utf-8") as f:
            keys = parse_repo_keys(f.read())
    except FileNotFoundError:
        return {}
    except (RepoConfigError, OSError) as e:
        detail = f"{target}: {e}"
        if detail != _repo_keys_error_logged:
            _repo_keys_error_logged = detail
            log_event("error", "repo_keys.unusable", path=target, error=str(e)[:300])
        return {}
    _repo_keys_error_logged = ""
    return keys


def advertised_workspace_kinds(repo_keys: dict[str, dict[str, str]]) -> list[str]:
    """What this build is WILLING to be handed, in the poll body. `git-remote`
    appears ONLY with a non-empty repo-key map mounted: advertising a workspace
    kind whose every operation this runner would refuse locally is the exact
    failure the capability negotiation exists to prevent."""
    kinds = [WORKSPACE_KIND_CHANNEL_TAR]
    if repo_keys:
        kinds.append(WORKSPACE_KIND_GIT_REMOTE)
    return kinds


def normalize_commit_sha(value: Any) -> str | None:
    """A commit id is 40 lowercase hex characters or it is not a commit id.
    Short ids are refused rather than resolved: "check out exactly this commit"
    is the whole promise, and a prefix is a request to guess."""
    candidate = str(value or "").strip().lower()
    return candidate if COMMIT_SHA_RE.match(candidate) else None


def resolve_workspace_ref(workspace_ref: dict[str, Any],
                          repo_keys: dict[str, dict[str, str]]) -> dict[str, Any]:
    """workspaceRef (the union) + the customer's repo-key map → the concrete
    plan for this run's workspace initContainer. Pure, and the ONLY place a
    repoKey becomes a URL.

    Raises WorkspaceRefError — a refusal — for anything this cluster is not
    authorized or able to do. It never reads a credential value: the credential
    is fetched once, at Secret-construction time, and travels no further.
    """
    ref = workspace_ref or {}
    # An absent `kind` is an older FixControl, whose workspaces are tarballs.
    kind = str(ref.get("kind") or WORKSPACE_KIND_CHANNEL_TAR)

    if kind == WORKSPACE_KIND_CHANNEL_TAR:
        return {
            "kind": WORKSPACE_KIND_CHANNEL_TAR,
            "digest": str(ref.get("digest") or ""),
            "sizeBytes": int(ref.get("sizeBytes") or 0),
        }

    if kind != WORKSPACE_KIND_GIT_REMOTE:
        raise WorkspaceRefError(
            f"workspaceRef.kind {kind!r} is not served by this runner "
            f"(supported: {', '.join((WORKSPACE_KIND_CHANNEL_TAR, WORKSPACE_KIND_GIT_REMOTE))})")

    repo_key = str(ref.get("repoKey") or "").strip()
    if not repo_key:
        raise WorkspaceRefError("workspaceRef.kind git-remote carries no repoKey")
    entry = repo_keys.get(repo_key)
    if not entry:
        # THE local authorization check. FixControl names a key; this cluster
        # decides whether that key means anything here. It never means a URL
        # FixControl supplied, because FixControl supplies none.
        raise WorkspaceRefError(
            f"repoKey {repo_key!r} has no mapping in this cluster's repo-key configuration")
    commit_sha = normalize_commit_sha(ref.get("commitSha"))
    if not commit_sha:
        raise WorkspaceRefError(
            f"workspaceRef.commitSha {ref.get('commitSha')!r} is not a 40-character commit id")

    resolved: dict[str, Any] = {
        "kind": WORKSPACE_KIND_GIT_REMOTE,
        "repoKey": repo_key,
        "commitSha": commit_sha,
        "url": entry["url"],
        "username": entry.get("username") or DEFAULT_GIT_USERNAME,
        "credentialKey": entry.get("credentialKey") or "",
        "patchDigest": "",
        "patchSizeBytes": 0,
    }

    patch = ref.get("patch")
    if patch not in (None, {}):
        if not isinstance(patch, dict):
            raise WorkspaceRefError("workspaceRef.patch must be an object when present")
        digest = str(patch.get("digest") or "").strip().lower()
        if not SHA256_DIGEST_RE.match(digest):
            raise WorkspaceRefError(
                f"workspaceRef.patch.digest {patch.get('digest')!r} is not a sha256 digest")
        resolved["patchDigest"] = digest
        resolved["patchSizeBytes"] = int(patch.get("sizeBytes") or 0)
    return resolved


def read_git_credential(credential_key: str, directory: str | None = None) -> str:
    """Read one credential out of the customer-owned Secret mount.

    Returns "" when the entry names no credential (a public or
    network-authenticated remote). A NAMED credential that is missing is an
    error, not an empty string: falling through to an anonymous clone would
    turn a credential-management mistake into a confusing 403 from a forge.
    """
    if not credential_key:
        return ""
    path = os.path.join(directory or GIT_CREDENTIALS_DIR, credential_key)
    try:
        with open(path, "r", encoding="utf-8") as f:
            value = f.read().strip()
    except OSError as e:
        raise WorkspaceRefError(
            f"git credential {credential_key!r} is not mounted on this runner "
            f"({e.__class__.__name__})") from e
    if not value:
        raise WorkspaceRefError(f"git credential {credential_key!r} is mounted but empty")
    return value


def parse_patch_manifest(raw: bytes | str) -> tuple[list[str], list[str], str]:
    """`.fc-patch-manifest.json` → (writes, deletes, patchFingerprint).

    Version 1 only, and refused rather than best-guessed: this manifest is what
    decides which files in a verified checkout get overwritten, so an
    unrecognised shape must stop the run instead of applying "what parsed".
    """
    try:
        doc = json.loads(raw.decode("utf-8") if isinstance(raw, bytes) else raw)
    except ValueError as e:
        raise SystemExit(f"fc-test-runner: {PATCH_MANIFEST_NAME} is not valid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise SystemExit(f"fc-test-runner: {PATCH_MANIFEST_NAME} must be a JSON object")
    if doc.get("version") != 1:
        raise SystemExit(
            f"fc-test-runner: {PATCH_MANIFEST_NAME} version {doc.get('version')!r} is not 1")

    def _paths(field: str) -> list[str]:
        values = doc.get(field) or []
        if not isinstance(values, list):
            raise SystemExit(f"fc-test-runner: {PATCH_MANIFEST_NAME}.{field} must be a list")
        out: list[str] = []
        for entry in values:
            path = str(entry or "").strip()
            if not path:
                raise SystemExit(f"fc-test-runner: {PATCH_MANIFEST_NAME}.{field} has an empty path")
            # `./x` and `x` are the same repo-relative path; normalise the one
            # spelling tar archives commonly use. Traversal is NOT handled here
            # — every path is resolved against the workspace root at apply time,
            # which is the only check that can be trusted.
            out.append(path[2:] if path.startswith("./") else path)
        return out

    return _paths("writes"), _paths("deletes"), str(doc.get("patchFingerprint") or "")


def parse_checkout_report(log_text: str) -> dict[str, Any] | None:
    """The checkout container's structured log → what it actually did.

    The container is the only witness of `git rev-parse HEAD`; this parses its
    last CHECKOUT_EVENT line back out. A commitSha that is not 40 hex characters
    is discarded — evidence is a claim, and a claim assembled out of an
    unparseable log is not one worth making.
    """
    found: dict[str, Any] | None = None
    for line in (log_text or "").splitlines():
        line = line.strip()
        if not line.startswith("{") or CHECKOUT_EVENT not in line:
            continue
        try:
            doc = json.loads(line)
        except ValueError:
            continue
        if not isinstance(doc, dict) or doc.get("event") != CHECKOUT_EVENT:
            continue
        commit = normalize_commit_sha(doc.get("commitSha"))
        if not commit:
            continue
        found = {
            "commitSha": commit,
            "patchApplied": bool(doc.get("patchApplied")),
            "patchDigest": str(doc.get("patchDigest") or "") or None,
        }
    return found


def workspace_evidence(kind: str, report: dict[str, Any] | None) -> dict[str, Any] | None:
    """The additive `evidence.workspace` block, or None for "no claim".

    Emitted only for the git-remote lane and only when the checkout container's
    own report could be read: `commitSha` must be what this cluster OBSERVED.
    FixControl refuses evidence whose commitSha does not match its request, and
    a runner that echoed the request would make that check decorative.
    """
    if kind != WORKSPACE_KIND_GIT_REMOTE or not report:
        return None
    return {
        "kind": WORKSPACE_KIND_GIT_REMOTE,
        "commitSha": report["commitSha"],
        "patchApplied": bool(report.get("patchApplied")),
        "patchDigest": report.get("patchDigest") or None,
    }


def rfc3339_ms(value: str | None) -> int | None:
    """RFC3339 → epoch milliseconds; None when absent/unparseable."""
    if not value:
        return None
    from datetime import datetime, timezone

    try:
        dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def step_result(step: dict[str, Any], status: str, exit_code: int | None,
                duration_ms: int, log: str, mask_values: list[str] | None) -> dict[str, Any]:
    """One SandboxStepResult, masked and truncated — the shape
    src/server/sandbox-runtime/types.ts declares."""
    return {
        "kind": step.get("kind"),
        "name": step.get("name"),
        "status": status,
        "exitCode": exit_code,
        "durationMs": duration_ms,
        "log": truncate_log(mask_log(log, mask_values)),
    }


def steps_from_init_statuses(statuses: list[dict[str, Any]],
                             executed: list[tuple[str, dict[str, Any]]],
                             skipped: list[dict[str, Any]],
                             logs: dict[str, str],
                             mask_values: list[str] | None,
                             deadline_exceeded: bool) -> tuple[list[dict[str, Any]], str]:
    """initContainerStatuses + fetched logs → (steps, run status).

    Status mapping, in the SandboxStepResult vocabulary:
      terminated exit 0                → passed
      terminated non-zero              → failed  (timeout when the Job's
                                          activeDeadline is what stopped it)
      never started (chain aborted)    → skipped, with an explicit log line
      non-required step                → skipped, v1 limitation log line

    Run status is the three-value wire contract: `passed` when every executed
    step passed, `failed` on a non-zero step exit, `error` when the run-wide
    deadline stopped the chain (a timeout is not a test verdict).
    """
    by_name = {s.get("name"): s for s in statuses or []}
    steps: list[dict[str, Any]] = []
    run_status = "passed"
    chain_broken = False
    for container_name, step in executed:
        state = (by_name.get(container_name) or {}).get("state") or {}
        terminated = state.get("terminated")
        if not terminated:
            steps.append(step_result(step, "skipped", None, 0, UNREACHED_STEP_LOG, mask_values))
            continue
        exit_code = terminated.get("exitCode")
        started_ms = rfc3339_ms(terminated.get("startedAt"))
        finished_ms = rfc3339_ms(terminated.get("finishedAt"))
        duration = max(0, (finished_ms - started_ms)) if (started_ms and finished_ms) else 0
        if exit_code == 0:
            status = "passed"
        elif deadline_exceeded and not chain_broken:
            status = "timeout"
        else:
            status = "failed"
        if status != "passed" and not chain_broken:
            chain_broken = True
            run_status = "error" if status == "timeout" else "failed"
        steps.append(step_result(step, status, exit_code, duration,
                                 logs.get(container_name, ""), mask_values))
    for step in skipped:
        steps.append(step_result(step, "skipped", None, 0, OPTIONAL_STEP_LOG, mask_values))
    if deadline_exceeded and run_status == "passed":
        run_status = "error"
    return steps, run_status


def classify_readiness_failure(status: dict[str, str], diagnoses: dict[str, str]) -> str:
    """Why did the environment never come up? Pure — the whole point is that it
    is testable without a cluster.

    Precedence is by ACTIONABILITY, not by severity: an image that will not pull
    and a pod that cannot be scheduled are unambiguous cluster/config facts and
    are reported first; a container that starts and dies is next; only when
    nothing more specific is known does this fall back to
    `readiness_timeout` — the one readiness kind FixControl treats as
    application-class, i.e. the only one that may reach a code fix.
    """
    kinds = set(diagnoses.values())
    if KIND_IMAGE_PULL in kinds:
        return KIND_IMAGE_PULL
    if KIND_SCHEDULING in kinds:
        return KIND_SCHEDULING
    if KIND_STARTUP_FAILURE in kinds:
        return KIND_STARTUP_FAILURE
    if any(v == "failed" for v in status.values()):
        # The pod reached a terminal phase without a diagnosable waiting reason:
        # it started and died. That is a startup failure, not a slow probe.
        return KIND_STARTUP_FAILURE
    return KIND_READINESS_TIMEOUT


def service_reports(status: dict[str, str], digests: dict[str, str]) -> list[dict[str, Any]]:
    """Per-service readiness in the shape EnvironmentReport wants.

    Reported only on a readiness FAILURE, where "db=passed, cache=timeout" is
    the whole diagnosis and one flat verdict for the topology would be a lie
    about the containers that did come up. `pending` — a service still waiting
    when a sibling failed the run — is reported as `timeout`, the readiness
    vocabulary's name for "never went green".
    """
    out: list[dict[str, Any]] = []
    for name in sorted(status):
        readiness = status[name]
        if readiness == "pending":
            readiness = "timeout"
        if readiness not in ("passed", "failed", "timeout", "skipped"):
            continue
        entry: dict[str, Any] = {"name": name, "readiness": readiness}
        if name in digests:
            entry["digest"] = digests[name]
        out.append(entry)
    return out


def build_evidence(status: str, steps: list[dict[str, Any]], resolved_images: dict[str, str],
                   namespace: str, provision_ms: int, teardown: str,
                   failure_kind: str | None = None,
                   services: list[dict[str, Any]] | None = None,
                   workspace: dict[str, Any] | None = None) -> dict[str, Any]:
    """The evidence contract, verbatim. FixControl attaches the environment
    spec hash and the plan fingerprint itself — this runner supplies the
    digests, the step results and the logs, and recomputes neither.

    `failureKind`, `services` and `workspace` are additive and are emitted only
    when this process actually knows them: an absent key means "no claim", which
    the host reads conservatively, while an always-present key would force every
    older FixControl to reason about a value this runner sometimes guessed.
    """
    evidence = {
        "status": status,
        "steps": steps,
        "resolvedImages": dict(sorted(resolved_images.items())),
        "namespace": namespace,
        "provisionMs": provision_ms,
        "teardown": teardown,
    }
    if failure_kind:
        evidence["failureKind"] = failure_kind
    if services:
        evidence["services"] = services
    if workspace:
        evidence["workspace"] = workspace
    return evidence


# ═══════════════════════════ Kubernetes IO ═══════════════════════════


def read_pod_log(kube: Any, namespace: str, pod: str, container: str) -> str:
    """Fetch one container's log.

    `KubeClient` returns parsed JSON; pod logs are text/plain, so this uses
    the client's `get_text` when the shared module offers one and otherwise
    reads the endpoint directly with the in-pod ServiceAccount token — the
    same auth the client uses, no second credential.
    """
    path = (f"/api/v1/namespaces/{namespace}/pods/{pod}/log"
            f"?container={urllib.parse.quote(container)}&timestamps=false")
    getter = getattr(kube, "get_text", None)
    if callable(getter):
        try:
            return str(getter(path))
        except Exception as e:  # noqa: BLE001 — a missing log must not fail the run
            return f"[log unavailable: {e}]"
    try:
        with open(f"{SA_DIR}/token", "r") as f:
            token = f.read().strip()
        ctx = ssl.create_default_context(cafile=f"{SA_DIR}/ca.crt")
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        req = urllib.request.Request(f"https://{host}:{port}{path}",
                                     headers={"Authorization": f"Bearer {token}"})
        with urllib.request.urlopen(req, context=ctx, timeout=30) as resp:
            return resp.read().decode("utf-8", "replace")
    except Exception as e:  # noqa: BLE001
        return f"[log unavailable: {e}]"


def diagnose_pod(pod_status: dict[str, Any]) -> str | None:
    """What is keeping this pod from becoming ready — in the closed failure
    vocabulary, or None when nothing diagnosable is visible yet.

    Pure, and reading only fields Kubernetes fills in itself: container waiting
    reasons and the PodScheduled condition. Nothing here scrapes customer output
    (a substring match on a log line is exactly how a broken cluster ends up
    rewriting someone's code).
    """
    for container in (pod_status.get("containerStatuses") or []):
        waiting = (container.get("state") or {}).get("waiting") or {}
        reason = waiting.get("reason")
        if reason in IMAGE_PULL_REASONS:
            return KIND_IMAGE_PULL
        if reason in STARTUP_REASONS:
            return KIND_STARTUP_FAILURE
    if pod_status.get("phase") == "Pending":
        for cond in (pod_status.get("conditions") or []):
            if (cond.get("type") == "PodScheduled" and cond.get("status") == "False"
                    and cond.get("reason") == "Unschedulable"):
                return KIND_SCHEDULING
    return None


def wait_services_ready(kube: Any, namespace: str, ordered: list[dict[str, Any]],
                        deadline: float) -> tuple[bool, dict[str, str], dict[str, str],
                                                  dict[str, str]]:
    """Poll until every service is Ready (or Running, when it declared no
    probe). Returns `(ok, per-service status, resolved digests, diagnoses)`.

    Fail fast: the caller tears the namespace down and reports `failed` with
    the per-service status, before a single plan step runs. A service without a
    probe is started but not awaited beyond Running — reported as `skipped`
    readiness, exactly as the Phase 1 report does, so flakiness stays
    diagnosable.

    `diagnoses` is the fourth return value and the whole reason this loop is
    worth reading twice: it is the only place in the system where "the image
    never pulled" is still distinguishable from "the probe never went green".
    Once the namespace is torn down, the pods are gone and nobody can tell.
    """
    expected = {str(s.get("name")): bool(s.get("readiness")) for s in ordered}
    status: dict[str, str] = {n: "pending" for n in expected}
    digests: dict[str, str] = {}
    diagnoses: dict[str, str] = {}
    while time.monotonic() < deadline:
        pods = (kube.get(f"/api/v1/namespaces/{namespace}/pods"
                         f"?labelSelector=fixcontrol.role%3Dservice") or {}).get("items", [])
        for pod in pods:
            labels = ((pod.get("metadata") or {}).get("labels") or {})
            name = labels.get("fixcontrol.service")
            if name not in expected:
                continue
            pod_status = pod.get("status") or {}
            statuses = pod_status.get("containerStatuses") or []
            if statuses and statuses[0].get("imageID") and name not in digests:
                digests[name] = resolve_digest(statuses[0]["imageID"])
            cause = diagnose_pod(pod_status)
            if cause:
                diagnoses[name] = cause
            elif name in diagnoses:
                # It recovered (an image pull that eventually succeeded is not a
                # failure); a stale diagnosis would misreport a later timeout.
                diagnoses.pop(name, None)
            phase = pod_status.get("phase")
            if phase in ("Failed", "Succeeded"):
                status[name] = "failed"
                continue
            if phase != "Running":
                continue
            if not expected[name]:
                status[name] = "skipped"
                continue
            ready = any(c.get("type") == "Ready" and c.get("status") == "True"
                        for c in (pod_status.get("conditions") or []))
            status[name] = "passed" if ready else "pending"
        if all(v in ("passed", "skipped") for v in status.values()):
            return True, status, digests, diagnoses
        if any(v == "failed" for v in status.values()):
            break
        time.sleep(2)
    for name, value in status.items():
        if value == "pending":
            status[name] = "timeout"
    return False, status, digests, diagnoses


def wait_job(kube: Any, namespace: str, deadline: float) -> tuple[str, dict[str, Any] | None]:
    """Poll the Job until it terminates. Returns `(verdict, pod)` where
    verdict is `succeeded` / `failed` / `deadline` / `timeout` (our own outer
    bound fired before the Job's)."""
    while time.monotonic() < deadline:
        job = kube.get(f"/apis/batch/v1/namespaces/{namespace}/jobs/{JOB_NAME}") or {}
        st = job.get("status") or {}
        conditions = st.get("conditions") or []
        deadline_hit = any(c.get("type") == "Failed" and c.get("reason") == "DeadlineExceeded"
                           and c.get("status") == "True" for c in conditions)
        done = bool(st.get("succeeded")) or bool(st.get("failed")) or deadline_hit
        if done:
            pods = (kube.get(f"/api/v1/namespaces/{namespace}/pods"
                             f"?labelSelector=fixcontrol.role%3Dplan") or {}).get("items", [])
            pod = pods[0] if pods else None
            if deadline_hit:
                return "deadline", pod
            return ("succeeded" if st.get("succeeded") else "failed"), pod
        time.sleep(2)
    return "timeout", None


def is_not_found(error: Exception) -> bool:
    """A 404 from the shared KubeClient (which raises KubeError(status, body)),
    with a string fallback so a monkeypatched client in a smoke behaves the
    same."""
    return getattr(error, "status", None) == 404 or "404" in str(error)


def delete_namespace(kube: Any, namespace: str) -> str:
    """Teardown verdict: `clean` (gone or 404), `partial` (delete accepted,
    still Terminating when we stopped waiting — the TTL sweeper finishes it),
    `failed` (the API refused). A teardown failure never masks the run
    result."""
    try:
        kube.delete(f"/api/v1/namespaces/{namespace}")
    except Exception as e:  # noqa: BLE001
        if is_not_found(e):
            return "clean"
        log_event("error", "teardown.failed", namespace=namespace, error=str(e)[:300])
        return "failed"
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            kube.get(f"/api/v1/namespaces/{namespace}")
        except Exception as e:  # noqa: BLE001
            if is_not_found(e):
                return "clean"
            log_event("warn", "teardown.poll_failed", namespace=namespace, error=str(e)[:300])
            return "partial"
        time.sleep(2)
    return "partial"


def sweep_expired_namespaces(kube: Any) -> int:
    """Invariant 8 / acceptance 9: reclaim every ephemeral namespace whose TTL
    has passed, regardless of which process created it. Runs every poll cycle,
    so a SIGKILL + restart reclaims the previous life's leftovers without any
    state carried across the restart — the label IS the state."""
    try:
        listing = kube.get("/api/v1/namespaces?labelSelector=fixcontrol.sandbox%3D1") or {}
    except Exception as e:  # noqa: BLE001
        log_event("warn", "sweep.list_failed", error=str(e)[:300])
        return 0
    reclaimed = 0
    for name in expired_namespaces(listing.get("items") or [], time.time()):
        try:
            kube.delete(f"/api/v1/namespaces/{name}")
            reclaimed += 1
            _metric_bump("fc_test_runner_namespaces_reclaimed_total")
            log_event("info", "sweep.reclaimed", namespace=name)
        except Exception as e:  # noqa: BLE001
            log_event("warn", "sweep.delete_failed", namespace=name, error=str(e)[:300])
    return reclaimed


# ═══════════════════════════ Operation execution ═══════════════════════════

# Runs in flight: runId → {"namespace", "cancelled"}. `test.cancel` flips
# `cancelled` and deletes the namespace; the executing thread notices and
# reports rather than pretending the run completed.
_ACTIVE: dict[str, dict[str, Any]] = {}
_ACTIVE_LOCK = threading.Lock()


def post_result(fc: Any, operation_id: str, outcome: str, *, reason_code: str | None = None,
                message: str | None = None, evidence: dict[str, Any] | None = None) -> None:
    """Post the operation result outbound. Every outcome is posted — a refusal
    is a *result*, never a silent drop (invariant 9). Retries are the shared
    client's job; a failure here is logged loudly and the operation expires
    server-side as a recorded outcome rather than a lost message."""
    body: dict[str, Any] = {
        "operationId": operation_id,
        "agentId": AGENT_ID,
        "clusterId": CLUSTER,
        "tenant": TENANT,
        "outcome": outcome,
    }
    if reason_code:
        body["reasonCode"] = reason_code
    if message:
        body["message"] = message
    if evidence is not None:
        body["evidence"] = evidence
    try:
        status, text = fc.post_json("/api/agent/result", body)
        if 200 <= status < 300:
            log_event("info", "result.posted", operationId=operation_id, outcome=outcome,
                      reasonCode=reason_code)
        else:
            log_event("error", "result.post_rejected", operationId=operation_id,
                      outcome=outcome, status_code=status, body=text[:300])
    except Exception as e:  # noqa: BLE001
        log_event("error", "result.post_failed", operationId=operation_id, outcome=outcome,
                  error=str(e)[:300])


def refuse(fc: Any, operation_id: str, reason_code: str, message: str) -> None:
    _metric_bump("fc_test_runner_operations_refused_total", reason_code)
    _metric_bump("fc_test_runner_runs_total", "refused")
    log_event("warn", "operation.refused", operationId=operation_id,
              reasonCode=reason_code, message=message)
    post_result(fc, operation_id, "refused", reason_code=reason_code, message=message)


def execute_test_run(kube: Any, fc: Any, op: dict[str, Any]) -> None:
    """One `test.run`, cradle to grave. Teardown is in a `finally` so it runs
    after success, failure, refusal-after-provision and any exception."""
    operation_id = str(op.get("operationId") or "")
    spec = op.get("payload") or {}
    mask_values = [str(v) for v in (spec.get("maskValues") or [])]

    run_id = sanitize_run_id(str(spec.get("runId") or ""))
    if not run_id:
        refuse(fc, operation_id, "not_allowlisted",
               f"runId {spec.get('runId')!r} is not an acceptable run identifier")
        return
    toolchain = str(spec.get("image") or "")
    if not toolchain:
        refuse(fc, operation_id, "not_allowlisted", "TestRunSpec carries no toolchain image")
        return
    if not image_allowed(toolchain, ALLOWED_TOOLCHAIN_IMAGE_PREFIXES):
        refuse(fc, operation_id, "not_allowlisted",
               f"toolchain image {toolchain} is outside this cluster's allowed prefixes "
               f"(ALLOWED_TOOLCHAIN_IMAGE_PREFIXES)")
        return
    # The SAME allowlist over the service images. They are pulled and run in
    # this cluster exactly as the toolchain image is, so allowlisting one and
    # not the other allowlists nothing.
    bad_images = unallowed_service_images(
        list(((spec.get("environment") or {}).get("services")) or []),
        ALLOWED_TOOLCHAIN_IMAGE_PREFIXES)
    if bad_images:
        refuse(fc, operation_id, "not_allowlisted",
               f"service image(s) outside this cluster's allowed prefixes "
               f"(ALLOWED_TOOLCHAIN_IMAGE_PREFIXES): {', '.join(bad_images)}")
        return
    # What the plan asks this cluster to EXECUTE, checked before anything is
    # created. A signed operation proves who asked; it does not bound what was
    # asked for.
    try:
        validate_plan_commands(spec.get("plan") or {}, spec.get("extraAllowedCommands"))
    except SpecError as e:
        refuse(fc, operation_id, "not_allowlisted", str(e))
        return

    # Where the workspace comes from, decided HERE — before a single object is
    # created — because the answer can be "this cluster refuses". A repoKey with
    # no local mapping never becomes a namespace, let alone a clone attempt.
    try:
        resolved_workspace = resolve_workspace_ref(spec.get("workspaceRef") or {},
                                                   load_repo_keys())
        git_credential = read_git_credential(str(resolved_workspace.get("credentialKey") or ""))
    except WorkspaceRefError as e:
        refuse(fc, operation_id, "not_allowlisted", str(e))
        return
    workspace_kind = str(resolved_workspace.get("kind"))

    services = list(((spec.get("environment") or {}).get("services")) or [])
    try:
        ordered = order_services(services)
        for svc in ordered:
            k8s_probe(svc.get("readiness"))  # validate before creating anything
    except SpecError as e:
        refuse(fc, operation_id, "not_allowlisted", str(e))
        return

    namespace = namespace_for(run_id)
    with _ACTIVE_LOCK:
        _ACTIVE[run_id] = {"namespace": namespace, "cancelled": False}

    provision_started = time.monotonic()
    resolved: dict[str, str] = {}
    steps: list[dict[str, Any]] = []
    status = "error"
    message: str | None = None
    reason_code: str | None = None
    outcome = "error"
    teardown = "failed"
    provision_ms = 0
    failure_kind: str | None = None
    services_evidence: list[dict[str, Any]] | None = None
    workspace_report: dict[str, Any] | None = None
    try:
        kube.post("/api/v1/namespaces",
                  namespace_manifest(run_id, TENANT, int(time.time()) + NAMESPACE_TTL_SECONDS))
        # The agent secret is only needed inside the run namespace when
        # something there must talk to FixControl: the tar fetch, or a patch
        # archive pull. A git-remote run with no patch needs neither key unless
        # the customer's repo entry names a git credential — and then that is
        # the ONLY key in the Secret.
        needs_agent_secret = (workspace_kind == WORKSPACE_KIND_CHANNEL_TAR
                              or bool(resolved_workspace.get("patchDigest")))
        creds = creds_secret_manifest(namespace, run_id,
                                      SECRET if needs_agent_secret else "",
                                      git_credential)
        if creds["data"]:
            kube.post(f"/api/v1/namespaces/{namespace}/secrets", creds)
        for svc in ordered:
            kube.post(f"/apis/apps/v1/namespaces/{namespace}/deployments",
                      deployment_manifest(namespace, run_id, TENANT, svc))
            kube.post(f"/api/v1/namespaces/{namespace}/services",
                      headless_service_manifest(namespace, run_id, str(svc.get("name"))))

        readiness_budget_ms = SERVICE_START_BUDGET_MS + sum(
            int(((s.get("readiness") or {}).get("timeoutMs")) or 0) for s in ordered
        )
        ok, service_status, resolved, diagnoses = wait_services_ready(
            kube, namespace, ordered, time.monotonic() + readiness_budget_ms / 1000.0)
        provision_ms = int((time.monotonic() - provision_started) * 1000)

        missing = [s for s in service_status if s not in resolved]
        if ok and missing:
            # Invariant 7: no digest, no provenance, no green.
            raise DigestError(
                "environment: no image digest resolved for service(s) " + ", ".join(sorted(missing))
            )
        if not ok:
            status = "failed"
            outcome = "failed"
            # The pods are about to be deleted: this is the last moment anyone
            # can tell an unpullable image from a slow probe.
            failure_kind = classify_readiness_failure(service_status, diagnoses)
            services_evidence = service_reports(service_status, resolved)
            message = "environment did not reach readiness: " + ", ".join(
                f"{n}={v}" for n, v in sorted(service_status.items()))
            steps = [step_result(s, "skipped", None, 0,
                                 "step not executed: the environment never reached readiness",
                                 mask_values)
                     for s in ((spec.get("plan") or {}).get("steps") or [])]
        else:
            job, executed, skipped = job_manifest(namespace, run_id, spec, operation_id,
                                                  RUNNER_IMAGE, resolved_workspace)
            kube.post(f"/apis/batch/v1/namespaces/{namespace}/jobs", job)
            run_timeout_s = max(1, int(spec.get("runTimeoutMs") or 0) // 1000)
            verdict, pod = wait_job(kube, namespace, time.monotonic() + run_timeout_s + 60)
            with _ACTIVE_LOCK:
                cancelled = _ACTIVE.get(run_id, {}).get("cancelled", False)
            if cancelled:
                status, outcome = "error", "failed"
                failure_kind = KIND_CANCELLED
                message = "cancelled"
                steps = [step_result(s, "skipped", None, 0, "run cancelled", mask_values)
                         for _, s in executed] + [
                    step_result(s, "skipped", None, 0, OPTIONAL_STEP_LOG, mask_values) for s in skipped]
            else:
                init_statuses = ((pod or {}).get("status") or {}).get("initContainerStatuses") or []
                pod_name = ((pod or {}).get("metadata") or {}).get("name", "")
                logs = {name: read_pod_log(kube, namespace, pod_name, name)
                        for name, _ in executed} if pod else {}
                git_remote = workspace_kind == WORKSPACE_KIND_GIT_REMOTE
                workspace_container = CHECKOUT_CONTAINER if git_remote else FETCH_CONTAINER
                fetch_state = next((c.get("state", {}).get("terminated")
                                    for c in init_statuses
                                    if c.get("name") == workspace_container), None)
                fetch_exit = fetch_state.get("exitCode") if fetch_state else None
                if fetch_exit == COMMIT_SHA_MISMATCH_EXIT:
                    # `git rev-parse HEAD` was not the commit the operation named.
                    # A run against the wrong source is refused, never retried:
                    # same family, same reason code, as a tampered tarball.
                    outcome, reason_code = "refused", "bad_signature"
                    status, message = "error", "workspace commit sha mismatch"
                    steps = [step_result(s, "skipped", None, 0, message, mask_values)
                             for _, s in executed]
                elif fetch_exit == WORKSPACE_DIGEST_MISMATCH_EXIT:
                    # The workspace (or, in the git-remote lane, the patch
                    # archive) did not hash to the digest the signed operation
                    # promised — an authenticity failure, in the bad_signature
                    # family.
                    outcome, reason_code = "refused", "bad_signature"
                    status = "error"
                    message = ("patch archive digest mismatch" if git_remote
                               else "workspace digest mismatch")
                    steps = [step_result(s, "skipped", None, 0, message, mask_values)
                             for _, s in executed]
                elif fetch_exit not in (0, None):
                    status, outcome = "error", "error"
                    # The workspace never landed, so nothing about the change was
                    # verified: infrastructure, never a verdict.
                    failure_kind = KIND_INFRASTRUCTURE
                    message = ("workspace checkout failed: " if git_remote
                               else "workspace fetch failed: ") + truncate_log(
                        mask_log(read_pod_log(kube, namespace, pod_name,
                                              workspace_container), mask_values))[-2000:]
                    steps = [step_result(s, "skipped", None, 0, "workspace unavailable", mask_values)
                             for _, s in executed]
                else:
                    if git_remote and pod:
                        # The checkout container is the only witness of what it
                        # checked out; its structured log is how that fact
                        # reaches the evidence. Unparseable ⇒ no claim.
                        workspace_report = parse_checkout_report(
                            read_pod_log(kube, namespace, pod_name, CHECKOUT_CONTAINER))
                        if workspace_report is None:
                            log_event("warn", "workspace.report_unreadable", runId=run_id,
                                      namespace=namespace)
                    steps, status = steps_from_init_statuses(
                        init_statuses, executed, skipped, logs, mask_values,
                        deadline_exceeded=(verdict in ("deadline", "timeout")))
                    outcome = "succeeded" if status == "passed" else (
                        "failed" if status == "failed" else "error")
                    if status == "failed":
                        # A required step of the plan exited non-zero inside a
                        # healthy environment: the one fact here that IS about
                        # the change, and the only one allowed to reach the
                        # revision loop.
                        failure_kind = KIND_TEST_FAILURE
                    if verdict == "timeout":
                        message = "run exceeded runTimeoutMs"
    except DigestError as e:
        status, outcome, message = "error", "error", str(e)
        failure_kind = KIND_INFRASTRUCTURE
        log_event("error", "run.digest_unresolved", runId=run_id, error=str(e)[:300])
    except Exception as e:  # noqa: BLE001 — every failure still tears down and reports
        status, outcome, message = "error", "error", f"in-cluster runner error: {e}"
        failure_kind = KIND_INFRASTRUCTURE
        log_event("error", "run.failed", runId=run_id, error=str(e)[:300])
    finally:
        teardown = delete_namespace(kube, namespace)
        with _ACTIVE_LOCK:
            _ACTIVE.pop(run_id, None)

    _metric_bump("fc_test_runner_runs_total", outcome)
    workspace_claim = workspace_evidence(workspace_kind, workspace_report)
    evidence = build_evidence(status, steps, resolved, namespace, provision_ms, teardown,
                              failure_kind=failure_kind, services=services_evidence,
                              workspace=workspace_claim)
    log_event("info", "run.finished", runId=run_id, namespace=namespace, status=status,
              outcome=outcome, teardown=teardown, provisionMs=provision_ms,
              failureKind=failure_kind, workspaceKind=workspace_kind,
              commitSha=(workspace_claim or {}).get("commitSha"))
    post_result(fc, operation_id, outcome, reason_code=reason_code,
                message=(mask_log(message, mask_values) if message else None), evidence=evidence)


def execute_test_cancel(kube: Any, fc: Any, op: dict[str, Any]) -> None:
    """`test.cancel`: delete the run's namespace and record the cancellation.
    The in-flight run reports `failed` + "cancelled" itself; a cancel for a run
    this process does not hold still deletes the namespace, because another
    fc-test-runner life may have created it."""
    operation_id = str(op.get("operationId") or "")
    target = op.get("target") or {}
    payload = op.get("payload") or {}
    run_id = sanitize_run_id(str(payload.get("runId") or target.get("name") or ""))
    if not run_id:
        refuse(fc, operation_id, "not_allowlisted", "test.cancel carries no acceptable runId")
        return
    namespace = namespace_for(run_id)
    with _ACTIVE_LOCK:
        active = _ACTIVE.get(run_id)
        if active:
            active["cancelled"] = True
    teardown = delete_namespace(kube, namespace)
    log_event("info", "run.cancelled", runId=run_id, namespace=namespace, teardown=teardown)
    _metric_bump("fc_test_runner_runs_total", "cancelled")
    post_result(fc, operation_id, "failed", message="cancelled",
                evidence=build_evidence("error", [], {}, namespace, 0, teardown,
                                        failure_kind=KIND_CANCELLED))


def handle_operation(kube: Any, fc: Any, op: dict[str, Any], nonces: Any) -> None:
    """Two-phase authorization, then dispatch. Nothing executes on the
    strength of the transport alone."""
    operation_id = str(op.get("operationId") or "")
    ok, reason = common.verify_operation(
        SECRET, op,
        expected_tenant=TENANT,
        expected_cluster=CLUSTER,
        agent_id=AGENT_ID,
        capabilities=CAPABILITIES,
        nonce_store=nonces,
        now=time.time(),
        skew_seconds=int(MAX_SKEW_SECONDS),
        signing_public_keys=SIGNING_PUBLIC_KEYS,
    )
    if not ok:
        detail = (common.signature_refusal_detail(op, SIGNING_PUBLIC_KEYS)
                  if reason == common.REASON_BAD_SIGNATURE
                  else f"local authorization refused: {reason}")
        refuse(fc, operation_id, str(reason or "capability_denied"), detail)
        return
    capability = op.get("capability")
    if capability == "test.run":
        execute_test_run(kube, fc, op)
    elif capability == "test.cancel":
        execute_test_cancel(kube, fc, op)
    else:
        refuse(fc, operation_id, "capability_denied",
               f"capability {capability!r} is not served by fc-test-runner")


# ═══════════════════════════ CLI modes ═══════════════════════════


def _safe_extract(tar: tarfile.TarFile, dest: str,
                  members: list[tarfile.TarInfo] | None = None) -> None:
    """Extract with path traversal and link escapes refused. A workspace tar is
    FixControl-produced, but "produced by us" is not a security property when
    the bytes crossed a network — this is checked, not assumed.

    `members` restricts the extraction to a chosen subset (the patch archive's
    declared writes); None means the whole archive, as the workspace tar wants.
    """
    dest_abs = os.path.abspath(dest)
    selected = list(tar.getmembers()) if members is None else list(members)
    for member in selected:
        target = os.path.abspath(os.path.join(dest_abs, member.name))
        if not (target == dest_abs or target.startswith(dest_abs + os.sep)):
            raise SystemExit(f"fc-test-runner: refusing tar member outside workspace: {member.name!r}")
        if member.issym() or member.islnk():
            link_target = os.path.abspath(
                os.path.join(os.path.dirname(target), member.linkname))
            if not link_target.startswith(dest_abs + os.sep):
                raise SystemExit(
                    f"fc-test-runner: refusing link escaping workspace: {member.name!r}")
    try:
        # Python ≥3.12: belt and braces on top of the validation above.
        tar.extractall(dest_abs, members=selected, filter="data")  # type: ignore[call-arg]
    except TypeError:
        tar.extractall(dest_abs, members=selected)  # noqa: S202 — every member validated above


def _workspace_path(dest_abs: str, relative: str) -> str:
    """Resolve a repo-relative manifest path inside the workspace, or refuse.

    The one place a path out of `.fc-patch-manifest.json` becomes a filesystem
    path. `..`, absolute paths and anything that resolves through a symlink out
    of the tree are refused — the manifest crossed a network, so its paths get
    the same treatment as the tar members next to them.
    """
    if os.path.isabs(relative) or relative.startswith("~"):
        raise SystemExit(f"fc-test-runner: refusing absolute patch path: {relative!r}")
    target = os.path.realpath(os.path.join(dest_abs, relative))
    root = os.path.realpath(dest_abs)
    if not (target == root or target.startswith(root + os.sep)):
        raise SystemExit(f"fc-test-runner: refusing patch path outside workspace: {relative!r}")
    return target


def fetch_workspace(operation_id: str) -> int:
    """`--fetch-workspace <operationId>` — the Job's fetch initContainer.

    GET the tar.gz over the same outbound channel, verify sha256 against
    WORKSPACE_DIGEST **before** unpacking, then extract. A mismatch exits
    WORKSPACE_DIGEST_MISMATCH_EXIT, which the runner maps to
    refused/`bad_signature` ("workspace digest mismatch"): bytes that do not
    hash to what the signed operation promised are not the workspace, whatever
    else they may be.
    """
    expected = (os.environ.get("WORKSPACE_DIGEST") or "").strip()
    dest = os.environ.get("WORKSPACE_DIR", "/workspace")
    fc = common.FCClient(URL, AGENT_ID, SECRET, user_agent="fc-test-runner/1.0",
                         component="fc-test-runner")
    status, data = fc.get_bytes(
        f"/api/agent/workspace/{common.quote_path_segment(operation_id)}")
    if not (200 <= status < 300):
        # An unavailable workspace is an infrastructure failure, not an
        # authenticity one — a distinct exit code so the runner does not report
        # `bad_signature` for a 503.
        log_event("error", "workspace.fetch_failed", operationId=operation_id,
                  status_code=status, sizeBytes=len(data or b""))
        return 1
    actual = "sha256:" + hashlib.sha256(data).hexdigest()
    if not expected or actual != expected:
        log_event("error", "workspace.digest_mismatch", operationId=operation_id,
                  expected=expected or "(unset)", actual=actual, sizeBytes=len(data))
        return WORKSPACE_DIGEST_MISMATCH_EXIT
    os.makedirs(dest, exist_ok=True)
    with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tar:
        _safe_extract(tar, dest)
    log_event("info", "workspace.extracted", operationId=operation_id, digest=actual,
              sizeBytes=len(data), dest=dest)
    return 0


# ── The git-remote lane's initContainer ────────────────────────────────────


def _git_env(credential: str, username: str, workspace: str = "") -> dict[str, str]:
    """The environment `git` runs under. This function is the whole credential
    story of the checkout container, so it is short on purpose:

      · GIT_ASKPASS — git asks the helper on stdin/stdout. The credential
        therefore never enters a URL (so never `.git/config`, never a log line,
        never an error message) and never enters argv (so never `ps`, never a
        process-listing sidecar).
      · GIT_TERMINAL_PROMPT=0 — an unauthenticated remote must fail, not hang
        forever waiting for a tty that a Job pod does not have.
      · GIT_CONFIG_NOSYSTEM + a private HOME — no /etc/gitconfig, no inherited
        `insteadOf` rewrite that could redirect the clone somewhere else.
      · GIT_CONFIG_COUNT/KEY/VALUE for `safe.directory` — a Kubernetes emptyDir
        is created root-owned and 0777, so a repository initialised in it by
        uid 65532 trips git's dubious-ownership check. The exemption is scoped
        to exactly this one directory, set through the environment (never argv,
        never a config file a later step could edit), and it is a statement
        about a volume this pod owns outright.
      · No proxy inheritance is stripped: the customer's own egress policy is
        what decides where this container may connect.
    """
    home = os.environ.get("HOME") or "/tmp"
    env = {
        "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
        "HOME": home,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.path.join(home, ".gitconfig-fc"),
        "LC_ALL": "C",
    }
    if workspace:
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "safe.directory"
        env["GIT_CONFIG_VALUE_0"] = os.path.abspath(workspace)
    for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "GIT_SSL_CAINFO",
                 "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY",
                 "http_proxy", "https_proxy", "no_proxy"):
        if os.environ.get(name):
            env[name] = os.environ[name]
    if credential:
        env["GIT_ASKPASS"] = GIT_ASKPASS_PATH
        env["FC_GIT_USERNAME"] = username or DEFAULT_GIT_USERNAME
        env["FC_GIT_PASSWORD"] = credential
    return env


def _git(args: list[str], *, cwd: str, env: dict[str, str], secret: str,
         timeout: int = 900) -> tuple[int, str]:
    """Run one git command. Returns `(exit code, combined output)` with the
    credential scrubbed out of the output unconditionally — git has no reason to
    echo it, and "has no reason to" is not a control."""
    try:
        proc = subprocess.run(  # noqa: S603 — fixed argv, no shell, no interpolation
            ["git", *args], cwd=cwd, env=env, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
    except FileNotFoundError:
        return 127, "git is not installed in the runner image"
    except subprocess.TimeoutExpired:
        return 124, f"git {args[0]} timed out after {timeout}s"
    out = (proc.stdout or b"").decode("utf-8", "replace")
    if secret:
        out = out.replace(secret, MASKED)
    return proc.returncode, out.strip()


def _fetch_commit(dest: str, commit_sha: str, env: dict[str, str],
                  secret: str) -> tuple[bool, str]:
    """Get `commit_sha` into the repository at `dest`, cheapest first.

    A depth-1 clone of a branch tip does NOT contain an arbitrary commit, so
    "shallow" and "exact SHA" are only compatible when the server allows
    fetching a SHA directly (`uploadpack.allowReachableSHA1InWant`, which
    GitHub/GitLab/Gitea enable and a bare in-house remote often does not). The
    ladder is therefore: ask for the commit shallowly, then ask for it at full
    depth, then fall back to fetching every branch and tag. Each rung costs more
    bytes than the last and none of them is allowed to succeed with the wrong
    commit — that is `git rev-parse HEAD`'s job, afterwards.
    """
    attempts: list[tuple[str, list[str]]] = [
        ("shallow-sha", ["fetch", "--no-tags", "--depth", "1", "origin", commit_sha]),
        ("full-sha", ["fetch", "--no-tags", "origin", commit_sha]),
        ("all-refs", ["fetch", "--no-tags", "--prune", "origin",
                      "+refs/heads/*:refs/remotes/origin/*"]),
        ("all-refs-tags", ["fetch", "--tags", "origin",
                           "+refs/heads/*:refs/remotes/origin/*"]),
    ]
    last = ""
    for label, args in attempts:
        code, out = _git(args, cwd=dest, env=env, secret=secret)
        if code == 0:
            # A fetch that succeeds still has to actually contain the commit:
            # the all-refs rungs fetch everything and prove nothing by exiting 0.
            have, _ = _git(["cat-file", "-e", f"{commit_sha}^{{commit}}"],
                           cwd=dest, env=env, secret=secret)
            if have == 0:
                log_event("info", "workspace.fetched", strategy=label, commitSha=commit_sha)
                return True, label
            last = f"{label}: remote accepted the fetch but the commit is not present"
            continue
        last = f"{label}: {out[-500:]}"
        log_event("warn", "workspace.fetch_attempt_failed", strategy=label, error=last[-300:])
    return False, last


def _apply_patch_archive(data: bytes, dest: str) -> tuple[int, int, str]:
    """Apply the patch archive over a VERIFIED checkout.

    Deletes first, then the declared writes — the order matters when a rename is
    expressed as delete-then-write of paths that differ only by case. Only paths
    the manifest declares are applied: an archive member nobody declared is not
    a file this run was authorized to change, and it is skipped and counted
    rather than quietly landed.

    Returns `(writes, deletes, patchFingerprint)`.
    """
    dest_abs = os.path.abspath(dest)
    with tarfile.open(fileobj=BytesIO(data), mode="r:gz") as tar:
        try:
            manifest_member = tar.getmember(PATCH_MANIFEST_NAME)
        except KeyError:
            try:
                manifest_member = tar.getmember("./" + PATCH_MANIFEST_NAME)
            except KeyError:
                raise SystemExit(
                    f"fc-test-runner: patch archive has no {PATCH_MANIFEST_NAME}") from None
        handle = tar.extractfile(manifest_member)
        if handle is None:
            raise SystemExit(f"fc-test-runner: {PATCH_MANIFEST_NAME} is not a regular file")
        writes, deletes, fingerprint = parse_patch_manifest(handle.read())

        for relative in deletes:
            target = _workspace_path(dest_abs, relative)
            if os.path.isdir(target) and not os.path.islink(target):
                shutil.rmtree(target)
            elif os.path.lexists(target):
                os.remove(target)
            else:
                # The cloud believes it deleted a file this commit does not
                # have. Reported, not fatal: the checkout is the authority on
                # what the commit contains, and the run can still be judged.
                log_event("warn", "patch.delete_missing", path=relative)

        wanted = set(writes)
        selected: list[tarfile.TarInfo] = []
        seen: set[str] = set()
        undeclared = 0
        for member in tar.getmembers():
            name = member.name[2:] if member.name.startswith("./") else member.name
            if name in (PATCH_MANIFEST_NAME, ""):
                continue
            if name in wanted:
                member.name = name
                selected.append(member)
                seen.add(name)
            elif member.isfile():
                undeclared += 1
        missing = sorted(wanted - seen)
        if missing:
            raise SystemExit(
                "fc-test-runner: patch archive declares writes it does not carry: "
                + ", ".join(missing[:10]))
        if undeclared:
            log_event("warn", "patch.undeclared_members_skipped", count=undeclared)
        _safe_extract(tar, dest_abs, selected)
    return len(writes), len(deletes), fingerprint


def checkout_workspace(operation_id: str) -> int:
    """`--checkout-workspace <operationId>` — the Job's checkout initContainer,
    and the reason the source tree never transits FixControl Cloud.

    clone → checkout the exact commit, detached → VERIFY `git rev-parse HEAD`
    → (optionally) GET the patch archive, verify its sha256 BEFORE unpacking,
    apply it. Exit codes are the contract:

        COMMIT_SHA_MISMATCH_EXIT      HEAD is not the requested commit
        WORKSPACE_DIGEST_MISMATCH_EXIT  the patch archive is not its digest
        1                             everything else — infrastructure

    The first two are authenticity failures the runner reports as refusals; the
    third is an infrastructure failure that never becomes a verdict about
    anybody's code.
    """
    url = (os.environ.get("GIT_REMOTE_URL") or "").strip()
    commit_sha = normalize_commit_sha(os.environ.get("GIT_COMMIT_SHA"))
    dest = os.environ.get("WORKSPACE_DIR", "/workspace")
    username = (os.environ.get("GIT_USERNAME") or "").strip()
    credential = os.environ.get(GIT_CREDENTIAL_KEY) or ""
    patch_digest = (os.environ.get("PATCH_DIGEST") or "").strip().lower()

    if not url or not commit_sha:
        log_event("error", "workspace.checkout_misconfigured", operationId=operation_id,
                  hasUrl=bool(url), commitShaValid=bool(commit_sha))
        return 1
    if "@" in urllib.parse.urlsplit(url).netloc:
        # Userinfo in the URL would put a credential in `.git/config` and in
        # every git error message. The repo-key parser has no spelling for it;
        # this is the second line of that same defence.
        log_event("error", "workspace.checkout_misconfigured", operationId=operation_id,
                  reason="remote url carries userinfo")
        return 1

    os.makedirs(dest, exist_ok=True)
    env = _git_env(credential, username, dest)
    for args in (["init", "--quiet"], ["config", "advice.detachedHead", "false"]):
        code, out = _git(args, cwd=dest, env=env, secret=credential)
        if code != 0:
            log_event("error", "workspace.checkout_failed", operationId=operation_id,
                      step=args[0], error=out[-500:])
            return 1
    # `remote add` on a directory that already has an origin is an error, and a
    # container that restarted onto a half-written emptyDir must converge rather
    # than fail on the bookkeeping. `set-url` is the same statement, made twice.
    code, out = _git(["remote", "add", "origin", url], cwd=dest, env=env, secret=credential)
    if code != 0:
        code, out = _git(["remote", "set-url", "origin", url], cwd=dest, env=env,
                         secret=credential)
    if code != 0:
        log_event("error", "workspace.checkout_failed", operationId=operation_id,
                  step="remote", error=out[-500:])
        return 1

    fetched, detail = _fetch_commit(dest, commit_sha, env, credential)
    if not fetched:
        log_event("error", "workspace.checkout_failed", operationId=operation_id,
                  step="fetch", commitSha=commit_sha, error=detail[-500:])
        return 1

    code, out = _git(["checkout", "--detach", "--force", commit_sha],
                     cwd=dest, env=env, secret=credential)
    if code != 0:
        log_event("error", "workspace.checkout_failed", operationId=operation_id,
                  step="checkout", commitSha=commit_sha, error=out[-500:])
        return 1

    code, head = _git(["rev-parse", "HEAD"], cwd=dest, env=env, secret=credential)
    head = head.strip()
    if code != 0 or head != commit_sha:
        # The one comparison the whole lane rests on. Not a prefix match, not a
        # case-insensitive match: byte-for-byte, against the commit the SIGNED
        # operation named.
        log_event("error", "workspace.commit_mismatch", operationId=operation_id,
                  expected=commit_sha, actual=head or "(unreadable)")
        return COMMIT_SHA_MISMATCH_EXIT

    patch_applied = False
    if patch_digest:
        fc = common.FCClient(URL, AGENT_ID, SECRET, user_agent="fc-test-runner/1.0",
                             component="fc-test-runner")
        status, data = fc.get_bytes(
            f"/api/agent/workspace/{common.quote_path_segment(operation_id)}")
        if not (200 <= status < 300):
            log_event("error", "patch.fetch_failed", operationId=operation_id,
                      status_code=status, sizeBytes=len(data or b""))
            return 1
        actual = "sha256:" + hashlib.sha256(data).hexdigest()
        if actual != patch_digest:
            # Verified BEFORE unpacking, exactly as the workspace tar is: bytes
            # that do not hash to what the signed operation promised are not the
            # patch, whatever else they may be.
            log_event("error", "patch.digest_mismatch", operationId=operation_id,
                      expected=patch_digest, actual=actual, sizeBytes=len(data))
            return WORKSPACE_DIGEST_MISMATCH_EXIT
        writes, deletes, fingerprint = _apply_patch_archive(data, dest)
        patch_applied = True
        log_event("info", "patch.applied", operationId=operation_id, digest=actual,
                  writes=writes, deletes=deletes, patchFingerprint=fingerprint or None,
                  sizeBytes=len(data))

    # The line the runner parses back out of this container's log. It is the
    # ONLY channel by which "what did this cluster actually check out" reaches
    # the evidence, so it carries the OBSERVED head, never the requested one.
    log_event("info", CHECKOUT_EVENT, operationId=operation_id, commitSha=head,
              patchApplied=patch_applied, patchDigest=patch_digest or None, dest=dest)
    return 0


def poll_loop() -> None:
    fc = common.FCClient(URL, AGENT_ID, SECRET, user_agent="fc-test-runner/1.0",
                         component="fc-test-runner")
    kube = common.KubeClient()
    # Persisted, so a pod eviction is not a replay window (plan open question
    # 6). Its own ConfigMap, distinct from fc-agent's: two identities must not
    # share a single-use ledger.
    nonces = common.NonceStore(kube, POD_NAMESPACE, NONCE_CONFIGMAP)
    common.set_log_context(agent=AGENT_NAME, cluster=CLUSTER, tenant=TENANT)
    repo_keys = load_repo_keys()
    log_event("info", "startup", url=URL, capabilities=list(CAPABILITIES),
              pollSeconds=POLL, namespaceTtlSeconds=NAMESPACE_TTL_SECONDS,
              maxConcurrentRuns=MAX_CONCURRENT_RUNS,
              allowedToolchainPrefixes=list(ALLOWED_TOOLCHAIN_IMAGE_PREFIXES) or None,
              allowedCommands=sorted(ALLOWED_COMMANDS),
              allowedCommandsSource=("built-in default" if ALLOWED_COMMANDS == DEFAULT_ALLOWED_COMMANDS
                                     else "ALLOWED_COMMANDS"),
              workspaceKinds=advertised_workspace_kinds(repo_keys),
              # The KEYS, never the URLs behind them: a repo-key map is customer
              # topology, and the log is the one place it would leak by habit.
              repoKeys=sorted(repo_keys) or None)
    # The permissive default, said out loud once per process. Empty means "any
    # image FixControl names is pulled and run in this cluster" — backward
    # compatible on purpose (an install that never set it keeps working), and
    # the opposite of ALLOWED_NAMESPACES, which allowlists NOTHING when empty.
    if not ALLOWED_TOOLCHAIN_IMAGE_PREFIXES:
        log_event("warn", "config.image_allowlist_open",
                  setting="ALLOWED_TOOLCHAIN_IMAGE_PREFIXES",
                  message="empty ⇒ ANY toolchain or service image FixControl sends will be "
                          "pulled and run in this cluster. Set it to your own registry "
                          "prefixes (e.g. \"registry.internal/,docker.io/library/\") to close "
                          "that door; see install/values.example.env §8.")
    widened = sorted(ALLOWED_COMMANDS - DEFAULT_ALLOWED_COMMANDS)
    if widened:
        log_event("warn", "config.command_allowlist_widened",
                  setting="ALLOWED_COMMANDS", commands=widened,
                  message="this cluster admits plan commands the shipped default does not")
    while True:
        # Sweep first: a restarted process reclaims the previous life's
        # leftovers before it takes on new work (invariant 8).
        sweep_expired_namespaces(kube)
        with _ACTIVE_LOCK:
            capacity = MAX_CONCURRENT_RUNS - len(_ACTIVE)
        if capacity > 0:
            try:
                status, text = fc.post_json("/api/agent/poll", {
                    "clusterId": CLUSTER,
                    "agentName": AGENT_NAME,
                    "version": RUNNER_VERSION,
                    "capabilities": list(CAPABILITIES),
                    # ADDITIVE, and re-read every cycle so mounting the
                    # repo-key ConfigMap starts the git-remote lane without a
                    # restart. `/api/agent/poll` validates with a non-strict
                    # zod object, so a FixControl that has never heard of this
                    # field drops it and answers exactly as before.
                    "workspaceKinds": advertised_workspace_kinds(load_repo_keys()),
                })
                if not (200 <= status < 300):
                    raise RuntimeError(f"poll returned {status}: {text[:200]}")
                resp = json.loads(text) if text.strip() else {}
                operations = resp.get("operations", []) if isinstance(resp, dict) else list(resp or [])
            except Exception as e:  # noqa: BLE001
                _metric_bump("fc_test_runner_poll_failures_total")
                log_event("warn", "poll.failed", error=str(e)[:300])
                operations = []
            for op in operations[:capacity]:
                threading.Thread(target=handle_operation, args=(kube, fc, op, nonces),
                                 name=f"op-{op.get('operationId')}", daemon=False).start()
        time.sleep(POLL)


def _require_env(*, outbound_only: bool = False) -> None:
    """Boot guard. Fail fast and loudly on a misconfigured deploy rather than
    polling forever against nothing — and refuse plaintext HTTP unless the
    operator opted in, exactly as fc-signer does (the agent secret is the only
    thing protecting tenant data on the wire).

    `outbound_only` is the fetch initContainer's variant: it authenticates and
    downloads, but never verifies an operation, so it is deliberately given
    neither the cluster id nor the tenant — one credential less inside the pod
    that also runs customer test code."""
    required: tuple[tuple[str, str], ...] = (
        ("FIXCONTROL_URL", URL), ("FIXCONTROL_AGENT_ID", AGENT_ID),
        ("FIXCONTROL_AGENT_SECRET", SECRET),
    )
    if not outbound_only:
        required = required + (("FIXCONTROL_CLUSTER_ID", CLUSTER), ("FIXCONTROL_TENANT", TENANT))
    missing = [name for name, value in required if not value]
    if missing:
        raise SystemExit(f"fc-test-runner refusing to start: missing env {', '.join(missing)}")
    if URL.startswith("http://") and os.environ.get("ALLOW_INSECURE_FIXCONTROL_URL") != "1":
        raise SystemExit(
            f"fc-test-runner refusing to start: FIXCONTROL_URL={URL!r} is plaintext HTTP. "
            f"Point it at https:// or set ALLOW_INSECURE_FIXCONTROL_URL=1 (dev only)."
        )


def main(argv: list[str]) -> int:
    if "--sentinel" in argv:
        # The Job's main container. Every step ran as an initContainer; this
        # exists only so the pod has a container to Succeed with.
        log_event("info", "sentinel.exit")
        return 0
    if "--fetch-workspace" in argv:
        idx = argv.index("--fetch-workspace")
        if idx + 1 >= len(argv):
            raise SystemExit("fc-test-runner: --fetch-workspace needs an operation id")
        _require_env(outbound_only=True)
        return fetch_workspace(argv[idx + 1])
    if "--checkout-workspace" in argv:
        idx = argv.index("--checkout-workspace")
        if idx + 1 >= len(argv):
            raise SystemExit("fc-test-runner: --checkout-workspace needs an operation id")
        # A checkout with no patch talks to the customer's git remote and to
        # nothing else — it holds no FixControl credential and must not demand
        # one. Only the patch pull needs the outbound channel.
        if (os.environ.get("PATCH_DIGEST") or "").strip():
            _require_env(outbound_only=True)
        return checkout_workspace(argv[idx + 1])
    # A repo-key file that is present but unusable is a misconfigured deploy:
    # fail loudly at boot rather than silently serving a runner that refuses
    # every git-remote operation it is handed. (A file that breaks LATER, while
    # the pod runs, degrades to "no git-remote lane" instead — a bad edit to a
    # live ConfigMap must not crash-loop a runner mid-run.)
    if os.path.exists(REPO_KEYS_FILE):
        try:
            with open(REPO_KEYS_FILE, "r", encoding="utf-8") as f:
                parse_repo_keys(f.read())
        except (RepoConfigError, OSError) as e:
            raise SystemExit(f"fc-test-runner refusing to start: {REPO_KEYS_FILE}: {e}") from e
    _require_env()
    start_health_server()
    poll_loop()
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        log_event("info", "shutdown")
