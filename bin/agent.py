#!/usr/bin/env python3
"""
fc-agent — outbound-only FixControl agent (Phase 2a, rollout operations).

Reference implementation of docs/PLAN-fc-agent-outbound-connectivity.md for
customers whose Kubernetes API and Argo CD are NOT reachable from the
internet. The agent dials out; FixControl never dials in. The complete
firewall requirement is `egress customer → api.fixcontrol.ai:443`, and the
inbound requirement is: none.

It also carries CI verdicts to PRIVATE GitLab/Jenkins hosts (Phase 3 of
docs/PLAN-generic-cicd-gates.md): FixControl registers a signed
`ci.approve_deployment` / `ci.reject_deployment` operation, the agent
re-authorizes it locally, re-checks that the host is still paused, and performs
the host's own resume write from inside the network. The address of the host is
NEVER taken from the operation — see CI_CONFIG below.

It replaces watcher + signer with ONE component and adds the operation
channel:

    fc-rollout-watcher + fc-signer   →  events out   (kept, absorbed below)
    fc-receiver (ingress-exposed)    →  operations in (replaced by poll-out)

What it does, every POLL_SECONDS:

  1. POST /api/agent/poll  → a list of SignedOperations FixControl has
     REGISTERED (never executed) for this cluster.
  2. For each operation, run the plan's eight local checks in order. Checks
     1-5 and 8 are the shared envelope pass in bin/fc_agent_common.py; checks
     6 (customer-owned allowlist) and 7 (live revision) are here, because they
     need this cluster's own configuration and its live objects.
  3. Execute the survivors against the PRIVATE Kubernetes/Argo API, or against
     the manifests repo for the default GitOps profile.
  4. POST /api/agent/result — including every refusal, with its reason code.
     A silent drop would violate invariant 9 of the plan.

The two checks that carry the most weight:

  · Check 6 reads ALLOWED_NAMESPACES / ALLOWED_ROLLOUTS from the agent's own
    ConfigMap. A FixControl-side bug or compromise that emits "promote
    everything in kube-system" is refused by the CUSTOMER's configuration.
    That is the property that makes this deployable in a serious environment.
  · Check 7 reads the live Rollout microseconds before acting, so a stale
    approval cannot ship a revision nobody reviewed. Same comparison rules as
    FixControl's revision-pin.ts and bin/git-promote-bot.py: 24-char
    truncation, and null/empty/"current" are sentinels meaning "unpinned".

Promotion profiles, in the plan's policy order:

  (a) PROMOTE_MODE=git       DEFAULT. Writes the same promotion marker commit
                             that FixControl's git_promote dispatcher writes
                             (.fixcontrol/argo-promotions/<ns>/<name>/<id>.yaml);
                             fc-git-promote-bot / Argo CD picks it up. Every
                             promotion is a reviewable, revertable commit in
                             the customer's own history.
  (b) ARGO_LOCAL_API=1       Opt-in live mutation path. Used ONLY for
                             rollout.abort here — promotion stays on (a)/(c)
                             so invariant 5 ("the highest-security profile is
                             the default") holds by construction. With
                             ARGO_LOCAL_API=0 an operation that would need the
                             local API is refused `capability_denied`.
  (c) PROMOTE_MODE=receiver  Forwards the shipped fc-receiver HMAC envelope
                             over ClusterIP. Same receiver code, same
                             verification — one less internet-facing surface.

Events (EVENTS_ENABLED=1): a poll loop over the allowlisted namespaces diffs
Rollout phase/step and POSTs the SHIPPED FixControl Kubernetes-webhook payload
(HMAC over the raw body under FIXCONTROL_K8S_SECRET, X-FixControl-Signature /
X-FixControl-Account) — byte-identical to what bin/signer.py sends today, so
an existing tenant's ingest and gates keep working unchanged.
v1 POLLS on POLL_SECONDS. The plan calls for a real watch; that is a latency
optimisation on this same payload, not a protocol change, and lands later.

Env — identity + credentials (Secret `fc-agent`, never a ConfigMap):
  FIXCONTROL_URL            e.g. https://api.fixcontrol.ai
  FIXCONTROL_AGENT_ID       agent identity issued at enrolment
  FIXCONTROL_AGENT_SECRET   HMAC secret for envelopes + request auth
  FIXCONTROL_CLUSTER_ID     the Cluster id registered in /settings/devops
  FIXCONTROL_TENANT         the tenant this agent is bound to (check 1)
  FIXCONTROL_K8S_SECRET     per-tenant Kubernetes webhook secret (events)
  GIT_PROMOTE_CREDENTIAL    PAT with contents:write on the manifests repo
  RECEIVER_SECRET           fc-receiver outbound HMAC secret (receiver mode)

Env — customer-owned policy (ConfigMap `fc-agent-config`):
  FIXCONTROL_SIGNING_PUBLIC_KEYS
                            base64 Ed25519 public keys (comma/space separated,
                            max 2) this cluster TRUSTS to authorize operations.
                            Set ⇒ only `alg: ed25519` envelopes signed by one of
                            them are accepted; an HMAC envelope is refused
                            bad_signature, with no fallback. Unset ⇒ legacy
                            shared-secret verification, which production
                            installs must not stay on: under it the key that
                            authorizes this agent is a key this agent holds.
                            PUBLIC material — a ConfigMap, never a Secret, and
                            never fetched over the FixControl channel.
  AGENT_NAME                default fc-agent
  AGENT_CAPABILITIES        csv, default rollout.promote,rollout.abort,rollout.status
  CI_CONFIG                 JSON — the private CI hosts this agent may write to
                            (check 6 for ci.*). Empty/absent = allowlist nothing.
  CI_TIMEOUT_SECONDS        default 10 — per CI-host call, bounded
  CI_CA_BUNDLE              optional path to the internal CA bundle for the CI
                            hosts (a mounted ConfigMap). No "skip TLS" knob.
  ALLOWED_NAMESPACES        csv — check 6. Empty = allowlist nothing.
  ALLOWED_ROLLOUTS          csv of "ns/name" items, or "*" for every rollout
                            inside the allowlisted namespaces
  POLL_SECONDS              default 10
  CLOCK_SKEW_SECONDS        default 300
  PROMOTE_MODE              git (default) | receiver | none (CI/CD gates only:
                            every rollout.promote is refused capability_denied)
  GIT_PROMOTE_REPO/BRANCH   manifests repo coordinates (git mode)
  RECEIVER_URL              http://fc-receiver.argo-demo.svc.cluster.local (receiver mode)
  ARGO_LOCAL_API            "0" default — opt-in live Argo API (abort only)
  EVENTS_ENABLED            "1" default
  METRICS_HOST/METRICS_PORT default 127.0.0.1:8080 (loopback: no Service)
  AGENT_WORK_DIR            default /tmp/fc-agent (emptyDir; git clones)
  DRY_RUN                   "1" logs decisions without touching git/cluster
  ALLOW_INSECURE_FIXCONTROL_URL=1   opt into plaintext http:// (dev only)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

import fc_agent_common as fc  # noqa: E402  (path shim above must run first)

AGENT_VERSION = "1.0.0"

# ── Identity + credentials (required — fail fast on boot) ───────────────────
FIXCONTROL_URL = os.environ["FIXCONTROL_URL"].rstrip("/")
AGENT_ID = os.environ["FIXCONTROL_AGENT_ID"]
AGENT_SECRET = os.environ["FIXCONTROL_AGENT_SECRET"]
CLUSTER_ID = os.environ["FIXCONTROL_CLUSTER_ID"]
# Check 1 needs a bound tenant. Deliberately required rather than defaulted:
# a missing tenant would make tenant_mismatch unenforceable, and an agent that
# cannot refuse a foreign tenant's operation is not the design.
TENANT = os.environ["FIXCONTROL_TENANT"]

# HTTPS guard runs at import, like bin/signer.py — a misconfigured prod deploy
# must not reach the first poll.
fc.assert_fixcontrol_url_secure(FIXCONTROL_URL, "fc-agent")

# ── Customer-owned policy ───────────────────────────────────────────────────
AGENT_NAME = os.environ.get("AGENT_NAME", "fc-agent")
CAPABILITIES = set(fc.csv_env(
    "AGENT_CAPABILITIES", "rollout.promote,rollout.abort,rollout.status"))
ALLOWED_NAMESPACES = fc.csv_env("ALLOWED_NAMESPACES")
ALLOWED_ROLLOUTS = fc.csv_env("ALLOWED_ROLLOUTS")
POLL_SECONDS = float(os.environ.get("POLL_SECONDS", "10"))
CLOCK_SKEW_SECONDS = int(os.environ.get("CLOCK_SKEW_SECONDS", str(fc.DEFAULT_SKEW_SECONDS)))
PROMOTE_MODE = os.environ.get("PROMOTE_MODE", "git").strip().lower()
GIT_PROMOTE_REPO = os.environ.get("GIT_PROMOTE_REPO", "")
GIT_PROMOTE_BRANCH = os.environ.get("GIT_PROMOTE_BRANCH", "main")
GIT_PROMOTE_CREDENTIAL = os.environ.get("GIT_PROMOTE_CREDENTIAL", "")
RECEIVER_URL = os.environ.get("RECEIVER_URL", "").rstrip("/")
RECEIVER_SECRET = os.environ.get("RECEIVER_SECRET", "")
ARGO_LOCAL_API = os.environ.get("ARGO_LOCAL_API", "0") == "1"
EVENTS_ENABLED = os.environ.get("EVENTS_ENABLED", "1") == "1"
K8S_WEBHOOK_SECRET = os.environ.get("FIXCONTROL_K8S_SECRET", "")
DRY_RUN = os.environ.get("DRY_RUN") == "1"
METRICS_HOST = os.environ.get("METRICS_HOST", "127.0.0.1")
METRICS_PORT = int(os.environ.get("METRICS_PORT", "8080"))
WORK_DIR = Path(os.environ.get("AGENT_WORK_DIR", "/tmp/fc-agent"))
POD_NAMESPACE = os.environ.get("POD_NAMESPACE", "argo-demo")
NONCE_CONFIGMAP = os.environ.get("NONCE_CONFIGMAP", "fc-agent-nonces")
CI_TIMEOUT_SECONDS = float(os.environ.get("CI_TIMEOUT_SECONDS", "10"))
# Check 3's trust anchor. A malformed value ABORTS the process rather than
# parsing to "nothing pinned": silently dropping back to the shared secret is
# the one failure mode the pin exists to prevent, so it must never be the
# consequence of a typo.
try:
    SIGNING_PUBLIC_KEYS = fc.parse_signing_public_keys(
        os.environ.get("FIXCONTROL_SIGNING_PUBLIC_KEYS"))
except fc.SigningKeyConfigError as _e:
    raise SystemExit(f"fc-agent: {_e}") from _e
CI_CA_BUNDLE = os.environ.get("CI_CA_BUNDLE", "").strip()

ROLLOUTS_API = "/apis/argoproj.io/v1alpha1"
EVENT_ENDPOINT = "/api/integrations/devops/kubernetes/webhook"

# Argo eventType → (action, status) in FixControl's PipelinePhase vocabulary.
# Copied verbatim from bin/signer.py: the agent replaces watcher→signer with
# one component, and the receiving end's ci_status check must render the same
# colours it renders today.
EVENT_MAP = {
    "rollout-step-completed": ("step_completed", "running"),
    "rollout-paused":         ("paused",         "awaiting_approval"),
    "rollout-completed":      ("completed",      "succeeded"),
    "rollout-aborted":        ("aborted",        "failed"),
}

# Wired in main(); the smokes assign fakes so every check is exercised
# clusterless (same pattern as scripts/smoke-git-promote-revision-pin.py).
FC: fc.FCClient | None = None
KUBE: fc.KubeClient | None = None
NONCES: fc.NonceStore | None = None

_LAST_POLL_OK = threading.Event()


def _fc() -> fc.FCClient:
    if FC is None:
        raise RuntimeError("fc-agent: FixControl client not wired (call main())")
    return FC


def _kube() -> fc.KubeClient:
    if KUBE is None:
        raise RuntimeError("fc-agent: Kubernetes client not wired (call main())")
    return KUBE


# ── Check 6 — the customer-owned allowlist ──────────────────────────────────

def is_allowlisted(namespace: str | None, name: str | None) -> bool:
    """Check 6. BOTH the namespace and the ns/name pair must be allowed.

    Fail-closed on every axis: an empty ALLOWED_NAMESPACES allowlists nothing,
    a missing target is not allowlisted, and "*" only ever widens WITHIN the
    namespaces the customer already named. There is deliberately no
    "allow all namespaces" spelling.
    """
    if not namespace or not name:
        return False
    if namespace not in ALLOWED_NAMESPACES:
        return False
    if "*" in ALLOWED_ROLLOUTS:
        return True
    return f"{namespace}/{name}" in ALLOWED_ROLLOUTS


# ── Check 7 — live revision, read from the private API ──────────────────────

def rollout_path(namespace: str, name: str) -> str:
    return (f"{ROLLOUTS_API}/namespaces/{fc.quote_path_segment(namespace)}"
            f"/rollouts/{fc.quote_path_segment(name)}")


def read_rollout(namespace: str, name: str) -> dict[str, Any] | None:
    """Live Rollout, or None when it is unreadable.

    None means "we do not know", never "there is no drift" — the callers
    distinguish the two: check 7 fails OPEN on missing knowledge (same stance
    as revision-pin.ts: only a POSITIVE mismatch refuses), while rollout.status
    fails the operation because "I could not read it" IS the answer there.
    """
    try:
        body = _kube().get(rollout_path(namespace, name))
    except fc.KubeError as e:
        fc.log_event("warn", "rollout.read_failed", namespace=namespace, rollout=name,
                     status=e.status, error=str(e)[:200])
        return None
    return body if isinstance(body, dict) else None


def rollout_revision_candidates(body: dict[str, Any]) -> list[str]:
    """Live revision candidates, in the signer's vocabulary — the image TAG
    first (tag after the ':' of the LAST path segment, never the registry-port
    ':' of `registry:5000/repo/name`), then the full image string, plus
    status.updateRevision when Argo sets it. Multiple candidates because the
    approval may have captured either emission mode; a match on ANY of them
    means the paused revision is still the reviewed one.

    Mirrors extractRolloutRevision in revision-pin.ts and
    _candidates_from_rollout in bin/git-promote-bot.py.
    """
    out: list[str] = []

    def push(v: object) -> None:
        if isinstance(v, str) and v and v not in out:
            out.append(v)

    status = body.get("status")
    if isinstance(status, dict):
        push(status.get("updateRevision"))
    spec = body.get("spec") if isinstance(body.get("spec"), dict) else {}
    template = spec.get("template") if isinstance(spec.get("template"), dict) else {}
    pod_spec = template.get("spec") if isinstance(template.get("spec"), dict) else {}
    containers = pod_spec.get("containers") if isinstance(pod_spec.get("containers"), list) else []
    image = containers[0].get("image") if containers and isinstance(containers[0], dict) else None
    if isinstance(image, str) and image:
        last_segment = image.split("/")[-1]
        colon = last_segment.find(":")
        if colon > 0:
            push(last_segment[colon + 1:])
        push(image)
    annotations = (body.get("metadata") or {}).get("annotations") \
        if isinstance(body.get("metadata"), dict) else None
    if isinstance(annotations, dict):
        push(annotations.get("rollout.argoproj.io/revision"))
    return out


def expected_revision(op: dict[str, Any]) -> str | None:
    """target.expectRevision, with the shipped sentinel rules.

    "", null, "~" and "current" all mean UNPINNED. `current` in particular is
    the k8s provider's no-revision fallback: pinning on it would compare
    sentinel-to-sentinel and pass for ANY paused revision, so it must not be
    treated as a pin (mirrors parsePipelineRunForArgo in resolve-target.ts).
    """
    target = op.get("target") if isinstance(op.get("target"), dict) else {}
    raw = target.get("expectRevision")
    if raw is None:
        return None
    raw = str(raw).strip()
    if raw in ("", "null", "~", "current"):
        return None
    return raw


def evaluate_pin(captured: str | None,
                 candidates: list[str] | None) -> tuple[str, str]:
    """Pure pin verdict — mirrors evaluateRevisionPin in revision-pin.ts.

    Both sides compare under the k8s provider's 24-char truncation
    (externalRunId stores revision.slice(0, 24)), so a marker captured from a
    truncated revision does not false-refuse against the full 40-hex revision
    the live Rollout reports.

      ("unpinned", reason)        no pin / live unknown  → proceed
      ("match",    live_revision) pin verified           → proceed
      ("refuse",   live_revision) POSITIVE mismatch      → revision_drift
    """
    if captured is None:
        return ("unpinned", "no_expect_revision")
    if not candidates:
        return ("unpinned", "live_revision_unknown")
    for live in candidates:
        if live[:24] == captured[:24]:
            return ("match", live)
    return ("refuse", candidates[0])


def check_revision(op: dict[str, Any], namespace: str,
                   name: str) -> tuple[bool, str, str]:
    """Check 7 for rollout.promote / rollout.abort.

    Returns (ok, verdict, detail). Unreadable live state is `unpinned` — a
    flaky API server must not brick every promotion, and the server-side pin
    in revision-pin.ts already ran on the same revision.
    """
    captured = expected_revision(op)
    if captured is None:
        return True, "unpinned", "no_expect_revision"
    body = read_rollout(namespace, name)
    candidates = rollout_revision_candidates(body) if body else None
    verdict, detail = evaluate_pin(captured, candidates or None)
    return verdict != "refuse", verdict, detail


# ── Execution — profile (a): GitOps marker commit ───────────────────────────

def _git(args: list[str], cwd: Path | None = None,
         timeout: int = 60) -> tuple[bool, str]:
    """git with the credential injected via GIT_CONFIG_* — identical scheme to
    bin/git-promote-bot.py and FixControl's git-promote.ts, so the PAT never
    lands in .git/config on the (read-only-rootfs) pod's emptyDir."""
    env = dict(os.environ)
    env["GIT_TERMINAL_PROMPT"] = "0"
    if GIT_PROMOTE_CREDENTIAL:
        env["GIT_CONFIG_COUNT"] = "1"
        env["GIT_CONFIG_KEY_0"] = "http.extraheader"
        env["GIT_CONFIG_VALUE_0"] = (
            f"Authorization: {fc.basic_auth_header('x-access-token', GIT_PROMOTE_CREDENTIAL)}")
    try:
        r = subprocess.run(["git"] + args, cwd=cwd, env=env,
                           capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, "[timeout]"
    except FileNotFoundError as e:
        return False, f"git missing: {e}"
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def _safe_segment(s: str) -> str:
    """Path-safe marker segment — mirrors safeSegment in git-promote.ts so a
    hostile rolloutName cannot escape the marker directory."""
    out = "".join(c if (c.isalnum() or c in "._-") else "_" for c in str(s))
    return out[:128] or "_"


def _yaml_string(s: str) -> str:
    """Always quoted — keeps a number/boolean/`null`-shaped value from being
    mis-typed by a YAML 1.1 parser on the consumer side (yamlString in
    git-promote.ts)."""
    return '"' + str(s).replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_marker(namespace: str, name: str, revision: str | None, approval_id: str,
                 task_id: str, decided_by: str, channel: str,
                 signed_at: str | None = None) -> str:
    """Byte-compatible with buildMarker() in
    src/server/integrations/devops/argo/git-promote.ts.

    Field order, quoting and the two header comments are taken literally: the
    consumer is the SHIPPED bin/git-promote-bot.py, whose tiny YAML-ish parser
    and revision-pin logic are pinned against this exact shape by
    scripts/smoke-git-promote-revision-pin.py. The extra provenance comment is
    a comment line, which that parser skips.
    """
    return "\n".join([
        "# FixControl Argo Rollouts promotion marker (Tier 3, git_promote profile).",
        "# Generated by decideOrchestrationApproval — do not edit by hand.",
        f"# Materialised in-cluster by fc-agent {AGENT_VERSION} from a signed operation.",
        "v: 1",
        "action: promote",
        f"namespace: {_yaml_string(namespace)}",
        f"rolloutName: {_yaml_string(name)}",
        f"revision: {'null' if revision is None else _yaml_string(revision)}",
        f"approvalId: {_yaml_string(approval_id)}",
        f"taskId: {_yaml_string(task_id)}",
        f"decidedBy: {_yaml_string(decided_by)}",
        f"channel: {channel}",
        f"signedAt: {signed_at or fc.rfc3339()}",
        "",
    ])


def marker_path(namespace: str, name: str, approval_id: str) -> str:
    return (f".fixcontrol/argo-promotions/{_safe_segment(namespace)}"
            f"/{_safe_segment(name)}/{_safe_segment(approval_id)}.yaml")


def _op_field(op: dict[str, Any], key: str, default: str) -> str:
    """Read a decision field from payload (preferred) or target."""
    payload = op.get("payload") if isinstance(op.get("payload"), dict) else {}
    target = op.get("target") if isinstance(op.get("target"), dict) else {}
    for source in (payload, target):
        value = source.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return default


def promote_via_git(op: dict[str, Any], namespace: str,
                    name: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """Profile (a) — the default. Commit the promotion marker; the shipped
    fc-git-promote-bot (or Argo CD itself) turns it into the rollout step.

    Returns (outcome, reasonCode, message, evidence).
    """
    approval_id = _op_field(op, "approvalId", str(op.get("operationId") or "unknown"))
    task_id = _op_field(op, "taskId", str(op.get("operationId") or "unknown"))
    decided_by = _op_field(op, "decidedBy", "fixcontrol")
    channel = _op_field(op, "channel", "system")
    revision = expected_revision(op)
    rel = marker_path(namespace, name, approval_id)

    if DRY_RUN:
        fc.log_event("info", "promote.dry_run", mode="git", namespace=namespace,
                     rollout=name, marker=rel, approval_id=approval_id)
        return (fc.OUTCOME_SUCCEEDED, None, f"[DRY] would commit {rel}",
                {"commitSha": "dry-run", "markerPath": rel, "mode": "git"})

    if not GIT_PROMOTE_REPO:
        return (fc.OUTCOME_FAILED, None,
                "PROMOTE_MODE=git but GIT_PROMOTE_REPO is unset", {"mode": "git"})

    WORK_DIR.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="promote-", dir=str(WORK_DIR)))
    try:
        ok, out = _git(["clone", "--branch", GIT_PROMOTE_BRANCH, "--single-branch",
                        "--depth", "1", "--", GIT_PROMOTE_REPO, str(work)])
        if not ok:
            return (fc.OUTCOME_FAILED, None, f"git clone failed: {out[:300]}",
                    {"mode": "git"})

        target = work / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            build_marker(namespace, name, revision, approval_id, task_id,
                         decided_by, channel),
            encoding="utf-8")

        # Same bot identity as FixControl's dispatcher, so `git log` reads the
        # same whether the marker was written from SaaS or from in-cluster.
        _git(["config", "user.email", "argo-bot@fixcontrol.ai"], cwd=work)
        _git(["config", "user.name", "FixControl Argo Bot"], cwd=work)

        ok, out = _git(["add", "--", rel], cwd=work)
        if not ok:
            return (fc.OUTCOME_FAILED, None, f"git add failed: {out[:300]}",
                    {"mode": "git", "markerPath": rel})

        msg = (f"feat(argo-promote): {namespace}/{name} approved by {decided_by} "
               f"via {channel} (gate {approval_id})")
        ok, out = _git(["commit", "-m", msg], cwd=work)
        if not ok and "nothing to commit" not in out:
            return (fc.OUTCOME_FAILED, None, f"git commit failed: {out[:300]}",
                    {"mode": "git", "markerPath": rel})
        # "nothing to commit" = this approval already produced this exact
        # marker. operationId is the idempotency key end to end, so a re-fire
        # collapses to the same success rather than a spurious failure.

        ok, out = _git(["push", "--", "origin", GIT_PROMOTE_BRANCH], cwd=work)
        if not ok:
            return (fc.OUTCOME_FAILED, None, f"git push failed: {out[:300]}",
                    {"mode": "git", "markerPath": rel})

        _, sha = _git(["rev-parse", "HEAD"], cwd=work)
        commit_sha = sha.split()[0] if sha else ""
        fc.log_event("info", "promote.committed", namespace=namespace, rollout=name,
                     marker=rel, commit=commit_sha, approval_id=approval_id)
        return (fc.OUTCOME_SUCCEEDED, None, f"marker committed at {commit_sha[:12]}",
                {"commitSha": commit_sha, "markerPath": rel, "mode": "git"})
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ── Execution — profile (c): the in-cluster fc-receiver over ClusterIP ──────

def _receiver_post(action: str, namespace: str, name: str,
                   op: dict[str, Any]) -> tuple[str, str | None, str, dict[str, Any]]:
    """Forward the SHIPPED fc-receiver envelope (reverse-webhook.ts v1) over
    ClusterIP. Same secret material, same HMAC, same receiver code — the only
    thing that changes versus today is that the receiver no longer needs an
    Ingress, because the agent reaches it from inside."""
    if not RECEIVER_URL or not RECEIVER_SECRET:
        return (fc.OUTCOME_FAILED, None,
                "PROMOTE_MODE=receiver but RECEIVER_URL/RECEIVER_SECRET are unset",
                {"mode": "receiver"})
    envelope = {
        "v": 1,
        "action": action,
        "rolloutName": name,
        "namespace": namespace,
        "taskId": _op_field(op, "taskId", str(op.get("operationId") or "unknown")),
        "approvalId": _op_field(op, "approvalId", str(op.get("operationId") or "unknown")),
        "signedAt": fc.rfc3339(),
    }
    body = json.dumps(envelope, separators=(",", ":")).encode("utf-8")
    if DRY_RUN:
        fc.log_event("info", "promote.dry_run", mode="receiver", action=action,
                     namespace=namespace, rollout=name)
        return (fc.OUTCOME_SUCCEEDED, None, f"[DRY] would POST {action} to receiver",
                {"statusCode": 200, "mode": "receiver"})
    signature = hmac.new(RECEIVER_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    req = urllib.request.Request(
        f"{RECEIVER_URL}/{action}", data=body,
        headers={"Content-Type": "application/json",
                 "X-FixControl-Signature": f"sha256={signature}",
                 "User-Agent": f"fc-agent/{AGENT_VERSION}"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            status, text = resp.status, resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        status, text = e.code, e.read().decode("utf-8", "replace")
    except urllib.error.URLError as e:
        status, text = 0, f"network: {e}"
    if 200 <= status < 300:
        return (fc.OUTCOME_SUCCEEDED, None, text[:200], {"statusCode": status,
                                                         "mode": "receiver"})
    return (fc.OUTCOME_FAILED, None, f"receiver {status}: {text[:200]}",
            {"statusCode": status, "mode": "receiver"})


# ════════════════════════════════════════════════════════════════════════════
#  CI LANE — agent-carried deployment verdicts for PRIVATE GitLab/Jenkins
#  (Phase 3 of docs/PLAN-generic-cicd-gates.md)
# ════════════════════════════════════════════════════════════════════════════
#
# THE CUSTOMER OWNS THE ADDRESS. This is the whole security story of the lane
# and it is worth stating before the code: the operation FixControl signs
# carries a PROVIDER and a canonical run id, and nothing else. It does not
# carry a base URL, a token, or a hostname. The agent dials only the base_urls
# written in its OWN ConfigMap (CI_CONFIG), with credentials read from its own
# Secret-mounted env. A FixControl-side bug or compromise that emits "approve
# something at http://169.254.169.254/" has nothing to steer here — there is no
# field to put that address in. The class of attack is removed, not mitigated,
# exactly as ALLOWED_NAMESPACES removes it for rollouts (plan check 6).
#
# THE WAITING HOST IS THE TRUTH. The gate opened minutes or hours ago; whether
# the pipeline is still paused is a fact only the host knows. So every write is
# preceded by a read of the live pause, and "not waiting any more" is reported
# as the GOVERNANCE outcome `no_longer_pending` — never as an error, never
# retried. Same posture as revision_drift on the rollout lane.
#
# THE SAME READ PICKS THE PRIMITIVE (open question 13, decided 2026-08-23).
# A blocked GitLab deployment can be held by an approval rule (Premium) or by
# its own manual job (every tier, and the ONLY lane a CE project has). The
# pre-check already has the answer in its hands, so it chooses the endpoint —
# exactly as the direct FixControl executor has done since open question 11.
# Before this, a CE tenant behind an agent could open a governed deployment
# gate and never release it. See _gitlab_deployment.

# ── Canonical run-id parsers — Python parity with the TypeScript side ───────
#
# Byte-for-byte the same grammar as
#   src/server/integrations/devops/gitlab-ci/resolve-target.ts
#   src/server/integrations/devops/jenkins/resolve-target.ts
# including the refusals. Both sides must agree on which strings are addresses
# and which are not, because a parser that is more permissive here would let
# the agent build a REST path the FixControl side would never have produced.
#
# Deliberately re-implemented rather than "trusted because FixControl sent it":
# the envelope is signed, but signing proves origin, not well-formedness.

CI_PROVIDER_GITLAB = "gitlab-ci"
CI_PROVIDER_JENKINS = "jenkins"
CI_PROVIDERS = (CI_PROVIDER_GITLAB, CI_PROVIDER_JENKINS)

CI_ACTION_APPROVE = "approve"
CI_ACTION_REJECT = "reject"
CI_ACTIONS = (CI_ACTION_APPROVE, CI_ACTION_REJECT)

GITLAB_LANE_DEPLOYMENT = "deployment"
GITLAB_LANE_JOB = "job"
GITLAB_LANES = (GITLAB_LANE_DEPLOYMENT, GITLAB_LANE_JOB)

_NUMERIC_ID_RE = re.compile(r"^\d+$")
_INPUT_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,128}$")

_GITLAB_DEPLOYMENT_MARKER = "#deployment:"
_GITLAB_JOB_MARKER = "#job:"
_JENKINS_INPUT_MARKER = "@input:"

#: Response excerpts that reach a result are capped here — the contract's
#: "no response bodies longer than 2 KB". Applied AFTER redaction, so a secret
#: can never survive by sitting past the cut.
CI_EXCERPT_MAX_BYTES = 2048
#: How much of a CI response we read off the socket at all. A hostile or broken
#: host must not be able to make the agent buffer a gigabyte.
CI_READ_MAX_BYTES = 8192


def parse_gitlab_ci_run_id(address: Any) -> dict[str, str] | None:
    """`{project_id}#deployment:{id}` | `{project_id}#job:{id}` → a ref.

    Single-split on the FIRST `#`, like parseGitlabCiRunId: a project id cannot
    contain `#`, and the marker that follows decides which endpoint the tail
    addresses. A legacy bare id (`4242`) has no marker and does not parse —
    which is the intended answer, not a bug to paper over.
    """
    if not isinstance(address, str) or not address:
        return None
    hash_at = address.find("#")
    if hash_at <= 0:
        return None
    project_id = address[:hash_at]
    if not _NUMERIC_ID_RE.match(project_id):
        return None
    rest = address[hash_at:]
    if rest.startswith(_GITLAB_DEPLOYMENT_MARKER):
        deployment_id = rest[len(_GITLAB_DEPLOYMENT_MARKER):]
        if not _NUMERIC_ID_RE.match(deployment_id):
            return None
        return {"lane": GITLAB_LANE_DEPLOYMENT, "project_id": project_id,
                "deployment_id": deployment_id}
    if rest.startswith(_GITLAB_JOB_MARKER):
        job_id = rest[len(_GITLAB_JOB_MARKER):]
        if not _NUMERIC_ID_RE.match(job_id):
            return None
        return {"lane": GITLAB_LANE_JOB, "project_id": project_id, "job_id": job_id}
    return None


def build_gitlab_ci_run_id(ref: dict[str, str]) -> str | None:
    """Round-trip helper — mirrors buildGitlabCiRunId, same validation."""
    project_id = str(ref.get("project_id") or "").strip()
    if not _NUMERIC_ID_RE.match(project_id):
        return None
    if ref.get("lane") == GITLAB_LANE_DEPLOYMENT:
        tail = str(ref.get("deployment_id") or "").strip()
        marker = _GITLAB_DEPLOYMENT_MARKER
    elif ref.get("lane") == GITLAB_LANE_JOB:
        tail = str(ref.get("job_id") or "").strip()
        marker = _GITLAB_JOB_MARKER
    else:
        return None
    if not _NUMERIC_ID_RE.match(tail):
        return None
    return f"{project_id}{marker}{tail}"


def _is_usable_jenkins_job_name(value: Any) -> bool:
    """isUsableJobName from the TypeScript parser, character for character.
    `#` and `@` are what make the two delimiters unambiguous (Jenkins' own
    checkGoodName rejects both); control characters have no place in a value
    that ends up in a URL and in an audit field."""
    if not isinstance(value, str) or not value or len(value) > 255:
        return False
    if "#" in value or "@" in value:
        return False
    return all(0x20 <= ord(c) != 0x7F for c in value)


def parse_jenkins_run_id(address: Any) -> dict[str, str] | None:
    """`{jobName}#{buildNumber}@input:{inputId}` → a ref.

    A bare build id (`deploy-api#42`, what the Notification-Plugin lifecycle
    branch writes) has no `@input:` marker and therefore does not parse: it is
    a build row, not a pause, and there is nothing on it to resume.
    """
    if not isinstance(address, str) or not address:
        return None
    marker = address.find(_JENKINS_INPUT_MARKER)
    if marker <= 0:
        return None
    head = address[:marker]
    input_id = address[marker + len(_JENKINS_INPUT_MARKER):]
    if not _INPUT_ID_RE.match(input_id):
        return None
    hash_at = head.find("#")
    if hash_at <= 0:
        return None
    job_name = head[:hash_at]
    build_number = head[hash_at + 1:]
    if not _is_usable_jenkins_job_name(job_name):
        return None
    if not _NUMERIC_ID_RE.match(build_number):
        return None
    return {"job_name": job_name, "build_number": build_number, "input_id": input_id}


def build_jenkins_run_id(ref: dict[str, str]) -> str | None:
    """Round-trip helper — mirrors buildJenkinsInputRunId."""
    job_name = str(ref.get("job_name") or "").strip()
    build_number = str(ref.get("build_number") or "").strip()
    input_id = str(ref.get("input_id") or "").strip()
    if not _is_usable_jenkins_job_name(job_name):
        return None
    if not _NUMERIC_ID_RE.match(build_number):
        return None
    if not _INPUT_ID_RE.match(input_id):
        return None
    return f"{job_name}#{build_number}{_JENKINS_INPUT_MARKER}{input_id}"


def parse_ci_address(provider: str, address: Any) -> dict[str, str] | None:
    if provider == CI_PROVIDER_GITLAB:
        return parse_gitlab_ci_run_id(address)
    if provider == CI_PROVIDER_JENKINS:
        return parse_jenkins_run_id(address)
    return None


# ── CI_CONFIG — the customer-owned CI host allowlist (check 6 for ci.*) ─────
#
# JSON rather than the csv this file uses everywhere else, and for one reason:
# the allowlist is genuinely nested (a project has lanes, a lane has actions).
# Flattening that into comma-separated strings would mean inventing a
# mini-language an operator has to be taught; a JSON block in a ConfigMap is
# something a platform team can already read, review and diff.
#
#   {
#     "version": 1,
#     "providers": [
#       { "provider": "gitlab-ci",
#         "base_url": "https://gitlab.internal.example",
#         "credential_env": "GITLAB_CI_TOKEN",
#         "allowlist": { "projects": [
#           { "project_id": "77",
#             "lanes":   ["deployment", "job"],
#             "actions": ["approve", "reject"] } ] } },
#       { "provider": "jenkins",
#         "base_url": "https://jenkins.internal.example",
#         "credential_env": "JENKINS_CREDENTIAL",
#         "allowlist": { "jobs": [
#           { "job": "platform/deploy-api", "actions": ["approve", "reject"] } ] } }
#     ]
#   }
#
# There is deliberately NO wildcard spelling. An entry names at most two lanes
# and two actions, so a `*` would buy an operator nothing but the chance to
# grant more than they meant. Empty list = nothing allowed, same fail-closed
# stance as an empty ALLOWED_NAMESPACES.
#
# WHAT A `deployment` LANE GRANT MEANS — read this before writing one:
#
#   The lanes name the PAUSE OBJECT FixControl may address, not the REST
#   endpoint the agent ends up calling. A blocked GitLab deployment can be held
#   by an approval rule or by its own manual job, and only the host knows
#   which; the agent reads that at write time and uses the primitive that
#   actually holds the pause (open question 13). So:
#
#     "lanes": ["deployment"], "actions": ["approve"]
#         → may release a blocked deployment of this project, INCLUDING by
#           running the manual job the host reports as holding it. On GitLab
#           Free/CE that is the only thing it can ever mean, because CE has no
#           deployment-approval endpoint. The job is never one FixControl
#           chose: it is read out of the very deployment the operation
#           authorized.
#     "lanes": ["deployment"], "actions": ["reject"]
#         → may refuse a blocked deployment. On an approval-rule pause that is
#           a real host write; on a manual-job pause there is nothing to write
#           and the agent says so (`no_refusal_primitive`) — the job stays
#           unplayed, which is the refusal taking effect.
#     "lanes": ["job"]
#         → the separate, wider grant: FixControl may address a manual job of
#           this project DIRECTLY, by job id. Not needed for the above.

def parse_ci_config(raw: str) -> dict[str, dict[str, Any]]:
    """CI_CONFIG text → {provider: entry}. Fail-closed on every axis.

    Three grades of rejection, on purpose:

      · unreadable document (bad JSON, unknown version, `providers` not a list)
        → the WHOLE config is dropped. We cannot tell which parts were meant.
      · a duplicate entry for a known provider → the whole config is dropped
        too. Two base_urls for `gitlab-ci` means the agent would have to GUESS
        which host to dial, and guessing which host receives a governed write
        is precisely the answer that must never be invented.
      · one unusable entry (unknown provider, missing base_url, credential env
        not set in the pod) → THAT entry is dropped, loudly; the rest keeps
        working. An unusable entry can never match anything anyway, so failing
        the operator's whole GitLab config over a half-written Jenkins one
        would be punishment, not safety.
    """
    text = (raw or "").strip()
    if not text:
        return {}
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as e:
        fc.log_event("error", "ci_config.unparseable", error=str(e)[:200],
                     note="CI_CONFIG is not valid JSON; NO CI host is allowlisted")
        return {}
    if not isinstance(doc, dict):
        fc.log_event("error", "ci_config.not_an_object",
                     note="CI_CONFIG must be an object with a `providers` list")
        return {}
    version = doc.get("version", 1)
    if version != 1:
        fc.log_event("error", "ci_config.unknown_version", version=version,
                     note="this agent only understands CI_CONFIG version 1")
        return {}
    entries = doc.get("providers")
    if not isinstance(entries, list):
        fc.log_event("error", "ci_config.no_providers_list",
                     note="CI_CONFIG.providers must be a list")
        return {}

    out: dict[str, dict[str, Any]] = {}
    for raw_entry in entries:
        if not isinstance(raw_entry, dict):
            fc.log_event("warn", "ci_config.entry_not_an_object")
            continue
        provider = str(raw_entry.get("provider") or "").strip()
        if provider not in CI_PROVIDERS:
            fc.log_event("warn", "ci_config.unknown_provider", provider=provider,
                         note="this agent carries CI writes for gitlab-ci and jenkins only")
            continue
        if provider in out:
            fc.log_event("error", "ci_config.duplicate_provider", provider=provider,
                         note="two entries for one provider is ambiguous; NO CI host "
                              "is allowlisted until it is resolved")
            return {}
        entry = _parse_ci_entry(provider, raw_entry)
        if entry is None:
            continue
        out[provider] = entry
    return out


def _parse_ci_entry(provider: str, raw_entry: dict[str, Any]) -> dict[str, Any] | None:
    base_url = str(raw_entry.get("base_url") or "").strip().rstrip("/")
    if not base_url:
        fc.log_event("error", "ci_config.no_base_url", provider=provider)
        return None
    parsed = urllib.parse.urlparse(base_url)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        fc.log_event("error", "ci_config.bad_base_url", provider=provider,
                     note="base_url must be an http(s) origin")
        return None
    if parsed.scheme == "http":
        # Not refused: a private CI host on a flat internal network is a real
        # deployment, and this agent never leaves that network. Said out loud
        # so it is a choice on the record rather than an oversight.
        fc.log_event("warn", "ci_config.plaintext_base_url", provider=provider,
                     note="the CI credential will travel unencrypted on this network")

    credential_env = str(raw_entry.get("credential_env") or "").strip()
    if not credential_env:
        fc.log_event("error", "ci_config.no_credential_env", provider=provider)
        return None
    credential = os.environ.get(credential_env, "").strip()
    if not credential:
        # Dropped rather than kept-and-failed-later: an entry we cannot
        # authenticate with is not a configured host, and refusing it as
        # `not_allowlisted` with "no local entry" is the honest message.
        fc.log_event("error", "ci_config.credential_env_unset", provider=provider,
                     credential_env=credential_env,
                     note="mount it from the fc-agent-ci Secret; this provider is "
                          "NOT allowlisted until it is set")
        return None
    if provider == CI_PROVIDER_JENKINS and ":" not in credential:
        fc.log_event("error", "ci_config.jenkins_credential_shape",
                     credential_env=credential_env,
                     note="Jenkins credentials are `user:apiToken`; this provider is "
                          "NOT allowlisted until it has that shape")
        return None

    allowlist = raw_entry.get("allowlist")
    if not isinstance(allowlist, dict):
        fc.log_event("error", "ci_config.no_allowlist", provider=provider)
        return None
    rules = (_parse_gitlab_allowlist(allowlist) if provider == CI_PROVIDER_GITLAB
             else _parse_jenkins_allowlist(allowlist))
    return {"provider": provider, "base_url": base_url,
            "credential_env": credential_env, "rules": rules}


def _actions_of(raw: Any) -> set[str]:
    if not isinstance(raw, list):
        return set()
    return {a for a in (str(x).strip() for x in raw) if a in CI_ACTIONS}


def _parse_gitlab_allowlist(allowlist: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    """{project_id: {"lanes": {...}, "actions": {...}}}. Anything unrecognised
    is dropped rather than kept: an allowlist entry nobody can read is an
    allowlist entry nobody reviewed."""
    out: dict[str, dict[str, set[str]]] = {}
    for item in allowlist.get("projects") or []:
        if not isinstance(item, dict):
            continue
        project_id = str(item.get("project_id") or "").strip()
        if not _NUMERIC_ID_RE.match(project_id):
            fc.log_event("warn", "ci_config.bad_project_id", project_id=project_id)
            continue
        lanes = {lane for lane in (str(x).strip() for x in (item.get("lanes") or []))
                 if lane in GITLAB_LANES}
        out[project_id] = {"lanes": lanes, "actions": _actions_of(item.get("actions"))}
    return out


def _parse_jenkins_allowlist(allowlist: dict[str, Any]) -> dict[str, dict[str, set[str]]]:
    """{job_name: {"actions": {...}}} — exact match, folders spelled as the
    full path name (`platform/deploy-api`), exactly as Jenkins reports them."""
    out: dict[str, dict[str, set[str]]] = {}
    for item in allowlist.get("jobs") or []:
        if not isinstance(item, dict):
            continue
        job = str(item.get("job") or "").strip()
        if not _is_usable_jenkins_job_name(job):
            fc.log_event("warn", "ci_config.bad_job_name", job=job[:120])
            continue
        out[job] = {"actions": _actions_of(item.get("actions"))}
    return out


CI_CONFIG = parse_ci_config(os.environ.get("CI_CONFIG", ""))


def ci_action_for(capability: str) -> str | None:
    if capability == fc.CAP_CI_APPROVE_DEPLOYMENT:
        return CI_ACTION_APPROVE
    if capability == fc.CAP_CI_REJECT_DEPLOYMENT:
        return CI_ACTION_REJECT
    return None


def ci_allowlist_check(provider: str, ref: dict[str, str],
                       action: str) -> tuple[bool, str]:
    """Check 6 for the CI lane. Returns (allowed, human detail).

    Fail-closed on every axis: no entry for the provider, no rule for the
    project/job, the lane not granted, the action not granted.
    """
    entry = CI_CONFIG.get(provider)
    if entry is None:
        return False, (f"no local CI_CONFIG entry for provider {provider!r}; this "
                       f"agent dials only hosts named in its own ConfigMap")
    rules = entry["rules"]
    if provider == CI_PROVIDER_GITLAB:
        rule = rules.get(ref["project_id"])
        if rule is None:
            return False, f"GitLab project {ref['project_id']} is not on this agent's allowlist"
        if ref["lane"] not in rule["lanes"]:
            return False, (f"the {ref['lane']} lane is not allowlisted for GitLab "
                           f"project {ref['project_id']}")
        if action not in rule["actions"]:
            return False, (f"{action} is not allowlisted for GitLab project "
                           f"{ref['project_id']}")
        return True, "allowlisted"
    rule = rules.get(ref["job_name"])
    if rule is None:
        return False, f"Jenkins job {ref['job_name']!r} is not on this agent's allowlist"
    if action not in rule["actions"]:
        return False, f"{action} is not allowlisted for Jenkins job {ref['job_name']!r}"
    return True, "allowlisted"


# ── CI host transport (stdlib urllib, bounded, redirect-refusing) ───────────

_CI_SSL_CONTEXT: ssl.SSLContext | None = None


def _ci_ssl_context() -> ssl.SSLContext:
    """One context, built once. CI_CA_BUNDLE lets a customer trust their
    internal CA — which is the normal case for a private GitLab or Jenkins.
    There is deliberately no "skip verification" knob: an agent that can be
    told to ignore TLS is an agent whose CI credential can be harvested by
    anyone on the path."""
    global _CI_SSL_CONTEXT
    if _CI_SSL_CONTEXT is None:
        _CI_SSL_CONTEXT = (ssl.create_default_context(cafile=CI_CA_BUNDLE)
                           if CI_CA_BUNDLE else ssl.create_default_context())
    return _CI_SSL_CONTEXT


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse EVERY redirect.

    The FixControl-side clients allow a same-origin 307/308 and refuse the
    rest. The agent is stricter on purpose, and it costs nothing: it dials only
    origins written in its own ConfigMap, so a redirect is never something it
    needs to chase — while following one would risk carrying a `PRIVATE-TOKEN`
    or a Jenkins API token to whatever host the `Location` names, and following
    a method-dropping 302 would turn a governed WRITE into a GET and then
    report a success that never happened.

    Returning None here makes urllib stop rather than follow; the 3xx surfaces
    as an HTTPError and is classified `host_refused`.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: D102
        return None


_CI_OPENER: Any = None


def _ci_opener() -> Any:
    global _CI_OPENER
    if _CI_OPENER is None:
        _CI_OPENER = urllib.request.build_opener(
            _NoRedirect(), urllib.request.HTTPSHandler(context=_ci_ssl_context()))
    return _CI_OPENER


def _ci_http(method: str, url: str, headers: dict[str, str],
             body: bytes | None = None,
             timeout: float | None = None) -> tuple[int, dict[str, str], bytes]:
    """The ONE socket call of the CI lane, and the ONE seam the smokes replace.

    Returns (status, lowercased response headers, body bytes). status 0 means
    the host did not answer at all (DNS/TLS/socket/timeout) → `host_unreachable`;
    everything else, 3xx included, is a real answer the caller classifies. At
    most CI_READ_MAX_BYTES is read off the socket.
    """
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with _ci_opener().open(req, timeout=timeout or CI_TIMEOUT_SECONDS) as resp:
            return (resp.status, {k.lower(): v for k, v in resp.headers.items()},
                    resp.read(CI_READ_MAX_BYTES))
    except urllib.error.HTTPError as e:
        raw = b""
        try:
            raw = e.read(CI_READ_MAX_BYTES)
        except Exception:  # noqa: BLE001 — a body we cannot read is not a failure
            pass
        return e.code, {k.lower(): v for k, v in (e.headers or {}).items()}, raw
    except urllib.error.URLError as e:
        return 0, {}, f"network: {e}".encode("utf-8")
    except (TimeoutError, OSError, ValueError) as e:
        return 0, {}, f"network: {e}".encode("utf-8")


def ci_credentials() -> list[str]:
    """Every CI credential currently in the pod's environment. Used ONLY by the
    sanitizer, to redact the material itself out of anything we quote."""
    out: list[str] = []
    for entry in CI_CONFIG.values():
        value = os.environ.get(entry["credential_env"], "")
        if value:
            out.append(value)
            # The Basic form too: a Jenkins error page can echo the header back.
            out.append(base64.b64encode(value.encode("utf-8")).decode("ascii"))
    return out


#: Header-ish / field-ish secret carriers, redacted by NAME so an unknown token
#: FORMAT is still caught. The value pattern runs to the end of the line or to
#: the closing quote — deliberately greedy, because `Authorization: Basic <b64>`
#: has a SPACE inside the secret, and a pattern that stopped at whitespace would
#: redact the word "Basic" and publish the credential after it. Over-redacting a
#: debug excerpt costs a little context; under-redacting costs a live token.
_CI_SECRETISH_RE = re.compile(
    r"(?i)\b(private[-_]?token|authorization|api[-_]?token|access[-_]?token|"
    r"set-cookie|cookie|crumb|token|password|passwd|secret)\b"
    r"\s*[\"']?\s*[:=]\s*[\"']?[^\r\n\"']*")
#: GitLab's own token prefixes (glpat-, glrt-, gloas-, …), redacted by SHAPE so
#: a token pasted into a free-text error body is caught even without a label.
_CI_GITLAB_TOKEN_RE = re.compile(r"\bgl[a-z]{2,6}-[A-Za-z0-9_\-]{8,}")


def ci_sanitize(text: str, credentials: list[str] | None = None) -> str:
    """Redact, THEN truncate to the contract's 2 KB.

    Order matters: truncating first would let a secret survive by sitting past
    the cut in a longer body that a later change happens to quote.
    """
    if not text:
        return ""
    for cred in credentials if credentials is not None else ci_credentials():
        if cred:
            text = text.replace(cred, "[redacted]")
    text = _CI_GITLAB_TOKEN_RE.sub("[redacted]", text)
    text = _CI_SECRETISH_RE.sub(lambda m: f"{m.group(1)}: [redacted]", text)
    encoded = text.encode("utf-8")[:CI_EXCERPT_MAX_BYTES]
    return encoded.decode("utf-8", "ignore")


def ci_evidence(http_status: int | None, host_state_after: str | None, *,
                excerpt: str | None = None,
                used_crumb: bool = False,
                played_job_id: str | None = None,
                pause_model: str | None = None,
                deployable_id: str | None = None) -> dict[str, Any]:
    """The contract's result evidence: {httpStatus, hostStateAfter, checkedAt}.

    `hostStateAfter` is BEST EFFORT and may be null — a re-read that fails must
    never turn a landed write into a reported failure. `responseExcerpt` is
    added only on a non-success and is always sanitized + capped.

    The three optional GitLab fields are the write-time lane refinement's
    report back (open question 13): `pauseModel` names WHICH primitive the
    pre-check found holding the deployment, `deployableId` names the job it
    found, and `playedJobId` is set only when a job was actually played. The
    FixControl side reads `playedJobId` to stamp the right external reference;
    the other two are audit evidence. All three are ids and enum-ish strings —
    never anything the host wrote — so none of them can carry a secret.
    """
    evidence: dict[str, Any] = {
        "httpStatus": http_status,
        "hostStateAfter": host_state_after,
        "checkedAt": fc.rfc3339(),
    }
    if excerpt:
        evidence["responseExcerpt"] = excerpt
    if used_crumb:
        evidence["usedCrumb"] = True
    if played_job_id:
        evidence["playedJobId"] = played_job_id
    if pause_model:
        evidence["pauseModel"] = pause_model
    if deployable_id:
        evidence["deployableId"] = deployable_id
    return evidence


def _ci_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8", "replace")) if raw.strip() else None
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None


def _ci_refuse(reason: str, message: str,
               evidence: dict[str, Any]) -> tuple[str, str, str, dict[str, Any]]:
    return fc.OUTCOME_REFUSED, reason, message, evidence


def _ci_unreachable(provider: str, phase: str,
                    raw: bytes) -> tuple[str, str, str, dict[str, Any]]:
    return _ci_refuse(
        fc.REASON_HOST_UNREACHABLE,
        f"{provider} did not answer the {phase} ({ci_sanitize(raw.decode('utf-8', 'replace'))[:200]})",
        ci_evidence(None, None))


def _ci_call(entry: dict[str, Any], method: str, path: str, *,
             body: Any = None, phase: str = "read",
             extra_headers: dict[str, str] | None = None,
             accept_json: bool = True) -> tuple[int, dict[str, str], bytes]:
    """One authenticated call to the configured host. The credential is read
    from the environment HERE, per call — never carried in a variable that
    could end up in a log line or an evidence field."""
    provider = entry["provider"]
    credential = os.environ.get(entry["credential_env"], "")
    headers: dict[str, str] = {
        "User-Agent": f"fc-agent/{AGENT_VERSION}",
        "Accept": "application/json" if accept_json else "*/*",
    }
    # Caller-supplied headers go on FIRST, so the credential below cannot be
    # displaced by them. The only caller that passes any is the Jenkins crumb
    # retry, and the crumb's header NAME is read out of the host's own
    # response — a host that answered `crumbRequestField: "Authorization"`
    # would otherwise strip the agent's own authentication off the write.
    # _jenkins_crumb already refuses such a name; this ordering means the
    # ordering itself is not what we are relying on.
    headers.update(extra_headers or {})
    if provider == CI_PROVIDER_GITLAB:
        headers["PRIVATE-TOKEN"] = credential
    else:
        # Jenkins' documented scripted-client convention, and the same one the
        # FixControl-side credential.ts builds: the env holds `user:apiToken`.
        headers["Authorization"] = "Basic " + base64.b64encode(
            credential.encode("utf-8")).decode("ascii")
    payload: bytes | None = None
    if body is not None:
        payload = json.dumps(body, separators=(",", ":")).encode("utf-8")
        headers["Content-Type"] = "application/json"
    url = entry["base_url"] + path
    status, resp_headers, raw = _ci_http(method, url, headers, payload)
    fc.metric_bump("fc_agent_ci_calls_total", (provider, phase, status))
    fc.log_event("info" if 200 <= status < 300 else "warn", "ci.call",
                 provider=provider, phase=phase, method=method, path=path,
                 status_code=status)
    return status, resp_headers, raw


# ── GitLab executors ────────────────────────────────────────────────────────

def classify_gitlab_deployment_pause(body: Any) -> tuple[str, str | None]:
    """Which primitive is holding a blocked deployment — `("approval_rules",
    None)` or `("manual_job", job_id)`.

    Python parity with classifyGitlabDeploymentPause in
    src/server/integrations/devops/gitlab-ci/approve-deployment.ts, evidence
    order included:

      1. ANY sign of an approval model wins — a non-empty
         `approval_summary.rules`, a non-empty `approvals`, or a positive
         `pending_approval_count`. Those fields exist only where the FEATURE
         exists, so their presence is proof of the Premium lane. Preferring
         them keeps a Premium tenant on the endpoint that records a real
         REJECTION, which the job lane cannot express at all.
      2. Otherwise a `deployable` sitting on `manual` IS the pause, and its id
         is the address. GitLab CE 19.3 sends exactly this and nothing else.
      3. Anything else → `approval_rules`, i.e. the pre-decision behaviour
         verbatim: POST the approval and let the tier-honest 404 answer.
         Guessing "play something" with no manual job in sight would be
         inventing a write.

    `bool` is deliberately excluded from the numeric arm: in Python `True` is
    an `int`, and `pending_approval_count: true` must not read as "1 pending".
    """
    d = body if isinstance(body, dict) else {}
    summary = d.get("approval_summary")
    rules = summary.get("rules") if isinstance(summary, dict) else None
    if isinstance(rules, list) and rules:
        return "approval_rules", None
    approvals = d.get("approvals")
    if isinstance(approvals, list) and approvals:
        return "approval_rules", None
    pending = d.get("pending_approval_count")
    if isinstance(pending, (int, float)) and not isinstance(pending, bool) and pending > 0:
        return "approval_rules", None
    deployable = d.get("deployable")
    if isinstance(deployable, dict) and deployable.get("status") == "manual":
        job_id = deployable.get("id")
        if isinstance(job_id, int) and not isinstance(job_id, bool):
            return "manual_job", str(job_id)
        if isinstance(job_id, str) and _NUMERIC_ID_RE.match(job_id):
            return "manual_job", job_id
    return "approval_rules", None


def _gitlab_deployment(entry: dict[str, Any], ref: dict[str, str], action: str,
                       comment: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """Approve or reject ONE blocked GitLab deployment.

    Order and semantics mirror approveGitlabDeployment in
    src/server/integrations/devops/gitlab-ci/approve-deployment.ts, including
    the tier honesty: deployment approvals are a Premium/Ultimate feature, so a
    403/404 on the APPROVAL endpoint is `tier_unavailable`, never a credential
    story. `represented_as` is deliberately not sent — with one identity to
    offer, naming an approval rule would be a guess, and a wrong guess is an
    approval recorded against the wrong rule.

    THE LANE IS READ, NOT ASSUMED (plan open question 13, decided 2026-08-23).
    Until this decision the agent authorized one endpoint and used it, so a
    GitLab CE deployment — which is held by a manual job and has no approval
    endpoint at all — came back `tier_unavailable` and could NEVER be released
    through FixControl. The agent now makes the SAME write-time refinement the
    direct FixControl executor has made since open question 11: the pre-check
    read says which primitive holds the pause, and that is the one written to.

      approval rules present → POST …/deployments/:id/approval  (both verdicts)
      no rules, manual job   → approve plays the DEPLOYABLE, whose id comes
                               from THIS live read; reject writes nothing.

    WHAT THAT DOES AND DOES NOT WIDEN. The envelope still authorizes exactly
    one target: this deployment. The job that gets played is not a job
    FixControl named — it is the job the host itself reports as the thing
    holding that authorized deployment. FixControl cannot steer it: there is no
    field in the envelope that reaches `deployable.id`. What the operation
    grants is therefore unchanged in substance ("release the pause on
    deployment N"), and only the primitive is picked from the host's answer.

    ALLOWLIST SEMANTICS, stated because an operator must be able to predict it:
    the `deployment` lane in CI_CONFIG governs the PAUSE OBJECT, not the REST
    endpoint. Allowlisting `{"lanes": ["deployment"], "actions": ["approve"]}`
    for a project therefore permits a play on that deployment's own deployable.
    A separate `job` lane grant is NOT required, and adding one grants
    something else: the right to play jobs addressed DIRECTLY by FixControl.
    """
    base = f"/api/v4/projects/{fc.quote_path_segment(ref['project_id'])}" \
           f"/deployments/{fc.quote_path_segment(ref['deployment_id'])}"

    status, _h, raw = _ci_call(entry, "GET", base, phase="precheck")
    if status == 0:
        return _ci_unreachable(CI_PROVIDER_GITLAB, "pre-check", raw)
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"GitLab answered {status} when asked about deployment "
            f"{ref['deployment_id']} — the deployment or project is gone, or the "
            f"configured token cannot see it. Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    live = _ci_json(raw)
    live_status = live.get("status") if isinstance(live, dict) else None
    if not isinstance(live_status, str):
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            "GitLab answered the deployment read with something that is not the "
            "documented JSON — most often a login page, which means the "
            "configured token is not being accepted. Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    if live_status != "blocked":
        return _ci_refuse(
            fc.REASON_NO_LONGER_PENDING,
            f'GitLab is no longer holding deployment {ref["deployment_id"]} for '
            f'approval (it is "{live_status}") — it was decided on the host, the '
            f"pipeline moved on, or it was cancelled. The FixControl verdict "
            f"stands; nothing was written.",
            ci_evidence(status, live_status))

    # THE FORK. Same response, no second round trip: a second GET would be a
    # second chance for the host to have moved on between the two reads.
    model, deployable_id = classify_gitlab_deployment_pause(live)
    if model == "manual_job":
        return _gitlab_deployment_via_job(entry, ref, deployable_id or "", action,
                                          comment, precheck_status=status)

    verdict = "approved" if action == CI_ACTION_APPROVE else "rejected"
    status, _h, raw = _ci_call(entry, "POST", f"{base}/approval", phase="write",
                               body={"status": verdict, "comment": comment})
    if status == 0:
        return _ci_unreachable(CI_PROVIDER_GITLAB, "approval write", raw)
    if status in (403, 404):
        return _ci_refuse(
            fc.REASON_TIER_UNAVAILABLE,
            "GitLab did not accept a deployment approval for this project. "
            "Deployment approvals are a GitLab Premium/Ultimate feature, and on "
            "Premium/Ultimate the configured token must be named on an approval "
            "rule for this environment. On GitLab Free, gate the deployment with "
            "a manual job instead — that lane works on every plan.",
            ci_evidence(status, "blocked",
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"GitLab refused the deployment {verdict} with {status}. Nothing was written.",
            ci_evidence(status, "blocked",
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))

    return (fc.OUTCOME_SUCCEEDED, None,
            f"deployment {ref['deployment_id']} {verdict} on GitLab",
            ci_evidence(status, _gitlab_state_after(entry, base, "status")))


def _gitlab_deployment_via_job(entry: dict[str, Any], ref: dict[str, str],
                               deployable_id: str, action: str, comment: str,
                               *, precheck_status: int
                               ) -> tuple[str, str | None, str, dict[str, Any]]:
    """The manual-job half of a `#deployment:` operation — the pause is a
    blocked deployment and what holds it is its own deployable, on `manual`.

    APPROVE plays that job. REJECT writes nothing at all, and that is the
    decision open question 13 turned on, so it is spelled out here rather than
    left to be inferred:

    GitLab has no primitive that records a refusal on this lane. `/approval`
    does not exist off Premium; cancelling the job or the pipeline is a
    DIFFERENT act that destroys work nobody decided on. But nothing needs
    writing, because the pause holds by DEFAULT: a manual job runs only when
    somebody plays it, and FixControl has now decided that nobody will. The
    deployment stays `blocked`, the job stays unplayed, and the pipeline never
    ships. That IS the enforcement — the absence of a write is not the
    enforcement failing, it is the shape the enforcement takes.

    So this is reported as a REFUSAL with its own code
    (`no_refusal_primitive`), and FixControl translates that one code into the
    same non-failure completion the DIRECT executor already produces for this
    exact case: no external reference, audit
    `devops.gitlab_deployment_rejection_not_written`, realised consequence
    `rejected`. The two carriages therefore agree — which is the property the
    whole carriage design exists to keep.
    """
    if action == CI_ACTION_REJECT:
        return _ci_refuse(
            fc.REASON_NO_REFUSAL_PRIMITIVE,
            f"GitLab is holding deployment {ref['deployment_id']} with manual job "
            f"{deployable_id}, and GitLab has no primitive that records a refusal "
            f"on that lane — this project has no deployment-approval endpoint, and "
            f"cancelling the job would destroy work nobody decided on. Nothing was "
            f"written, and nothing needed to be: the job stays unplayed, so the "
            f"deployment stays blocked and the pipeline never ships. The FixControl "
            f"verdict stands and IS in force; the GitLab host was simply not told.",
            ci_evidence(precheck_status, "blocked", pause_model="manual_job",
                        deployable_id=deployable_id))

    # Approve: play the deployable. `_gitlab_job` re-checks that the job is
    # still `manual` before it writes, which is exactly what playGitlabJob does
    # on the direct side — a pre-check the deployment read cannot substitute
    # for, because it answers about a DIFFERENT object.
    #
    # NOTE — no second allowlist check on purpose. Check 6 already ran, for the
    # `deployment` lane, on the address FixControl authorized; see the
    # ALLOWLIST SEMANTICS note in _gitlab_deployment. Re-running it here
    # against the `job` lane would demand a grant the operator was never told
    # to make and would break every CE tenant on the lane this decision exists
    # to open.
    job_ref = {"lane": GITLAB_LANE_JOB, "project_id": ref["project_id"],
               "job_id": deployable_id}
    outcome, reason, message, evidence = _gitlab_job(entry, job_ref, comment)
    evidence["pauseModel"] = "manual_job"
    if outcome == fc.OUTCOME_SUCCEEDED:
        message = (f"deployment {ref['deployment_id']} released on GitLab by playing "
                   f"its manual job {deployable_id}")
    return outcome, reason, message, evidence


def _gitlab_job(entry: dict[str, Any], ref: dict[str, str],
                comment: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """Play ONE manual GitLab job — the approve lane only.

    Mirrors playGitlabJob: pre-check that the job is still `manual`, then
    `POST …/play` with NO body. `job_variables_attributes` exists and is
    deliberately not sent: FixControl releases the job the pipeline author
    defined; it does not re-parameterise it.

    `comment` is accepted and unused — GitLab's play endpoint has nowhere to put
    it. It still travels in the result evidence, which is where the join to the
    FixControl approval id lives for this lane.
    """
    base = f"/api/v4/projects/{fc.quote_path_segment(ref['project_id'])}" \
           f"/jobs/{fc.quote_path_segment(ref['job_id'])}"

    status, _h, raw = _ci_call(entry, "GET", base, phase="precheck")
    if status == 0:
        return _ci_unreachable(CI_PROVIDER_GITLAB, "pre-check", raw)
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"GitLab answered {status} when asked about job {ref['job_id']} — the "
            f"job or project is gone, or the configured token cannot see it. "
            f"Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    live = _ci_json(raw)
    live_status = live.get("status") if isinstance(live, dict) else None
    if not isinstance(live_status, str):
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            "GitLab answered the job read with something that is not the documented "
            "JSON — most often a login page, which means the configured token is "
            "not being accepted. Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    if live_status != "manual":
        return _ci_refuse(
            fc.REASON_NO_LONGER_PENDING,
            f'GitLab is no longer holding job {ref["job_id"]} for a human (it is '
            f'"{live_status}") — it was played on the host, the pipeline moved on, '
            f"or it was cancelled. The FixControl verdict stands; nothing was written.",
            ci_evidence(status, live_status))

    status, _h, raw = _ci_call(entry, "POST", f"{base}/play", phase="write")
    if status == 0:
        return _ci_unreachable(CI_PROVIDER_GITLAB, "play", raw)
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"GitLab refused to run job {ref['job_id']} ({status}) — the configured "
            f"token needs at least the Developer role, Maintainer on a protected "
            f"branch. Nothing was written.",
            ci_evidence(status, "manual",
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))

    played = _ci_json(raw)
    after = played.get("status") if isinstance(played, dict) else None
    if not isinstance(after, str):
        after = _gitlab_state_after(entry, base, "status")
    # `playedJobId` is what lets the FixControl side stamp `gitlab:played:<code>`
    # rather than `gitlab:approved:<code>` when this ran as the manual-job half
    # of a DEPLOYMENT operation. Without it `realisedProfile()` would report
    # `deployment_approval` — telling an operator their verdict was recorded as
    # a deployment approval on a plan that has no such feature.
    return (fc.OUTCOME_SUCCEEDED, None, f"job {ref['job_id']} played on GitLab",
            ci_evidence(status, after, played_job_id=ref["job_id"]))


def _gitlab_state_after(entry: dict[str, Any], path: str, field: str) -> str | None:
    """Best-effort re-read for `hostStateAfter`. Every failure is swallowed on
    purpose: the write already landed, and a flaky read must never be allowed
    to report otherwise."""
    try:
        status, _h, raw = _ci_call(entry, "GET", path, phase="state_after")
        if not 200 <= status < 300:
            return None
        body = _ci_json(raw)
        value = body.get(field) if isinstance(body, dict) else None
        return value if isinstance(value, str) else None
    except Exception as e:  # noqa: BLE001
        fc.log_event("warn", "ci.state_after_failed", provider=entry["provider"],
                     error=str(e)[:200])
        return None


# ── Jenkins executor ────────────────────────────────────────────────────────

def _jenkins_job_path(job_name: str) -> str:
    """`folder/child` → `/job/folder/job/child`, every segment encoded — so a
    job name with a space addresses correctly (buildJenkinsJobPath parity)."""
    return "".join(f"/job/{fc.quote_path_segment(s)}"
                   for s in job_name.split("/") if s)


#: A crumb header name Jenkins may legitimately ask for. Anything else is not
#: a crumb field; see _jenkins_crumb.
_CRUMB_FIELD_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
_RESERVED_HEADER_NAMES = frozenset({
    "authorization", "private-token", "cookie", "content-type", "content-length",
    "host", "user-agent", "accept",
})


def _jenkins_crumb(entry: dict[str, Any]) -> dict[str, str] | None:
    """`GET /crumbIssuer/api/json` → {field, value, cookie}, or None.

    The field NAME is read from the response rather than hard-coded: a reverse
    proxy or an older Jenkins may name it differently, and guessing produces a
    second 403 that looks like a permission problem. Crumbs are SESSION-bound,
    so the issuer's cookie is carried alongside — the header alone earns the
    same 403 again.
    """
    status, headers, raw = _ci_call(entry, "GET", "/crumbIssuer/api/json",
                                    phase="crumb")
    if not 200 <= status < 300:
        return None
    body = _ci_json(raw)
    if not isinstance(body, dict):
        return None
    value = body.get("crumb")
    field = body.get("crumbRequestField")
    if not isinstance(value, str) or not isinstance(field, str) or not value or not field:
        return None
    if not _CRUMB_FIELD_RE.match(field) or field.lower() in _RESERVED_HEADER_NAMES:
        # The field name arrives from the HOST and becomes a request header
        # name. A response naming `Authorization` (or smuggling a newline into
        # the name) is not a crumb; it is an attempt to reshape our own
        # request. Refused, and the caller then reports the ORIGINAL 403.
        fc.log_event("warn", "ci.crumb_field_rejected", provider=entry["provider"],
                     field=field[:64])
        return None
    cookie = ""
    raw_cookie = headers.get("set-cookie") or ""
    pairs = [part.split(";")[0].strip() for part in raw_cookie.split(",")
             if "=" in part.split(";")[0]]
    if pairs:
        cookie = "; ".join(pairs)
    return {"field": field, "value": value, "cookie": cookie}


def _jenkins_input(entry: dict[str, Any], ref: dict[str, str],
                   action: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """Proceed or abort ONE paused Jenkins `input` step.

    Mirrors proceedJenkinsInput. Two things it deliberately does NOT do:
    it does not use the `proceedUrl` the pending-actions response hands back
    (root-relative, would double a context path — the address comes from our own
    frozen id), and it does not supply parameter values (`proceedEmpty` is
    precisely "continue with the defaults the pipeline author wrote").
    """
    build = f"{_jenkins_job_path(ref['job_name'])}/{fc.quote_path_segment(ref['build_number'])}"
    pending_path = f"{build}/wfapi/pendingInputActions"

    status, _h, raw = _ci_call(entry, "GET", pending_path, phase="precheck")
    if status == 0:
        return _ci_unreachable(CI_PROVIDER_JENKINS, "pre-check", raw)
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"Jenkins answered {status} for the pending inputs of "
            f"{ref['job_name']}#{ref['build_number']} — the build is gone, the "
            f"configured credential cannot see it, or the Pipeline REST API plugin "
            f"is not installed. Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    pending = _ci_json(raw)
    if not isinstance(pending, list):
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            "Jenkins answered the pending-input read with something that is not the "
            "documented JSON list — most often a login page, which means the "
            "configured credential is not being accepted. Nothing was written.",
            ci_evidence(status, None,
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace"))))
    match = next((p for p in pending
                  if isinstance(p, dict) and p.get("id") == ref["input_id"]), None)
    if match is None:
        return _ci_refuse(
            fc.REASON_NO_LONGER_PENDING,
            f'Jenkins is no longer holding input "{ref["input_id"]}" on '
            f'{ref["job_name"]}#{ref["build_number"]} — it was proceeded or aborted '
            f"on the host, the step timed out, or the build moved on. The FixControl "
            f"verdict stands; nothing was written.",
            ci_evidence(status, "input_not_pending"))
    inputs = match.get("inputs")
    if isinstance(inputs, list) and inputs:
        return _ci_refuse(
            fc.REASON_PARAMETERIZED_INPUT,
            "this Jenkins `input` step asks the approver for parameter values, and "
            "Jenkins does not document the form encoding its /submit endpoint "
            "expects. FixControl will not guess it on a governed write. Split the "
            "step: keep a parameterless `input(id: …)` as the approval gate, and "
            "read the values from build parameters or from a separate step.",
            ci_evidence(status, "input_pending"))

    verb = "proceedEmpty" if action == CI_ACTION_APPROVE else "abort"
    write_path = f"{build}/input/{fc.quote_path_segment(ref['input_id'])}/{verb}"

    status, headers, raw = _ci_call(entry, "POST", write_path, phase="write",
                                    accept_json=False)
    used_crumb = False
    if status == 403 and _looks_like_crumb_refusal(headers, raw):
        # Only when Jenkins ITSELF named the crumb. A 403 that did not is a
        # permission fact, and dressing it up as CSRF sends the operator to the
        # wrong screen. Both attempts live inside ONE operation, so the retry is
        # not a second external write and cannot double-proceed a pipeline.
        crumb = _jenkins_crumb(entry)
        if crumb:
            extra = {crumb["field"]: crumb["value"]}
            if crumb["cookie"]:
                extra["Cookie"] = crumb["cookie"]
            status, headers, raw = _ci_call(entry, "POST", write_path, phase="write",
                                            extra_headers=extra, accept_json=False)
            used_crumb = True

    if status == 0:
        return _ci_unreachable(CI_PROVIDER_JENKINS, verb, raw)
    if not 200 <= status < 300:
        return _ci_refuse(
            fc.REASON_HOST_REFUSED,
            f"Jenkins refused the {verb} with {status}. The account behind the "
            f"configured `user:apiToken` needs Job/Build permission on this job "
            f"(and Overall/Read on the instance) to release an input step. "
            f"Nothing was written.",
            ci_evidence(status, "input_pending",
                        excerpt=ci_sanitize(raw.decode("utf-8", "replace")),
                        used_crumb=used_crumb))

    return (fc.OUTCOME_SUCCEEDED, None,
            f'input "{ref["input_id"]}" {verb} on {ref["job_name"]}#{ref["build_number"]}',
            ci_evidence(status, _jenkins_state_after(entry, pending_path, ref["input_id"]),
                        used_crumb=used_crumb))


def _looks_like_crumb_refusal(headers: dict[str, str], raw: bytes) -> bool:
    """Did this 403 say the CRUMB was the problem? Jenkins answers a crumb
    failure with "No valid crumb was included in the request"; some proxies fold
    it into a header instead. The body is read for this ONE boolean and then
    dropped — it never reaches a log or an evidence field unsanitized."""
    if "crumb" in (headers.get("x-you-are-authenticated-as") or "").lower():
        return True
    return "crumb" in raw.decode("utf-8", "replace").lower()


def _jenkins_state_after(entry: dict[str, Any], pending_path: str,
                         input_id: str) -> str | None:
    """Best-effort: is the input still pending after the write? Failures are
    swallowed — the write landed, and a flaky read must not say otherwise."""
    try:
        status, _h, raw = _ci_call(entry, "GET", pending_path, phase="state_after")
        if not 200 <= status < 300:
            return None
        pending = _ci_json(raw)
        if not isinstance(pending, list):
            return None
        still = any(isinstance(p, dict) and p.get("id") == input_id for p in pending)
        return "input_pending" if still else "input_released"
    except Exception as e:  # noqa: BLE001
        fc.log_event("warn", "ci.state_after_failed", provider=entry["provider"],
                     error=str(e)[:200])
        return None


# ── The CI operation router ─────────────────────────────────────────────────

def ci_comment(op: dict[str, Any]) -> str:
    """`payload.comment` — the FixControl approval id + decider, which is what
    makes the two ledgers joinable. Never optional: a write with no join key is
    a write nobody can reconcile, so a missing comment falls back to the
    operationId rather than to nothing."""
    payload = op.get("payload") if isinstance(op.get("payload"), dict) else {}
    comment = payload.get("comment")
    if isinstance(comment, str) and comment.strip():
        return comment.strip()[:1000]
    return f"FixControl operation {op.get('operationId') or 'unknown'}"


def execute_ci(op: dict[str, Any],
               capability: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """Check 6 + the pre-check + the write, for ONE ci.* operation.

    The order is load-bearing and matches the rollout lane's: parse, then the
    CUSTOMER's allowlist, and only then a single byte on the wire. An operation
    the customer never allowlisted must not produce so much as a read against
    their CI host.
    """
    target = op.get("target") if isinstance(op.get("target"), dict) else {}
    provider = str(target.get("provider") or "").strip()
    address = target.get("address")
    action = ci_action_for(capability)
    if action is None:
        return (fc.OUTCOME_REFUSED, fc.REASON_CAPABILITY_DENIED,
                f"{capability} is not a CI capability", {})

    ref = parse_ci_address(provider, address)
    if ref is None:
        # Unparseable is refused as `not_allowlisted`, deliberately: an address
        # we cannot read matches no allowlist entry, and the closed reason set
        # has no code for "malformed". Fail-closed and honest — the FixControl
        # side calls the same condition `unparseable_run`.
        return (fc.OUTCOME_REFUSED, fc.REASON_NOT_ALLOWLISTED,
                f"target.address {str(address)[:120]!r} is not a canonical "
                f"{provider or 'CI'} run id; nothing was written", {})

    allowed, detail = ci_allowlist_check(provider, ref, action)
    if not allowed:
        return (fc.OUTCOME_REFUSED, fc.REASON_NOT_ALLOWLISTED, detail, {})

    entry = CI_CONFIG[provider]
    comment = ci_comment(op)

    if DRY_RUN:
        fc.log_event("info", "ci.dry_run", provider=provider, action=action,
                     address=address)
        return (fc.OUTCOME_SUCCEEDED, None,
                f"[DRY] would {action} {provider} {address}",
                ci_evidence(None, "dry-run"))

    if provider == CI_PROVIDER_GITLAB:
        if ref["lane"] == GITLAB_LANE_DEPLOYMENT:
            return _gitlab_deployment(entry, ref, action, comment)
        if action == CI_ACTION_REJECT:
            # GitLab has no "refuse this manual job" primitive, and the closest
            # thing (cancelling the job or the pipeline) kills work nobody
            # decided on. A manual job that is never played is ALREADY the
            # enforced refusal. FixControl resolves this combination as
            # unconfigured and never registers it, so this arm is the defensive
            # backstop — see play-job.ts, "WHY THERE IS NO REJECT HERE".
            #
            # `no_refusal_primitive`, not `capability_denied` (changed with open
            # question 13): the customer's allowlist is not what stopped this,
            # and saying so would send an operator to fix a file that is
            # already right. Same fact, same code, as the deployment lane's
            # manual-job reject.
            return (fc.OUTCOME_REFUSED, fc.REASON_NO_REFUSAL_PRIMITIVE,
                    "GitLab has no reject primitive for a manual job; a job that is "
                    "never played is already the enforced refusal. Nothing was written, "
                    "and nothing needed to be — the FixControl verdict stands and IS in "
                    "force.", {})
        return _gitlab_job(entry, ref, comment)

    return _jenkins_input(entry, ref, action)


# ── Execution — the operation router ────────────────────────────────────────

def do_promote(op: dict[str, Any], namespace: str,
               name: str) -> tuple[str, str | None, str, dict[str, Any]]:
    if PROMOTE_MODE == "receiver":
        return _receiver_post("promote", namespace, name, op)
    if PROMOTE_MODE == "git":
        return promote_via_git(op, namespace, name)
    if PROMOTE_MODE == "none":
        # A CI/CD-gate-only install. Not a misconfiguration and not an unknown
        # value: the customer said this agent has no promotion path, so the
        # refusal names that rather than implying a typo.
        return (fc.OUTCOME_REFUSED, fc.REASON_CAPABILITY_DENIED,
                "PROMOTE_MODE=none: this agent carries CI/CD gate verdicts and "
                "has no promotion path", {"mode": "none"})
    # An unknown PROMOTE_MODE is a customer configuration error, and the safe
    # reading of "I do not know how I am allowed to promote" is: I am not.
    return (fc.OUTCOME_REFUSED, fc.REASON_CAPABILITY_DENIED,
            f"unknown PROMOTE_MODE={PROMOTE_MODE!r}", {"mode": PROMOTE_MODE})


def do_abort(op: dict[str, Any], namespace: str,
             name: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """rollout.abort. There is no GitOps spelling of "abort" — a marker commit
    cannot express it — so abort needs either the in-cluster receiver
    (profile c) or the opt-in local Argo API (profile b). With neither
    enabled the operation is refused `capability_denied`, which is exactly
    acceptance criterion 6: an operation that would need the local API is
    refused unless the customer explicitly turned it on."""
    if PROMOTE_MODE == "receiver":
        return _receiver_post("abort", namespace, name, op)
    if not ARGO_LOCAL_API:
        return (fc.OUTCOME_REFUSED, fc.REASON_CAPABILITY_DENIED,
                "rollout.abort needs PROMOTE_MODE=receiver or ARGO_LOCAL_API=1",
                {"mode": PROMOTE_MODE, "argoLocalApi": False})
    if DRY_RUN:
        fc.log_event("info", "abort.dry_run", namespace=namespace, rollout=name)
        return (fc.OUTCOME_SUCCEEDED, None, "[DRY] would set status.abort=true",
                {"mode": "argo_local_api"})
    try:
        _kube().patch(f"{rollout_path(namespace, name)}/status",
                      {"status": {"abort": True}})
    except fc.KubeError as e:
        return (fc.OUTCOME_FAILED, None, f"abort patch failed: {e}",
                {"mode": "argo_local_api", "statusCode": e.status})
    return (fc.OUTCOME_SUCCEEDED, None, "status.abort set",
            {"mode": "argo_local_api"})


def do_status(op: dict[str, Any], namespace: str,
              name: str) -> tuple[str, str | None, str, dict[str, Any]]:
    """rollout.status — a pure read. Unlike check 7, an unreadable object is a
    FAILED operation here: "I could not read it" is the answer being asked
    for, and reporting success with an empty phase would be a silent lie."""
    body = read_rollout(namespace, name)
    if body is None:
        return (fc.OUTCOME_FAILED, None, "rollout unreadable", {})
    status = body.get("status") if isinstance(body.get("status"), dict) else {}
    candidates = rollout_revision_candidates(body)
    evidence: dict[str, Any] = {
        "phase": status.get("phase"),
        "revision": candidates[0] if candidates else None,
    }
    conditions = status.get("pauseConditions")
    if isinstance(conditions, list) and conditions and isinstance(conditions[0], dict):
        evidence["pausedAt"] = conditions[0].get("startTime")
    return (fc.OUTCOME_SUCCEEDED, None, f"phase={evidence.get('phase')}", evidence)


def execute(op: dict[str, Any], capability: str, namespace: str,
            name: str) -> tuple[str, str | None, str, dict[str, Any]]:
    if capability == fc.CAP_ROLLOUT_PROMOTE:
        return do_promote(op, namespace, name)
    if capability == fc.CAP_ROLLOUT_ABORT:
        return do_abort(op, namespace, name)
    if capability == fc.CAP_ROLLOUT_STATUS:
        return do_status(op, namespace, name)
    # test.run / test.cancel belong to fc-test-runner, which holds a DIFFERENT
    # ServiceAccount by design (plan invariant 4). They can only reach this
    # router if AGENT_CAPABILITIES was misconfigured to claim them, and check 8
    # already refuses that — this arm is the defensive backstop.
    return (fc.OUTCOME_REFUSED, fc.REASON_CAPABILITY_DENIED,
            f"{capability} is not executed by fc-agent (see fc-test-runner)", {})


# ── Result posting ──────────────────────────────────────────────────────────

def post_result(operation_id: str, outcome: str, *, reason_code: str | None = None,
                message: str | None = None, evidence: dict[str, Any] | None = None,
                started_at: str, finished_at: str) -> int:
    """POST /api/agent/result. operationId is the idempotency key end to end,
    so a result delivered twice collapses to one outcome server-side."""
    body: dict[str, Any] = {
        "operationId": operation_id,
        "outcome": outcome,
        "startedAt": started_at,
        "finishedAt": finished_at,
    }
    if reason_code:
        body["reasonCode"] = reason_code
    if message:
        body["message"] = message[:2000]
    if evidence:
        body["evidence"] = evidence
    status, text = _fc().post_json("/api/agent/result", body)
    if not (200 <= status < 300):
        fc.log_event("error", "result.post_failed", operation_id=operation_id,
                     outcome=outcome, status_code=status, body=text[:200])
    return status


def handle_operation(op: Any) -> dict[str, Any]:
    """The eight local checks + execution + result post, for ONE operation.

    Returns the result body that was posted (handy for smokes); an operation
    without an operationId cannot be reported and is logged instead — it is
    the only case where nothing is posted, because there is nothing to post it
    against.
    """
    started_at = fc.rfc3339()
    operation_id = op.get("operationId") if isinstance(op, dict) else None
    capability = op.get("capability") if isinstance(op, dict) else None
    target = op.get("target") if isinstance(op, dict) and isinstance(op.get("target"), dict) else {}
    namespace = target.get("namespace")
    name = target.get("name")
    # ci.* addresses its target with (provider, address) instead of
    # (namespace, name); both are logged so one log filter covers both lanes.
    ci_provider = target.get("provider")
    ci_address = target.get("address")

    def finish(outcome: str, reason: str | None, message: str,
               evidence: dict[str, Any] | None = None) -> dict[str, Any]:
        finished_at = fc.rfc3339()
        fc.metric_bump("fc_agent_operations_total", (capability or "unknown", outcome))
        if outcome == fc.OUTCOME_REFUSED and reason:
            fc.metric_bump("fc_agent_refusals_total", reason)
        result = {
            "operationId": operation_id, "outcome": outcome, "reasonCode": reason,
            "message": message, "evidence": evidence,
            "startedAt": started_at, "finishedAt": finished_at,
        }
        fc.log_event("warn" if outcome != fc.OUTCOME_SUCCEEDED else "info",
                     f"operation.{outcome}", operation_id=operation_id,
                     capability=capability, namespace=namespace, rollout=name,
                     provider=ci_provider, address=ci_address,
                     reason=reason, message=message[:200])
        if not operation_id:
            fc.log_event("error", "operation.unreportable",
                         reason="missing operationId", capability=capability)
            return result
        post_result(str(operation_id), outcome, reason_code=reason, message=message,
                    evidence=evidence, started_at=started_at, finished_at=finished_at)
        return result

    # Checks 1-5 + 8 (shared envelope pass). The nonce is consumed inside, as
    # soon as checks 1-5 pass — see verify_operation's docstring.
    ok, reason = fc.verify_operation(
        AGENT_SECRET, op,
        expected_tenant=TENANT, expected_cluster=CLUSTER_ID, agent_id=AGENT_ID,
        capabilities=CAPABILITIES, nonce_store=NONCES,
        skew_seconds=CLOCK_SKEW_SECONDS,
        signing_public_keys=SIGNING_PUBLIC_KEYS,
    )
    if not ok:
        # The reason CODE stays inside the closed wire vocabulary; the
        # DIAGNOSIS rides along in the message, which is what surfaces on the
        # gate. For bad_signature that distinction matters most: "downgrade
        # refused" and "signed by a key I do not trust" are the same code and
        # very different operator actions.
        detail = (fc.signature_refusal_detail(op, SIGNING_PUBLIC_KEYS)
                  if reason == fc.REASON_BAD_SIGNATURE
                  else f"local authorization refused: {reason}")
        return finish(fc.OUTCOME_REFUSED, reason, detail)

    # The CI lane forks here. It has its own check 6 (the CI_CONFIG allowlist)
    # and its own check 7 (the live pause on the host, read inside the executor
    # microseconds before the write) — the same two questions as the rollout
    # lane, asked of a different world.
    if capability in fc.CI_CAPABILITIES:
        try:
            outcome, reason, message, evidence = execute_ci(op, str(capability))
        except Exception as e:  # noqa: BLE001 — one bad operation must not kill the loop
            fc.log_event("error", "operation.threw", operation_id=operation_id,
                         capability=capability, error=str(e)[:300])
            return finish(fc.OUTCOME_FAILED, None, f"agent error: {str(e)[:300]}")
        return finish(outcome, reason, message, evidence)

    # Check 6 — customer-owned allowlist.
    if not is_allowlisted(namespace, name):
        return finish(fc.OUTCOME_REFUSED, fc.REASON_NOT_ALLOWLISTED,
                      f"{namespace}/{name} is not on this agent's allowlist")

    # Check 7 — live revision, for the mutating capabilities only. A status
    # read must not be blocked by drift; reporting drift IS its job.
    if capability in (fc.CAP_ROLLOUT_PROMOTE, fc.CAP_ROLLOUT_ABORT):
        passed, verdict, detail = check_revision(op, str(namespace), str(name))
        if not passed:
            return finish(fc.OUTCOME_REFUSED, fc.REASON_REVISION_DRIFT,
                          f"expectRevision={expected_revision(op)} but live "
                          f"revision is {detail}",
                          {"expectRevision": expected_revision(op),
                           "liveRevision": detail})
        fc.log_event("info", "revision.checked", operation_id=operation_id,
                     namespace=namespace, rollout=name, verdict=verdict, detail=detail)

    try:
        outcome, reason, message, evidence = execute(
            op, str(capability), str(namespace), str(name))
    except Exception as e:  # noqa: BLE001 — one bad operation must not kill the loop
        fc.log_event("error", "operation.threw", operation_id=operation_id,
                     capability=capability, error=str(e)[:300])
        return finish(fc.OUTCOME_FAILED, None, f"agent error: {str(e)[:300]}")
    return finish(outcome, reason, message, evidence)


# ── Poll loop ───────────────────────────────────────────────────────────────

def poll_once() -> float:
    """One POST /api/agent/poll + dispatch. Returns the next sleep interval —
    the server may steer it (intervalSeconds) so a fleet can be slowed down
    centrally without a redeploy."""
    status, text = _fc().post_json("/api/agent/poll", {
        "clusterId": CLUSTER_ID,
        "agentName": AGENT_NAME,
        "version": AGENT_VERSION,
        "capabilities": sorted(CAPABILITIES),
    })
    if not (200 <= status < 300):
        _LAST_POLL_OK.clear()
        fc.log_event("warn", "poll.failed", status_code=status, body=text[:200])
        return POLL_SECONDS
    _LAST_POLL_OK.set()
    try:
        body = json.loads(text) if text else {}
    except json.JSONDecodeError:
        fc.log_event("warn", "poll.bad_json", body=text[:200])
        return POLL_SECONDS
    operations = body.get("operations")
    if isinstance(operations, list):
        for op in operations:
            handle_operation(op)
    interval = body.get("intervalSeconds")
    try:
        return max(1.0, float(interval)) if interval is not None else POLL_SECONDS
    except (TypeError, ValueError):
        return POLL_SECONDS


# ── Event path (absorbed from watcher.py + signer.py) ───────────────────────

def snapshot(r: dict[str, Any]) -> dict[str, Any]:
    """Rollout → the watcher's state snapshot (bin/watcher.py snapshot())."""
    meta = r.get("metadata", {}) if isinstance(r.get("metadata"), dict) else {}
    spec = r.get("spec", {}) if isinstance(r.get("spec"), dict) else {}
    status = r.get("status", {}) if isinstance(r.get("status"), dict) else {}
    containers = ((spec.get("template") or {}).get("spec") or {}).get("containers") or []
    image = containers[0].get("image") if containers and isinstance(containers[0], dict) else None
    annotations = meta.get("annotations") or {}
    return {
        "uid": meta.get("uid"),
        "namespace": meta.get("namespace") or "default",
        "name": meta.get("name"),
        "image": image,
        "replicas": spec.get("replicas") or 0,
        "phase": status.get("phase"),
        "current_step_index": status.get("currentStepIndex"),
        # Per-deploy mission-link hint, forwarded as `issueKey` so the
        # deployment gate auto-opens against the right mission.
        "issue_key": annotations.get("fixcontrol.ai/issue-key") or None,
        "revision": (rollout_revision_candidates(r) or [None])[0],
    }


def event_type_for(prev: dict[str, Any] | None, cur: dict[str, Any]) -> str | None:
    """Argo-style eventType, so EVENT_MAP handles it unchanged
    (bin/watcher.py event_type_for())."""
    if prev is None:
        return None  # initial observation, no event
    if cur["phase"] == "Healthy" and prev["phase"] != "Healthy":
        return "rollout-completed"
    if cur["phase"] == "Degraded" and prev["phase"] != "Degraded":
        return "rollout-aborted"
    if cur["phase"] == "Paused" and prev["phase"] != "Paused":
        return "rollout-paused"
    if (cur["current_step_index"] is not None and prev["current_step_index"] is not None
            and cur["current_step_index"] > prev["current_step_index"]):
        return "rollout-step-completed"
    return None


def to_fc_payload(cur: dict[str, Any], event_type: str) -> dict[str, Any]:
    """The SHIPPED FixControl Kubernetes-webhook payload — same field set and
    same vocabulary as to_fc_payload() in bin/signer.py, so the ingest side
    cannot tell whether watcher+signer or the agent sent it."""
    action, status = EVENT_MAP.get(event_type, (event_type or "unknown", "running"))
    payload: dict[str, Any] = {
        "kind": "Rollout",
        "namespace": cur["namespace"],
        "name": cur["name"],
        "action": action,
        "status": status,
        "image": cur.get("image"),
        "revision": cur.get("revision") or cur.get("image"),
        "replicas": int(cur.get("replicas") or 0),
        "actor": "fc-agent",
        "cluster": CLUSTER_ID,
    }
    if cur.get("issue_key"):
        payload["issueKey"] = cur["issue_key"]
    return payload


def emit_event(cur: dict[str, Any], event_type: str) -> int:
    """POST the event outbound. HMAC over the RAW body under the per-tenant
    K8s webhook secret — the shipped contract, deliberately NOT the agent
    envelope, so today's tenants keep working while the sender changes."""
    payload = to_fc_payload(cur, event_type)
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    if not K8S_WEBHOOK_SECRET:
        fc.log_event("warn", "event.no_secret", rollout=cur["name"],
                     namespace=cur["namespace"],
                     note="FIXCONTROL_K8S_SECRET unset; event dropped")
        return 0
    signature = hmac.new(K8S_WEBHOOK_SECRET.encode("utf-8"), body, hashlib.sha256).hexdigest()
    status, text = _fc().post_raw(EVENT_ENDPOINT, body, {
        "Content-Type": "application/json",
        "X-FixControl-Signature": f"sha256={signature}",
        "X-FixControl-Account": CLUSTER_ID,
    })
    fc.metric_bump("fc_agent_events_total", (payload["action"], status))
    fc.log_event("info" if 200 <= status < 300 else "warn",
                 "event.sent" if 200 <= status < 300 else "event.failed",
                 rollout=cur["name"], namespace=cur["namespace"],
                 action=payload["action"], status_code=status,
                 body=None if 200 <= status < 300 else text[:200])
    return status


def events_tick(state: dict[str, dict[str, Any]]) -> int:
    """One pass over the allowlisted namespaces. Returns the number of events
    emitted. Scope is ALLOWED_NAMESPACES, not the cluster: the agent watches
    exactly what the customer allowlisted, never more."""
    emitted = 0
    for ns in ALLOWED_NAMESPACES:
        try:
            listing = _kube().get(f"{ROLLOUTS_API}/namespaces/{fc.quote_path_segment(ns)}/rollouts")
        except fc.KubeError as e:
            if e.status != 404:
                fc.log_event("warn", "events.list_failed", namespace=ns,
                             status=e.status, error=str(e)[:200])
            continue
        for item in (listing.get("items") or []) if isinstance(listing, dict) else []:
            cur = snapshot(item)
            uid = cur.get("uid")
            if not uid or not cur.get("name"):
                continue
            prev = state.get(uid)
            event_type = event_type_for(prev, cur)
            state[uid] = cur
            if event_type:
                emit_event(cur, event_type)
                emitted += 1
    return emitted


def events_loop() -> None:
    state: dict[str, dict[str, Any]] = {}
    while True:
        try:
            events_tick(state)
        except Exception as e:  # noqa: BLE001 — the event loop must keep going
            fc.log_event("error", "events.iteration_failed", error=str(e)[:300])
        time.sleep(POLL_SECONDS)


# ── Entrypoint ──────────────────────────────────────────────────────────────

def main() -> None:
    global FC, KUBE, NONCES
    fc.set_log_context(cluster=CLUSTER_ID, agent=AGENT_ID, tenant=TENANT,
                       component="fc-agent")
    FC = fc.FCClient(FIXCONTROL_URL, AGENT_ID, AGENT_SECRET,
                     user_agent=f"fc-agent/{AGENT_VERSION}", component="fc-agent")
    KUBE = fc.KubeClient()
    NONCES = fc.NonceStore(KUBE, POD_NAMESPACE, NONCE_CONFIGMAP)

    fc.serve_health_and_metrics(METRICS_HOST, METRICS_PORT,
                                ready=_LAST_POLL_OK.is_set)
    fc.log_event("info", "startup", url=FIXCONTROL_URL, agent_name=AGENT_NAME,
                 version=AGENT_VERSION, capabilities=sorted(CAPABILITIES),
                 allowed_namespaces=ALLOWED_NAMESPACES,
                 allowed_rollouts=ALLOWED_ROLLOUTS, promote_mode=PROMOTE_MODE,
                 argo_local_api=ARGO_LOCAL_API, events_enabled=EVENTS_ENABLED,
                 poll_seconds=POLL_SECONDS, dry_run=DRY_RUN,
                 metrics=f"{METRICS_HOST}:{METRICS_PORT}",
                 # The CI hosts this agent will dial, by name — so an operator
                 # can read the actual write surface out of the boot log
                 # instead of guessing at the ConfigMap. Never the credentials.
                 ci_providers=sorted(CI_CONFIG.keys()),
                 ci_base_urls=[CI_CONFIG[p]["base_url"] for p in sorted(CI_CONFIG)],
                 # Which FixControl signing keys this cluster trusts, by
                 # fingerprint — so an operator can confirm the pin from the
                 # boot log against `agent-signing-key export`. Empty means
                 # legacy shared-secret verification, and says so.
                 signing_key_pins=[fc.signing_key_fingerprint(k)
                                   for k in SIGNING_PUBLIC_KEYS] or "none (legacy hmac-sha256)")

    if EVENTS_ENABLED:
        threading.Thread(target=events_loop, name="fc-agent-events",
                         daemon=True).start()

    interval = POLL_SECONDS
    while True:
        try:
            interval = poll_once()
        except Exception as e:  # noqa: BLE001 — the poll loop must keep going
            fc.log_event("error", "poll.iteration_failed", error=str(e)[:300])
            interval = POLL_SECONDS
        time.sleep(interval)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        fc.log_event("info", "shutdown", reason="keyboard_interrupt")
