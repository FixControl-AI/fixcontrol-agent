"""
fc_agent_common — shared wire contract for the outbound-only FixControl agents.

Phase 2a of docs/PLAN-fc-agent-outbound-connectivity.md. This module is the
ONE place the customer-side components agree with FixControl on bytes:

  bin/agent.py        rollout.promote / rollout.abort / rollout.status,
                      ci.approve_deployment / ci.reject_deployment, + events
  bin/test-runner.py  test.run / test.cancel (separate identity, separate RBAC)

Both dial OUT. FixControl never opens a socket into the customer network; it
*registers a signed authorization* the agent may later redeem, and the agent
re-authorizes it locally before it executes anything (plan §"Two-phase
authorization"). Everything here is stdlib-only on purpose: the deployable
image must not carry a pip resolver, and a customer's security team must be
able to read the whole trust boundary in one file.

WIRE CONTRACT (FixControl implements the identical shapes in TypeScript;
any deviation here is an interop break, not a refactor):

 1. Canonical JSON — the ONLY serialization a signature is ever computed over:
        json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    UTF-8 encoded. Sorted keys because two independent implementations must
    produce the same bytes without agreeing on field order.

 2. SignedOperation envelope:
        protocolVersion: 1
        alg:             "ed25519" | "hmac-sha256"   (see ASYMMETRIC AUTHORITY)
        operationId:     "agop-…"          (also the end-to-end idempotency key)
        tenant, clusterId, agentId?        (agentId pins one agent instance)
        capability:      rollout.promote | rollout.abort | rollout.status
                       | test.run | test.cancel
                       | ci.approve_deployment | ci.reject_deployment
        target:          { namespace?, name?, expectRevision? }        rollout.*
                         { provider, address }                         ci.*
        payload?:        capability-specific (e.g. the TestRunSpec, or
                         { comment } for ci.*)
        issuedAt, expiresAt: RFC3339
        nonce:           single-use
        signature:       alg=ed25519      "ed25519=" + hex(Ed25519_sign(FC private
                                          key, canonical(envelope WITHOUT the
                                          signature field)))
                         alg=hmac-sha256  "sha256=" + hex(HMAC_SHA256(secret,
                                          canonical(envelope WITHOUT signature)))

    ── ASYMMETRIC AUTHORITY ────────────────────────────────────────────────
    The two algorithms are not two flavours of one thing; they are a security
    boundary and its predecessor.

    Under `hmac-sha256` the key that SIGNS an operation is the same shared
    secret this agent holds to authenticate its own requests. That means a
    compromised agent can mint FixControl operations for itself: transport
    authentication and operation AUTHORITY rest on one key. Under `ed25519`
    FixControl signs with a private key it alone holds, and the agent verifies
    with a public key pinned in its OWN ConfigMap at install time — never
    fetched over the FixControl channel, and never usable to sign. The agent
    is structurally verify-only: `bin/fc_ed25519.py` transcribes no signing
    code at all, so there is no private-key path in this process to steal.

    Which mode applies is decided HERE, by the customer's configuration, and
    it is a one-way ratchet:

      · FIXCONTROL_SIGNING_PUBLIC_KEYS set (1 or 2 keys)
            → ONLY `alg: "ed25519"` is accepted, verified against those keys.
              An `hmac-sha256` envelope is refused `bad_signature`. There is
              no negotiation, no "try the other one", no silent fallback.
      · unset
            → legacy `hmac-sha256`, so an install from before this change
              keeps working. PRODUCTION INSTALLS MUST PIN. See README Step 16.

    Downgrade defence: `alg` is a signed field. It is inside the canonical
    bytes both sides hash, so flipping `"ed25519"` to `"hmac-sha256"` on the
    wire breaks the signature it is trying to escape. And because the pinned
    key list — not the envelope — chooses the verifier, an attacker who could
    somehow forge a valid HMAC still has nothing a pinned agent will look at.

 3. Request authentication towards FixControl (every /api/agent/* call):
        x-fixcontrol-agent:      <agentId>
        x-fixcontrol-timestamp:  <RFC3339 now>
        x-fixcontrol-signature:  sha256=<hex HMAC(secret, timestamp + "." + payload)>
    where `payload` is the exact raw body string on POST, and the request PATH
    on GET (e.g. "/api/agent/workspace/agop-x"). The server tolerates ±300 s of
    clock skew — the same bounded-skew stance the shipped fc-receiver takes.

    This layer stays a per-agent HMAC on purpose, and pinning a signing key
    does not change it. It answers a different question — "is this the agent
    it claims to be, on THIS call" — and a symmetric key is the right shape
    for it: both parties must be able to produce it. What it can never do is
    forge an operation, because operation authority now lives on a key the
    agent does not have. That separation is the entire change.

 4. Endpoints:
        POST {FC}/api/agent/poll    → { operations: [SignedOperation…], intervalSeconds }
        POST {FC}/api/agent/result  → 200
        GET  {FC}/api/agent/workspace/{operationId} → tar.gz bytes (test.run only)

 5. Refusal reason codes — closed set, exact strings. EVERY refusal is posted
    back as a result with outcome="refused"; a silent drop would violate
    invariant 9 of the plan ("nothing fails silently").

The local authorization order lives in verify_operation() below: checks 1-5
and 8 of the plan's eight-step table. Checks 6 (allowlist) and 7 (live
revision) are capability-specific and belong to the caller — agent.py owns
them for rollouts, test-runner.py owns its own equivalents.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, Callable, Iterable, Mapping, Sequence

# The vendored RFC 8032 verifier ships beside this file (both Dockerfiles copy
# it into the same directory). Put that directory on the path explicitly: this
# module is also loaded BY FILE SPEC from the clusterless smokes, and a spec
# load does not add the file's own directory the way a script invocation does.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import fc_ed25519  # noqa: E402

# ── Protocol constants ──────────────────────────────────────────────────────

PROTOCOL_VERSION = 1
#: Legacy: the shared per-agent secret is both the transport key and the
#: operation-signing key. Accepted only while NO signing key is pinned.
ALG_HMAC_SHA256 = "hmac-sha256"
#: FixControl signs, the agent verifies with a pinned public key. The agent
#: cannot sign: fc_ed25519 has no signing code.
ALG_ED25519 = "ed25519"

SIGNATURE_PREFIX_HMAC = "sha256="
SIGNATURE_PREFIX_ED25519 = "ed25519="

#: Two, so a rotation has a window in which both the retiring and the incoming
#: key verify. Not more: a pin list is a trust anchor, and an unbounded one
#: turns "which keys may authorize my cluster" into a question nobody can
#: answer by reading the ConfigMap.
MAX_PINNED_SIGNING_KEYS = 2

CAP_ROLLOUT_PROMOTE = "rollout.promote"
CAP_ROLLOUT_ABORT = "rollout.abort"
CAP_ROLLOUT_STATUS = "rollout.status"
CAP_TEST_RUN = "test.run"
CAP_TEST_CANCEL = "test.cancel"
#: Phase 3 of docs/PLAN-generic-cicd-gates.md — agent-carried CI writes for
#: GitLab/Jenkins hosts FixControl cannot dial. Approve and reject are two
#: capabilities rather than one for the same reason rollout.promote and
#: rollout.abort are: the customer's local allowlist must be able to grant
#: "may release a pause" without granting "may fail a pipeline".
CAP_CI_APPROVE_DEPLOYMENT = "ci.approve_deployment"
CAP_CI_REJECT_DEPLOYMENT = "ci.reject_deployment"

#: The closed operation vocabulary. The plan's non-goals are explicit that
#: there is no "run this command" operation — anything not in this set is
#: refused before it reaches a router.
KNOWN_CAPABILITIES = frozenset({
    CAP_ROLLOUT_PROMOTE, CAP_ROLLOUT_ABORT, CAP_ROLLOUT_STATUS,
    CAP_TEST_RUN, CAP_TEST_CANCEL,
    CAP_CI_APPROVE_DEPLOYMENT, CAP_CI_REJECT_DEPLOYMENT,
})

#: The two CI capabilities, as a set — agent.py routes on this rather than on
#: a string prefix, so a future `ci.something_else` cannot slip into the CI
#: executor by accident of naming.
CI_CAPABILITIES = frozenset({CAP_CI_APPROVE_DEPLOYMENT, CAP_CI_REJECT_DEPLOYMENT})

REASON_TENANT_MISMATCH = "tenant_mismatch"
REASON_CLUSTER_MISMATCH = "cluster_mismatch"
REASON_BAD_SIGNATURE = "bad_signature"
REASON_EXPIRED = "expired"
REASON_REPLAY = "replay"
REASON_NOT_ALLOWLISTED = "not_allowlisted"
REASON_REVISION_DRIFT = "revision_drift"
REASON_CAPABILITY_DENIED = "capability_denied"

# ── CI-lane refusals (Phase 3 wire contract) ────────────────────────────────
# All six are GOVERNANCE outcomes or terminal host facts, never silent drops:
# each one is posted as a result with this code plus its evidence.
#
#: The host is no longer holding the pause — someone decided on the host, the
#: pipeline moved on, the step timed out. The FixControl verdict stands and
#: nothing was written. Same posture as REASON_REVISION_DRIFT.
REASON_NO_LONGER_PENDING = "no_longer_pending"
#: A Jenkins `input` step that asks the approver for parameter values. Jenkins
#: does not document the form encoding its /submit endpoint expects, and a
#: governed write must not guess one.
REASON_PARAMETERIZED_INPUT = "parameterized_input"
#: 403/404 on the GitLab deployment-approval endpoint: deployment approvals are
#: a Premium/Ultimate feature and the identity must be named on an approval
#: rule. A tier fact, not a credential fact — reporting it as auth would send
#: the operator hunting a permission problem that does not exist.
REASON_TIER_UNAVAILABLE = "tier_unavailable"
#: DNS, TLS, socket, timeout — the CI host did not answer at all.
REASON_HOST_UNREACHABLE = "host_unreachable"
#: Any other non-2xx from the CI host (401, 403 on a non-approval endpoint,
#: 404, 5xx, an unparseable body where JSON was documented).
REASON_HOST_REFUSED = "host_refused"
#: The host HAS no primitive that could record this refusal, and none is
#: needed: the pause holds precisely because nothing released it (open
#: question 13, decided 2026-08-23). A GitLab deployment held by a manual job
#: is the only case today — GitLab's `/approval` endpoint does not exist off
#: Premium, and the nearest thing (cancelling the job or the pipeline) is a
#: DIFFERENT act that destroys work nobody decided on.
#:
#: Deliberately NOT `capability_denied`: that code says "the customer's own
#: allowlist forbids this", which would send an operator to edit an allowlist
#: that is already correct. And deliberately NOT `tier_unavailable`: that code
#: says "buy Premium, or gate with a manual job instead" — advice that is
#: absurd to a tenant who IS gating with a manual job and whose rejection was
#: enforced perfectly. The refusal here is not a failure to act; it is the
#: report that the enforcement needed no act.
REASON_NO_REFUSAL_PRIMITIVE = "no_refusal_primitive"

#: Closed set — FixControl renders these on the gate as governance findings,
#: so a new code invented agent-side would surface as an unknown outcome.
#: Mirrored verbatim by AGENT_REFUSAL_REASONS in
#: src/server/integrations/devops/agent/envelope.ts, which is a Zod enum on
#: /api/agent/result: a code that is not in BOTH lists is a 400, not a gate.
REFUSAL_REASONS = frozenset({
    REASON_TENANT_MISMATCH, REASON_CLUSTER_MISMATCH, REASON_BAD_SIGNATURE,
    REASON_EXPIRED, REASON_REPLAY, REASON_NOT_ALLOWLISTED,
    REASON_REVISION_DRIFT, REASON_CAPABILITY_DENIED,
    REASON_NO_LONGER_PENDING, REASON_PARAMETERIZED_INPUT,
    REASON_TIER_UNAVAILABLE, REASON_HOST_UNREACHABLE, REASON_HOST_REFUSED,
    REASON_NO_REFUSAL_PRIMITIVE,
})

OUTCOME_SUCCEEDED = "succeeded"
OUTCOME_FAILED = "failed"
OUTCOME_REFUSED = "refused"

DEFAULT_SKEW_SECONDS = 300
#: Same ladder as bin/signer.py: retry transient failures three times, then
#: dead-letter with a JSON log line a SIEM-side replay tool can scrape.
DEFAULT_RETRY_BACKOFFS = (1.0, 5.0, 30.0)
DEFAULT_TIMEOUT_SECONDS = 10.0

SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"


# ── Canonical serialization + envelope signing ──────────────────────────────

def canonical_bytes(obj: Any) -> bytes:
    """The one serialization a signature is ever computed over.

    sort_keys because the TypeScript producer and this Python consumer must
    agree on bytes without agreeing on insertion order; ensure_ascii=False so
    a non-ASCII namespace name is signed as UTF-8 rather than as \\uXXXX escapes
    (JSON.stringify on the FixControl side does not escape them either).
    """
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def _secret_bytes(secret: str | bytes) -> bytes:
    return secret if isinstance(secret, bytes) else str(secret).encode("utf-8")


def operation_signing_input(op: Mapping[str, Any]) -> bytes:
    """Canonical bytes of the envelope WITHOUT `signature`.

    Every other key is included — deliberately, and without an allow-list, so
    that a field FixControl adds in a later revision is still covered by the
    signature instead of being silently strippable by a man in the middle.
    """
    return canonical_bytes({k: v for k, v in op.items() if k != "signature"})


def sign_operation(secret: str | bytes, op: Mapping[str, Any]) -> str:
    """Return the `signature` value ("sha256=<hex>") for an envelope."""
    mac = hmac.new(_secret_bytes(secret), operation_signing_input(op), hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def verify_operation_signature(secret: str | bytes, op: Mapping[str, Any]) -> bool:
    presented = op.get("signature")
    if not isinstance(presented, str) or not presented.startswith(SIGNATURE_PREFIX_HMAC):
        return False
    expected = sign_operation(secret, op)
    # Constant-time so a length or prefix mismatch is not a timing oracle.
    return hmac.compare_digest(presented.strip().lower(), expected.lower())


# ── Pinned FixControl signing keys (the asymmetric lane) ────────────────────

class SigningKeyConfigError(ValueError):
    """The operator SET a pin list this agent cannot read.

    Deliberately an exception rather than "parsed to nothing". Every other
    fail-closed default in this agent degrades towards refusing MORE — an
    unparseable CI_CONFIG allowlists no host, an empty ALLOWED_NAMESPACES
    allowlists no namespace. An unreadable pin list is the opposite: treating
    it as "no keys pinned" would silently drop the agent back to accepting
    HMAC envelopes, which is precisely the posture the pin exists to leave.
    So a malformed value stops the process at startup instead.
    """


def parse_signing_public_keys(raw: str | None) -> tuple[bytes, ...]:
    """FIXCONTROL_SIGNING_PUBLIC_KEYS → raw 32-byte Ed25519 public keys.

    Wire form: base64 of the raw key (standard or URL-safe alphabet, padding
    optional), comma- or whitespace-separated. This is the form
    `scripts/agent-signing-key.ts export` prints on the FixControl side and
    the form the ConfigMap example carries — one line an operator can paste.

    Empty / unset → `()`, meaning "not pinned", meaning legacy HMAC. Anything
    else that cannot be read is a {@link SigningKeyConfigError}: see the class
    docstring for why silence would be the wrong answer here.
    """
    if raw is None:
        return ()
    text = raw.strip()
    if not text:
        return ()
    tokens = [t for t in text.replace(",", " ").split() if t]
    keys: list[bytes] = []
    for token in tokens:
        pad = "=" * (-len(token) % 4)
        decoded: bytes | None = None
        for decoder in (base64.urlsafe_b64decode, base64.b64decode):
            try:
                candidate = decoder(token + pad)
            except Exception:  # noqa: BLE001 — every decode failure is one answer
                continue
            if len(candidate) == fc_ed25519.PUBLIC_KEY_BYTES:
                decoded = candidate
                break
        if decoded is None:
            raise SigningKeyConfigError(
                f"FIXCONTROL_SIGNING_PUBLIC_KEYS entry {token[:12]!r}… is not "
                f"base64 of a {fc_ed25519.PUBLIC_KEY_BYTES}-byte Ed25519 public key")
        if decoded in keys:
            raise SigningKeyConfigError(
                "FIXCONTROL_SIGNING_PUBLIC_KEYS lists the same key twice; a "
                "rotation window needs two DIFFERENT keys")
        keys.append(decoded)
    if len(keys) > MAX_PINNED_SIGNING_KEYS:
        raise SigningKeyConfigError(
            f"FIXCONTROL_SIGNING_PUBLIC_KEYS carries {len(keys)} keys; at most "
            f"{MAX_PINNED_SIGNING_KEYS} may be pinned (the retiring key and the "
            "incoming one)")
    return tuple(keys)


def signing_key_fingerprint(public_key: bytes) -> str:
    """Last 8 hex of sha256(raw key). Display only — for confirming that the
    cluster pins the key FixControl thinks it published. Matches the FixControl
    side's `signingKeyFingerprint`."""
    return hashlib.sha256(public_key).hexdigest()[-8:]


def verify_operation_signature_ed25519(
    public_keys: Sequence[bytes], op: Mapping[str, Any],
) -> bytes | None:
    """The pinned key that signed this envelope, or None.

    Returns the KEY rather than a bool so a caller can log which of a
    rotation pair verified — the one fact that tells an operator whether the
    retiring key is still in use and the rotation may be completed.
    """
    presented = op.get("signature")
    if not isinstance(presented, str) or not presented.startswith(SIGNATURE_PREFIX_ED25519):
        return None
    try:
        raw = bytes.fromhex(presented[len(SIGNATURE_PREFIX_ED25519):].strip())
    except ValueError:
        return None
    if len(raw) != fc_ed25519.SIGNATURE_BYTES:
        return None
    message = operation_signing_input(op)
    for key in public_keys:
        if fc_ed25519.verify(key, message, raw):
            return key
    return None


def signature_refusal_detail(
    op: Any, public_keys: Sequence[bytes] = (),
) -> str:
    """The operator-facing sentence behind a `bad_signature`.

    The REASON CODE stays `bad_signature` for every way an envelope's
    authority cannot be established — including an HMAC envelope arriving at a
    pinned agent. That is a deliberate choice, not an omission:

      · The refusal vocabulary is a closed set mirrored by a Zod enum on
        /api/agent/result. A code invented here is a 400 on FixControl, so the
        refusal that most needs to reach a human would be the one that cannot.
      · `bad_signature` already means exactly this. The pre-existing rule is
        that an unknown `protocolVersion` is `bad_signature` too — "I could
        not establish this envelope's authority" is the whole meaning.
      · Splitting it would tell a prober WHICH axis failed. An attacker
        learning "your agent is not pinned yet" from a reason code is a free
        gift.

    What the operator loses that way is the diagnosis, so this function hands
    it back in the `message` field, which surfaces on the gate and in the
    agent log next to the code.
    """
    alg = op.get("alg") if isinstance(op, Mapping) else None
    if not public_keys:
        return ("the operation's HMAC signature does not verify against this "
                "agent's shared secret")
    pins = ", ".join(signing_key_fingerprint(k) for k in public_keys)
    if alg != ALG_ED25519:
        return (
            f"this agent pins {len(public_keys)} FixControl signing key(s) "
            f"[{pins}] and therefore accepts alg={ALG_ED25519!r} ONLY; the "
            f"envelope offered alg={alg!r}. Refused as a downgrade — a pinned "
            "agent never falls back to the shared secret, because that secret "
            "is one this agent itself holds and could forge with.")
    return (
        f"the Ed25519 signature does not verify against any of the "
        f"{len(public_keys)} pinned FixControl signing key(s) [{pins}] — the "
        "envelope was signed by a key this cluster does not trust, or a field "
        "was altered after signing")


# ── Time helpers ────────────────────────────────────────────────────────────

def rfc3339(ts: float | None = None) -> str:
    """RFC3339 UTC, second precision. The string we sign is the string we
    send — never re-formatted in between."""
    dt = datetime.fromtimestamp(time.time() if ts is None else ts, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_rfc3339(value: Any) -> float | None:
    """RFC3339 → epoch seconds, or None when unparseable.

    None is a *fail-closed* input for expiry: an envelope whose expiresAt we
    cannot read has no bounded lifetime, so it is refused as `expired` rather
    than treated as eternal.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


# ── Structured logging (Tier 5.1 parity with bin/signer.py) ─────────────────

_LOG_LOCK = threading.Lock()
_LOG_CONTEXT: dict[str, Any] = {}


def set_log_context(**fields: Any) -> None:
    """Fields stamped on every subsequent log line (cluster, agent, tenant).
    Same single field set across the process so a SIEM filters without
    per-event-type rules."""
    with _LOG_LOCK:
        _LOG_CONTEXT.update({k: v for k, v in fields.items() if v is not None})


def log_event(level: str, event: str, **fields: Any) -> None:
    """JSON-on-stdout structured log line."""
    with _LOG_LOCK:
        base = dict(_LOG_CONTEXT)
    line = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "level": level,
        "event": event,
        **base,
        **{k: v for k, v in fields.items() if v is not None},
    }
    print(json.dumps(line, separators=(",", ":"), ensure_ascii=False), flush=True)


# ── Metrics (Tier 5.3 parity with bin/signer.py) ────────────────────────────

_METRICS_LOCK = threading.Lock()
_metrics: dict[str, Any] = {
    "fc_agent_outbound_total": {},      # {(path, status_code): n}
    "fc_agent_operations_total": {},    # {(capability, outcome): n}
    "fc_agent_refusals_total": {},      # {reason: n}
    "fc_agent_events_total": {},        # {(action, status_code): n}
    "fc_agent_ci_calls_total": {},      # {(provider, phase, status_code): n}
    "fc_agent_retries_total": 0,
    "fc_agent_dlq_total": 0,
    "fc_agent_nonce_store_failures_total": 0,
}


def metric_bump(key: str, sub: Any = None, n: int | float = 1) -> None:
    with _METRICS_LOCK:
        if sub is None:
            _metrics[key] = _metrics[key] + n
        else:
            _metrics[key][sub] = _metrics[key].get(sub, 0) + n


def metrics_snapshot() -> dict[str, Any]:
    """Copy of the counters — for smokes and tests, never for hot paths."""
    with _METRICS_LOCK:
        return {k: (dict(v) if isinstance(v, dict) else v) for k, v in _metrics.items()}


def _label(value: Any) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"')


def render_metrics() -> bytes:
    """Prometheus exposition (text/plain; version=0.0.4)."""
    lines: list[str] = []
    with _METRICS_LOCK:
        lines.append("# HELP fc_agent_outbound_total Outbound calls to FixControl by path + HTTP status.")
        lines.append("# TYPE fc_agent_outbound_total counter")
        for (path, code), n in sorted(_metrics["fc_agent_outbound_total"].items()):
            lines.append(f'fc_agent_outbound_total{{path="{_label(path)}",status_code="{_label(code)}"}} {n}')
        lines.append("# HELP fc_agent_operations_total Redeemed operations by capability + outcome.")
        lines.append("# TYPE fc_agent_operations_total counter")
        for (cap, outcome), n in sorted(_metrics["fc_agent_operations_total"].items()):
            lines.append(f'fc_agent_operations_total{{capability="{_label(cap)}",outcome="{_label(outcome)}"}} {n}')
        lines.append("# HELP fc_agent_refusals_total Local-authorization refusals by reason code.")
        lines.append("# TYPE fc_agent_refusals_total counter")
        for reason, n in sorted(_metrics["fc_agent_refusals_total"].items()):
            lines.append(f'fc_agent_refusals_total{{reason="{_label(reason)}"}} {n}')
        lines.append("# HELP fc_agent_events_total Outbound cluster events by action + HTTP status.")
        lines.append("# TYPE fc_agent_events_total counter")
        for (action, code), n in sorted(_metrics["fc_agent_events_total"].items()):
            lines.append(f'fc_agent_events_total{{action="{_label(action)}",status_code="{_label(code)}"}} {n}')
        lines.append("# HELP fc_agent_ci_calls_total Calls to a private CI host by provider + phase + HTTP status.")
        lines.append("# TYPE fc_agent_ci_calls_total counter")
        for (provider, phase, code), n in sorted(_metrics["fc_agent_ci_calls_total"].items()):
            lines.append(
                f'fc_agent_ci_calls_total{{provider="{_label(provider)}",'
                f'phase="{_label(phase)}",status_code="{_label(code)}"}} {n}')
        lines.append("# HELP fc_agent_retries_total Retry attempts against FixControl (excludes first attempt).")
        lines.append("# TYPE fc_agent_retries_total counter")
        lines.append(f'fc_agent_retries_total {_metrics["fc_agent_retries_total"]}')
        lines.append("# HELP fc_agent_dlq_total Outbound calls that failed every retry and were dead-lettered.")
        lines.append("# TYPE fc_agent_dlq_total counter")
        lines.append(f'fc_agent_dlq_total {_metrics["fc_agent_dlq_total"]}')
        lines.append("# HELP fc_agent_nonce_store_failures_total ConfigMap nonce-store writes that fell back to memory.")
        lines.append("# TYPE fc_agent_nonce_store_failures_total counter")
        lines.append(f'fc_agent_nonce_store_failures_total {_metrics["fc_agent_nonce_store_failures_total"]}')
    return ("\n".join(lines) + "\n").encode("utf-8")


# ── Request authentication towards FixControl ───────────────────────────────

def sign_request(secret: str | bytes, timestamp: str, payload: str | bytes) -> str:
    """sha256=<hex HMAC(secret, timestamp + "." + payload)>.

    The timestamp is inside the MAC on purpose: without it a captured body
    could be replayed forever, and the ±300 s server-side skew window would
    have nothing authenticated to check.
    """
    if isinstance(payload, bytes):
        payload = payload.decode("utf-8")
    mac = hmac.new(_secret_bytes(secret), f"{timestamp}.{payload}".encode("utf-8"),
                   hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def auth_headers(agent_id: str, secret: str | bytes, payload: str | bytes,
                 timestamp: str | None = None) -> dict[str, str]:
    """The three headers every /api/agent/* request carries."""
    ts = timestamp or rfc3339()
    return {
        "x-fixcontrol-agent": agent_id,
        "x-fixcontrol-timestamp": ts,
        "x-fixcontrol-signature": sign_request(secret, ts, payload),
    }


# ── The local authorization pass (plan checks 1-5 + 8) ──────────────────────

def verify_operation(
    secret: str | bytes,
    op: Any,
    *,
    expected_tenant: str,
    expected_cluster: str,
    agent_id: str | None,
    capabilities: Iterable[str],
    nonce_store: "NonceStore | None" = None,
    now: float | None = None,
    skew_seconds: int = DEFAULT_SKEW_SECONDS,
    consume_nonce: bool = True,
    signing_public_keys: Sequence[bytes] = (),
) -> tuple[bool, str | None]:
    """Checks 1-5 and 8 of the plan's two-phase authorization, in order.

        1. tenant_mismatch      tenant  == my bound tenant
        2. cluster_mismatch     cluster == my bound clusterId
        3. bad_signature        the envelope's signature verifies against the
                                PINNED FixControl key (or, on an unpinned
                                install, against the shared secret)
        4. expired              now < expiresAt (bounded skew; a not-yet-valid
                                issuedAt is ALSO `expired` — the closed reason
                                set has no separate code, and both mean "this
                                authorization is not valid at this instant")
        5. replay               nonce unused, per the persisted NonceStore
        8. capability_denied    capability is in MY set, and an envelope pinned
                                to another agentId is not mine to redeem

    Checks 6 (local allowlist) and 7 (live revision) are capability-specific
    and stay with the caller: they need cluster reads this module deliberately
    does not perform.

    `signing_public_keys` is the customer's OWN pin list, read from this
    agent's ConfigMap by `parse_signing_public_keys` and never from anything
    FixControl sends. Non-empty is a ratchet: check 3 then accepts
    `alg: "ed25519"` verified against one of those keys and NOTHING else. An
    `hmac-sha256` envelope arriving at a pinned agent is refused
    `bad_signature` — see `signature_refusal_detail` for why that reason code
    and not a new one, and for the sentence the operator gets alongside it.

    Empty means an install that predates the pin, which keeps verifying the
    shared secret so it does not break on upgrade. That mode is a migration
    step, not a supported production posture: under it the key that signs an
    operation is the same key this process holds, so a compromise of this
    process is a compromise of the authority over it.

    Side effect, and it is load-bearing: when `consume_nonce` is set the nonce
    is written to the store as soon as checks 1-5 pass — BEFORE check 8. Two
    reasons. Writing earlier would let unauthenticated garbage grow the store
    (a DoS on a ConfigMap); writing later would leave a cryptographically valid
    envelope replayable after a capability refusal.

    Returns (True, None) or (False, <reason code from REFUSAL_REASONS>).
    """
    if not isinstance(op, dict):
        return False, REASON_BAD_SIGNATURE
    now = time.time() if now is None else now

    # 1 + 2 — identity binding. Checked against the agent's OWN configuration,
    # never against a value read out of the same envelope.
    if str(op.get("tenant") or "") != str(expected_tenant or ""):
        return False, REASON_TENANT_MISMATCH
    if str(op.get("clusterId") or "") != str(expected_cluster or ""):
        return False, REASON_CLUSTER_MISMATCH

    # 3 — signature. An unknown protocolVersion/alg is `bad_signature` rather
    # than a separate code: we cannot establish this envelope's authority, and
    # "I could not verify it" is exactly what bad_signature means to the gate.
    #
    # THE PIN LIST CHOOSES THE VERIFIER, NOT THE ENVELOPE. That ordering is the
    # downgrade defence: a pinned agent never asks the envelope which algorithm
    # it would prefer to be checked with.
    if op.get("protocolVersion") != PROTOCOL_VERSION:
        return False, REASON_BAD_SIGNATURE
    if signing_public_keys:
        if op.get("alg") != ALG_ED25519:
            return False, REASON_BAD_SIGNATURE
        if verify_operation_signature_ed25519(signing_public_keys, op) is None:
            return False, REASON_BAD_SIGNATURE
    else:
        if op.get("alg") != ALG_HMAC_SHA256:
            return False, REASON_BAD_SIGNATURE
        if not verify_operation_signature(secret, op):
            return False, REASON_BAD_SIGNATURE

    # 4 — expiry, both directions.
    expires = parse_rfc3339(op.get("expiresAt"))
    if expires is None or now > expires + skew_seconds:
        return False, REASON_EXPIRED
    issued = parse_rfc3339(op.get("issuedAt"))
    if issued is not None and issued - skew_seconds > now:
        return False, REASON_EXPIRED

    # 5 — single use.
    nonce = op.get("nonce")
    if not isinstance(nonce, str) or not nonce.strip():
        return False, REASON_REPLAY
    if nonce_store is not None:
        if nonce_store.seen(nonce):
            return False, REASON_REPLAY
        if consume_nonce:
            nonce_store.remember(nonce, op.get("expiresAt") or rfc3339(now + skew_seconds))

    # 8 — capability + agent pinning. An envelope addressed to another agent
    # instance is refused with capability_denied: the closed reason set has no
    # "not my identity" code, and from the gate's point of view the effect is
    # the same governance finding — this agent may not do this.
    pinned = op.get("agentId")
    if agent_id and isinstance(pinned, str) and pinned and pinned != agent_id:
        return False, REASON_CAPABILITY_DENIED
    capability = op.get("capability")
    allowed = {c for c in capabilities}
    if capability not in KNOWN_CAPABILITIES or capability not in allowed:
        return False, REASON_CAPABILITY_DENIED

    return True, None


# ── HTTPS guard ─────────────────────────────────────────────────────────────

def assert_fixcontrol_url_secure(url: str, component: str = "fc-agent") -> None:
    """Same stance as bin/signer.py Tier 2.1, and for the same reason: the
    agent secret is the only thing protecting tenant data on the wire.
    Plaintext HTTP is opt-in via ALLOW_INSECURE_FIXCONTROL_URL=1 for the kind
    dev rig (host FixControl at http://172.17.0.1:3000); anything else fails
    fast on boot so a misconfigured prod deploy cannot quietly leak.
    """
    if url.startswith("http://") and os.environ.get("ALLOW_INSECURE_FIXCONTROL_URL") != "1":
        raise SystemExit(
            f"{component} refusing to start: FIXCONTROL_URL={url!r} is plaintext "
            f"HTTP. Either point it at https:// or set "
            f"ALLOW_INSECURE_FIXCONTROL_URL=1 (dev only)."
        )


# ── FixControl client ───────────────────────────────────────────────────────

class FCClient:
    """Outbound HTTP to FixControl with the agent's request authentication.

    Retry ladder mirrors bin/signer.py exactly (1 s / 5 s / 30 s, transient
    only): connection errors and 5xx are retried, 4xx is terminal because a
    signature mismatch or a schema rejection will not change on the third
    attempt. All-fail emits a `dlq.write` JSON log line + bumps
    fc_agent_dlq_total, which is the same replay surface a queue would be.

    Every attempt re-signs with a FRESH timestamp — a 30 s backoff must not
    push a retry outside the server's ±300 s skew window on a slow link.
    """

    def __init__(
        self,
        base_url: str,
        agent_id: str,
        secret: str | bytes,
        *,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        retry_backoffs: Iterable[float] = DEFAULT_RETRY_BACKOFFS,
        user_agent: str = "fc-agent/1.0",
        component: str = "fc-agent",
    ) -> None:
        self.base_url = base_url.rstrip("/")
        assert_fixcontrol_url_secure(self.base_url, component)
        self.agent_id = agent_id
        self.secret = _secret_bytes(secret)
        self.timeout = timeout
        self.retry_backoffs = tuple(float(b) for b in retry_backoffs)
        self.user_agent = user_agent

    # -- public ------------------------------------------------------------

    def post_json(self, path: str, obj: Any) -> tuple[int, str]:
        """POST a JSON body. Signs the EXACT bytes it puts on the wire."""
        body = canonical_bytes(obj)
        status, raw = self._with_retries(
            "POST", path,
            lambda: (body, {
                "Content-Type": "application/json",
                **auth_headers(self.agent_id, self.secret, body.decode("utf-8")),
            }),
        )
        return status, raw.decode("utf-8", "replace")

    def get_bytes(self, path: str) -> tuple[int, bytes]:
        """GET raw bytes (the workspace tarball for test.run).

        On GET there is no body, so the signed payload is the request PATH —
        otherwise every GET would share one signature and be replayable across
        operations.
        """
        return self._with_retries(
            "GET", path,
            lambda: (None, auth_headers(self.agent_id, self.secret, path)),
        )

    def post_raw(self, path: str, body: bytes, headers: Mapping[str, str]) -> tuple[int, str]:
        """POST with caller-supplied headers and no agent authentication.

        Used for the cluster-event path, which keeps the SHIPPED Kubernetes
        webhook contract (raw-body HMAC under the per-tenant K8s webhook
        secret, X-FixControl-Signature / X-FixControl-Account) rather than the
        agent envelope — so an existing tenant's ingest keeps working while
        the agent replaces watcher+signer as the sender.
        """
        status, raw = self._with_retries("POST", path, lambda: (body, dict(headers)))
        return status, raw.decode("utf-8", "replace")

    # -- internals ---------------------------------------------------------

    def _send(self, method: str, path: str, body: bytes | None,
              headers: Mapping[str, str]) -> tuple[int, bytes]:
        url = f"{self.base_url}{path}"
        req = urllib.request.Request(
            url, data=body,
            headers={"User-Agent": self.user_agent, **headers},
            method=method,
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read()[:4096]
        except urllib.error.URLError as e:
            return 0, f"network: {e}".encode("utf-8")
        except (TimeoutError, OSError) as e:  # socket timeouts surface here
            return 0, f"network: {e}".encode("utf-8")

    def _with_retries(
        self, method: str, path: str,
        build: Callable[[], tuple[bytes | None, Mapping[str, str]]],
    ) -> tuple[int, bytes]:
        attempts = (0.0, *self.retry_backoffs)
        status, raw = 0, b"no attempt"
        for i, delay in enumerate(attempts):
            if delay > 0:
                metric_bump("fc_agent_retries_total")
                log_event("info", "retry.wait", attempt=i + 1, delay_seconds=delay,
                          path=path, method=method)
                time.sleep(delay)
            body, headers = build()  # fresh timestamp + signature per attempt
            status, raw = self._send(method, path, body, headers)
            metric_bump("fc_agent_outbound_total", (path, status))
            if 200 <= status < 300:
                return status, raw
            if 400 <= status < 500:
                log_event("warn", "outbound.4xx_terminal", path=path, method=method,
                          status_code=status, body=raw[:200].decode("utf-8", "replace"))
                return status, raw
        metric_bump("fc_agent_dlq_total")
        log_event("error", "dlq.write", path=path, method=method, status_code=status,
                  body=raw[:500].decode("utf-8", "replace"), attempts=len(attempts))
        return status, raw


# ── Kubernetes client ───────────────────────────────────────────────────────

class KubeError(Exception):
    """Non-2xx from the Kubernetes API. Carries the status so callers can
    distinguish 404 (object gone → a real answer) from 403 (RBAC too narrow →
    an operator problem) without parsing strings."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"kube api {status}: {body[:300]}")
        self.status = status
        self.body = body


class KubeClient:
    """Kubernetes API over urllib with the in-pod ServiceAccount token.

    Same construction as bin/watcher.py: Bearer token from the projected SA
    volume, TLS pinned to the apiserver CA in that same volume. Credentials
    are read LAZILY on first use so the class can be constructed (and
    monkeypatched) outside a Pod — every smoke in this repo runs clusterless.
    """

    def __init__(self, base_url: str | None = None, *, sa_dir: str = SA_DIR,
                 timeout: float = DEFAULT_TIMEOUT_SECONDS) -> None:
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.base_url = (base_url or f"https://{host}:{port}").rstrip("/")
        self.sa_dir = sa_dir
        self.timeout = timeout
        self._token: str | None = None
        self._ctx: ssl.SSLContext | None = None

    def _credentials(self) -> tuple[str, ssl.SSLContext]:
        if self._token is None or self._ctx is None:
            with open(f"{self.sa_dir}/token", "r", encoding="utf-8") as f:
                self._token = f.read().strip()
            self._ctx = ssl.create_default_context(cafile=f"{self.sa_dir}/ca.crt")
        return self._token, self._ctx

    def _request(self, method: str, path: str, obj: Any = None,
                 content_type: str = "application/json") -> Any:
        token, ctx = self._credentials()
        body = None if obj is None else canonical_bytes(obj)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(f"{self.base_url}{path}", data=body,
                                     headers=headers, method=method)
        try:
            with urllib.request.urlopen(req, context=ctx, timeout=self.timeout) as resp:
                raw = resp.read()
        except urllib.error.HTTPError as e:
            raise KubeError(e.code, e.read().decode("utf-8", "replace")) from None
        except urllib.error.URLError as e:
            raise KubeError(0, f"network: {e}") from None
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {}

    def get(self, path: str) -> Any:
        return self._request("GET", path)

    def post(self, path: str, obj: Any) -> Any:
        return self._request("POST", path, obj)

    def put(self, path: str, obj: Any) -> Any:
        return self._request("PUT", path, obj)

    def patch(self, path: str, obj: Any,
              content_type: str = "application/merge-patch+json") -> Any:
        return self._request("PATCH", path, obj, content_type=content_type)

    def delete(self, path: str) -> Any:
        return self._request("DELETE", path)


# ── Nonce store ─────────────────────────────────────────────────────────────

def _nonce_key(nonce: str) -> str:
    """ConfigMap keys are restricted to [-._a-zA-Z0-9]; a nonce is opaque
    server-issued text. Hash it — we only ever need equality, never the
    original value, and hashing also keeps the stored material meaningless to
    anyone who can read the ConfigMap."""
    return "n-" + hashlib.sha256(nonce.encode("utf-8")).hexdigest()[:40]


class NonceStore:
    """Single-use enforcement, persisted in a ConfigMap in the agent's own
    namespace (plan open question 6: "persist, with expiry-based pruning").

    Persistence matters because the agent must refuse a replay across its own
    restarts — an in-memory-only store turns a pod eviction into a replay
    window. When the ConfigMap is unwritable (RBAC drift, API outage) the
    store degrades to memory-only with a warn log and a bumped counter; the
    replay window is then bounded by the envelope expiry (minutes), which is
    a documented degradation rather than a silent one.

    Pruning happens on every write: entries whose expiry has passed can never
    be replayed anyway, so keeping them only grows the object toward the 1 MiB
    ConfigMap ceiling.
    """

    def __init__(self, kube: KubeClient | None, namespace: str,
                 name: str = "fc-agent-nonces") -> None:
        self.kube = kube
        self.namespace = namespace
        self.name = name
        self.path = f"/api/v1/namespaces/{namespace}/configmaps/{name}"
        self._entries: dict[str, str] = {}   # hashed nonce → expiresAt (RFC3339)
        self._resource_version: str | None = None
        self._persistent = kube is not None
        self._loaded = False

    # -- public ------------------------------------------------------------

    def seen(self, nonce: str) -> bool:
        self._ensure_loaded()
        return _nonce_key(nonce) in self._entries

    def remember(self, nonce: str, expires_at: str) -> None:
        self._ensure_loaded()
        self._entries[_nonce_key(nonce)] = expires_at
        pruned = self._prune()
        if not self._persistent:
            return
        try:
            self._write(pruned)
        except Exception as e:  # noqa: BLE001 — degradation must never abort an operation
            self._degrade("nonce_store.write_failed", e)

    def reload(self) -> None:
        self._loaded = False
        self._ensure_loaded()

    # -- internals ---------------------------------------------------------

    def _degrade(self, event: str, error: Exception) -> None:
        metric_bump("fc_agent_nonce_store_failures_total")
        self._persistent = False
        log_event("warn", event, namespace=self.namespace, configmap=self.name,
                  error=str(error)[:300],
                  note="falling back to in-memory nonces; replay defence is now "
                       "bounded by operation expiry only")

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.kube is None:
            return
        try:
            body = self.kube.get(self.path)
        except KubeError as e:
            if e.status == 404:
                return  # first boot — created on the first remember()
            self._degrade("nonce_store.read_failed", e)
            return
        except Exception as e:  # noqa: BLE001
            self._degrade("nonce_store.read_failed", e)
            return
        data = body.get("data") if isinstance(body, dict) else None
        if isinstance(data, dict):
            self._entries = {str(k): str(v) for k, v in data.items()}
        meta = body.get("metadata") if isinstance(body, dict) else None
        if isinstance(meta, dict):
            self._resource_version = meta.get("resourceVersion")

    def _prune(self, now: float | None = None) -> list[str]:
        now = time.time() if now is None else now
        expired = [
            key for key, value in self._entries.items()
            if (parse_rfc3339(value) or 0.0) < now
        ]
        for key in expired:
            del self._entries[key]
        return expired

    def _write(self, pruned: list[str]) -> None:
        """PUT the whole object. Deliberately not PATCH: the agent's RBAC
        grants get/create/update on this ONE ConfigMap by name and nothing
        else, so a full replace keeps the Role minimal (see
        install/base/agent/fc-agent.yaml). `pruned` is accepted so a future
        merge-patch variant stays a drop-in."""
        assert self.kube is not None
        obj = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": self.name, "namespace": self.namespace},
            "data": dict(self._entries),
        }
        if self._resource_version:
            obj["metadata"]["resourceVersion"] = self._resource_version
        try:
            result = self.kube.put(self.path, obj)
        except KubeError as e:
            if e.status == 404:
                result = self.kube.post(
                    f"/api/v1/namespaces/{self.namespace}/configmaps",
                    {k: v for k, v in obj.items() if k != "metadata"}
                    | {"metadata": {"name": self.name, "namespace": self.namespace}},
                )
            elif e.status == 409:
                # Another writer moved the object (v1 is single-agent, so this
                # is a restart race). Re-read, re-merge, retry once.
                self._resource_version = None
                self._loaded = False
                mine = dict(self._entries)
                self._ensure_loaded()
                self._entries.update(mine)
                self._prune()
                result = self.kube.put(self.path, {
                    "apiVersion": "v1", "kind": "ConfigMap",
                    "metadata": {"name": self.name, "namespace": self.namespace,
                                 **({"resourceVersion": self._resource_version}
                                    if self._resource_version else {})},
                    "data": dict(self._entries),
                })
            else:
                raise
        meta = result.get("metadata") if isinstance(result, dict) else None
        if isinstance(meta, dict) and meta.get("resourceVersion"):
            self._resource_version = meta["resourceVersion"]


# ── /healthz + /metrics listener ────────────────────────────────────────────

def make_health_handler(ready: Callable[[], bool] | None = None):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802 — required name
            if self.path == "/healthz":
                healthy = True if ready is None else bool(ready())
                self.send_response(200 if healthy else 503)
                self.end_headers()
                self.wfile.write(b"ok" if healthy else b"degraded")
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

        def log_message(self, fmt: str, *args: Any) -> None:  # noqa: A003
            # Structured events are emitted by the caller; suppress the
            # per-request access log so stdout stays one JSON line per event.
            return

    return Handler


def serve_health_and_metrics(host: str = "127.0.0.1", port: int = 8080,
                             ready: Callable[[], bool] | None = None) -> threading.Thread:
    """Start the health/metrics listener on a daemon thread.

    Default bind is LOOPBACK: the agent is outbound-only and ships without a
    Service, so nothing in the cluster should be able to reach it. Flip the
    host to 0.0.0.0 only together with an explicit ingress NetworkPolicy for
    the Prometheus scrape.
    """
    server = HTTPServer((host, port), make_health_handler(ready))
    thread = threading.Thread(target=server.serve_forever, name="fc-agent-metrics",
                              daemon=True)
    thread.start()
    return thread


# ── Small shared helpers ────────────────────────────────────────────────────

def csv_env(name: str, default: str = "") -> list[str]:
    """Comma-separated ConfigMap value → list. Customer-owned configuration is
    read this way everywhere so an empty value is an empty list, never a
    one-element list containing "" (which would allowlist a nameless target)."""
    return [s.strip() for s in os.environ.get(name, default).split(",") if s.strip()]


def basic_auth_header(username: str, secret: str) -> str:
    """`Authorization: Basic …` value for git-over-HTTPS credential injection.
    Same scheme as FixControl's git-promote.ts and bin/git-promote-bot.py:
    the PAT travels via http.extraheader and never lands in .git/config."""
    return "Basic " + base64.b64encode(
        f"{username}:{secret}".encode("utf-8")).decode("ascii")


def quote_path_segment(value: str) -> str:
    """URL-escape one path segment for the K8s / FixControl API paths."""
    return urllib.parse.quote(str(value), safe="")
