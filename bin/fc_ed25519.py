"""
fc_ed25519 — Ed25519 signature VERIFICATION, pure stdlib, verify-only.

── Why this file exists ────────────────────────────────────────────────────
The fc-agent images carry no pip resolver and no compiled extension: a
customer's security team must be able to read the entire trust boundary out of
`bin/`, and `docker/agent/Dockerfile` installs nothing. CPython's standard
library has SHA-512 and big integers but no Ed25519, so the RFC 8032
verification equation is implemented here rather than imported.

── Provenance ──────────────────────────────────────────────────────────────
Transcribed from the reference implementation in **RFC 8032, Appendix A
("Ed25519 Python illustration", Josefsson & Liusvaara, January 2017)**, which
the RFC publishes for exactly this purpose. Copyright (c) 2017 IETF Trust and
the persons identified as authors of the code; the RFC's own terms permit
reproduction. The transcription is faithful — same curve constants, same
extended-coordinate point arithmetic, same decompression, same verification
equation — with three deliberate departures:

  1. **Verify only.** `secret_expand`, `secret_to_public` and `sign` are NOT
     transcribed. The agent must be structurally incapable of producing a
     FixControl signature: there is no private-key code path in this process,
     so a compromised agent cannot mint an operation even with its own memory
     in hand. That is the whole point of moving off the shared HMAC secret.
  2. **Exceptions become False.** The reference raises on malformed input; a
     verifier that raises is a verifier a caller can forget to wrap, and the
     agent's answer to "I cannot establish this envelope's authority" is
     always a refusal, never a traceback. `verify()` returns bool and raises
     nothing.
  3. **Type hints + names** in this repo's style.

── Performance ─────────────────────────────────────────────────────────────
About 4 ms per verification on the agent's own image (two variable-base scalar
multiplications in Python integers). Operations arrive at human-decision
frequency — single digits per hour on a busy tenant — so a constant-factor
slower verifier costs nothing that matters. This code is NOT constant-time,
which is correct for its job: it handles only PUBLIC keys and PUBLIC
signatures. There is no secret here to leak through a timing channel.

── What this module does NOT decide ────────────────────────────────────────
Whether a key is TRUSTED. `verify()` answers "does this signature belong to
this public key", nothing more. Which public keys the agent pins is
`fc_agent_common.parse_signing_public_keys()` reading the customer's own
ConfigMap, and the agent never learns a key over the FixControl channel.
"""
from __future__ import annotations

import hashlib

__all__ = ["PUBLIC_KEY_BYTES", "SIGNATURE_BYTES", "verify"]

#: A compressed Ed25519 public key (RFC 8032 §5.1.5).
PUBLIC_KEY_BYTES = 32
#: R || S (RFC 8032 §5.1.6).
SIGNATURE_BYTES = 64

# ── Curve constants (RFC 8032 §5.1) ─────────────────────────────────────────

_P = 2 ** 255 - 19
#: The order of the base-point group, L.
_Q = 2 ** 252 + 27742317777372353535851937790883648493


def _modp_inv(x: int) -> int:
    return pow(x, _P - 2, _P)


_D = -121665 * _modp_inv(121666) % _P
_MODP_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def _sha512_modq(data: bytes) -> int:
    return int.from_bytes(hashlib.sha512(data).digest(), "little") % _Q


# ── Points: extended homogeneous coordinates (X, Y, Z, T) ───────────────────
# x = X/Z, y = Y/Z, x*y = T/Z. One inversion at the very end instead of one
# per point operation — the reason the reference uses this representation.

_Point = "tuple[int, int, int, int]"


def _point_add(p: _Point, q: _Point) -> _Point:  # type: ignore[valid-type]
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _point_mul(s: int, p: _Point) -> _Point:  # type: ignore[valid-type]
    q: _Point = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            q = _point_add(q, p)
        p = _point_add(p, p)
        s >>= 1
    return q


def _point_equal(p: _Point, q: _Point) -> bool:  # type: ignore[valid-type]
    # x1/z1 == x2/z2  ⇔  x1*z2 == x2*z1, and likewise for y.
    if (p[0] * q[2] - q[0] * p[2]) % _P != 0:
        return False
    if (p[1] * q[2] - q[1] * p[2]) % _P != 0:
        return False
    return True


def _recover_x(y: int, sign: int) -> int | None:
    """The x matching this y and sign bit, or None if the y is off-curve."""
    if y >= _P:
        return None
    x2 = (y * y - 1) * _modp_inv(_D * y * y + 1) % _P
    if x2 == 0:
        # x == 0 has only one root; a sign bit of 1 would claim the
        # non-canonical encoding of it.
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P != 0:
        x = x * _MODP_SQRT_M1 % _P
    if (x * x - x2) % _P != 0:
        return None  # not a square: the point is not on the curve
    if (x & 1) != sign:
        x = _P - x
    return x


_G_Y = 4 * _modp_inv(5) % _P
_G_X = _recover_x(_G_Y, 0)
assert _G_X is not None  # the RFC's base point is on the curve by construction
_G: _Point = (_G_X, _G_Y, 1, _G_X * _G_Y % _P)


def _point_decompress(data: bytes) -> _Point | None:  # type: ignore[valid-type]
    if len(data) != PUBLIC_KEY_BYTES:
        return None
    y = int.from_bytes(data, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % _P)


# ── The one public entry point ──────────────────────────────────────────────

def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature over `message` by
    `public_key` (32 raw bytes, compressed, as RFC 8032 encodes them).

    Never raises. Every malformed input — wrong length, an off-curve point, a
    non-canonical scalar — is False, because from the agent's point of view all
    of them mean the same thing: this envelope's authority cannot be
    established, so it is refused.

    Verification equation (RFC 8032 §5.1.7, the non-batch form):

        [8][s]B  ==  [8]R + [8][SHA512(R ‖ A ‖ M) mod L]A

    The cofactor-8 multiplication is omitted exactly as the reference omits it:
    the cofactorless equation is what the RFC's own illustration checks, and
    both accept every signature a conforming signer produces.
    """
    if not isinstance(public_key, (bytes, bytearray)) or len(public_key) != PUBLIC_KEY_BYTES:
        return False
    if not isinstance(signature, (bytes, bytearray)) or len(signature) != SIGNATURE_BYTES:
        return False
    if not isinstance(message, (bytes, bytearray)):
        return False

    public_key = bytes(public_key)
    signature = bytes(signature)

    a = _point_decompress(public_key)
    if a is None:
        return False
    r_bytes = signature[:32]
    r = _point_decompress(r_bytes)
    if r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    # A scalar at or above L is a non-canonical encoding and is rejected —
    # without this check the signature would be malleable.
    if s >= _Q:
        return False

    h = _sha512_modq(r_bytes + public_key + bytes(message))
    return _point_equal(_point_mul(s, _G), _point_add(r, _point_mul(h, a)))
