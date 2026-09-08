"""TAP primitives for the TAPClient SDK — self-contained (publishable).

This is a conforming implementation of the TAP v0.1 wire crypto: Ed25519 over
JCS-canonicalized event bodies and compact-JWS passports. It reproduces
`tap/test-vectors.json` byte-for-byte (see tests/test_conformance.py), which is
how a standalone SDK stays interoperable with the reference implementation and
with the JS SDK.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import time
from datetime import datetime, timezone
from typing import Any

import jcs  # RFC 8785 JSON Canonicalization Scheme
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

SPEC_VERSION = "tap/0.1"
PASSPORT_TYP = "tap-passport+jwt"
DEFAULT_ISSUER = "https://verifier.example.com"
DEFAULT_TTL_S = 3600

RESULT_CODES = frozenset({
    "OK", "DENIED_SCOPE", "DENIED_POLICY", "TOOL_ERROR",
    "TIMEOUT", "UPSTREAM_4XX", "UPSTREAM_5XX", "VALIDATION_ERROR",
    # §9.2, provisional — no Verifier enforces these yet [TAP-AUTHORITY-*]
    "DENIED_AUTHORITY_EXPIRED", "DENIED_AUTHORITY_REVOKED", "DENIED_AUTHORITY_REUSED",
})

# Action taxonomy — [TAP-EVT-KIND]. Implementations MAY define namespaced
# extension kinds prefixed ``x-``; verifiers MUST preserve unknown kinds
# verbatim, so this set is a reference for validation, never a filter.
ACTION_KINDS = frozenset({
    "tool_call", "agent_delegate", "received_delegation", "agent_message",
    "denied", "decision", "checkpoint",
})

# --- canonicalization guard ([TAP-CANON-NUMBERS]) -----------------------------------

MAX_SAFE_INT = 2**53 - 1


class CanonicalizationError(ValueError):
    """A signed body contains a value JCS cannot canonicalize identically across
    implementations — a fractional/exponent number, or an out-of-range integer.
    Fractional quantities (e.g. decision ``score``) MUST be encoded as strings."""


def canonical_guard(value: Any) -> None:
    """Reject any float or unsafe integer anywhere in a signed body — §3.4."""
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise CanonicalizationError(
            "fractional/float numbers are forbidden in a signed body; encode as a string"
        )
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalizationError(f"integer {value} exceeds ±(2^53−1) safe range")
        return
    if isinstance(value, dict):
        for v in value.values():
            canonical_guard(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            canonical_guard(v)


# --- encoding ----------------------------------------------------------------

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def text_digest(text: str) -> str:
    """Digest of a UTF-8 string — the value signed when plaintext lives in the annex (§6.1)."""
    return digest(text.encode("utf-8"))


def json_digest(obj: Any) -> str:
    """Digest over the JCS-canonical bytes of a JSON value — cross-language stable (§6.1)."""
    return digest(jcs.canonicalize(obj))


# --- keys --------------------------------------------------------------------

def load_signer(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))


def generate_signer() -> tuple[Ed25519PrivateKey, str]:
    """Return a new Ed25519 signer and its 32-byte seed hex (shown/stored once)."""
    seed_hex = secrets.token_bytes(32).hex()
    return load_signer(seed_hex), seed_hex


def public_jwk(sk: Ed25519PrivateKey, kid: str) -> dict:
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
            "use": "sig", "kid": kid, "x": b64u(raw)}


# --- crypto-suite dispatch & revocation [TAP-SUITE-DISPATCH], [TAP-KEY-REVOCATION] ---------------


class RevokedKey(ValueError):
    """The signing key's revocation boundary excludes this record.

    A distinct type from UnknownSuite so a caller can tell "this key was retired"
    from "this key speaks a suite I do not implement" — different operational
    responses, and only the first says anything about the record's authenticity
    at the time it was signed.
    """


class UnknownSuite(ValueError):
    """The key declares a crypto suite this implementation does not recognize.

    A conforming verifier MUST reject it rather than fall back to a default
    ([TAP-SUITE-DISPATCH]). New suites are registry additions, never silent widening.
    """


class InvalidRecord(ValueError):
    """A record failed a structural or freshness check during verification.

    A distinct type from a bare ``AssertionError`` for two reasons: `python -O`
    strips `assert` statements, so a verifier whose typ/kid/alg/freshness checks
    are assertions accepts a forged token under any production image that sets
    the flag; and a caller catching verification failures should not also be
    catching arbitrary `AssertionError`s raised by unrelated bugs elsewhere in
    the process.
    """


class PassportExpired(InvalidRecord):
    """A Passport's freshness window [TAP-PASSPORT-VALIDATE] excludes `now`.

    A distinct type from InvalidRecord's other structural failures (wrong typ,
    mismatched kid, forged alg) so a caller can tell "this passport aged out" —
    an expected, common outcome — from "this token is malformed or fraudulent".
    """


# v0.1 recognizes only Ed25519.
_SUITES = {("EdDSA", "Ed25519"): "tap-ed25519"}


def suite_for_jwk(jwk: dict) -> str:
    """Resolve a JWK's declared (alg, crv) to a TAP suite id, or raise."""
    key = (jwk.get("alg"), jwk.get("crv"))
    suite = _SUITES.get(key)
    if suite is None:
        raise UnknownSuite(
            f"unrecognized crypto suite for key {jwk.get('kid')!r}: {key}"
        )
    return suite


def key_revoked_at(jwk: dict) -> int | None:
    """Optional epoch-seconds revocation boundary for a key [TAP-KEY-REVOCATION]."""
    revoked_at = jwk.get("revoked_at")
    return int(revoked_at) if revoked_at is not None else None


def parse_ts(ts: str) -> int:
    """RFC 3339 UTC timestamp -> epoch seconds. Raises on anything unparseable."""
    return int(datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())


def check_not_revoked(jwk: dict, signed_at: str | int | None) -> None:
    """Enforce a key's revocation boundary against the record's own timestamp
    [TAP-KEY-REVOCATION].

    ``signed_at`` is an Event's ``ts`` (RFC 3339) or a Passport's ``iat`` (epoch
    seconds). Both are INSIDE the signing input, so a holder of a compromised key
    cannot backdate a record past the boundary without breaking its signature —
    which is what makes this check sound before the signature is verified.

    Revocation is an effective-time boundary, not blanket repudiation: records
    signed before ``revoked_at`` stay valid. A record that cannot place itself in
    time, signed by a key that IS revoked, is rejected — evidence that cannot
    prove its own effective time is not evidence.
    """
    revoked = key_revoked_at(jwk)
    if revoked is None:
        return
    if signed_at is None:
        raise RevokedKey("key is revoked and the record carries no timestamp to place it")
    try:
        at = signed_at if isinstance(signed_at, int) else parse_ts(signed_at)
    except Exception as exc:
        raise RevokedKey(f"key is revoked and the record timestamp is unparseable: {exc}")
    if at >= revoked:
        raise RevokedKey(f"key revoked at {revoked}; record is timestamped {at}")


# --- passport (compact JWS / JWT) --------------------------------------------

def sign_passport(sk: Ed25519PrivateKey, kid: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": PASSPORT_TYP, "kid": kid}
    seg = (b64u(json.dumps(header, separators=(",", ":")).encode())
           + "." +
           b64u(json.dumps(claims, separators=(",", ":")).encode()))
    sig = sk.sign(seg.encode("ascii"))
    return seg + "." + b64u(sig)


def verify_passport(jwk: dict, token: str, now: int | None = None) -> dict:
    """Validate a Passport [TAP-PASSPORT-VALIDATE]."""
    suite_for_jwk(jwk)  # dispatch off the declared suite; raises on unknown
    now = int(time.time()) if now is None else now
    h_b64, p_b64, s_b64 = token.split(".")
    pk = Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
    pk.verify(b64u_dec(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))
    header = json.loads(b64u_dec(h_b64))
    claims = json.loads(b64u_dec(p_b64))
    # §3.1: checking the JWK's suite alone leaves the field alg-confusion attacks
    # actually target — the signature above is a perfectly good Ed25519
    # signature even when the header lies about `alg` [TAP-SIG-ALG].
    if header.get("alg") != "EdDSA":
        raise InvalidRecord(f"unsupported alg in JOSE header: {header.get('alg')!r}")
    if header.get("typ") != PASSPORT_TYP:
        raise InvalidRecord(f"wrong token type: {header.get('typ')!r}")
    if header.get("kid") != jwk["kid"]:
        raise InvalidRecord(f"kid mismatch: header={header.get('kid')!r} jwk={jwk['kid']!r}")
    check_not_revoked(jwk, claims.get("iat"))
    # Freshness with the +/-60 s skew allowance, written as the spec's inequality
    # so the two cannot drift apart [TAP-PASSPORT-VALIDATE].
    if not (claims["iat"] - 60 <= now < claims["exp"] + 60):
        raise PassportExpired(
            f"passport expired / not yet valid: iat={claims['iat']} exp={claims['exp']} now={now}"
        )
    return claims


# --- event (detached sig over JCS canonical body) ----------------------------

def signing_input(event_body: dict) -> bytes:
    body = {k: v for k, v in event_body.items() if k != "sig"}
    return jcs.canonicalize(body)


def sign_event(sk: Ed25519PrivateKey, event_body: dict) -> dict:
    canonical_guard({k: v for k, v in event_body.items() if k != "sig"})
    sig = sk.sign(signing_input(event_body))
    return {**event_body, "sig": b64u(sig)}


def verify_event(jwk: dict, event: dict) -> bool:
    """Verify one Event [TAP-EVT-VERIFY].

    Suite dispatch and the revocation boundary are part of verification, not a
    layer above it: a primitive that skips either does not conform, however
    faithfully a caller might re-implement them elsewhere.
    """
    suite_for_jwk(jwk)  # dispatch off the declared suite; raises on unknown
    check_not_revoked(jwk, event.get("ts"))
    pk = Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
    pk.verify(b64u_dec(event["sig"]), signing_input(event))
    if event["kid"] != jwk["kid"]:
        raise InvalidRecord(f"kid mismatch: event={event['kid']!r} jwk={jwk['kid']!r}")
    return True


# --- product helpers ---------------------------------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _b32(value: int, length: int) -> str:
    out = []
    for _ in range(length):
        out.append(_CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(out))


def new_id(prefix: str) -> str:
    ts_ms = int(time.time() * 1000)
    rand = int.from_bytes(secrets.token_bytes(10), "big")
    return f"{prefix}_{_b32(ts_ms, 10)}{_b32(rand, 16)}"


def now_ts() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def new_nonce() -> bytes:
    """A per-record nonce (128 bits) — §3.3 cid anti-oracle requirement."""
    return secrets.token_bytes(16)


def cid_from_prompt(prompt: str | bytes, nonce: bytes | None = None) -> str:
    """cid = digest(utf8(prompt) ‖ nonce) — §3.3.

    The nonce MUST carry ≥128 bits of entropy so identical prompts do not
    collide on cid and cid cannot serve as a confirmation oracle. If omitted,
    16 random bytes are generated. Concatenation order is part of the byte
    contract (matches tap_ref.py).
    """
    raw = prompt.encode() if isinstance(prompt, str) else prompt
    if nonce is None:
        nonce = new_nonce()
    elif len(nonce) < 16:
        raise ValueError("cid nonce MUST be at least 16 bytes (128 bits)")
    return digest(raw + nonce)


def checkpoint_root(event_ids: list[str]) -> str:
    """Merkle root over event_ids per §6.3 (normative construction, matches tap_ref.py).

    Leaf = SHA-256(0x00 ‖ utf8(event_id))
    Node = SHA-256(0x01 ‖ left ‖ right)
    Odd  = final node promoted unchanged (no duplication)
    Empty → SHA-256(b"")
    """
    if not event_ids:
        return digest(b"")
    level = [hashlib.sha256(b'\x00' + eid.encode("utf-8")).digest() for eid in event_ids]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(hashlib.sha256(b'\x01' + level[i] + level[i + 1]).digest())
            else:
                nxt.append(level[i])  # promote odd node unchanged
        level = nxt
    return "sha256:" + level[0].hex()


def scope_satisfied(scope_used: str | None, passport_scope: list[str]) -> bool:
    """Exact-match scope check [TAP-SCOPE-MATCH].

    v0.1 matches scope tokens by exact string equality: no wildcards, no prefix
    rule, no case folding, and `read:database` does NOT cover
    `read:database.users`. This is the narrowest possible rule on purpose — a
    matching semantics that grants more than it literally says would be a
    privilege-escalation surface in the one check TAP performs itself. Richer
    schemes belong in a Service Profile.
    """
    return scope_used is None or scope_used in passport_scope
