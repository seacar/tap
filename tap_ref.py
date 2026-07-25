#!/usr/bin/env python3
"""
TAP — Traceable Agent Protocol · reference implementation (v0.1)

A minimal, dependency-light reference for the cryptographic operations that
define TAP interoperability:

  1. The Passport  — a compact JWS/JWT (JOSE), EdDSA / Ed25519.
  2. The Event     — a JSON object carrying a *detached* Ed25519 signature
                     computed over the JCS (RFC 8785) canonicalization of the
                     event body with the `sig` field removed. The signed body
                     carries **digests, not raw data** (§7.1); the human-readable
                     plaintext travels in a separate, redactable **annex**.

This file is normative-by-example: any conforming implementation MUST reproduce
the signatures in test-vectors.json byte-for-byte from the fixed seed below. The
published vectors exercise the digests-only envelope (§7.1), a decision event
with string scores (§7.4 / the §3.4 no-fractional-numbers rule), and the
checkpoint Merkle reconciliation case (§7.3).
"""
import json, base64, hashlib, pathlib, secrets
import jcs  # RFC 8785 JSON Canonicalization Scheme
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey,
)
from cryptography.hazmat.primitives import serialization

# ---------- encoding helpers ----------

def b64u(b: bytes) -> str:
    """base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")

def b64u_dec(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))

def digest(data: bytes) -> str:
    """TAP digest string: '<alg>:<hex>' (§3.3)."""
    return "sha256:" + hashlib.sha256(data).hexdigest()

def text_digest(text: str) -> str:
    """Digest of a plaintext string (its UTF-8 bytes) — the value signed in the
    body when the plaintext itself lives in the redactable annex (§7.1)."""
    return digest(text.encode("utf-8"))

def json_digest(obj) -> str:
    """Digest over the JCS-canonical bytes of a JSON value (cross-language stable)."""
    return digest(jcs.canonicalize(obj))

# ---------- canonicalization guard (§3.4) ----------

MAX_SAFE_INT = 2**53 - 1

class CanonicalizationError(ValueError):
    """A signed body contains a value JCS cannot canonicalize identically across
    implementations — a fractional/exponent number, or an out-of-range integer."""

def canonical_guard(value) -> None:
    """Reject any JSON number with a fractional part/exponent, or any integer
    outside the IEEE-754 safe range, anywhere in a signed body (§3.4). Fractional
    quantities (e.g. a decision `score`) MUST be encoded as strings."""
    if isinstance(value, bool):
        return  # booleans are fine; not numbers
    if isinstance(value, float):
        raise CanonicalizationError(
            "fractional/float numbers are forbidden in a signed body; encode as a string"
        )
    if isinstance(value, int):
        if abs(value) > MAX_SAFE_INT:
            raise CanonicalizationError(f"integer {value} exceeds the ±(2^53−1) safe range")
        return
    if isinstance(value, dict):
        for v in value.values():
            canonical_guard(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            canonical_guard(v)

# ---------- context id (§3.3) ----------

def new_nonce() -> bytes:
    """A per-record nonce (128 bits) so identical prompts do not collide on `cid`
    and `cid` cannot serve as a confirmation oracle for a low-entropy prompt."""
    return secrets.token_bytes(16)

def cid_from_prompt(prompt: str | bytes, nonce: bytes) -> str:
    """cid = digest( canonical prompt bytes ‖ nonce ) (§3.3). The nonce is the
    trailing bytes; it is REQUIRED and SHOULD carry ≥128 bits of entropy. The cid
    is opaque to a verifier (which never recomputes it); the nonce need not be
    transported. Concatenation order is part of the byte contract."""
    raw = prompt.encode("utf-8") if isinstance(prompt, str) else prompt
    if len(nonce) < 16:
        raise ValueError("cid nonce MUST be at least 16 bytes (128 bits)")
    return digest(raw + nonce)

# ---------- checkpoint Merkle (§7.3) ----------
# NOTE: this is a DISTINCT Merkle profile from verifier/transparency.py, which
# hashes whole JCS-canonical events as leaves and DUPLICATES a lone odd node.
# The checkpoint profile hashes event_ids and PROMOTES an odd node unchanged.

_CKPT_LEAF = b"\x00"
_CKPT_NODE = b"\x01"

def _ckpt_leaf(event_id: str) -> bytes:
    return hashlib.sha256(_CKPT_LEAF + event_id.encode("utf-8")).digest()

def _ckpt_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_CKPT_NODE + left + right).digest()

def checkpoint_root(event_ids: list[str]) -> str:
    """Merkle root over `event_id`s (§7.3), ordered by seq ascending by the caller.
    Leaf = SHA256(0x00‖utf8(event_id)); interior = SHA256(0x01‖left‖right); an odd
    node is promoted unchanged (no duplication); an empty interval yields
    `"sha256:" + SHA256("")`. Returns a digest string."""
    if not event_ids:
        return digest(b"")
    level = [_ckpt_leaf(eid) for eid in event_ids]
    while len(level) > 1:
        nxt: list[bytes] = []
        for i in range(0, len(level), 2):
            if i + 1 < len(level):
                nxt.append(_ckpt_node(level[i], level[i + 1]))
            else:
                nxt.append(level[i])  # promote the odd node unchanged
        level = nxt
    return "sha256:" + level[0].hex()

# ---------- keys & crypto-suite dispatch (§3.6 pt.1) ----------

class UnknownSuite(ValueError):
    """The key declares a crypto suite this verifier does not recognize. A
    conforming verifier MUST reject it rather than fall back to a default (§15)."""

# v0.1 recognizes only Ed25519. Future suites are registry additions, not rewrites.
_SUITES = {("EdDSA", "Ed25519"): "tap-ed25519"}

def suite_for_jwk(jwk: dict) -> str:
    """Resolve a JWK's declared (alg, crv) to a TAP crypto-suite id, or raise
    UnknownSuite. Verification dispatches off the returned suite."""
    key = (jwk.get("alg"), jwk.get("crv"))
    suite = _SUITES.get(key)
    if suite is None:
        raise UnknownSuite(f"unrecognized crypto suite for key {jwk.get('kid')!r}: {key}")
    return suite

def key_revoked_at(jwk: dict) -> int | None:
    """Optional epoch-seconds revocation boundary for a key (§3.2)."""
    ra = jwk.get("revoked_at")
    return int(ra) if ra is not None else None

def load_signer(seed_hex: str) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))

def public_jwk(sk: Ed25519PrivateKey, kid: str) -> dict:
    raw = sk.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return {"kty": "OKP", "crv": "Ed25519", "alg": "EdDSA",
            "use": "sig", "kid": kid, "x": b64u(raw)}

# ---------- the Passport (compact JWS / JWT, JOSE) ----------

def sign_passport(sk: Ed25519PrivateKey, kid: str, claims: dict) -> str:
    header = {"alg": "EdDSA", "typ": "tap-passport+jwt", "kid": kid}
    seg = (b64u(json.dumps(header, separators=(",", ":")).encode())
           + "." +
           b64u(json.dumps(claims, separators=(",", ":")).encode()))
    sig = sk.sign(seg.encode("ascii"))
    return seg + "." + b64u(sig)

def verify_passport(jwk: dict, token: str, now: int) -> dict:
    suite_for_jwk(jwk)  # dispatch off the declared suite; raises on unknown
    h_b64, p_b64, s_b64 = token.split(".")
    pk = Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
    pk.verify(b64u_dec(s_b64), f"{h_b64}.{p_b64}".encode("ascii"))  # raises on bad sig
    header = json.loads(b64u_dec(h_b64))
    claims = json.loads(b64u_dec(p_b64))
    assert header["typ"] == "tap-passport+jwt", "wrong token type"
    assert header["kid"] == jwk["kid"], "kid mismatch"
    revoked = key_revoked_at(jwk)
    assert revoked is None or claims["iat"] < revoked, "key revoked as of iat"
    assert claims["iat"] - 60 <= now < claims["exp"] + 60, "passport expired / not yet valid"
    return claims

# ---------- the Event (detached sig over JCS canonical body) ----------

def signing_input(event_body: dict) -> bytes:
    """Canonical bytes that get signed: JCS(event without `sig`)."""
    body = {k: v for k, v in event_body.items() if k != "sig"}
    return jcs.canonicalize(body)

def sign_event(sk: Ed25519PrivateKey, event_body: dict) -> dict:
    canonical_guard({k: v for k, v in event_body.items() if k != "sig"})
    sig = sk.sign(signing_input(event_body))
    return {**event_body, "sig": b64u(sig)}

def verify_event(jwk: dict, event: dict) -> bool:
    suite_for_jwk(jwk)  # dispatch off the declared suite; raises on unknown
    pk = Ed25519PublicKey.from_public_bytes(b64u_dec(jwk["x"]))
    pk.verify(b64u_dec(event["sig"]), signing_input(event))  # raises on tamper
    assert event["kid"] == jwk["kid"], "kid mismatch"
    return True

# ---------- deterministic test-vector generation ----------

if __name__ == "__main__":
    SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"  # fixed, public test key
    KID = "key_2026_ref01"
    sk = load_signer(SEED)
    jwk = public_jwk(sk, KID)

    # cid = digest(prompt ‖ nonce). Fixed nonce so the vector reproduces exactly.
    PROMPT = "Resolve support ticket #8842 for account holder lookup"
    NONCE = bytes.fromhex("00112233445566778899aabbccddeeff")
    cid = cid_from_prompt(PROMPT, NONCE)

    AID = "agt_01JABCDEF1111111111111111"
    JTI = "psp_01JABCDEF0000000000000000"

    passport_claims = {
        "iss": "https://getsworn.ai",
        "iat": 1767225600,                 # 2026-01-01T00:00:00Z
        "exp": 1767229200,                 # +1h
        "jti": JTI,
        "aid": AID,
        "cid": cid,
        "scope": ["read:database", "call:tool"],
        "meta": {"framework": "langgraph", "model": "gemini-2.5-pro",
                 "agent_name": "support-triage"},
    }
    passport = sign_passport(sk, KID, passport_claims)

    # ----- tool_call event (digests-only body + redactable annex, §7.1) -----
    EVT_TOOL = "evt_01JABCDEFGHJKMNPQRSTVWXYZ0"
    tool_intent = "Call db_query to fetch users for the support ticket"
    tool_reasoning = "The ticket references an account lookup; fetch the user row first."
    args = {"table": "users", "limit": 50}
    tool_body = {
        "v": "tap/0.1",
        "event_id": EVT_TOOL,
        "passport_jti": JTI,
        "aid": AID,
        "cid": cid,
        "seq": 7,
        "ts": "2026-01-01T00:03:11.482Z",
        "action": {
            "kind": "tool_call",
            "intent_digest": text_digest(tool_intent),
            "tool": "db_query",
            "scope_used": "read:database",
            "args_digest": json_digest(args),
        },
        "evidence": {
            "reasoning_digest": text_digest(tool_reasoning),
            "model_output_digest": digest(b"<full model reasoning trace>"),
            # First Event of the record binds the negotiated outcome (anti-downgrade, §4.1).
            "nego": {"version": "tap/0.1", "suite": "tap-ed25519", "attestation": "server"},
        },
        "result": {"status": "success", "code": "OK", "latency_ms": 142, "error": None},
        "attestor": "agent",
        "action_ref": "act_01JABCDEF2222222222222222",
        "kid": KID,
    }
    tool_event = sign_event(sk, tool_body)
    tool_annex = {
        "event_id": EVT_TOOL,
        "intent": tool_intent,
        "args_preview": args,
        "reasoning": tool_reasoning,
    }

    # ----- decision event (digests + string scores, §7.4) -----
    EVT_DEC = "evt_01JABCDEFGHJKMNPQRSTVWXYZ1"
    dec_intent = "Decide how to resolve refund ticket #8842"
    question = "How should I resolve refund ticket #8842?"
    rationale_refund = "Within policy; SLA breached"
    reason_escalate = "Higher cost; not required by policy"
    reason_deny = "Would violate refund policy v3"
    options = [
        {"id": "refund", "score": "0.71", "chosen": True,
         "rationale_digest": text_digest(rationale_refund)},
        {"id": "escalate", "score": "0.52", "chosen": False,
         "reason_digest": text_digest(reason_escalate)},
        {"id": "deny", "score": "0.10", "chosen": False,
         "reason_digest": text_digest(reason_deny)},
    ]
    dec_body = {
        "v": "tap/0.1",
        "event_id": EVT_DEC,
        "passport_jti": JTI,
        "aid": AID,
        "cid": cid,
        "seq": 8,
        "ts": "2026-01-01T00:03:12.004Z",
        "action": {
            "kind": "decision",
            "intent_digest": text_digest(dec_intent),
            "tool": "resolve_ticket",
            "scope_used": None,
        },
        "decision": {
            "question_digest": text_digest(question),
            "chosen": "refund",
            "selection": "policy-weighted-argmax",
            "options": options,
            "options_digest": json_digest(options),
        },
        "evidence": {"model_output_digest": digest(b"<full model reasoning + option set>")},
        "result": {"status": "success", "code": "OK", "latency_ms": 38, "error": None},
        "attestor": "agent",
        "action_ref": "act_01JABCDEF3333333333333333",
        "kid": KID,
    }
    dec_event = sign_event(sk, dec_body)
    dec_annex = {
        "event_id": EVT_DEC,
        "intent": dec_intent,
        "decision": {
            "question": question,
            "options": [
                {"id": "refund", "rationale": rationale_refund},
                {"id": "escalate", "reason": reason_escalate},
                {"id": "deny", "reason": reason_deny},
            ],
        },
    }

    # ----- checkpoint event (seals seq 1..8, §7.3) -----
    EVT_CKPT = "evt_01JABCDEFGHJKMNPQRSTVWXYZ2"
    sealed_ids = [EVT_TOOL, EVT_DEC]
    event_id_root = checkpoint_root(sealed_ids)
    ckpt_body = {
        "v": "tap/0.1",
        "event_id": EVT_CKPT,
        "passport_jti": JTI,
        "aid": AID,
        "cid": cid,
        "seq": 9,
        "ts": "2026-01-01T00:03:12.500Z",
        "action": {"kind": "checkpoint", "tool": None, "scope_used": None},
        "checkpoint": {"through_seq": 8, "event_id_root": event_id_root, "count": 2},
        "result": {"status": "success", "code": "OK", "latency_ms": 1, "error": None},
        "attestor": "agent",
        "kid": KID,
    }
    ckpt_event = sign_event(sk, ckpt_body)

    # ----- self-checks -----
    assert verify_passport(jwk, passport, now=1767225601)
    assert verify_event(jwk, tool_event)
    assert verify_event(jwk, dec_event)
    assert verify_event(jwk, ckpt_event)
    # digests-only: the plaintext is NOT in the signed body
    assert "intent" not in tool_event["action"] and "args_preview" not in tool_event["action"]
    assert "reasoning" not in tool_event["evidence"]
    # annex plaintext verifies against the signed digests
    assert text_digest(tool_annex["intent"]) == tool_event["action"]["intent_digest"]
    assert json_digest(tool_annex["args_preview"]) == tool_event["action"]["args_digest"]
    # the §3.4 number rule is enforced
    try:
        canonical_guard({"score": 0.71}); raise SystemExit("FAIL: float not rejected")
    except CanonicalizationError:
        pass
    # unknown suite is rejected, never defaulted
    try:
        verify_event({**jwk, "alg": "RS256", "crv": "P-256"}, tool_event)
        raise SystemExit("FAIL: unknown suite not rejected")
    except UnknownSuite:
        pass
    # tamper on any signed field fails
    tampered = {**tool_event, "action": {**tool_event["action"], "tool": "drop_table"}}
    try:
        verify_event(jwk, tampered); raise SystemExit("FAIL: tamper not detected")
    except Exception:
        pass

    vectors = {
        "_about": "TAP v0.1 reference test vectors (whitepaper). Reproduce byte-for-byte from the seed.",
        "ed25519_private_seed_hex": SEED,
        "jwks": {"keys": [jwk]},
        "cid_construction": {
            "prompt": PROMPT,
            "nonce_hex": NONCE.hex(),
            "cid": cid,
            "_note": "cid = sha256( utf8(prompt) ‖ nonce )",
        },
        "passport": {
            "claims": passport_claims,
            "header": {"alg": "EdDSA", "typ": "tap-passport+jwt", "kid": KID},
            "compact_jwt": passport,
        },
        "event": {
            "canonical_signing_input_sha256": hashlib.sha256(signing_input(tool_event)).hexdigest(),
            "signed_event": tool_event,
            "annex": tool_annex,
        },
        "decision": {
            "canonical_signing_input_sha256": hashlib.sha256(signing_input(dec_event)).hexdigest(),
            "signed_event": dec_event,
            "annex": dec_annex,
        },
        "checkpoint": {
            "canonical_signing_input_sha256": hashlib.sha256(signing_input(ckpt_event)).hexdigest(),
            "signed_event": ckpt_event,
            "reconciliation": {
                "event_ids": sealed_ids,
                "event_id_root": event_id_root,
                "empty_interval_root": checkpoint_root([]),
            },
        },
        "tamper_check": "verify_event MUST reject when any signed field changes",
    }
    # Always write next to this file, never to the caller's cwd — running the
    # generator from a parent directory used to leave a second, stale copy of
    # the conformance contract lying around.
    out_path = pathlib.Path(__file__).resolve().parent / "test-vectors.json"
    with open(out_path, "w") as f:
        json.dump(vectors, f, indent=2)

    print("JWK (public):", json.dumps(jwk))
    print("\nPASSPORT (compact JWT):\n", passport)
    print("\nTOOL_CALL event canonical signing-input SHA-256:\n",
          hashlib.sha256(signing_input(tool_event)).hexdigest())
    print("\nDECISION event canonical signing-input SHA-256:\n",
          hashlib.sha256(signing_input(dec_event)).hexdigest())
    print("\nCHECKPOINT event_id_root:\n", event_id_root)
    print("\nAll self-checks passed: passport ✓  tool_call ✓  decision ✓  checkpoint ✓  guard ✓  suite ✓  tamper-rejected ✓")
