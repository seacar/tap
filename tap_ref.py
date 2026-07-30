#!/usr/bin/env python3
"""
TAP — Traceable Agent Protocol · reference implementation (v0.1)

A minimal, dependency-light reference for the cryptographic operations that
define TAP interoperability:

  1. The Passport  — a compact JWS/JWT (JOSE), EdDSA / Ed25519.
  2. The Event     — a JSON object carrying a *detached* Ed25519 signature
                     computed over the JCS (RFC 8785) canonicalization of the
                     event body with the `sig` field removed. The signed body
                     carries **digests, not raw data** [TAP-EVT-ENVELOPE, §6.1];
                     the human-readable plaintext travels in a separate,
                     redactable **annex** [TAP-EVT-ANNEX, §6.1.1].

This file is normative-by-example: any conforming implementation MUST reproduce
the signatures in test-vectors.json byte-for-byte from the fixed seed below.

Section references use the stable anchor tags defined in TAP-spec-v0.1.md
(`[TAP-…]`), with the current section number alongside. Cite the tag: section
numbers move, tags do not.

The published vectors exercise:
  * the digests-only envelope                    [TAP-EVT-ENVELOPE, §6.1]
  * a decision event with string scores          [TAP-EVT-DECISION, §6.4]
                                                 [TAP-CANON-NUMBERS, §3.4]
  * checkpoint Merkle reconciliation             [TAP-EVT-CHECKPOINT, §6.3]
  * Unicode / escaping canonicalization torture  [TAP-CANON-JCS, §3.4]
  * a `negative` section of records a conforming
    verifier MUST reject or flag                 [TAP-CONFORMANCE, §14]
"""
import json, base64, datetime, hashlib, pathlib, secrets
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
    body when the plaintext itself lives in the redactable annex
    [TAP-EVT-ANNEX, §6.1.1]."""
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

# ---------- checkpoint Merkle [TAP-EVT-CHECKPOINT, §6.3] ----------
# NOTE: TAP's checkpoint Merkle profile is deliberately NOT the profile a
# transparency log uses. Transparency-log profiles (RFC 6962 and friends) hash
# whole canonical records as leaves and DUPLICATE a lone odd node; the checkpoint
# profile hashes `event_id`s and PROMOTES an odd node unchanged. A deployment
# that anchors checkpoint roots into a transparency log therefore runs two
# distinct Merkle constructions and must not share code between them.

_CKPT_LEAF = b"\x00"
_CKPT_NODE = b"\x01"

def _ckpt_leaf(event_id: str) -> bytes:
    return hashlib.sha256(_CKPT_LEAF + event_id.encode("utf-8")).digest()

def _ckpt_node(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(_CKPT_NODE + left + right).digest()

def checkpoint_root(event_ids: list[str]) -> str:
    """Merkle root over the `event_id`s a checkpoint seals — the half-open interval
    `(from_seq, through_seq]`, ordered by seq ascending by the caller
    [TAP-EVT-CHECKPOINT, §6.3].
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
    """Optional epoch-seconds revocation boundary for a key [TAP-KEY-REVOCATION, §3.2]."""
    ra = jwk.get("revoked_at")
    return int(ra) if ra is not None else None

def parse_ts(ts: str) -> int:
    """RFC 3339 UTC timestamp -> epoch seconds. Raises on anything unparseable."""
    return int(datetime.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp())

def check_not_revoked(jwk: dict, signed_at: str | int | None) -> None:
    """Enforce the key's revocation boundary against the record's own timestamp
    [TAP-KEY-REVOCATION, §3.2]: a record signed at or after `revoked_at` is invalid.

    `signed_at` is the Event's `ts` (RFC 3339) or the Passport's `iat` (epoch s) —
    both live INSIDE the signed body, so an attacker cannot backdate one without
    breaking the signature. That is what makes this check meaningful before the
    signature has been verified.

    A record whose timestamp is missing or unparseable while the key IS revoked is
    rejected: it cannot prove it predates the revocation, and evidence that cannot
    prove its own effective time is not evidence."""
    revoked = key_revoked_at(jwk)
    if revoked is None:
        return
    if signed_at is None:
        raise ValueError("key is revoked and the record carries no timestamp to place it")
    try:
        at = signed_at if isinstance(signed_at, int) else parse_ts(signed_at)
    except Exception as exc:
        raise ValueError(f"key is revoked and the record timestamp is unparseable: {exc}")
    if at >= revoked:
        raise ValueError(f"key revoked at {revoked}; record is timestamped {at}")

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
    check_not_revoked(jwk, claims.get("iat"))
    # Freshness with the ±60 s skew allowance of [TAP-PASSPORT-VALIDATE, §5.3].
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
    """Verify one Event [TAP-EVT-VERIFY, §6.5]: resolve the suite, enforce the key's
    revocation boundary against the Event's own signed `ts`, then check the
    detached signature over JCS(body without `sig`)."""
    suite_for_jwk(jwk)  # dispatch off the declared suite; raises on unknown
    check_not_revoked(jwk, event.get("ts"))
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
        # A neutral example issuer on purpose: the conformance contract must not
        # bake in any one operator's hostname.
        "iss": "https://verifier.example.com",
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

    # ----- checkpoint event [TAP-EVT-CHECKPOINT, §6.3] -----
    # The interval is HALF-OPEN and SELF-DESCRIBING: (from_seq, through_seq].
    # `from_seq` is what lets a verifier reconcile a checkpoint on its own,
    # without reconstructing the state of whichever earlier checkpoint it
    # succeeds — and without silently mis-scoping the interval when an earlier
    # checkpoint never arrived. It is 0 for the first checkpoint of a record.
    # Here: (6, 8] seals exactly the tool_call (seq 7) and decision (seq 8).
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
        "checkpoint": {"from_seq": 6, "through_seq": 8,
                       "event_id_root": event_id_root, "count": 2},
        "result": {"status": "success", "code": "OK", "latency_ms": 1, "error": None},
        "attestor": "agent",
        "kid": KID,
    }
    ckpt_event = sign_event(sk, ckpt_body)

    # ----- canonicalization torture event [TAP-CANON-JCS, §3.4] -----
    # Every other vector is pure ASCII, which leaves the hardest half of RFC 8785
    # untested: string escaping, non-BMP characters, and member ordering, which JCS
    # defines over UTF-16 code units rather than code points or bytes. Two
    # implementations can agree perfectly on ASCII and still diverge here, and a
    # divergence means a Signer and a Verifier disagree about what was signed —
    # the one failure mode TAP exists to prevent. So the contract exercises it.
    #
    # Every non-ASCII character below is written as an explicit \u escape. A
    # conformance vector whose meaning depends on this file's encoding, or on a
    # reader spotting a combining mark by eye, is not a contract.
    EVT_CANON = "evt_01JABCDEFGHJKMNPQRSTVWXYZ3"

    # `action.tool` is one of the few literal (non-digest) strings in a signed body,
    # so it carries the string-escaping cases: a combining mark, a non-BMP character
    # that UTF-16 must represent as a surrogate pair, the two characters JCS escapes
    # with a backslash, and a C0 control that JCS emits in short \u form.
    canon_tool = (
        "tool_nai\u0308ve"        # 'i' + COMBINING DIAERESIS — decomposed, NOT precomposed
        "_\U0001f511"             # U+1F511 KEY: surrogate pair in UTF-16
        "_\"quoted\""            # JCS escapes the quote
        "_back\\slash"           # ... and the backslash
        "_\u0007bell"             # C0 control
    )

    # Member-ordering torture, digested through JCS so the ordering IS part of the
    # signed bytes. JCS sorts members by UTF-16 code unit: the empty key sorts first,
    # ASCII sorts below non-ASCII, and a non-BMP key sorts by its LEADING SURROGATE
    # (U+D83D) — which places it BELOW U+FB03, even though its code point is far
    # above. That is the case where sorting by code point, the obvious
    # implementation, silently disagrees with the spec.
    canon_args = {
        "\U0001f511": "non-BMP key: orders by leading surrogate U+D83D, not code point",
        "\ufb03": "U+FB03 orders ABOVE the surrogate pair under UTF-16 ordering",
        "z": "plain ascii",
        "a": "plain ascii",
        "": "the empty key is legal JSON and sorts first",
        "e\u0301": "NFD: 'e' + COMBINING ACUTE",
        "\u00e9": "NFC: precomposed U+00E9 — a DIFFERENT key; JCS does not normalize",
        "nul\u0000inside": "a NUL inside a key is legal JSON",
        "tab\tnewline\n": "escapes JCS emits in short form",
    }
    canon_reasoning = (
        "Mixed scripts and directions: \u0645\u0631\u062d\u0628\u0627 (Arabic, RTL), "
        "\u3053\u3093\u306b\u3061\u306f (Japanese), "
        "\U0001f9ea\U0001f512 (two non-BMP characters), "
        "a zero-width joiner \u200d, a no-break space \u00a0, "
        "and a right-to-left override \u202e."
    )
    canon_body = {
        "v": "tap/0.1",
        "event_id": EVT_CANON,
        "passport_jti": JTI,
        "aid": AID,
        "cid": cid,
        "seq": 10,
        "ts": "2026-01-01T00:03:13.117Z",
        "action": {
            "kind": "tool_call",
            "intent_digest": text_digest(canon_reasoning),
            "tool": canon_tool,
            "scope_used": "call:tool",
            "args_digest": json_digest(canon_args),
        },
        "evidence": {"reasoning_digest": text_digest(canon_reasoning)},
        "result": {"status": "success", "code": "OK", "latency_ms": 7, "error": None},
        "attestor": "agent",
        "action_ref": "act_01JABCDEF4444444444444444",
        "kid": KID,
    }
    canon_event = sign_event(sk, canon_body)
    canon_annex = {
        "event_id": EVT_CANON,
        "intent": canon_reasoning,
        "args_preview": canon_args,
        "reasoning": canon_reasoning,
    }

    # ----- negative cases [TAP-CONFORMANCE, §14] -----
    # Reproduction alone is a weak contract: it proves an implementation can SIGN
    # like the reference, not that it REJECTS what the reference rejects. Most of
    # §13 is about rejection, so the vectors carry rejection cases too, each with a
    # machine-readable `expect` so a conformance suite can iterate rather than
    # hand-roll one assertion per case.
    #
    # `expect: "reject"`  — verification MUST fail.
    # `expect: "flag"`    — the record verifies cryptographically but MUST be
    #                       surfaced as an integrity signal, never silently accepted.

    # A validly-signed passport whose header `typ` is a plain JWT — the RFC 8725
    # token-confusion case [TAP-PASSPORT-HEADER, §5.1].
    wrong_typ_header = {"alg": "EdDSA", "typ": "JWT", "kid": KID}
    _seg = (b64u(json.dumps(wrong_typ_header, separators=(",", ":")).encode()) + "." +
            b64u(json.dumps(passport_claims, separators=(",", ":")).encode()))
    wrong_typ_passport = _seg + "." + b64u(sk.sign(_seg.encode("ascii")))

    # The reference tool_call, re-signed with absent optionals spelled as explicit
    # nulls. It verifies against its OWN signature — that is the whole problem. Two
    # conforming Signers describing the identical action would produce different
    # signed bytes, so their checkpoints would disagree while every individual
    # signature checked out. Only the omit rule [TAP-EVT-OMIT, §6.1] catches it, and
    # only a vector makes the rule testable.
    explicit_nulls_body = {k: v for k, v in tool_event.items() if k != "sig"}
    explicit_nulls_body["parent_event_id"] = None
    explicit_nulls_body["policy_decision"] = None
    explicit_nulls_event = sign_event(sk, explicit_nulls_body)

    # Two events claiming the same (aid, seq) with different content, both validly
    # signed — the replay/tamper indicator of [TAP-EVT-SEQ, §6.3].
    dup_seq_body = {k: v for k, v in tool_event.items() if k != "sig"}
    dup_seq_body["event_id"] = "evt_01JABCDEFGHJKMNPQRSTVWXYZ9"
    dup_seq_body["action"] = {**tool_event["action"], "tool": "db_delete"}
    dup_seq_event = sign_event(sk, dup_seq_body)

    # A checkpoint that commits to only ONE of the two events actually delivered in
    # its interval. The signature is valid; the reconciliation is not. The missing
    # id is provable suppression, not benign loss.
    short_root = checkpoint_root([EVT_TOOL])
    short_ckpt_body = {k: v for k, v in ckpt_event.items() if k != "sig"}
    short_ckpt_body["event_id"] = "evt_01JABCDEFGHJKMNPQRSTVWXYZ8"
    short_ckpt_body["checkpoint"] = {"from_seq": 6, "through_seq": 8,
                                     "event_id_root": short_root, "count": 1}
    short_ckpt_event = sign_event(sk, short_ckpt_body)

    negative = {
        "_about": (
            "Records a conforming implementation MUST reject (expect:'reject') or "
            "MUST surface as an integrity signal (expect:'flag'). Reproducing the "
            "positive vectors proves an implementation can sign; these prove it "
            "refuses what the reference refuses."
        ),
        "unknown_suite_rs256": {
            "expect": "reject",
            "reason": "verification MUST dispatch off the key's declared suite and "
                      "reject an unrecognized one, never fall back to a default",
            "spec": "[TAP-SUITE-DISPATCH, §3.6]",
            "jwk": {**jwk, "alg": "RS256", "crv": "P-256"},
            "event": tool_event,
        },
        "unknown_suite_alg_none": {
            "expect": "reject",
            "reason": "`alg: none` MUST NOT be accepted",
            "spec": "[TAP-SIG-ALG, §3.1]",
            "jwk": {**jwk, "alg": "none"},
            "event": tool_event,
        },
        "passport_wrong_typ": {
            "expect": "reject",
            "reason": "explicit `typ` of tap-passport+jwt is REQUIRED; any other "
                      "type MUST be rejected (token confusion)",
            "spec": "[TAP-PASSPORT-HEADER, §5.1]",
            "jwk": jwk,
            "compact_jwt": wrong_typ_passport,
        },
        "event_signed_after_revocation": {
            "expect": "reject",
            "reason": "the key's revoked_at is at or before the event's own signed "
                      "ts, so the record falls outside the key's effective window",
            "spec": "[TAP-KEY-REVOCATION, §3.2]",
            "jwk": {**jwk, "revoked_at": parse_ts(tool_event["ts"]) - 1},
            "event": tool_event,
        },
        "event_before_revocation_still_valid": {
            "expect": "accept",
            "reason": "revocation is an effective-time boundary, not all-or-nothing "
                      "repudiation: records signed before it remain valid",
            "spec": "[TAP-KEY-REVOCATION, §3.2]",
            "jwk": {**jwk, "revoked_at": parse_ts(tool_event["ts"]) + 3600},
            "event": tool_event,
        },
        "tampered_event": {
            "expect": "reject",
            "reason": "any change to any signed field MUST invalidate the signature",
            "spec": "[TAP-EVT-VERIFY, §6.5]",
            "jwk": jwk,
            "event": {**tool_event,
                      "action": {**tool_event["action"], "tool": "drop_table"}},
        },
        "explicit_nulls_non_conforming": {
            "expect": "flag",
            "reason": "absent optional fields MUST be omitted, not sent as null; "
                      "this record is self-consistently signed but structurally "
                      "divergent, so its signing input differs from the reference "
                      "for a logically identical action",
            "spec": "[TAP-EVT-OMIT, §6.1]",
            "jwk": jwk,
            "event": explicit_nulls_event,
            "reference_event_id": EVT_TOOL,
            "diverges_on": ["parent_event_id", "policy_decision"],
            "canonical_signing_input_sha256":
                hashlib.sha256(signing_input(explicit_nulls_event)).hexdigest(),
        },
        "duplicate_aid_seq": {
            "expect": "flag",
            "reason": "a duplicate (aid, seq) carrying different content is a "
                      "tamper/replay indicator; both signatures verify, which is "
                      "exactly why the verifier must check sequence integrity too",
            "spec": "[TAP-EVT-SEQ, §6.3]",
            "jwk": jwk,
            "events": [tool_event, dup_seq_event],
        },
        "checkpoint_omits_delivered_event": {
            "expect": "flag",
            "reason": "the checkpoint's Merkle root commits to fewer event_ids than "
                      "were delivered in its interval; recomputing the root over the "
                      "delivered ids MUST mismatch and MUST be surfaced",
            "spec": "[TAP-EVT-CHECKPOINT, §6.3]",
            "jwk": jwk,
            "event": short_ckpt_event,
            "delivered_event_ids": sealed_ids,
            "committed_event_ids": [EVT_TOOL],
        },
    }

    # ----- self-checks -----
    # Everything the vectors assert about themselves is checked here first, so a
    # broken contract fails at generation time rather than in someone else's CI.
    assert verify_passport(jwk, passport, now=1767225601)
    for ev in (tool_event, dec_event, ckpt_event, canon_event):
        assert verify_event(jwk, ev)

    # digests-only: the plaintext is NOT in the signed body [TAP-EVT-ENVELOPE, §6.1]
    assert "intent" not in tool_event["action"] and "args_preview" not in tool_event["action"]
    assert "reasoning" not in tool_event["evidence"]

    # annex plaintext verifies against the signed digests [TAP-EVT-ANNEX, §6.1.1]
    assert text_digest(tool_annex["intent"]) == tool_event["action"]["intent_digest"]
    assert json_digest(tool_annex["args_preview"]) == tool_event["action"]["args_digest"]
    assert text_digest(canon_annex["reasoning"]) == canon_event["evidence"]["reasoning_digest"]
    assert json_digest(canon_annex["args_preview"]) == canon_event["action"]["args_digest"]

    # absent optionals are OMITTED, never null [TAP-EVT-OMIT, §6.1]
    for ev in (tool_event, dec_event, ckpt_event, canon_event):
        for absent in ("parent_event_id", "policy_decision"):
            assert absent not in ev, f"{absent} must be omitted when absent, not null"

    # the no-fractional-numbers rule is enforced [TAP-CANON-NUMBERS, §3.4]
    for bad in ({"score": 0.71}, {"n": 2**53}):
        try:
            canonical_guard(bad); raise SystemExit(f"FAIL: {bad} not rejected")
        except CanonicalizationError:
            pass

    # the checkpoint's interval is self-describing and its root reconciles
    ck = ckpt_event["checkpoint"]
    assert ck["from_seq"] == 6 and ck["through_seq"] == 8
    assert ck["count"] == len(sealed_ids) == 2
    assert [e["seq"] for e in (tool_event, dec_event)] == [7, 8], "sealed events must lie in (6, 8]"
    assert checkpoint_root(sealed_ids) == ck["event_id_root"]
    assert checkpoint_root([]) == digest(b"")

    # UTF-16 member ordering: the non-BMP key orders by its LEADING SURROGATE, so it
    # sorts BELOW U+FB03 despite the far larger code point. Sorting by code point —
    # the obvious implementation — gets this backwards, and would silently produce
    # different signed bytes.
    canon_keys = json.loads(jcs.canonicalize(canon_args).decode("utf-8")).keys()
    order = list(canon_keys)
    assert order[0] == "", "the empty key sorts first"
    assert order.index("\U0001f511") < order.index("\ufb03"), \
        "non-BMP key must order by leading surrogate, below U+FB03"
    assert order.index("e\u0301") != order.index("\u00e9"), \
        "JCS must not normalize: NFD and NFC are distinct members"

    # every negative case behaves as its `expect` says
    for name, case in negative.items():
        if name.startswith("_"):
            continue
        expect = case["expect"]
        if "compact_jwt" in case:
            attempt = lambda: verify_passport(case["jwk"], case["compact_jwt"], now=1767225601)
        elif "event" in case:
            attempt = lambda: verify_event(case["jwk"], case["event"])
        else:
            # multi-record cases (duplicate seq) verify individually by design —
            # the signal is sequence integrity, which lives above verify_event.
            for ev in case["events"]:
                assert verify_event(case["jwk"], ev)
            continue
        if expect == "reject":
            try:
                attempt(); raise SystemExit(f"FAIL: negative case {name!r} was accepted")
            except SystemExit:
                raise
            except Exception:
                pass
        else:
            # "accept" and "flag" cases are cryptographically valid on purpose; a
            # "flag" is a signal a verifier raises ABOVE the signature check.
            assert attempt(), f"negative case {name!r} should verify but did not"

    # the explicit-nulls case really does diverge structurally from the reference,
    # while remaining validly signed — which is why prose, not crypto, has to catch it
    assert (negative["explicit_nulls_non_conforming"]["canonical_signing_input_sha256"]
            != hashlib.sha256(signing_input(tool_event)).hexdigest())

    # the short checkpoint really does fail reconciliation
    assert checkpoint_root(sealed_ids) != short_ckpt_event["checkpoint"]["event_id_root"]

    vectors = {
        "_about": (
            "TAP v0.1 conformance vectors. Reproduce byte-for-byte from the seed. "
            "Generated by tap_ref.py — do not hand-edit."
        ),
        "_spec_version": "0.1.2",
        "_wire_version": "tap/0.1",
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
                "from_seq": ck["from_seq"],
                "through_seq": ck["through_seq"],
                "event_ids": sealed_ids,
                "event_id_root": event_id_root,
                "empty_interval_root": checkpoint_root([]),
                "_note": "root commits to event_ids in the half-open interval "
                         "(from_seq, through_seq], ordered by seq ascending",
            },
        },
        "canonicalization": {
            "_about": (
                "RFC 8785 string escaping, non-BMP characters, and UTF-16 member "
                "ordering. An implementation that reproduces every other vector and "
                "fails this one does not agree with the reference on what was signed."
            ),
            "canonical_signing_input_sha256":
                hashlib.sha256(signing_input(canon_event)).hexdigest(),
            "signed_event": canon_event,
            "annex": canon_annex,
            "member_ordering": {
                "args": canon_args,
                "jcs_member_order": order,
                "args_digest": canon_event["action"]["args_digest"],
                "_note": "JCS orders members by UTF-16 code unit, so a non-BMP key "
                         "orders by its leading surrogate (U+D83D) and therefore "
                         "sorts BELOW U+FB03 despite the larger code point",
            },
        },
        "negative": negative,
        "tamper_check": "verify_event MUST reject when any signed field changes",
    }
    # Always write next to this file, never to the caller's cwd — running the
    # generator from a parent directory used to leave a second, stale copy of
    # the conformance contract lying around.
    #
    # ensure_ascii=True on purpose: the vectors file stays pure ASCII, so the
    # canonicalization cases survive any transport, editor, or terminal that would
    # otherwise mangle them. The \u escapes ARE the contract.
    out_path = pathlib.Path(__file__).resolve().parent / "test-vectors.json"
    with open(out_path, "w", encoding="ascii") as f:
        json.dump(vectors, f, indent=2, ensure_ascii=True)

    print("JWK (public):", json.dumps(jwk))
    print("\nPASSPORT (compact JWT):\n", passport)
    for label, ev in (("TOOL_CALL", tool_event), ("DECISION", dec_event),
                      ("CHECKPOINT", ckpt_event), ("CANONICALIZATION", canon_event)):
        print(f"\n{label} canonical signing-input SHA-256:\n",
              hashlib.sha256(signing_input(ev)).hexdigest())
    print("\nCHECKPOINT event_id_root:\n", event_id_root)
    print(f"\nnegative cases: {len([k for k in negative if not k.startswith('_')])}")
    print("\nAll self-checks passed: passport ✓  tool_call ✓  decision ✓  checkpoint ✓  "
          "canonicalization ✓  omit-nulls ✓  guard ✓  suite ✓  revocation ✓  negatives ✓")
