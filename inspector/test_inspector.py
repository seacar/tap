#!/usr/bin/env python3
"""The Inspector's shared logic layer works, and wraps the SDK rather than
re-implementing it.

A local debugging tool that verifies *differently* from the SDK teaches you about
the tool instead of about your records — the one thing an inspector must never do.
So the point of these tests is less "the CLI runs" than "what the Inspector says
about a record is what a Verifier would say".

Run:  python inspector/test_inspector.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))
sys.path.insert(0, str(REPO))

import json  # noqa: E402

from inspector import core  # noqa: E402
from tap_sdk.core import verify_event, verify_passport  # noqa: E402


def _identity_and_passport():
    identity = core.generate_key()
    passport = core.mint_passport(
        private_key_hex=identity["private_key_hex"], kid=identity["kid"],
        task_prompt="inspect me", scope=["read:database"],
    )
    return identity, passport


def _sign_one(identity, passport) -> dict:
    return core.sign_event_for_passport(
        private_key_hex=identity["private_key_hex"], kid=identity["kid"], passport=passport,
        kind="tool_call", intent="Call db_query", tool="db_query",
        scope_used="read:database", args={"table": "users"},
    )


def test_generate_key_produces_a_usable_identity() -> None:
    identity = core.generate_key()
    jwk = identity["public_jwk"]
    assert jwk["kty"] == "OKP" and jwk["crv"] == "Ed25519" and jwk["alg"] == "EdDSA"
    assert len(bytes.fromhex(identity["private_key_hex"])) == 32, "a 32-byte Ed25519 seed"
    assert jwk["kid"] == identity["kid"]


def test_minted_passport_verifies_with_the_sdk() -> None:
    """Not "the Inspector accepts its own output" — the SDK primitive accepts it."""
    identity, passport = _identity_and_passport()
    claims = verify_passport(identity["public_jwk"], passport.compact,
                             now=passport.claims["iat"] + 1)
    assert claims["scope"] == ["read:database"]
    assert claims["cid"] == passport.claims["cid"]


def test_signed_event_verifies_and_carries_no_plaintext() -> None:
    identity, passport = _identity_and_passport()
    event = _sign_one(identity, passport)
    assert verify_event(identity["public_jwk"], event)
    # Digest-only body [TAP-EVT-ENVELOPE]: the plaintext belongs in the annex.
    assert "intent" not in event["action"] and "intent_digest" in event["action"]
    for absent in ("parent_event_id", "policy_decision"):
        assert absent not in event, f"{absent} must be omitted when absent, not null"


def test_tampering_is_reported_as_invalid() -> None:
    """The single most important thing an inspector can tell you."""
    identity, passport = _identity_and_passport()
    event = _sign_one(identity, passport)
    tampered = {**event, "action": {**event["action"], "tool": "drop_table"}}
    try:
        verify_event(identity["public_jwk"], tampered)
    except Exception:
        return
    raise AssertionError("a tampered event must not verify")


def test_verify_agrees_with_the_sdk_on_a_local_record() -> None:
    """The Inspector's own `verify` path must reach the same verdict as the SDK."""
    identity, passport = _identity_and_passport()
    event = _sign_one(identity, passport)
    jwks_source = json.dumps({"keys": [identity["public_jwk"]]})

    report = core.verify(jwks_source=jwks_source, passport_compact=passport.compact,
                         events=[event])
    assert report["passport"]["valid"], report
    assert report["events"]["invalid_sig"] == 0, report


def test_authority_binding_is_surfaced_read_only() -> None:
    """[TAP-EVT-AUTHORIZATION / TAP-AUTHORITY-EFFECT, §9.2, provisional]: the
    Inspector displays the bound approval and its effect label — display only,
    no enforcement (revocation/reuse are surfaced by tap_sdk.verify, not
    independently checked here — see the next test)."""
    vectors = json.loads((REPO / "test-vectors.json").read_text(encoding="utf-8"))
    av = vectors["authorization"]
    resolve_key = {k["kid"]: k for k in vectors["jwks"]["keys"]}.get

    record = core.build_record_from_local(
        passport_claims=None, events=[av["signed_event"]], resolve_key=resolve_key,
    )
    ev = record["events"][0]
    assert ev["sig_valid"], record
    assert ev["authorization"]["authz_id"] == av["signed_event"]["authorization"]["authz_id"]
    assert ev["authority_effect"] == "authorized_match"

    from tap_sdk import verify as V
    rendered = core.render_chain_ascii(V.annotate_assurance(record))
    assert av["signed_event"]["authorization"]["authz_id"] in rendered
    assert "authority_effect=authorized_match" in rendered


def test_authority_revocation_is_surfaced_via_a_supplied_resolver() -> None:
    """[TAP-AUTHORITY-REVOKE, §9.2, provisional]: `make_revocation_resolver`
    loads a local {id: revoked_at} map (a debugging convenience, not a
    registry this tool operates) and `build_record_from_local` wires it in."""
    vectors = json.loads((REPO / "test-vectors.json").read_text(encoding="utf-8"))
    av = vectors["authorization"]
    authz_id = av["signed_event"]["authorization"]["authz_id"]
    resolve_key = {k["kid"]: k for k in vectors["jwks"]["keys"]}.get

    # No resolver: not flagged.
    record = core.build_record_from_local(
        passport_claims=None, events=[av["signed_event"]], resolve_key=resolve_key,
    )
    assert record["events"][0]["authority_revoked"] is False

    # A resolver revoking this authz_id in the deep past (well before the
    # vector's own signed `ts`): flagged, and rendered.
    revoke_source = json.dumps({authz_id: 1})
    resolve_authority_revocation = core.make_revocation_resolver(revoke_source)
    record = core.build_record_from_local(
        passport_claims=None, events=[av["signed_event"]], resolve_key=resolve_key,
        resolve_authority_revocation=resolve_authority_revocation,
    )
    ev = record["events"][0]
    assert ev["sig_valid"], record
    assert ev["authority_revoked"] is True

    from tap_sdk import verify as V
    rendered = core.render_chain_ascii(V.annotate_assurance(record))
    assert "REVOKED" in rendered


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# Inspector agrees with the SDK it wraps ✓")


if __name__ == "__main__":
    main()
