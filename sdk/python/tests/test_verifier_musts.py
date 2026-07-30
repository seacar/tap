#!/usr/bin/env python3
"""Verifier MUST-behaviours that are easy to regress.

These guard the checks a conforming verifier cannot skip, all of which are part
of verification itself rather than a layer above it:

  * suite dispatch [TAP-SUITE-DISPATCH] — resolve the key's declared suite and
    REJECT an unrecognized one rather than defaulting to Ed25519;
  * key revocation [TAP-KEY-REVOCATION] — reject records signed at or after the
    key's ``revoked_at``, for **events as well as passports**, and keep accepting
    records signed before it;
  * exact scope matching [TAP-SCOPE-MATCH] — no wildcards, no prefix rule.

Every one of these has been missing from some build of this SDK. Event
revocation in particular was enforced only in the higher-level ``verify`` module,
so anyone calling the documented ``verify_event`` primitive got no check at all.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk.core import (  # noqa: E402
    RevokedKey,
    UnknownSuite,
    key_revoked_at,
    load_signer,
    parse_ts,
    public_jwk,
    scope_satisfied,
    sign_event,
    sign_passport,
    suite_for_jwk,
    verify_event,
    verify_passport,
)

VECTORS = json.loads((Path(__file__).resolve().parents[3] / "test-vectors.json").read_text())
JWK = VECTORS["jwks"]["keys"][0]
EVENT = VECTORS["event"]["signed_event"]
PASSPORT = VECTORS["passport"]["compact_jwt"]
IAT = VECTORS["passport"]["claims"]["iat"]


def test_known_suite_resolves() -> None:
    assert suite_for_jwk(JWK) == "tap-ed25519"


def test_unknown_suite_rejected_not_defaulted() -> None:
    for bad in ({"alg": "RS256", "crv": "P-256"}, {"alg": "none", "crv": "Ed25519"},
                {"alg": "HS256", "crv": None}):
        hostile = {**JWK, **bad}
        for call in (lambda: verify_event(hostile, EVENT),
                     lambda: verify_passport(hostile, PASSPORT, now=IAT + 1)):
            try:
                call()
            except UnknownSuite:
                continue
            raise AssertionError(f"unknown suite {bad} was not rejected")


def test_revoked_key_rejects_passport() -> None:
    assert key_revoked_at(JWK) is None
    revoked = {**JWK, "revoked_at": IAT - 1}  # revoked before the passport was issued
    try:
        verify_passport(revoked, PASSPORT, now=IAT + 1)
    except RevokedKey:
        return
    raise AssertionError("passport signed by a revoked key was accepted")


def test_revoked_key_rejects_event() -> None:
    """The gap that mattered: revocation was enforced for passports only, so the
    documented event-verification primitive accepted records signed by a key its
    owner had already reported compromised."""
    event_ts = parse_ts(EVENT["ts"])
    revoked = {**JWK, "revoked_at": event_ts - 1}
    try:
        verify_event(revoked, EVENT)
    except RevokedKey:
        return
    raise AssertionError("event signed by a revoked key was accepted")


def test_revocation_is_a_boundary_not_blanket_repudiation() -> None:
    """Records signed BEFORE the boundary stay valid — otherwise revoking a key
    would retroactively destroy every record it ever signed, which is the
    opposite of what an evidence system should do."""
    event_ts = parse_ts(EVENT["ts"])
    still_ok_event = {**JWK, "revoked_at": event_ts + 3600}
    assert verify_event(still_ok_event, EVENT)
    still_ok_passport = {**JWK, "revoked_at": IAT + 10_000}
    assert verify_passport(still_ok_passport, PASSPORT, now=IAT + 1)


def test_untimestamped_record_under_revoked_key_rejected() -> None:
    """A record that cannot place itself in time cannot prove it predates the
    revocation, so it MUST NOT get the benefit of the doubt."""
    undated = {k: v for k, v in EVENT.items() if k != "ts"}
    try:
        verify_event({**JWK, "revoked_at": IAT}, undated)
    except RevokedKey:
        return
    raise AssertionError("undated record under a revoked key was accepted")


def test_scope_matching_is_exact() -> None:
    """[TAP-SCOPE-MATCH]: exact string equality, no wildcards or prefixes. A
    looser rule here would be privilege escalation in the one check TAP makes."""
    granted = ["read:database", "call:tool"]
    assert scope_satisfied("read:database", granted)
    assert scope_satisfied(None, granted)          # action exercises no scope
    for denied in ("read:*", "*", "read:database.users", "READ:DATABASE",
                   "read:", "read:databas"):
        assert not scope_satisfied(denied, granted), f"{denied!r} must not match"


def test_round_trip_signing_still_works() -> None:
    sk = load_signer(VECTORS["ed25519_private_seed_hex"])
    jwk = public_jwk(sk, "key_roundtrip")
    body = {"v": "tap/0.1", "event_id": "evt_x", "seq": 1, "kid": "key_roundtrip"}
    assert verify_event(jwk, sign_event(sk, body))
    claims = {"iss": "https://verifier.example.com", "iat": IAT, "exp": IAT + 60,
              "jti": "psp_x", "aid": "agt_x", "cid": "sha256:00", "scope": []}
    assert verify_passport(jwk, sign_passport(sk, "key_roundtrip", claims), now=IAT + 1)


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# verifier MUST-behaviours enforced \u2713")


if __name__ == "__main__":
    main()
