#!/usr/bin/env python3
"""Verifier MUST-behaviours that are easy to regress (spec §3.2, §3.6, §15).

These guard the two checks a conforming verifier cannot skip:

  * algorithm-driven dispatch — resolve the key's declared suite and REJECT an
    unrecognized one rather than defaulting to Ed25519;
  * key revocation — reject records signed at or after the key's ``revoked_at``.

Both are MUST in the spec and both were missing from an earlier build of the
SDK core while the reference implementation had them.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk.core import (  # noqa: E402
    UnknownSuite,
    key_revoked_at,
    load_signer,
    public_jwk,
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


def test_revoked_key_rejected() -> None:
    assert key_revoked_at(JWK) is None
    revoked = {**JWK, "revoked_at": IAT - 1}  # revoked before the passport was issued
    try:
        verify_passport(revoked, PASSPORT, now=IAT + 1)
    except AssertionError:
        return
    raise AssertionError("passport signed by a revoked key was accepted")


def test_key_valid_before_revocation_still_verifies() -> None:
    still_ok = {**JWK, "revoked_at": IAT + 10_000}
    assert verify_passport(still_ok, PASSPORT, now=IAT + 1)


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
