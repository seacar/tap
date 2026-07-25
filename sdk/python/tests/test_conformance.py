#!/usr/bin/env python3
"""The TAPClient Python SDK reproduces the TAP conformance vectors byte-for-byte.

This is what makes the standalone SDK interoperable with the reference impl and
the JS SDK. Run:  python -m pytest  (or)  python tests/test_conformance.py
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk.core import (  # noqa: E402
    load_signer, sign_event, sign_passport, signing_input, verify_event, verify_passport,
)

# Locate test-vectors.json at the repo root (sdk/python/tests -> repo root).
VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors.json").read_text()
)


def main() -> None:
    seed = VECTORS["ed25519_private_seed_hex"]
    kid = VECTORS["jwks"]["keys"][0]["kid"]
    jwk = VECTORS["jwks"]["keys"][0]
    sk = load_signer(seed)
    n = 0
    print("TAP version 13"); print("1..4")

    # 1. passport reproduces
    n += 1
    got = sign_passport(sk, kid, VECTORS["passport"]["claims"])
    assert got == VECTORS["passport"]["compact_jwt"], "passport mismatch"
    print(f"ok {n} - passport reproduces reference vector")

    # 2. event signature reproduces
    n += 1
    signed = VECTORS["event"]["signed_event"]
    body = {k: v for k, v in signed.items() if k != "sig"}
    got_ev = sign_event(sk, body)
    assert got_ev["sig"] == signed["sig"], "event sig mismatch"
    assert hashlib.sha256(signing_input(signed)).hexdigest() == \
        VECTORS["event"]["canonical_signing_input_sha256"]
    print(f"ok {n} - event signature + JCS input reproduce reference vector")

    # 3. verify accepts reference records
    n += 1
    assert verify_passport(jwk, VECTORS["passport"]["compact_jwt"],
                           now=VECTORS["passport"]["claims"]["iat"] + 1)
    assert verify_event(jwk, signed)
    print(f"ok {n} - verifies reference passport + event")

    # 4. tamper rejected
    n += 1
    tampered = {**signed, "action": {**signed["action"], "tool": "drop_table"}}
    try:
        verify_event(jwk, tampered); raise AssertionError("tamper not detected")
    except AssertionError:
        raise
    except Exception:
        pass
    print(f"ok {n} - tamper rejected")
    print("# TAPClient Python SDK is TAP-conformant ✓")


if __name__ == "__main__":
    main()
