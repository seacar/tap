#!/usr/bin/env python3
"""The Python SDK reproduces the TAP conformance vectors byte-for-byte.

This is what makes a standalone SDK interoperable with the reference
implementation and with the TypeScript SDK. Every published vector is exercised,
not just the headline one: `[TAP-CONFORMANCE]` makes the fractional-score
decision case, the checkpoint Merkle case and the canonicalization case
mandatory, and for a while this suite checked none of them — it asserted four
things about a passport and one `tool_call` and declared conformance.

Rejection behaviour lives in `test_negative_vectors.py`. Both halves count.

Run:  python tests/test_conformance.py
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk.core import (  # noqa: E402
    checkpoint_root,
    digest,
    json_digest,
    load_signer,
    sign_event,
    sign_passport,
    signing_input,
    text_digest,
    verify_event,
    verify_passport,
)

# Locate test-vectors.json at the repo root (sdk/python/tests -> repo root).
VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors.json").read_text(encoding="utf-8")
)

SIGNED_CASES = ("event", "decision", "checkpoint", "canonicalization")


def main() -> None:
    seed = VECTORS["ed25519_private_seed_hex"]
    jwk = VECTORS["jwks"]["keys"][0]
    kid = jwk["kid"]
    sk = load_signer(seed)
    n = 0
    # "TAP version 13" is the Test Anything Protocol header — an unrelated TAP.
    print("TAP version 13")
    print("1..8")

    # 1. passport reproduces byte-for-byte
    n += 1
    got = sign_passport(sk, kid, VECTORS["passport"]["claims"])
    assert got == VECTORS["passport"]["compact_jwt"], "passport mismatch"
    print(f"ok {n} - passport reproduces reference vector")

    # 2. every signed case reproduces its signature AND its JCS signing input
    n += 1
    for case in SIGNED_CASES:
        signed = VECTORS[case]["signed_event"]
        body = {k: v for k, v in signed.items() if k != "sig"}
        assert sign_event(sk, body)["sig"] == signed["sig"], f"{case}: sig mismatch"
        assert (hashlib.sha256(signing_input(signed)).hexdigest()
                == VECTORS[case]["canonical_signing_input_sha256"]), f"{case}: JCS input mismatch"
    print(f"ok {n} - all {len(SIGNED_CASES)} signed cases reproduce sig + JCS input")

    # 3. verification accepts every reference record
    n += 1
    assert verify_passport(jwk, VECTORS["passport"]["compact_jwt"],
                           now=VECTORS["passport"]["claims"]["iat"] + 1)
    for case in SIGNED_CASES:
        assert verify_event(jwk, VECTORS[case]["signed_event"]), case
    print(f"ok {n} - verifies reference passport + every reference event")

    # 4. tamper on any signed field is rejected
    n += 1
    signed = VECTORS["event"]["signed_event"]
    tampered = {**signed, "action": {**signed["action"], "tool": "drop_table"}}
    try:
        verify_event(jwk, tampered)
        raise AssertionError("tamper not detected")
    except AssertionError:
        raise
    except Exception:
        pass
    print(f"ok {n} - tamper rejected")

    # 5. the fractional-score rule [TAP-CANON-NUMBERS]: scores are STRINGS, and
    #    no number anywhere in a signed body has a fractional part
    n += 1
    dec = VECTORS["decision"]["signed_event"]["decision"]
    for opt in dec["options"]:
        assert isinstance(opt.get("score"), str), f"score must be a string, got {opt.get('score')!r}"
    _assert_no_floats(VECTORS["decision"]["signed_event"])
    chosen = [o for o in dec["options"] if o.get("chosen")]
    assert len(chosen) == 1 and chosen[0]["id"] == dec["chosen"], \
        "exactly one option is chosen and decision.chosen names it"
    print(f"ok {n} - decision: string scores, no fractional numbers, one chosen option")

    # 6. checkpoint Merkle reconciliation [TAP-EVT-CHECKPOINT] — the construction
    #    the whole fail-open story rests on, and previously never tested
    n += 1
    rec = VECTORS["checkpoint"]["reconciliation"]
    cp = VECTORS["checkpoint"]["signed_event"]["checkpoint"]
    assert checkpoint_root(rec["event_ids"]) == rec["event_id_root"] == cp["event_id_root"], \
        "recomputed Merkle root must match the signed root"
    assert checkpoint_root([]) == rec["empty_interval_root"] == digest(b""), \
        "the empty interval has a defined root"
    assert cp["from_seq"] == rec["from_seq"] and cp["through_seq"] == rec["through_seq"], \
        "the sealed interval is self-describing"
    assert cp["count"] == len(rec["event_ids"]), "count must equal the committed leaf count"
    # order matters: reversing the leaves must change the root
    assert checkpoint_root(list(reversed(rec["event_ids"]))) != rec["event_id_root"], \
        "leaf order is part of the commitment"
    print(f"ok {n} - checkpoint Merkle root, empty interval, interval bounds, leaf order")

    # 7. canonicalization [TAP-CANON-JCS] — non-BMP characters, escaping, and
    #    UTF-16 member ordering. The half of RFC 8785 pure-ASCII vectors miss.
    n += 1
    canon = VECTORS["canonicalization"]
    order = canon["member_ordering"]["jcs_member_order"]
    args = canon["member_ordering"]["args"]
    assert json_digest(args) == canon["member_ordering"]["args_digest"], \
        "JCS digest over the torture object must match the reference"
    assert list(json.loads(__import__("jcs").canonicalize(args).decode("utf-8")).keys()) == order, \
        "JCS member ordering must match the reference ordering exactly"
    assert order[0] == "", "the empty key sorts first"
    assert order.index("\U0001f511") < order.index("\ufb03"), \
        "a non-BMP key orders by its leading surrogate, BELOW U+FB03"
    # Written as escapes: NFD ('e' + U+0301) and NFC (U+00E9) are DIFFERENT keys,
    # and a source file that shows them as two identical-looking glyphs proves
    # nothing. JCS does not normalize, so both must survive as distinct members.
    assert "e\u0301" in args and "\u00e9" in args, \
        "NFD and NFC keys must both survive as distinct members"
    assert args["e\u0301"] != args["\u00e9"], "the two are genuinely different entries"
    annex = canon["annex"]
    assert text_digest(annex["reasoning"]) == canon["signed_event"]["evidence"]["reasoning_digest"], \
        "UTF-8 digest of mixed-script plaintext must match across implementations"
    print(f"ok {n} - canonicalization: escaping, non-BMP, UTF-16 ordering, NFC/NFD")

    # 8. annex plaintext verifies against the signed digests [TAP-EVT-ANNEX], and
    #    no plaintext leaked into a signed body [TAP-EVT-ENVELOPE]
    n += 1
    ev = VECTORS["event"]
    assert text_digest(ev["annex"]["intent"]) == ev["signed_event"]["action"]["intent_digest"]
    assert json_digest(ev["annex"]["args_preview"]) == ev["signed_event"]["action"]["args_digest"]
    for case in SIGNED_CASES:
        body = VECTORS[case]["signed_event"]
        for forbidden in ("intent", "args", "args_preview", "reasoning"):
            assert forbidden not in body.get("action", {}), f"{case}: {forbidden} in signed action"
            assert forbidden not in body.get("evidence", {}), f"{case}: {forbidden} in signed evidence"
        # absent optionals are omitted, never null [TAP-EVT-OMIT]
        for absent in ("parent_event_id", "policy_decision"):
            assert absent not in body, f"{case}: {absent} present (must be omitted when absent)"
    print(f"ok {n} - annex digests verify; no plaintext and no explicit nulls in signed bodies")

    print("# Python SDK is TAP-conformant across every published vector ✓")


def _assert_no_floats(value, path: str = "") -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, float):
        raise AssertionError(f"fractional number in a signed body at {path}")
    if isinstance(value, dict):
        for k, v in value.items():
            _assert_no_floats(v, f"{path}.{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            _assert_no_floats(v, f"{path}[{i}]")


if __name__ == "__main__":
    main()
