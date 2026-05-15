#!/usr/bin/env python3
"""The `negative` half of the conformance contract [TAP-CONFORMANCE].

Reproducing the published signatures proves an implementation can *sign* like the
reference. It says nothing about whether it *refuses* what the reference refuses —
and a verifier that accepts everything reproduces every vector perfectly.

Each entry in `test-vectors.json -> negative` declares its own expected outcome,
so this file is a loop rather than a pile of hand-written cases, and adding a case
to the vectors automatically adds it here and to the TypeScript suite:

  expect: "reject"  — verification MUST fail
  expect: "accept"  — verification MUST succeed (revocation is a time boundary,
                      not blanket repudiation, and these cases pin that down)
  expect: "flag"    — the record is cryptographically valid and MUST still be
                      surfaced as an integrity or conformance signal

Run:  python tests/test_negative_vectors.py
"""
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk.core import (  # noqa: E402
    checkpoint_root,
    signing_input,
    verify_event,
    verify_passport,
)
from tap_sdk.verify import reconcile_checkpoint  # noqa: E402

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors.json").read_text(encoding="utf-8")
)
NEGATIVE = {k: v for k, v in VECTORS["negative"].items() if not k.startswith("_")}
NOW = VECTORS["passport"]["claims"]["iat"] + 1


def _attempt(case: dict) -> bool:
    """Run the verification a case describes. Raises on rejection."""
    if "compact_jwt" in case:
        return bool(verify_passport(case["jwk"], case["compact_jwt"], now=NOW))
    return bool(verify_event(case["jwk"], case["event"]))


def test_every_negative_case_behaves_as_declared() -> None:
    assert NEGATIVE, "the vectors must carry negative cases"
    for name, case in NEGATIVE.items():
        expect = case["expect"]
        if expect == "reject":
            try:
                _attempt(case)
            except Exception:
                continue
            raise AssertionError(
                f"{name}: MUST be rejected ({case['reason']}) — {case['spec']}"
            )
        elif expect == "accept":
            assert _attempt(case), f"{name}: MUST verify ({case['reason']})"
        elif expect == "flag":
            # A "flag" case is validly signed on purpose: the signal it carries
            # lives above the signature check, and an implementation that only
            # checks signatures will wave it through.
            if "events" in case:
                for ev in case["events"]:
                    assert verify_event(case["jwk"], ev), f"{name}: legs must verify"
            else:
                assert _attempt(case), f"{name}: MUST verify (the flag is not a sig failure)"
        else:
            raise AssertionError(f"{name}: unknown expect {expect!r}")


def test_explicit_nulls_diverge_structurally() -> None:
    """[TAP-EVT-OMIT]. The point of the rule: this record is validly signed, so no
    amount of signature checking catches it — but its signing input differs from
    the reference for a logically identical action, which means two conforming
    Signers would disagree on the bytes and their checkpoints would not match."""
    case = NEGATIVE["explicit_nulls_non_conforming"]
    event = case["event"]
    reference = VECTORS["event"]["signed_event"]

    assert verify_event(case["jwk"], event), "the non-conforming record still verifies"
    got = hashlib.sha256(signing_input(event)).hexdigest()
    assert got == case["canonical_signing_input_sha256"]
    assert got != hashlib.sha256(signing_input(reference)).hexdigest(), \
        "explicit nulls must produce different signed bytes — that is the whole problem"
    for field in case["diverges_on"]:
        assert field in event and event[field] is None
        assert field not in reference, "the reference omits absent optionals"


def test_duplicate_seq_is_detectable_despite_valid_signatures() -> None:
    """[TAP-EVT-SEQ]. Both legs verify; the tamper signal is the collision."""
    case = NEGATIVE["duplicate_aid_seq"]
    a, b = case["events"]
    assert verify_event(case["jwk"], a) and verify_event(case["jwk"], b)
    assert (a["aid"], a["seq"]) == (b["aid"], b["seq"]), "same (aid, seq)"
    assert a["event_id"] != b["event_id"] and a["action"] != b["action"], \
        "different content under the same sequence slot"


def test_checkpoint_omitting_a_delivered_event_fails_reconciliation() -> None:
    """[TAP-EVT-CHECKPOINT]. A signed checkpoint whose root commits to less than
    was delivered: the signature is fine, the reconciliation is not."""
    case = NEGATIVE["checkpoint_omits_delivered_event"]
    assert verify_event(case["jwk"], case["event"]), "the checkpoint itself is validly signed"

    delivered = [VECTORS["event"]["signed_event"], VECTORS["decision"]["signed_event"]]
    result = reconcile_checkpoint(case["event"], delivered)
    assert result["root_mismatch"], "recomputing the root over delivered ids must mismatch"
    assert not result["count_matches"], "the claimed count is short too"
    assert checkpoint_root(case["committed_event_ids"]) == \
        case["event"]["checkpoint"]["event_id_root"], "the short root is internally consistent"


def test_reconciliation_uses_the_signed_lower_bound() -> None:
    """The bug this replaced: reconciliation that ignores `from_seq` and sweeps
    every event with `seq <= through_seq` reports a mismatch on any record whose
    earlier checkpoint is missing — a false accusation manufactured by the
    verifier's own bookkeeping."""
    checkpoint = VECTORS["checkpoint"]["signed_event"]
    delivered = [VECTORS["event"]["signed_event"], VECTORS["decision"]["signed_event"]]

    # An event from BEFORE this checkpoint's interval, as a lost earlier segment
    # would leave behind. It must not be swept into this interval.
    earlier = {**VECTORS["event"]["signed_event"], "seq": 3,
               "event_id": "evt_from_a_previous_segment"}

    clean = reconcile_checkpoint(checkpoint, delivered)
    assert clean["root_valid"] and clean["count_matches"], "the honest record reconciles"

    with_earlier = reconcile_checkpoint(checkpoint, delivered + [earlier])
    assert with_earlier["root_valid"], \
        "an event below from_seq must be excluded, not counted as a mismatch"
    assert with_earlier["from_seq"] == 6 and with_earlier["count_received"] == 2


def test_mismatch_is_not_reported_as_provable_deletion() -> None:
    """A root mismatch says the delivered set is wrong. It does not identify which
    Event is missing, or whether one was added. Only an enumerated commitment
    supports the stronger claim — and overstating evidence is the one thing an
    audit tool must not do."""
    case = NEGATIVE["checkpoint_omits_delivered_event"]
    delivered = [VECTORS["event"]["signed_event"], VECTORS["decision"]["signed_event"]]
    result = reconcile_checkpoint(case["event"], delivered)
    assert result["root_mismatch"]
    assert result["provably_deleted"] == [], \
        "no leaf enumeration on the wire ⇒ no provable-deletion claim"

    # With the leaves enumerated, the specific suppressed id becomes provable.
    enumerated = {**VECTORS["checkpoint"]["signed_event"],
                  "reconciliation": {"event_ids": VECTORS["checkpoint"]["reconciliation"]["event_ids"]}}
    partial = reconcile_checkpoint(enumerated, [VECTORS["event"]["signed_event"]])
    assert partial["provably_deleted"] == [VECTORS["decision"]["signed_event"]["event_id"]]


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print(f"# {len(NEGATIVE)} negative vectors enforced ✓")


if __name__ == "__main__":
    main()
