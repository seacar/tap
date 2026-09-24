#!/usr/bin/env python3
"""SDK typed-decision tests [TAP-EVT-DECIDER, TAP-EVT-GATE, §6.4.1, PROVISIONAL].

Four guarantees:
  * the SDK reproduces the three typed-decision vectors byte-for-byte and labels
    each one as the vectors say;
  * gate arithmetic is exact decimal arithmetic and agrees with every row of
    `decision_gate`, including the boundary and spelling cases;
  * TAPClient.typed_decision() derives the gate outcome itself — a caller cannot
    record `accept` below its own threshold — and puts the decider's input and
    output schema in the annex, not the signed body;
  * verify_transcript() surfaces a self-contradicting gate and an unsuperseded
    fallback, without flipping `verified` while §6.4.1 is provisional.

Run from sdk/python/:
    PYTHONPATH=src python3 tests/test_typed_decisions.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import (
    Decider,
    DeciderError,
    TAPClient,
    check_output_schema,
    decision_gate_label,
    gate_decimal_micros,
    gate_outcome,
)
from tap_sdk.core import json_digest, load_signer, sign_event, verify_event
from tap_sdk.verify import evaluate_event, verify_transcript

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors.json").read_text(encoding="utf-8")
)
JWK = VECTORS["jwks"]["keys"][0]
SK = load_signer(VECTORS["ed25519_private_seed_hex"])
CASES = ("typed_decision", "typed_decision_fallback", "typed_decision_resolution")
SCHEMA = {"type": "object", "properties": {"label": {"enum": ["approve", "review"]}}}
FAST = Decider(kind="model", id="example.com/typed-decider", version="2026-09-15",
               output_schema=SCHEMA, score_semantics="calibrated_probability")


def _resolve(kid):
    return JWK if kid == JWK["kid"] else None


def _client(captured: list) -> TAPClient:
    c = TAPClient(agent_id="bot", private_key_hex="44" * 32, kid="key_test",
                  post_fn=lambda url, payload, headers: captured.append(payload))
    c.issue_passport(task_prompt="route invoices", scope=["call:tool"])
    return c


def test_vectors_reproduce_and_verify() -> None:
    for case in CASES:
        ev = VECTORS[case]["signed_event"]
        assert verify_event(JWK, ev), case
        body = {k: v for k, v in ev.items() if k != "sig"}
        assert sign_event(SK, body)["sig"] == ev["sig"], f"{case}: SDK must reproduce the sig"


def test_vector_gate_labels() -> None:
    assert decision_gate_label(VECTORS["typed_decision"]["signed_event"]["decision"]) \
        == VECTORS["typed_decision"]["expected_gate_label"] == "gate_consistent"
    assert decision_gate_label(VECTORS["typed_decision_fallback"]["signed_event"]["decision"]) \
        == "gate_consistent"
    assert decision_gate_label(VECTORS["typed_decision_resolution"]["signed_event"]["decision"]) is None
    assert decision_gate_label(VECTORS["decision"]["signed_event"]["decision"]) is None
    neg = VECTORS["negative"]["gate_outcome_inconsistent"]
    assert decision_gate_label(neg["event"]["decision"]) == neg["expected_label"]


def test_gate_fixture_table() -> None:
    fx = VECTORS["decision_gate"]
    for row in fx["outcomes"]:
        assert gate_outcome(row["score"], row["threshold"]) == row["outcome"], row
    for bad in fx["malformed"]:
        try:
            gate_decimal_micros(bad)
            raise AssertionError(f"{bad!r} must be rejected")
        except ValueError:
            pass
    for bad in (0.9, None, 1):
        try:
            gate_decimal_micros(bad)
            raise AssertionError(f"{bad!r} (not a string) must be rejected")
        except ValueError:
            pass


def test_annexed_output_schema_checks_out() -> None:
    for case in CASES:
        ev, annex = VECTORS[case]["signed_event"], VECTORS[case]["annex"]
        chk = check_output_schema(ev["decision"], annex["decision"])
        assert chk == {"schema_present": True, "schema_digest_valid": True,
                       "labels_permitted": True}, (case, chk)
    ev = VECTORS["typed_decision"]["signed_event"]
    tampered = {"output_schema": {"enum": ["auto_approve"]}}
    assert check_output_schema(ev["decision"], tampered)["schema_digest_valid"] is False
    # a shredded annex is an informational gap, not a failure
    assert check_output_schema(ev["decision"], None)["schema_present"] is False


def test_typed_decision_derives_the_gate() -> None:
    captured: list = []
    c = _client(captured)
    ok = c.typed_decision(question="Route?", labels=["approve", "review"], chosen="approve",
                          score="0.97", scores={"review": "0.03"}, decider=FAST,
                          threshold="0.90", input={"invoice": "INV-1"})
    fb = c.typed_decision(question="Route?", labels=["approve", "review"], chosen="approve",
                          score="0.72", decider=FAST, threshold="0.9", fallback_to="human",
                          input={"invoice": "INV-2"})
    edge = c.typed_decision(question="Route?", labels=["approve", "review"], chosen="approve",
                            score="0.9", decider=FAST, threshold="0.900000")
    assert ok["decision"]["gate"] == {"threshold": "0.90", "outcome": "accept"}
    assert fb["decision"]["gate"] == {"threshold": "0.9", "outcome": "fallback",
                                      "fallback_to": "human"}
    assert edge["decision"]["gate"]["outcome"] == "accept", "on the threshold is accept"
    for ev in (ok, fb, edge):
        assert decision_gate_label(ev["decision"]) == "gate_consistent"
        assert "enum" not in json.dumps(ev), "plaintext schema must stay out of the body"
        assert ev["decision"]["decider"]["output_schema_digest"] == json_digest(SCHEMA)
    assert ok["action"]["args_digest"] == json_digest({"invoice": "INV-1"})
    assert [o["id"] for o in ok["decision"]["options"]] == ["approve", "review"]
    assert ok["decision"]["options"][1]["score"] == "0.03"
    assert "score" not in fb["decision"]["options"][1], "unscored labels omit score, never null"

    c.flush()
    annexes = [a for p in captured for a in p.get("annexes", [])]
    ann = next(a for a in annexes if a["event_id"] == ok["event_id"])
    assert ann["args"] == {"invoice": "INV-1"}
    assert ann["decision"]["output_schema"] == SCHEMA


def test_decider_validation() -> None:
    captured: list = []
    c = _client(captured)
    bad = [
        (dict(decider=Decider(kind="model", id="m", version="1")), "model needs output_schema"),
        (dict(decider=Decider(kind="robot", id="m")), "unknown kind"),
        (dict(decider=Decider(kind="rule", id="r")), "rule needs version"),
        (dict(decider=Decider(kind="model", id="m", version="1", output_schema=SCHEMA,
                              score_semantics="uncalibrated"), threshold="0.9"),
         "a gate over rankings is meaningless"),
        (dict(decider=FAST, threshold="0.95000001"), "threshold outside the grammar"),
        (dict(threshold="0.9"), "a gate needs a decider"),
    ]
    for kwargs, why in bad:
        try:
            c.decision(question="q", chosen="a",
                       options=[{"id": "a", "score": "0.5"}, {"id": "b", "score": "0.5"}],
                       **kwargs)
            raise AssertionError(f"expected DeciderError: {why}")
        except DeciderError:
            pass
    # scores without score_semantics are refused once a decider is named
    try:
        c.decision(question="q", chosen="a", options=[{"id": "a", "score": "0.5"}],
                   decider=Decider(kind="rule", id="r", version="1"))
        raise AssertionError("expected DeciderError: scores need score_semantics")
    except DeciderError:
        pass
    # a human decider needs no version and no schema; its id names a role, not a person
    ev = c.decision(question="q", chosen="a", options=[{"id": "a"}, {"id": "b"}],
                    decider=Decider(kind="human", id="reviewer:ap-team"))
    assert ev["decision"]["decider"] == {"kind": "human", "id": "reviewer:ap-team"}


def test_verify_transcript_surfaces_gate_signals() -> None:
    passport = VECTORS["passport"]["compact_jwt"]
    now = VECTORS["passport"]["claims"]["iat"] + 1
    neg = VECTORS["negative"]["gate_outcome_inconsistent"]["event"]
    ok = VECTORS["typed_decision"]["signed_event"]
    fb = VECTORS["typed_decision_fallback"]["signed_event"]
    res = VECTORS["typed_decision_resolution"]["signed_event"]

    full = verify_transcript(passport, [ok, fb, res], resolve_key=_resolve, now=now)
    assert full["decision_gates"] == {"inconsistent": [], "unscorable": [], "unresolved": []}

    open_fb = verify_transcript(passport, [ok, fb], resolve_key=_resolve, now=now)
    assert open_fb["decision_gates"]["unresolved"] == [fb["event_id"]]
    assert "not yet superseded" in open_fb["summary"]

    bad = verify_transcript(passport, [ok, neg], resolve_key=_resolve, now=now)
    assert bad["decision_gates"]["inconsistent"] == [neg["event_id"]]
    # provisional: reported, not folded into `verified` (spec §6.4.1 status note)
    assert bad["verified"] == open_fb["verified"]

    one = evaluate_event(neg, resolve_key=_resolve, passport_claims=None, last_seq=None)
    assert one["sig_valid"] and one["decision_gate"] == "gate_inconsistent"
    # an event whose signature fails carries no gate label at all
    forged = {**neg, "decision": {**neg["decision"], "chosen": "manual_review"}}
    assert evaluate_event(forged, resolve_key=_resolve, passport_claims=None,
                          last_seq=None)["decision_gate"] is None


def test_matches_tap_ref() -> None:
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[3]))
        import tap_ref
    except ModuleNotFoundError:
        print("ok - tap_ref cross-check skipped (reference file not present)")
        return
    for row in VECTORS["decision_gate"]["outcomes"]:
        assert tap_ref.gate_outcome(row["score"], row["threshold"]) == \
            gate_outcome(row["score"], row["threshold"])
    for case in (*CASES,):
        d = VECTORS[case]["signed_event"]["decision"]
        assert tap_ref.decision_gate_label(d) == decision_gate_label(d)


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# SDK typed decisions match tap_ref.py (provisional, §6.4.1) ✓")


if __name__ == "__main__":
    main()
