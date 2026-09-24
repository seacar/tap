#!/usr/bin/env python3
"""Emit normalized envelope shapes for every event kind this SDK composes.

Half of a cross-language contract. `sdk/js/test/emitShapes.ts` is the other
half, and `scripts/check-envelope-parity.py` diffs the two and validates both
against `schemas/event.schema.json`.

Why a separate emitter rather than an assertion inside each SDK's own tests:
the divergences that actually happened were never visible from inside one
language. Python emitted `result.latency_ms: null` where TypeScript omitted the
key; Python's `record_output` used `tool: "agent.run"` where TypeScript used
`"agent.record"`. Both signed correctly. Both verified. Both passed every test
either SDK had, including the one named "the two SDKs compose identical
envelopes" — because that test asserted a *rule* about one SDK's output instead
of comparing the two. So this prints, and something else compares.

Volatile fields (ids, timestamps, digests, signatures) are normalized away: the
contract is the envelope's SHAPE — which keys are present, which are null, which
are omitted — not the values, which legitimately differ per run.

    PYTHONPATH=src python3 tests/emit_shapes.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import Decider, TAPClient  # noqa: E402

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
KID = "key_2026_ref01"

# Values that legitimately differ every run. Normalized to a marker so a diff
# reports envelope-shape drift and nothing else.
VOLATILE = {
    "event_id", "action_ref", "passport_jti", "aid", "cid", "ts", "sig",
    "intent_digest", "args_digest", "reasoning_digest", "model_output_digest",
    "question_digest", "rationale_digest", "reason_digest", "options_digest",
    "event_id_root", "kid", "parent_event_id",
}


def normalize(value, key=None):
    if key in VOLATILE:
        return f"<{key}>"
    # A measured latency is a real integer whose value is timing noise; the
    # contract is that the key is PRESENT when measured and ABSENT when not.
    if key == "latency_ms":
        return "<measured>"
    if isinstance(value, dict):
        return {k: normalize(v, k) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return [normalize(v) for v in value]
    return value


def shape_key(ev: dict) -> str:
    """One key per distinct envelope shape: the action kind, split further for
    typed decisions so the gated and ungated shapes are each compared."""
    key = ev["action"]["kind"]
    d = ev.get("decision") or {}
    if "gate" in d:
        key += ":gated-" + d["gate"]["outcome"]
    elif "decider" in d:
        key += ":typed"
    return key


def main() -> None:
    captured: list[dict] = []
    tap = TAPClient(agent_id="parity", private_key_hex=SEED, kid=KID,
                    post_fn=lambda url, payload, headers: captured.extend(payload["events"]))
    tap.issue_passport(task_prompt="parity", scope=["read:database"])

    @tap.trace(tool="db_query", scope="read:database", intent="Call db_query")
    def db_query(table, limit):
        return {"rows": 1}

    db_query("users", limit=50)
    tap.decision(question="Refund?", chosen="refund",
                 options=[{"id": "refund", "score": "0.71", "rationale": "policy allows"},
                          {"id": "deny", "score": "0.10", "reason": "would breach policy"}])
    # typed decisions (§6.4.1, provisional): gate accepted, gate fell back, and
    # the superseding decision — the three shapes the vectors pin down.
    schema = {"type": "object", "properties": {"label": {"enum": ["approve", "review"]}}}
    fast = Decider(kind="model", id="example.com/typed-decider", version="2026-09-15",
                   output_schema=schema, score_semantics="calibrated_probability")
    tap.typed_decision(question="Route?", labels=["approve", "review"], chosen="approve",
                       score="0.97", scores={"review": "0.03"}, decider=fast,
                       threshold="0.90", input={"invoice": "INV-1"})
    fb = tap.typed_decision(question="Route?", labels=["approve", "review"], chosen="approve",
                            score="0.72", decider=fast, threshold="0.90", fallback_to="llm",
                            input={"invoice": "INV-2"})
    tap.decision(question="Route?", chosen="review", input={"invoice": "INV-2"},
                 options=[{"id": "approve", "reason": "no PO match"},
                          {"id": "review", "rationale": "unusual total"}],
                 decider=Decider(kind="model", id="example.com/frontier-llm",
                                 version="2026-06-01", output_schema=schema),
                 parent_event_id=fb["event_id"], action_ref=fb["action_ref"])
    tap.record_output(output="done")
    tap.emit_checkpoint()
    tap.flush()

    shapes = {shape_key(ev): normalize(ev) for ev in captured}
    json.dump(shapes, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
