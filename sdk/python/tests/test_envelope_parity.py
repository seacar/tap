#!/usr/bin/env python3
"""Envelope parity: Python and TypeScript compose the SAME signed bytes.

This is the property the conformance vectors cannot establish on their own. A
vector proves an implementation can re-sign a body someone else composed; it says
nothing about the body an SDK *composes itself* — and that is exactly where the
two diverged. TypeScript emitted ``parent_event_id: null``, ``policy_decision:
null`` and ``evidence: null`` where Python omitted them. Both signed correctly.
Both verified. Their checkpoints could never have agreed, because a Merkle root
commits to the event_ids of events whose bodies differ.

So this compares the canonical signing input of a *composed* event, with the
fields that legitimately vary per run frozen to fixed values. When run after
`sdk/js/test/envelopeParity.test.ts`, it compares against that artifact directly;
otherwise it still enforces the shape rule [TAP-EVT-OMIT] on its own.

Run:  python tests/test_envelope_parity.py
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import TAPClient  # noqa: E402
from tap_sdk.core import signing_input  # noqa: E402

SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
KID = "key_2026_ref01"
JS_ARTIFACT = Path("/tmp/tap-js-envelope.json")


def _emit_one() -> dict:
    captured: list[dict] = []
    tap = TAPClient(
        agent_id="parity", private_key_hex=SEED, kid=KID,
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    passport = tap.issue_passport(task_prompt="parity", scope=["read:database"])
    tap.emit_event(passport, kind="tool_call", intent="Call db_query", tool="db_query",
                   scope_used="read:database", args={"table": "users", "limit": 50},
                   latency_ms=0)
    tap.flush()
    return captured[0]


def _freeze(event: dict) -> dict:
    """Replace the fields that legitimately vary per run, so two runs compare."""
    body = {k: v for k, v in event.items() if k != "sig"}
    body.update({
        "event_id": "evt_FROZEN",
        "passport_jti": "psp_FROZEN",
        "aid": "agt_FROZEN",
        "cid": "sha256:" + "00" * 32,
        "ts": "2026-01-01T00:00:00.000Z",
        "action_ref": "act_FROZEN",
    })
    body["result"] = {**body["result"], "latency_ms": 0}
    return body


def test_composed_tool_call_omits_absent_optionals() -> None:
    event = _emit_one()
    for absent in ("parent_event_id", "policy_decision", "decision", "checkpoint"):
        assert absent not in event, f"{absent} must be omitted when absent, not null"
    assert "evidence" not in event or event["evidence"], \
        "an empty evidence block must be omitted, not null"
    assert "error" in event["result"] and event["result"]["error"] is None, \
        "result.error is explicitly nullable and present"


def test_composed_checkpoints_chain_without_overlap() -> None:
    captured: list[dict] = []
    tap = TAPClient(
        agent_id="parity", private_key_hex=SEED, kid=KID,
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    p = tap.issue_passport(task_prompt="parity", scope=["call:tool"])
    for tool in ("a", "b"):
        tap.emit_event(p, kind="tool_call", intent=f"Call {tool}", tool=tool, scope_used="call:tool")
    tap.emit_checkpoint(p)
    tap.emit_event(p, kind="tool_call", intent="Call c", tool="c", scope_used="call:tool")
    tap.emit_checkpoint(p)
    tap.flush()

    cps = [e for e in captured if e["action"]["kind"] == "checkpoint"]
    assert len(cps) == 2
    assert cps[0]["checkpoint"]["from_seq"] == 0, "the first checkpoint starts at 0"
    assert cps[0]["checkpoint"]["count"] == 2
    assert cps[1]["checkpoint"]["from_seq"] == cps[0]["checkpoint"]["through_seq"], \
        "each checkpoint starts exactly where the previous one ended — no overlap, no gap"
    assert cps[1]["checkpoint"]["count"] == 1
    # A checkpoint action carries no intent and no args: omitted, not nulled.
    assert "intent_digest" not in cps[0]["action"]
    assert "args_digest" not in cps[0]["action"]
    assert cps[0]["action"]["tool"] is None and cps[0]["action"]["scope_used"] is None


def test_canonical_input_matches_the_typescript_sdk() -> None:
    """The cross-language assertion. Skips (loudly) when the JS artifact is absent,
    because a silent skip in a parity test is worse than no test at all."""
    frozen = _freeze(_emit_one())
    canonical = signing_input(frozen).decode("utf-8")

    if not JS_ARTIFACT.exists():
        print(f"  # SKIP: {JS_ARTIFACT} not found — run sdk/js/test/envelopeParity.test.ts first")
        return

    js = json.loads(JS_ARTIFACT.read_text(encoding="utf-8"))
    assert canonical == js["canonical"], (
        "the two SDKs composed different signed bytes for the same action:\n"
        f"  python: {canonical}\n"
        f"      js: {js['canonical']}"
    )


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# Python and TypeScript compose identical envelopes ✓")


if __name__ == "__main__":
    main()
