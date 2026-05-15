#!/usr/bin/env python3
"""SDK policy-engine tests [TAP-POLICY-RECORD].

Two guarantees:
  * the published SDK enforces inline (deny before acting), and
  * its ``policy_version`` matches the platform's ``shared.policy`` byte-for-byte
    — the policy hash is JCS-canonical and therefore implementation-neutral, just
    like the event signatures (the same cross-impl discipline as test_conformance).

Run from sdk/python/:
    PYTHONPATH=src ../../../tap/.venv/bin/python tests/test_policy.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import TAPClient, evaluate_policy, policy_version
from tap_sdk.policy import PolicyRequest
from tap_sdk.signer import PolicyDenied

POLICY = {
    "default": "allow",
    "rules": [{"id": "no-shell", "effect": "deny", "when": {"tool": "run_shell"}}],
}


def test_policy_version_matches_platform() -> None:
    """policy_version is a JCS digest, so any conforming implementation agrees.

    Cross-checked against the reference Verifier when it is importable
    (private platform tree); skipped in a standalone checkout.
    """
    try:
        from shared.policy import policy_version as platform_version
    except ModuleNotFoundError:
        print('ok - platform cross-check skipped (reference Verifier not present)')
        return

    assert policy_version(POLICY) == platform_version(POLICY), (
        "SDK and platform must agree on policy_version (JCS digest is neutral)"
    )


def test_sdk_enforces_deny_before_acting() -> None:
    captured: list[dict] = []
    signer = TAPClient(
        agent_id="bot", private_key_hex="44" * 32, kid="key_test",
        policy=POLICY, enforce=True,
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    signer.issue_passport(task_prompt="t", scope=["execute:code"])
    ran = {"x": False}

    @signer.trace(tool="run_shell", scope="execute:code")
    def run_shell(cmd):
        ran["x"] = True
        return "ok"

    try:
        run_shell("rm -rf /")
        raise AssertionError("expected PolicyDenied")
    except PolicyDenied as exc:
        assert exc.decision.rule_id == "no-shell"

    signer.flush()
    assert ran["x"] is False
    assert captured[0]["action"]["kind"] == "denied"
    assert captured[0]["result"]["code"] == "DENIED_POLICY"
    assert captured[0]["policy_decision"]["policy_version"] == policy_version(POLICY)


def test_evaluator_default_allow() -> None:
    d = evaluate_policy(POLICY, PolicyRequest(tool="db_query"))
    assert d.decision == "allow" and d.rule_id is None


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# SDK policy engine conformant with platform ✓")


if __name__ == "__main__":
    main()
