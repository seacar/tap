#!/usr/bin/env python3
"""SDK authority-binding tests [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL].

Mirrors test_policy.py's shape. Three guarantees:
  * TAPClient.authorize() + trace(authorize=, effect_of=) binds an Event to a
    declared expected effect, blocks *before acting* on an expired approval
    (the same inline-enforcement pattern as policy denial), and stamps
    result.effect_digest so the label is computable downstream;
  * authority_state_version is the SAME JCS-digest construction as
    tap_ref.py's, cross-checked when the reference file is importable;
  * authority_effect_label reproduces tap_ref.py's match/mismatch/unverified
    outcomes.

Run from sdk/python/:
    PYTHONPATH=src ../../../tap/.venv/bin/python tests/test_authority.py
"""
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import (
    TAPClient,
    Authorization,
    AuthorityExpired,
    authority_effect_label,
    authority_state_version,
    check_authority_window,
)
from tap_sdk.core import json_digest

AUTHORITY_STATE = {"policy": "refund-v3", "rules": ["max_refund_cents:10000"]}
TARGET_STATE = {"ticket": "8842", "status": "refunded", "refund_cents": 5000}


def test_authority_state_version_matches_tap_ref() -> None:
    """Same JCS-digest construction as tap_ref.py's authorization vector."""
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parents[4] / "tap"))
        import tap_ref
    except ModuleNotFoundError:
        print("ok - tap_ref cross-check skipped (reference file not present)")
        return

    assert authority_state_version(AUTHORITY_STATE) == tap_ref.json_digest(AUTHORITY_STATE), (
        "SDK and tap_ref.py must agree on authority_state_version (JCS digest is neutral)"
    )


def test_grant_and_to_record_roundtrip() -> None:
    auth = Authorization.grant(
        target_state=TARGET_STATE, authority_state=AUTHORITY_STATE,
        nbf=1000, exp=2000, issuer_kid="key_admin",
    )
    record = auth.to_record()
    assert record["authority_state_version"] == authority_state_version(AUTHORITY_STATE)
    assert record["target_state_digest"] == json_digest(TARGET_STATE)
    assert record["nbf"] == 1000 and record["exp"] == 2000
    assert record["issuer_kid"] == "key_admin"
    assert Authorization.from_record(record) == auth


def test_check_authority_window() -> None:
    auth = Authorization.grant(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE,
                               nbf=1000, exp=2000, issuer_kid="key_admin")
    check_authority_window(auth, now=1500)  # mid-window: must not raise
    check_authority_window(auth, now=1000 - 60)  # inclusive lower skew edge
    for bad_now in (1000 - 61, 2000 + 61):
        try:
            check_authority_window(auth, now=bad_now)
            raise AssertionError(f"expected AuthorityExpired at now={bad_now}")
        except AuthorityExpired as exc:
            assert exc.authorization is auth and exc.now == bad_now


def test_authority_effect_label() -> None:
    auth = Authorization.grant(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE,
                               nbf=1000, exp=2000, issuer_kid="key_admin")
    assert authority_effect_label(None, {"effect_digest": "x"}) is None
    assert authority_effect_label(auth, {}) == "unverified_authority"
    assert authority_effect_label(auth, {"effect_digest": json_digest(TARGET_STATE)}) == "authorized_match"
    other = {**TARGET_STATE, "refund_cents": 7500}
    assert authority_effect_label(auth, {"effect_digest": json_digest(other)}) == "authorized_mismatch"
    # dict form (as it appears on a decoded wire Event) works identically to the dataclass
    assert authority_effect_label(auth.to_record(), {"effect_digest": json_digest(TARGET_STATE)}) == "authorized_match"


def test_trace_binds_authorization_and_effect_digest() -> None:
    captured: list[dict] = []
    signer = TAPClient(
        agent_id="bot", private_key_hex="44" * 32, kid="key_test",
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    signer.issue_passport(task_prompt="t", scope=["call:tool"])
    auth = signer.authorize(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE, ttl_s=3600)

    @signer.trace(tool="issue_refund", scope="call:tool", authorize=auth,
                  effect_of=lambda ret: ret)
    def issue_refund():
        return TARGET_STATE

    issue_refund()
    signer.flush()

    ev = captured[0]
    assert ev["authorization"]["authz_id"] == auth.authz_id
    assert ev["result"]["effect_digest"] == json_digest(TARGET_STATE)
    assert authority_effect_label(ev["authorization"], ev["result"]) == "authorized_match"


def test_trace_blocks_before_acting_on_expired_authorization() -> None:
    """Same inline-enforcement shape as PolicyDenied: the wrapped fn never runs,
    and a signed `denied` event with DENIED_AUTHORITY_EXPIRED is still emitted."""
    captured: list[dict] = []
    signer = TAPClient(
        agent_id="bot", private_key_hex="44" * 32, kid="key_test",
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    signer.issue_passport(task_prompt="t", scope=["call:tool"])
    now = int(time.time())
    expired = signer.authorize(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE,
                               ttl_s=1, issuer_kid="key_test")
    object.__setattr__(expired, "exp", now - 3600)  # force well outside the skew window

    ran = {"x": False}

    @signer.trace(tool="issue_refund", scope="call:tool", authorize=expired)
    def issue_refund():
        ran["x"] = True
        return TARGET_STATE

    try:
        issue_refund()
        raise AssertionError("expected AuthorityExpired")
    except AuthorityExpired:
        pass

    signer.flush()
    assert ran["x"] is False
    assert captured[0]["action"]["kind"] == "denied"
    assert captured[0]["result"]["code"] == "DENIED_AUTHORITY_EXPIRED"
    assert captured[0]["authorization"]["authz_id"] == expired.authz_id


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# SDK authority binding matches tap_ref.py (provisional, §9.2) ✓")


if __name__ == "__main__":
    main()
