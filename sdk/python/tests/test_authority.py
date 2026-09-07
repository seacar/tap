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
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import (
    TAPClient,
    Authorization,
    AuthorityExpired,
    AuthorityRevoked,
    authority_effect_label,
    authority_state_version,
    check_authority_window,
    check_authority_not_revoked,
)
from tap_sdk.core import json_digest, load_signer, public_jwk, sign_event
from tap_sdk.verify import evaluate_event, verify_transcript

AUTHORITY_STATE = {"policy": "refund-v3", "rules": ["max_refund_cents:10000"]}
TARGET_STATE = {"ticket": "8842", "status": "refunded", "refund_cents": 5000}

VECTORS = json.loads(
    (Path(__file__).resolve().parents[3] / "test-vectors.json").read_text(encoding="utf-8")
)


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


def test_reproduces_fixed_vector_validity_window_and_effect_check() -> None:
    """`test-vectors.json -> authorization`'s own note: fixture data "so other
    implementations have fixed numbers to test against without needing their
    own seed." Cross-checking against these SAME numbers (not just this SDK's
    own freely-chosen nbf/exp) is what actually proves Python and TypeScript
    agree on [TAP-AUTHORITY-VALIDITY] and [TAP-AUTHORITY-EFFECT], not merely
    that each independently satisfies its own logic."""
    av = VECTORS["authorization"]
    auth = Authorization.from_record(av["signed_event"]["authorization"])
    vw = av["validity_window"]

    check_authority_window(auth, now=vw["accepted_now"])  # must not raise

    for bad_now in (vw["rejected_now_not_yet_valid"], vw["rejected_now_expired"]):
        try:
            check_authority_window(auth, now=bad_now)
            raise AssertionError(f"vector's rejected_now={bad_now} must raise AuthorityExpired")
        except AuthorityExpired:
            pass

    ec = av["effect_check"]
    assert authority_effect_label(auth, {"effect_digest": ec["authorized_match_effect_digest"]}) \
        == "authorized_match"
    assert authority_effect_label(auth, {"effect_digest": ec["authorized_mismatch_effect_digest"]}) \
        == "authorized_mismatch"
    assert authority_effect_label(auth, {}) == "unverified_authority"


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


def test_check_authority_not_revoked_boundary() -> None:
    """[TAP-AUTHORITY-REVOKE, §9.2, provisional]: an effective-time boundary,
    same math as key revocation — a record signed before it stays valid."""
    check_authority_not_revoked("auz_x", "sha256:v", None, signed_ts=1500)  # nothing revoked: no raise
    check_authority_not_revoked("auz_x", "sha256:v", 2000, signed_ts=1999)  # before boundary: no raise
    for bad_ts in (2000, 2001):
        try:
            check_authority_not_revoked("auz_x", "sha256:v", 2000, signed_ts=bad_ts)
            raise AssertionError(f"expected AuthorityRevoked at signed_ts={bad_ts}")
        except AuthorityRevoked as exc:
            assert exc.revoked_id == "auz_x" and exc.revoked_at == 2000 and exc.signed_ts == bad_ts


SEED = "55" * 32
KID = "key_revoke_test"


def _signed_authorized_event(*, authz_id: str, event_id: str, seq: int, action_ref: str) -> tuple[dict, str, dict]:
    """A minimal, independently-signed Event carrying `authorization`, plus the
    passport JWT and JWK a Verifier would need to check it — built directly
    with the crypto primitives rather than through TAPClient, so this file
    doesn't need a second signer identity's worth of scaffolding."""
    sk = load_signer(SEED)
    jwk = public_jwk(sk, KID)
    from tap_sdk.core import sign_passport, now_ts, new_id, text_digest

    passport_claims = {
        "iss": "https://verifier.example.com", "iat": 1000, "exp": 2000,
        "jti": new_id("psp"), "aid": "agt_revoke_test",
        "cid": "sha256:" + "0" * 64, "scope": ["call:tool"], "meta": {},
    }
    passport_jwt = sign_passport(sk, KID, passport_claims)
    auth = Authorization.grant(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE,
                               nbf=1000, exp=999999999, issuer_kid=KID, authz_id=authz_id)
    body = {
        "v": "tap/0.1", "event_id": event_id, "passport_jti": passport_claims["jti"],
        "aid": passport_claims["aid"], "cid": passport_claims["cid"], "seq": seq,
        "ts": now_ts(),
        "action": {"kind": "tool_call", "intent_digest": text_digest("t"),
                  "tool": "issue_refund", "scope_used": "call:tool"},
        "authorization": auth.to_record(),
        "result": {"status": "success", "code": "OK", "error": None},
        "attestor": "agent", "action_ref": action_ref, "kid": KID,
    }
    event = sign_event(sk, body)
    return event, passport_jwt, jwk


def test_evaluate_event_surfaces_revocation_via_resolver() -> None:
    event, _passport_jwt, jwk = _signed_authorized_event(
        authz_id="auz_revoke_1", event_id="evt_revoke_1", seq=1, action_ref="act_revoke_1")

    # No resolver supplied: the revocation signal stays False, not an error.
    res = evaluate_event(event, resolve_key=lambda kid: jwk, passport_claims=None, last_seq=None)
    assert res["sig_valid"] and res["authority_revoked"] is False

    # A resolver that knows about this authz_id, revoked in the past: flagged.
    res = evaluate_event(
        event, resolve_key=lambda kid: jwk, passport_claims=None, last_seq=None,
        resolve_authority_revocation=lambda authz_id, asv: 1 if authz_id == "auz_revoke_1" else None,
    )
    assert res["authority_revoked"] is True
    assert res["sig_valid"] is True, "revocation must not flip sig_valid"

    # A resolver that has never heard of this id: not flagged.
    res = evaluate_event(
        event, resolve_key=lambda kid: jwk, passport_claims=None, last_seq=None,
        resolve_authority_revocation=lambda authz_id, asv: None,
    )
    assert res["authority_revoked"] is False


def test_verify_transcript_detects_batch_local_authz_reuse() -> None:
    ev1, passport_jwt, jwk = _signed_authorized_event(
        authz_id="auz_reused", event_id="evt_reuse_1", seq=1, action_ref="act_reuse_1")
    ev2, _pj, _jwk = _signed_authorized_event(
        authz_id="auz_reused", event_id="evt_reuse_2", seq=2, action_ref="act_reuse_2")

    report = verify_transcript(passport_jwt, [ev1, ev2], resolve_key=lambda kid: jwk)
    assert len(report["authority_reuse"]) == 1
    reuse = report["authority_reuse"][0]
    assert reuse["authz_id"] == "auz_reused"
    assert {reuse["first_event_id"], reuse["reused_event_id"]} == {"evt_reuse_1", "evt_reuse_2"}

    # A single event carrying the id is not reuse.
    report = verify_transcript(passport_jwt, [ev1], resolve_key=lambda kid: jwk)
    assert report["authority_reuse"] == []


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# SDK authority binding matches tap_ref.py (provisional, §9.2) ✓")


if __name__ == "__main__":
    main()
