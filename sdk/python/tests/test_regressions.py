#!/usr/bin/env python3
"""Defects that shipped once, with the property each one violated.

Every case here passed the full suite at the time it was found. They are grouped
by the claim they falsified rather than by module, because that is what makes a
regression here worth catching: each one made a *stated guarantee* untrue while
every existing test stayed green.

Run:  PYTHONPATH=src python3 tests/test_regressions.py
"""
from __future__ import annotations

import json
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import TAPClient  # noqa: E402
from tap_sdk.authority import (  # noqa: E402
    AuthorityMalformed,
    check_authority_window,
)
from tap_sdk.core import (  # noqa: E402
    InvalidRecord,
    PassportExpired,
    b64u,
    load_signer,
    now_ts,
    public_jwk,
    sign_event,
    verify_passport,
)
from tap_sdk.server import ServerDenied, TAPServer  # noqa: E402
from tap_sdk.verify import evaluate_event, verify_transcript  # noqa: E402

AGENT_SEED = "11" * 32
SERVER_SEED = "22" * 32
AGENT_KID, SERVER_KID = "kid_agent", "kid_server"
KEYS = {
    AGENT_KID: public_jwk(load_signer(AGENT_SEED), AGENT_KID),
    SERVER_KID: public_jwk(load_signer(SERVER_SEED), SERVER_KID),
}

tests: list[tuple[str, object]] = []


def test(name):
    def deco(fn):
        tests.append((name, fn))
        return fn
    return deco


def _client(**kw) -> tuple[TAPClient, list]:
    captured: list = []
    tap = TAPClient(agent_id="regress", private_key_hex=AGENT_SEED, kid=AGENT_KID,
                    post_fn=lambda u, p, h: captured.extend(p["events"]), **kw)
    return tap, captured


# --- §7: a Signer cannot forge independent attestation [TAP-ASSURANCE-KEY] ---

@test("an agent signing both legs with its own key cannot reach two-sided")
def _():
    tap, events = _client()
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    for attestor in ("agent", "server"):
        tap.emit_event(p, kind="tool_call", intent="i", tool="x",
                       scope_used="call:x", action_ref="r1", attestor=attestor)
    tap.flush()
    # Both legs verify. The forgery is not a bad signature — it is a leg claiming
    # to be independent while signed by the very key it claims independence from.
    assert {e["kid"] for e in events} == {AGENT_KID}, "one key signed both legs"
    report = verify_transcript(p.compact, events, resolve_key=KEYS.get)
    assert report["assurance"]["by_action_ref"]["r1"] == "conflicting", report["assurance"]
    assert report["verified"] is False, "a forged server leg must not verify"


@test("a genuine server leg from an independent key still reaches two-sided")
def _():
    tap, events = _client()
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get,
                       post_fn=lambda u, p, h: events.extend(p["events"]))
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    tap.emit_event(p, kind="tool_call", intent="i", tool="x",
                   scope_used="call:x", action_ref="r1")
    server.attest(tool="x", passport_jwt=p.compact, action_ref="r1",
                  scope_used="call:x", execute=lambda: 1)
    tap.flush(); server.flush()
    report = verify_transcript(p.compact, events, resolve_key=KEYS.get)
    assert report["assurance"]["by_action_ref"]["r1"] == "two-sided", report["assurance"]


@test("a trust anchor rejects a server leg from an unrecognized key")
def _():
    tap, events = _client()
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get,
                       post_fn=lambda u, p, h: events.extend(p["events"]))
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    tap.emit_event(p, kind="tool_call", intent="i", tool="x",
                   scope_used="call:x", action_ref="r1")
    server.attest(tool="x", passport_jwt=p.compact, action_ref="r1",
                  scope_used="call:x", execute=lambda: 1)
    tap.flush(); server.flush()
    # "Different key" is only a floor. A deployment that knows WHICH keys may
    # attest as a server says so, and a leg from anything else is conflicting.
    report = verify_transcript(p.compact, events, resolve_key=KEYS.get,
                               is_server_key=lambda kid: kid == "some_other_gateway")
    assert report["assurance"]["by_action_ref"]["r1"] == "conflicting", report["assurance"]


# --- §4.2/§5: one Passport, many actions [TAP-REPLAY] -----------------------

@test("a server accepts every action under one passport, not just the first")
def _():
    tap, _ = _client()
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get, post_fn=lambda u, p, h: None)
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    # A Passport is minted per RECORD and attached to every action. Keying the
    # replay cache on `jti` at an action edge rejected call #2 of every record,
    # which made the Gateway unusable for any agent that calls more than one tool.
    for i in range(5):
        server.attest(tool="x", passport_jwt=p.compact, action_ref=f"r{i}",
                      scope_used="call:x", seq=p.reserve_seq(), execute=lambda: i)


@test("a replayed (aid, seq) slot is rejected even with a fresh action_ref")
def _():
    tap, _ = _client()
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get, post_fn=lambda u, p, h: None)
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    seq = p.reserve_seq()
    server.attest(tool="x", passport_jwt=p.compact, action_ref="first",
                  scope_used="call:x", seq=seq, execute=lambda: 1)
    try:
        # `action_ref` is caller-chosen, so rotating it must not evade the cache.
        server.attest(tool="x", passport_jwt=p.compact, action_ref="rotated",
                      scope_used="call:x", seq=seq, execute=lambda: 1)
        raise AssertionError("a replayed (aid, seq) slot must be rejected")
    except ServerDenied as exc:
        assert "replayed" in str(exc), exc


@test("a call with no seq is accepted but counted as un-enforceable")
def _():
    tap, _ = _client()
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get, post_fn=lambda u, p, h: None)
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    server.attest(tool="x", passport_jwt=p.compact, action_ref="r",
                  scope_used="call:x", execute=lambda: 1)
    # Honest rather than silent: without `seq` there is nothing
    # protocol-guaranteed-unique to key on, and the boundary says so.
    assert server.replay_unenforceable == 1, server.replay_unenforceable


@test("a delegation edge still enforces jti uniqueness")
def _():
    server = TAPServer(server_id="s", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                       resolve_key=KEYS.get, post_fn=lambda u, p, h: None,
                       replay_scope="delegation")
    tap, _ = _client()
    p = tap.issue_passport(task_prompt="t", scope=["call:x"])
    server.attest(tool="x", passport_jwt=p.compact, action_ref="a",
                  scope_used="call:x", execute=lambda: 1)
    try:
        server.attest(tool="x", passport_jwt=p.compact, action_ref="b",
                      scope_used="call:x", execute=lambda: 1)
        raise AssertionError("a repeated jti at a delegation edge must be rejected")
    except ServerDenied as exc:
        assert "jti" in str(exc), exc


# --- §5.3/§6.5: verification cannot be disabled by an interpreter flag -------

@test("passport checks raise rather than assert (survive python -O)")
def _():
    import subprocess
    # `python -O` strips `assert` statements. A verifier whose typ/kid/freshness
    # checks are assertions accepts an expired passport with the wrong typ and a
    # mismatched kid under a flag that any production image may set.
    script = '''
import json, time, sys
from tap_sdk.core import b64u, load_signer, public_jwk, verify_passport, InvalidRecord
sk = load_signer("11"*32); jwk = public_jwk(sk, "k1"); past = int(time.time()) - 100000
hdr = {"alg": "EdDSA", "typ": "application/jwt", "kid": "WRONG"}
claims = {"iss":"x","iat":past,"exp":past+60,"jti":"j","aid":"a",
          "cid":"sha256:"+"0"*64,"scope":["admin:*"]}
seg = (b64u(json.dumps(hdr,separators=(",",":")).encode()) + "." +
       b64u(json.dumps(claims,separators=(",",":")).encode()))
tok = seg + "." + b64u(sk.sign(seg.encode()))
try:
    verify_passport(jwk, tok)
    sys.exit("ACCEPTED under -O")
except InvalidRecord:
    pass
'''
    src = str(Path(__file__).resolve().parents[1] / "src")
    proc = subprocess.run([sys.executable, "-O", "-c", script],
                          capture_output=True, text=True, env={"PYTHONPATH": src, "PATH": ""})
    assert proc.returncode == 0, proc.stdout + proc.stderr


@test("a JOSE header of alg:none is rejected [TAP-SIG-ALG]")
def _():
    sk = load_signer(AGENT_SEED)
    jwk = KEYS[AGENT_KID]
    now = int(time.time())
    hdr = {"alg": "none", "typ": "tap-passport+jwt", "kid": AGENT_KID}
    claims = {"iss": "x", "iat": now, "exp": now + 60, "jti": "j", "aid": "a",
              "cid": "sha256:" + "0" * 64, "scope": []}
    seg = (b64u(json.dumps(hdr, separators=(",", ":")).encode()) + "." +
           b64u(json.dumps(claims, separators=(",", ":")).encode()))
    token = seg + "." + b64u(sk.sign(seg.encode()))
    # The signature is a perfectly good Ed25519 signature. The header still lies
    # about the algorithm, and §3.1 says that MUST NOT be accepted — checking the
    # JWK's suite alone leaves the field alg-confusion attacks actually target.
    try:
        verify_passport(jwk, token)
        raise AssertionError("alg:none in the JOSE header must be rejected")
    except InvalidRecord as exc:
        assert "alg" in str(exc), exc


@test("expiry is a typed error, not a substring of a message")
def _():
    from tap_sdk.verify import check_passport
    tap, _ = _client()
    p = tap.issue_passport(task_prompt="t", scope=[], ttl_s=1)
    res = check_passport(p.compact, resolve_key=KEYS.get,
                         now=int(time.time()) + 10_000)
    assert res["expired"] is True and res["valid"] is False, res
    try:
        verify_passport(KEYS[AGENT_KID], p.compact, now=int(time.time()) + 10_000)
        raise AssertionError("expected PassportExpired")
    except PassportExpired:
        pass


# --- a verifier must not be crashable by a record it is asked to read -------

@test("a malformed authorization block is labeled, never raised")
def _():
    sk = load_signer(AGENT_SEED)
    for bad in ({}, {"authz_id": "a"}, "a string", [1, 2], 7):
        event = sign_event(sk, {
            "v": "tap/0.1", "event_id": "evt_1", "passport_jti": "p", "aid": "a",
            "cid": "sha256:" + "00" * 32, "seq": 1, "ts": now_ts(),
            "action": {"kind": "tool_call", "tool": "t", "scope_used": None},
            "result": {"status": "success", "code": "OK", "error": None},
            "attestor": "agent", "kid": AGENT_KID, "authorization": bad,
        })
        # The signature is valid; a valid signature says nothing about SHAPE.
        # One poisoned event must not end the whole audit report.
        res = evaluate_event(event, resolve_key=KEYS.get, passport_claims=None,
                             last_seq=None,
                             resolve_authority_revocation=lambda i, v: None)
        assert res["authority_effect"] == "malformed_authority", (bad, res)


@test("the authority ENFORCEMENT path fails closed on a malformed block")
def _():
    # The labeling path never raises; the enforcement path must never wave one
    # through, because it reads the unsigned X-TAP-Authorization header (§11.1).
    for bad in ({}, {"nbf": "x", "exp": 1, "authz_id": "a",
                     "authority_state_version": "v", "target_state_digest": "d",
                     "issuer_kid": "k"}, "str", [1]):
        try:
            check_authority_window(bad, now=0)
            raise AssertionError(f"expected AuthorityMalformed for {bad!r}")
        except AuthorityMalformed:
            pass


# --- §11.3: reporting is fail-open FOR THE AGENT ----------------------------

@test("flush() returns promptly when the Verifier is unreachable")
def _():
    def unreachable(url, payload, headers):
        raise ConnectionError("verifier down")

    tap, _ = _client()
    tap._reporter._post = unreachable
    p = tap.issue_passport(task_prompt="t", scope=["x"])
    for _i in range(5):
        tap.emit_event(p, kind="tool_call", intent="i", tool="t", scope_used=None)

    # The obvious retry loop (drain, send, re-queue on failure, repeat until
    # empty) never terminates against a down Verifier: every drain hands back
    # what the last send just re-queued. That is a hot spin at shutdown, and
    # §11.3 says a Signer MUST NOT block execution on reporting availability.
    done = threading.Event()
    threading.Thread(target=lambda: (tap.flush(), done.set()), daemon=True).start()
    assert done.wait(5), "flush() did not return within 5s against a down Verifier"
    assert tap._reporter.failed_sends > 0, "a failed delivery must be visible"

    done_close = threading.Event()
    threading.Thread(target=lambda: (tap.close(), done_close.set()), daemon=True).start()
    assert done_close.wait(5), "close() did not return within 5s"


# --- §4.1: nego binds an outcome, never an aspiration [TAP-NEGO-BINDING] ----

@test("attestation:'requested' is never bound into evidence.nego")
def _():
    tap, events = _client()
    p = tap.issue_passport(task_prompt="t", scope=["x"], attestation="requested")
    tap.emit_event(p, kind="tool_call", intent="i", tool="t", scope_used=None)
    tap.flush()
    # `requested` is an OFFER (§4.1), never a selection. Binding it records the
    # Signer's own wish as a negotiated outcome, which is exactly what the
    # anti-downgrade check is supposed to be unable to say.
    nego = (events[0].get("evidence") or {}).get("nego")
    assert nego is None, f"requested must bind no nego, got {nego!r}"


# --- §8.1/§8.2: the delegation edge --------------------------------------

@test("an unsigned _meta.tap.cid cannot redirect the chain")
def _():
    from tap_sdk.signer import DelegationRejected
    sender, _ = _client()
    sp = sender.issue_passport(task_prompt="orchestrate", scope=["delegate:agent"])
    receiver = TAPClient(agent_id="rx", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                         post_fn=lambda u, p, h: None)
    # `_meta` is unsigned. Preferring it over the sender's SIGNED passport would
    # let a caller splice this record into an unrelated chain (§8.1) while every
    # signature still verified.
    meta = {"tap": {"action_ref": "a1", "cid": "sha256:" + "ff" * 32}}
    try:
        receiver.accept_a2a_delegation(meta=meta, sender_passport_jwt=sp.compact,
                                       resolve_key=KEYS.get, scope=["read:x"])
        raise AssertionError("a contradicting _meta cid must be rejected")
    except DelegationRejected as exc:
        assert "cid" in str(exc), exc


@test("a replayed delegation is rejected even with a rotated action_ref")
def _():
    from tap_sdk.signer import DelegationRejected
    sender, _ = _client()
    sp = sender.issue_passport(task_prompt="orchestrate", scope=["delegate:agent"])
    receiver = TAPClient(agent_id="rx", private_key_hex=SERVER_SEED, kid=SERVER_KID,
                         post_fn=lambda u, p, h: None)
    receiver.accept_a2a_delegation(meta={"tap": {"action_ref": "a1"}},
                                   sender_passport_jwt=sp.compact,
                                   resolve_key=KEYS.get, scope=["read:x"])
    try:
        # §8.2 names this failure explicitly: keying the cache on `action_ref`
        # "does not implement this rule", because a replayer picks a fresh one.
        receiver.accept_a2a_delegation(meta={"tap": {"action_ref": "ROTATED"}},
                                       sender_passport_jwt=sp.compact,
                                       resolve_key=KEYS.get, scope=["read:x"])
        raise AssertionError("a replayed delegation must be rejected")
    except DelegationRejected as exc:
        assert "replayed" in str(exc), exc


def main() -> int:
    failed = 0
    for name, fn in tests:
        try:
            fn()
            print(f"  ok   {name}")
        except Exception as exc:  # noqa: BLE001
            failed += 1
            print(f"  FAIL {name}\n         {type(exc).__name__}: {exc}")
    print(f"\n{len(tests) - failed}/{len(tests)} regression checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
