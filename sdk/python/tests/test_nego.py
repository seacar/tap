#!/usr/bin/env python3
"""The `nego` anti-downgrade binding ([TAP-NEGO-BINDING]).

The handshake itself is not signed, so a network intermediary can strip it and
force a silent downgrade to intent-only. The defence is to bind the negotiated
outcome into the *first* Event a Signer emits for a record. A Verifier then
compares what was claimed against what actually arrived: a Signer that recorded
`attestation:"server"` but for which no server leg exists is flagged identically
to a conflicting attestation (§7).

Three properties matter and each is easy to regress:

  * the binding lands on the first Event of a record and no other;
  * the default (`attestation="none"`) emits no `nego` at all, so existing
    records are unaffected;
  * an unrecognized attestation level is rejected rather than silently accepted.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import TAPClient  # noqa: E402
from tap_sdk.core import SPEC_VERSION  # noqa: E402

SEED = "44" * 32
KID = "key_nego_test"


def _client() -> tuple[TAPClient, list[dict]]:
    captured: list[dict] = []
    client = TAPClient(
        agent_id="nego-test",
        private_key_hex=SEED,
        kid=KID,
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    return client, captured


def _emit_two(client: TAPClient, passport) -> None:
    for tool in ("first_call", "second_call"):
        client.emit_event(passport, kind="tool_call", intent=f"Call {tool}",
                          tool=tool, scope_used="call:tool")
    client.flush()


def test_nego_bound_on_first_event_only() -> None:
    client, captured = _client()
    passport = client.issue_passport(
        task_prompt="t", scope=["call:tool"], attestation="server",
    )
    _emit_two(client, passport)

    first = (captured[0].get("evidence") or {}).get("nego")
    assert first == {
        "version": SPEC_VERSION,
        "suite": "tap-ed25519",
        "attestation": "server",
    }, f"first event must carry the negotiated outcome, got {first!r}"

    second = (captured[1].get("evidence") or {}).get("nego")
    assert second is None, "nego must appear exactly once per record"


def test_no_nego_by_default() -> None:
    """Backward compatible: a default passport never stamps nego."""
    client, captured = _client()
    passport = client.issue_passport(task_prompt="t", scope=["call:tool"])
    _emit_two(client, passport)
    for i, event in enumerate(captured):
        assert "nego" not in (event.get("evidence") or {}), f"event {i} carried nego"


def test_requested_binds_nothing() -> None:
    """`requested` is an OFFER, and an offer is never bound (§4.1).

    This test previously asserted the opposite — that a passport minted with
    `attestation="requested"` stamps `nego.attestation == "requested"` — and so
    locked in a spec violation. §4.1 is explicit: "`attestation: "requested"` is
    only ever an *offer*; it is not a valid selection", and the Signer "MUST NOT
    bind an *aspiration*". Binding a request records the Signer's own wish as a
    negotiated outcome, which makes the anti-downgrade check a restatement of
    what the Signer hoped for — detecting nothing.

    `negotiate.read_ack` already refused `requested` as a selection on the
    observed-ack path; only the operator-asserted path admitted it, so the two
    paths disagreed about the same rule.
    """
    client, captured = _client()
    passport = client.issue_passport(
        task_prompt="t", scope=["call:tool"], attestation="requested",
    )
    _emit_two(client, passport)
    for i, event in enumerate(captured):
        nego = (event.get("evidence") or {}).get("nego")
        assert nego is None, f"event {i} bound an aspiration: {nego!r}"


def test_asserted_server_still_binds() -> None:
    """An operator-asserted `server` is still bindable — the documented opt-in.

    §4.1 allows binding an outcome "its operator asserts and can stand behind"
    where the topology is fixed and no handshake rides the wire. That path stays
    open; only `requested` is excluded, because nobody can stand behind a wish.
    """
    client, captured = _client()
    passport = client.issue_passport(
        task_prompt="t", scope=["call:tool"], attestation="server",
    )
    _emit_two(client, passport)
    nego = captured[0]["evidence"]["nego"]
    assert nego["attestation"] == "server", nego


def test_invalid_attestation_rejected() -> None:
    client, _ = _client()
    for bad in ("two-sided", "yes", "", "SERVER"):
        try:
            client.issue_passport(task_prompt="t", scope=["call:tool"], attestation=bad)
        except ValueError:
            continue
        raise AssertionError(f"attestation={bad!r} should have been rejected")


def test_nego_is_inside_the_signature() -> None:
    """The binding is worthless unless it's covered by the signature."""
    from tap_sdk.core import public_jwk, load_signer, verify_event

    client, captured = _client()
    passport = client.issue_passport(
        task_prompt="t", scope=["call:tool"], attestation="server",
    )
    _emit_two(client, passport)

    jwk = public_jwk(load_signer(SEED), KID)
    event = captured[0]
    assert verify_event(jwk, event), "signed event must verify as-is"

    tampered = {**event, "evidence": {**event["evidence"],
                                      "nego": {**event["evidence"]["nego"],
                                               "attestation": "none"}}}
    try:
        verify_event(jwk, tampered)
    except Exception:
        return
    raise AssertionError("downgrading nego after signing must break verification")


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# nego anti-downgrade binding enforced ✓")


if __name__ == "__main__":
    main()
