#!/usr/bin/env python3
"""The capability handshake and the anti-downgrade binding [TAP-NEGOTIATE].

Until v0.1.2 the handshake existed only in the specification: no SDK, server, or
gateway ever sent `tap_hello`, while `[TAP-CONFORMANCE]` listed it as a MUST for
the Server class and the `nego` binding attested to a negotiation that had never
happened on the wire. The Signer bound whatever assurance level its operator had
configured, so the anti-downgrade check compared a claim against itself.

What must hold now:

  * a Signer and a Server negotiate a real outcome, and the Signer binds THAT;
  * an intermediary that strips the handshake produces no ack, so no `nego` is
    bound and the record degrades honestly to intent-only;
  * a Signer whose claim outruns reality — `attestation:"server"` with no server
    leg — is flagged as `conflicting`, which is the whole point.

Run:  python tests/test_handshake.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from tap_sdk import TAPClient  # noqa: E402
from tap_sdk.core import SPEC_VERSION  # noqa: E402
from tap_sdk.negotiate import (  # noqa: E402
    ACK_HEADER,
    HELLO_HEADER,
    NegotiationFailed,
    ack_from_headers,
    hello_from_headers,
    offer,
    read_ack,
    select,
)
from tap_sdk.verify import assurance_level, nego_violation  # noqa: E402

SEED = "55" * 32
KID = "key_handshake_test"


def _client() -> tuple[TAPClient, list[dict]]:
    captured: list[dict] = []
    client = TAPClient(
        agent_id="handshake-test", private_key_hex=SEED, kid=KID,
        post_fn=lambda url, payload, headers: captured.extend(payload.get("events", [])),
    )
    return client, captured


def test_offer_and_select_agree() -> None:
    hello = offer(kid=KID)
    assert hello["versions"] == [SPEC_VERSION]
    assert hello["suites"] == ["tap-ed25519"], "suites carry TAP suite ids, not JOSE algs"

    ack = select(hello, attests=True)
    assert ack == {"version": SPEC_VERSION, "suite": "tap-ed25519",
                   "attestation": "server", "checkpoints": "supported"}
    outcome = read_ack(ack)
    assert outcome.version == SPEC_VERSION
    assert outcome.suite == "tap-ed25519"
    assert outcome.attestation == "server"


def test_signer_cannot_offer_server() -> None:
    """`server` is the Server's selection. A Signer offering it would be claiming
    an outcome it is not in a position to grant."""
    for bad in ("server", "two-sided", "yes"):
        try:
            offer(kid=KID, attestation=bad)
        except ValueError:
            continue
        raise AssertionError(f"a Signer must not be able to offer {bad!r}")


def test_non_attesting_server_says_so() -> None:
    """A server that will not sign an execution leg must not answer 'server'.
    Answering it and then not signing manufactures a `conflicting` verdict that a
    Verifier holds against the *agent*."""
    ack = select(offer(kid=KID), attests=False)
    assert ack["attestation"] == "none"
    assert read_ack(ack).attestation == "none"


def test_no_mutual_version_fails_loudly() -> None:
    try:
        select({"versions": ["tap/9.9"], "suites": ["tap-ed25519"]}, attests=True)
    except NegotiationFailed:
        return
    raise AssertionError("a version mismatch must not silently succeed")


def test_header_carriage_round_trips() -> None:
    hello = offer(kid=KID)
    headers = {HELLO_HEADER: __import__("json").dumps(hello)}
    assert hello_from_headers(headers) == hello
    # case-insensitivity, because real header maps vary
    assert hello_from_headers({HELLO_HEADER.lower(): __import__("json").dumps(hello)}) == hello
    # a malformed header degrades to "no handshake" rather than taking down the request
    assert hello_from_headers({HELLO_HEADER: "{not json"}) is None
    assert ack_from_headers({}) is None
    assert ACK_HEADER == "X-TAP-Hello-Ack"


def test_negotiated_outcome_is_what_gets_bound() -> None:
    client, captured = _client()
    passport = client.issue_passport(task_prompt="t", scope=["call:tool"])

    # Full round trip: offer -> select -> record.
    ack = select(client.hello(), attests=True)
    outcome = client.negotiate(ack, passport)
    assert outcome.attestation == "server"

    client.emit_event(passport, kind="tool_call", intent="Call x", tool="x",
                      scope_used="call:tool")
    client.flush()

    nego = (captured[0].get("evidence") or {}).get("nego")
    assert nego == {"version": SPEC_VERSION, "suite": "tap-ed25519",
                    "attestation": "server"}, f"got {nego!r}"


def test_stripped_handshake_binds_nothing() -> None:
    """The attack the binding exists for. An intermediary drops the hello, so no
    ack comes back; the Signer has nothing honest to claim and says nothing. The
    record degrades to intent-only, visibly, instead of asserting an assurance
    level nobody promised."""
    client, captured = _client()
    passport = client.issue_passport(task_prompt="t", scope=["call:tool"])

    assert client.negotiate(None, passport) is None
    client.emit_event(passport, kind="tool_call", intent="Call x", tool="x",
                      scope_used="call:tool")
    client.flush()

    assert "nego" not in (captured[0].get("evidence") or {}), \
        "with no observed ack there is nothing truthful to bind"
    assert assurance_level([captured[0]]) == "intent-only"


def test_unusable_ack_is_treated_as_no_ack() -> None:
    """An ack naming a version or suite we do not speak is not an outcome we can
    stand behind, so it binds nothing rather than being taken at face value."""
    client, _ = _client()
    passport = client.issue_passport(task_prompt="t", scope=["call:tool"])
    for bad in ({"version": "tap/9.9", "suite": "tap-ed25519", "attestation": "server"},
                {"version": SPEC_VERSION, "suite": "tap-pq-9", "attestation": "server"},
                {"version": SPEC_VERSION, "suite": "tap-ed25519", "attestation": "requested"}):
        assert client.negotiate(bad, passport) is None, f"{bad!r} should be unusable"
    assert passport.nego() is None


def test_claim_without_a_server_leg_is_conflicting() -> None:
    """A Signer that binds `attestation:"server"` and never gets one is flagged
    identically to legs that disagree [TAP-NEGO-BINDING]."""
    client, captured = _client()
    passport = client.issue_passport(task_prompt="t", scope=["call:tool"])
    client.negotiate(select(client.hello(), attests=True), passport)
    client.emit_event(passport, kind="tool_call", intent="Call x", tool="x",
                      scope_used="call:tool")
    client.flush()

    legs = [captured[0]]  # agent leg only — the server never signed one
    assert nego_violation(legs), "a claimed server leg that never arrives is a violation"


def test_legacy_alg_field_is_accepted_on_input_only() -> None:
    """Early drafts showed a JOSE `alg` in the handshake. We read it so an older
    peer still interoperates, and never emit it."""
    ack = select({"versions": [SPEC_VERSION], "algs": ["EdDSA"]}, attests=True)
    assert "alg" not in ack and ack["suite"] == "tap-ed25519"
    assert read_ack({"version": SPEC_VERSION, "alg": "EdDSA",
                     "attestation": "server"}).suite == "tap-ed25519"


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# handshake negotiated, bound, and downgrade-detectable ✓")


if __name__ == "__main__":
    main()
