#!/usr/bin/env python3
"""The TAP-aware Gateway actually produces a server leg (spec §4.3).

The Gateway is how a fleet gets two-sided assurance without upgrading every
upstream tool, so it carries a lot of the protocol's weight — and until v0.1.2 it
had no tests at all and appeared in no CI job. What follows is the contract a
Signer is entitled to assume when it points at one:

  * the handshake is answered, so the Signer can bind a real negotiated outcome;
  * the upstream request is forwarded UNCHANGED, and its real response comes back;
  * the execution leg is signed with the GATEWAY's key, not the agent's — an
    attestation an agent could forge would attest to nothing;
  * that leg echoes the caller's `action_ref`, so a Verifier can correlate the two
    legs and reach `two-sided`;
  * a call with no valid Passport is refused rather than silently proxied.

Run:  python gateway/test_gateway.py
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "sdk" / "python" / "src"))
sys.path.insert(0, str(REPO))

import httpx  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from gateway.app import create_app  # noqa: E402
from tap_sdk import Authorization, TAPClient  # noqa: E402
from tap_sdk.core import load_signer, public_jwk  # noqa: E402
from tap_sdk.negotiate import ACK_HEADER, HELLO_HEADER, to_header  # noqa: E402
from tap_sdk.server import TAPServer  # noqa: E402
from tap_sdk.verify import assurance_level  # noqa: E402

AUTHORITY_STATE = {"policy": "refund-v3", "rules": ["max_refund_cents:10000"]}
TARGET_STATE = {"ticket": "8842", "status": "refunded", "refund_cents": 5000}

AGENT_SEED = "11" * 32
AGENT_KID = "key_agent_gw_test"
GATEWAY_SEED = "22" * 32
GATEWAY_KID = "key_gateway_gw_test"

# The two identities the whole exercise depends on being DIFFERENT: if the gateway
# signed with the agent's key, the "independent" execution attestation would be
# forgeable by the very party it is meant to hold to account.
KEYS = {
    AGENT_KID: public_jwk(load_signer(AGENT_SEED), AGENT_KID),
    GATEWAY_KID: public_jwk(load_signer(GATEWAY_SEED), GATEWAY_KID),
}


def _harness():
    """Wire a Gateway in front of a stub upstream, with no real network anywhere.

    `create_app` takes its TAPServer and upstream client by injection precisely so
    this is possible — the same dependency-injection seam the SDK uses elsewhere.
    """
    server_events: list[dict] = []
    tap_server = TAPServer(
        server_id="test-gateway",
        private_key_hex=GATEWAY_SEED,
        kid=GATEWAY_KID,
        resolve_key=KEYS.get,
        post_fn=lambda url, payload, headers: server_events.extend(payload.get("events", [])),
        flush_interval_s=0.05,
    )

    seen_upstream: list[httpx.Request] = []

    def upstream_handler(request: httpx.Request) -> httpx.Response:
        seen_upstream.append(request)
        return httpx.Response(200, json={"rows": 1}, headers={"X-Upstream": "yes"})

    upstream = httpx.Client(
        transport=httpx.MockTransport(upstream_handler),
        base_url="http://upstream.invalid",
    )
    app = create_app(tap_server=tap_server, upstream_client=upstream)
    return TestClient(app), tap_server, server_events, seen_upstream


def _agent() -> tuple[TAPClient, list[dict]]:
    agent_events: list[dict] = []
    client = TAPClient(
        agent_id="gw-test-agent", private_key_hex=AGENT_SEED, kid=AGENT_KID,
        post_fn=lambda url, payload, headers: agent_events.extend(payload.get("events", [])),
    )
    return client, agent_events


def test_health_is_never_proxied() -> None:
    http, _, _, seen = _harness()
    assert http.get("/health").json() == {"ok": True, "service": "tap-gateway"}
    assert not seen, "/health must not reach the upstream"


def test_handshake_is_answered() -> None:
    """[TAP-NEGOTIATE]. Without this the Signer has no observed outcome to bind, and
    the anti-downgrade check has nothing to compare against."""
    http, _, _, _ = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])

    hello = client.hello()
    resp = http.post("/db", json={"q": 1}, headers={
        **passport.http_headers("act_test_0001"),
        HELLO_HEADER: to_header(hello),
    })
    assert resp.status_code == 200

    ack_header = resp.headers.get(ACK_HEADER)
    assert ack_header, "the Gateway must answer a hello it was offered"
    outcome = client.negotiate(__import__("json").loads(ack_header), passport)
    assert outcome is not None and outcome.attestation == "server", \
        "a Gateway that signs execution legs must say so"


def test_no_hello_gets_no_ack() -> None:
    """A caller that did not negotiate must not be handed an ack it can bind: that
    would manufacture an assurance claim nobody made."""
    http, _, _, _ = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])
    resp = http.post("/db", json={"q": 1}, headers=passport.http_headers("act_test_0002"))
    assert resp.status_code == 200
    assert ACK_HEADER not in resp.headers


def test_upstream_is_forwarded_unchanged_and_response_returned() -> None:
    http, _, _, seen = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])

    resp = http.post("/db?limit=5", json={"q": 1},
                     headers=passport.http_headers("act_test_0003"))
    assert resp.status_code == 200
    assert resp.json() == {"rows": 1}, "the caller gets the upstream's real body"
    assert resp.headers.get("x-upstream") == "yes", "and its real headers"

    assert len(seen) == 1
    req = seen[0]
    assert req.url.path == "/db" and req.url.params["limit"] == "5"
    # TAP's own carriage is stripped: the upstream has never heard of TAP, and
    # leaking a passport to it would be handing out a credential for no reason.
    assert "x-agent-passport" not in {k.lower() for k in req.headers}
    assert "x-tap-action-ref" not in {k.lower() for k in req.headers}


def test_server_leg_is_signed_with_the_gateway_key_and_echoes_action_ref() -> None:
    http, tap_server, server_events, _ = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])

    http.post("/db", json={"q": 1}, headers=passport.http_headers("act_test_0004"))
    tap_server._reporter.flush()

    assert len(server_events) == 1, "exactly one execution leg"
    leg = server_events[0]
    assert leg["attestor"] == "server"
    assert leg["kid"] == GATEWAY_KID, "signed with the GATEWAY's key, not the agent's"
    assert leg["action_ref"] == "act_test_0004", "echoes the caller's action_ref"
    assert leg["cid"] == passport.cid, "same record"
    # Digest-only, like every other Event [TAP-EVT-ENVELOPE].
    assert "intent" not in leg["action"] and "intent_digest" in leg["action"]
    for absent in ("parent_event_id", "policy_decision"):
        assert absent not in leg, f"{absent} must be omitted when absent"


def test_agent_and_gateway_legs_reach_two_sided() -> None:
    """The whole point: an independent execution attestation that a Verifier can
    correlate with the agent's claim of intent [TAP-ASSURANCE]."""
    http, tap_server, server_events, _ = _harness()
    client, agent_events = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])
    action_ref = "act_test_0005"

    client.emit_event(passport, kind="tool_call", intent="Call /db", tool="/db",
                      scope_used="call:/db", action_ref=action_ref)
    http.post("/db", json={"q": 1}, headers=passport.http_headers(action_ref))
    client.flush()
    tap_server._reporter.flush()

    legs = [e for e in agent_events + server_events if e.get("action_ref") == action_ref]
    assert len(legs) == 2, f"expected an agent leg and a server leg, got {len(legs)}"
    assert assurance_level(legs) == "two-sided"


def test_authorization_crosses_the_gateway_boundary() -> None:
    """[TAP-EVT-AUTHORIZATION, §9.2, provisional]. Until now `authorization` had
    no wire channel across the Gateway's HTTP boundary at all — the server leg
    could not see or echo what the agent claimed to be approved under."""
    http, tap_server, server_events, seen = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])
    auth = client.authorize(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE, ttl_s=3600)

    resp = http.post("/db", json={"q": 1},
                     headers=passport.http_headers("act_test_auth_0001", authorization=auth.to_record()))
    assert resp.status_code == 200
    tap_server._reporter.flush()

    assert len(server_events) == 1
    assert server_events[0]["authorization"]["authz_id"] == auth.authz_id, \
        "the server leg echoes the caller's claimed approval"
    # TAP's own carriage is stripped, same as the passport/action-ref headers.
    assert "x-tap-authorization" not in {k.lower() for k in seen[0].headers}


def test_expired_authorization_is_denied_at_the_gateway() -> None:
    """Defense in depth: the Gateway applies [TAP-AUTHORITY-VALIDITY] itself
    rather than trusting a non-compliant Signer to have checked before it signed."""
    http, tap_server, server_events, seen = _harness()
    client, _ = _agent()
    passport = client.issue_passport(task_prompt="t", scope=["call:/db"])
    expired = Authorization.from_record({
        **client.authorize(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE).to_record(),
        "exp": int(__import__("time").time()) - 3600,
    })

    resp = http.post("/db", json={"q": 1},
                     headers=passport.http_headers("act_test_auth_0002", authorization=expired.to_record()))
    assert resp.status_code == 403
    assert resp.json()["error"] == "DENIED_AUTHORITY_EXPIRED"
    assert not seen, "an expired approval must never reach the upstream"

    tap_server._reporter.flush()
    assert server_events[0]["result"]["code"] == "DENIED_AUTHORITY_EXPIRED"
    assert server_events[0]["authorization"]["authz_id"] == expired.authz_id


def test_reused_authz_id_is_denied_at_the_gateway() -> None:
    """[TAP-AUTHORITY-REUSE, §9.2, provisional]: a second presentation of the
    same authz_id at this accept boundary must be rejected — even under a
    fresh passport (a distinct `jti`), so this is genuinely the authz_id check
    firing and not just [TAP-REPLAY]'s passport-jti defense."""
    http, tap_server, server_events, seen = _harness()
    client, _ = _agent()
    auth = client.authorize(target_state=TARGET_STATE, authority_state=AUTHORITY_STATE, ttl_s=3600)

    passport_1 = client.issue_passport(task_prompt="t", scope=["call:/db"])
    first = http.post("/db", json={"q": 1}, headers=passport_1.http_headers(
        "act_test_auth_0003a", authorization=auth.to_record()))
    assert first.status_code == 200

    passport_2 = client.issue_passport(task_prompt="t", scope=["call:/db"])
    assert passport_2.claims["jti"] != passport_1.claims["jti"], "a genuinely fresh passport"
    second = http.post("/db", json={"q": 1}, headers=passport_2.http_headers(
        "act_test_auth_0003b", authorization=auth.to_record()))
    assert second.status_code == 403
    assert second.json()["error"] == "DENIED_AUTHORITY_REUSED"
    assert len(seen) == 1, "the reused presentation must never reach the upstream"

    tap_server._reporter.flush()
    denied = [e for e in server_events if e["result"]["code"] == "DENIED_AUTHORITY_REUSED"]
    assert len(denied) == 1 and denied[0]["authorization"]["authz_id"] == auth.authz_id


def test_unattested_call_is_refused() -> None:
    """An action without a valid Passport is unattested, and a Gateway that proxied
    it anyway would be laundering an unauthenticated request through a component
    whose whole job is attestation."""
    http, _, _, seen = _harness()
    assert http.post("/db", json={"q": 1}).status_code == 401
    assert http.post("/db", json={"q": 1},
                     headers={"X-Agent-Passport": "not.a.jwt"}).status_code == 401
    assert not seen, "an unattested call must never reach the upstream"


def main() -> None:
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    print(f"1..{len(tests)}")
    for i, t in enumerate(tests, 1):
        t()
        print(f"ok {i} - {t.__name__}")
    print("# Gateway: handshake, pass-through, independent server leg, two-sided ✓")


if __name__ == "__main__":
    main()
