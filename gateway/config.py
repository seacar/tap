"""Environment-driven configuration and identity bootstrap for the Gateway."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass

import httpx

@dataclass(frozen=True)
class GatewayConfig:
    upstream_url: str
    verifier_url: str
    server_id: str
    private_key_hex: str
    kid: str
    enforce: bool
    policy: dict | None
    flush_interval_s: float

def _register_identity(verifier_url: str, server_id: str) -> tuple[str, str]:
    """Auto-register the Gateway's own signing identity with the Verifier
    (the same ``/v1/agents/register`` call any agent/server identity uses —
    see ``verifier/app.py::register_agent``). Convenience for getting started;
    an operator that restarts the Gateway with a *new* identity every time
    loses replay-cache and per-aid seq continuity for that identity, so this is
    not the steady-state deployment story. Prints the minted credentials once
    so the operator can pin GATEWAY_PRIVATE_KEY_HEX/GATEWAY_KID for future runs.
    """
    resp = httpx.post(f"{verifier_url.rstrip('/')}/v1/agents/register",
                      json={"agent_id": server_id}, timeout=30.0)
    resp.raise_for_status()
    data = resp.json()
    print(
        f"[gateway] auto-registered identity {server_id!r} — pin these for future "
        f"restarts:\n  GATEWAY_KID={data['kid']}\n"
        f"  GATEWAY_PRIVATE_KEY_HEX={data['private_key_hex']}"
    )
    return data["private_key_hex"], data["kid"]

def load_config() -> GatewayConfig:
    upstream_url = os.environ.get("GATEWAY_UPSTREAM_URL")
    if not upstream_url:
        raise ValueError("GATEWAY_UPSTREAM_URL is required (the upstream tool/server to proxy to)")

    verifier_url = os.environ.get("VERIFIER_URL", "http://127.0.0.1:8000")
    server_id = os.environ.get("GATEWAY_SERVER_ID", "tap-gateway")

    private_key_hex = os.environ.get("GATEWAY_PRIVATE_KEY_HEX")
    kid = os.environ.get("GATEWAY_KID")
    if not private_key_hex or not kid:
        if os.environ.get("GATEWAY_AUTO_REGISTER", "1") not in ("0", "false", "False"):
            private_key_hex, kid = _register_identity(verifier_url, server_id)
        else:
            raise ValueError(
                "GATEWAY_PRIVATE_KEY_HEX and GATEWAY_KID are required when "
                "GATEWAY_AUTO_REGISTER is disabled — pre-register via "
                "POST /v1/agents/register and set both env vars"
            )

    enforce = os.environ.get("GATEWAY_ENFORCE", "1") not in ("0", "false", "False")

    policy = None
    policy_file = os.environ.get("GATEWAY_POLICY_FILE")
    if policy_file:
        with open(policy_file) as f:
            policy = json.load(f)

    # How often the server-attested leg is batched to the Verifier (TAP-spec §10,
    # fail-open reporting). Default matches EventReporter's own default; lower it
    # for a snappier caller-visible two-sided result (e.g. a local demo).
    flush_interval_s = float(os.environ.get("GATEWAY_FLUSH_INTERVAL_S", "2.0"))

    return GatewayConfig(
        upstream_url=upstream_url,
        verifier_url=verifier_url,
        server_id=server_id,
        private_key_hex=private_key_hex,
        kid=kid,
        enforce=enforce,
        policy=policy,
        flush_interval_s=flush_interval_s,
    )
