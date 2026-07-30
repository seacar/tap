"""TAP-aware Gateway (spec §4.3) — a drop-in reverse proxy that brings
two-sided attestation to upstream tools that have never heard of TAP.

Where an upstream tool is not TAP-aware, the Gateway sits in front of it: it
terminates the handshake, verifies the inbound Passport, forwards the request
unchanged, observes the real result, and emits the server-attested Event. A
deployer can blanket an entire fleet of legacy MCP servers with two-sided
assurance by routing them through one Gateway, without waiting on any upstream
vendor to adopt TAP.

Reuses :class:`server.TAPServer` for verify/enforce/replay/attest — the Gateway
is that same server-leg contract, fronting a real HTTP upstream instead of a
local Python handler.
"""
from .app import create_app
from .config import GatewayConfig, load_config

__all__ = ["create_app", "GatewayConfig", "load_config"]
