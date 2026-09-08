#!/usr/bin/env python3
"""Production entrypoint for the TAP Gateway.

    GATEWAY_UPSTREAM_URL=https://legacy-tool.internal python -m tap_sdk.gateway.serve

Installed via ``pip install 'traceable-agent-protocol[gateway]'``.
"""
from __future__ import annotations

import os

import httpx
import uvicorn

from tap_sdk.gateway.app import create_app
from tap_sdk.gateway.config import load_config
from tap_sdk.gateway.keys import JWKSCache
from tap_sdk.server import TAPServer


def main() -> None:
    cfg = load_config()
    jwks = JWKSCache(cfg.verifier_url)
    tap_server = TAPServer(
        server_id=cfg.server_id, private_key_hex=cfg.private_key_hex, kid=cfg.kid,
        resolve_key=jwks.resolve, policy=cfg.policy,
        enforce=cfg.enforce, endpoint=cfg.verifier_url,
        flush_interval_s=cfg.flush_interval_s,
    )
    upstream = httpx.Client(base_url=cfg.upstream_url, timeout=30.0)
    app = create_app(tap_server=tap_server, upstream_client=upstream)
    port = int(os.environ.get("GATEWAY_PORT", "8090"))
    uvicorn.run(app, host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
