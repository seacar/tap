"""FastAPI proxy app for the TAP-aware Gateway (whitepaper §4.4).

The Gateway terminates the TAP handshake for an upstream tool that has never
heard of TAP: it verifies the inbound Passport, enforces scope/policy and
replay defense (all via ``TAPServer.attest``, TAP-spec §6, build spec §9.1),
forwards the request unchanged to the real upstream, observes the real result,
and signs a server-attested Event echoing the caller's ``action_ref``. This is
exactly the same server-leg contract ``TAPServer`` already implements for a
local Python handler — the Gateway fronts a real HTTP upstream instead.

NOTE: ``/health`` is reserved for the Gateway's own liveness probe and is never
proxied — an upstream tool actually named "health" would need a different path.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# gateway/ lives in distribution/, but its verify/enforce/attest machinery

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from tap_sdk.server import ServerDenied, TAPServer, UnattestedAction
from tap_sdk.core import digest, new_id

# Stripped both directions: hop-by-hop headers (RFC 7230 §6.1) plus TAP's own
# carriage headers (the upstream tool knows nothing about TAP) plus
# content-length (recomputed by the ASGI server from the actual body either way).
_STRIP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "x-agent-passport", "x-tap-action-ref",
}

def _strip_headers(headers) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k.lower() not in _STRIP_HEADERS}

def create_app(*, tap_server: TAPServer, upstream_client: httpx.Client) -> FastAPI:
    """Build the Gateway's ASGI app.

    A factory, not an import-time singleton — ``tap_server``/``upstream_client``
    are injected so tests (and alternate deployments) can wire a stub upstream
    and an in-process Verifier without any real network call, the same
    dependency-injection style ``TAPServer``/``TAPClient`` already use
    throughout the test suite.
    """
    app = FastAPI(title="TAP Gateway", version="0.1.0", docs_url=None, redoc_url=None)

    @app.get("/health")
    def health() -> dict:
        return {"ok": True, "service": "tap-gateway"}

    @app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def proxy(path: str, request: Request) -> Response:
        body = await request.body()
        passport_jwt = request.headers.get("x-agent-passport")
        action_ref = request.headers.get("x-tap-action-ref") or new_id("act")
        # Simplest default (whitepaper §4.4): the request path IS the tool
        # identifier. A configurable path->tool map is a documented future
        # extension, not needed for a single-upstream Gateway.
        tool = "/" + path
        upstream_path = tool + (f"?{request.url.query}" if request.url.query else "")

        captured: dict[str, Any] = {}

        def do_forward() -> dict:
            resp = upstream_client.request(
                request.method, upstream_path,
                headers=_strip_headers(request.headers), content=body,
            )
            captured["resp"] = resp
            # TAPServer.attest()'s return value is what gets JSON-digested into
            # the signed event's result_digest — raw response bytes must never
            # enter the signed envelope (§6.1 digests-only rule). The real
            # httpx.Response (actual bytes/headers the caller needs back) is
            # stashed in `captured` for the proxy handler below instead.
            return {"status_code": resp.status_code, "body_digest": digest(resp.content)}

        try:
            tap_server.attest(tool=tool, passport_jwt=passport_jwt, action_ref=action_ref,
                              execute=do_forward)
        except UnattestedAction as exc:
            return JSONResponse({"error": "unattested_action", "detail": str(exc)}, status_code=401)
        except ServerDenied as exc:
            return JSONResponse({"error": exc.code, "detail": str(exc)}, status_code=403)
        except Exception as exc:  # upstream network failure inside do_forward()
            return JSONResponse({"error": "UPSTREAM_ERROR", "detail": str(exc)}, status_code=502)

        resp = captured["resp"]
        return Response(content=resp.content, status_code=resp.status_code,
                        headers=_strip_headers(resp.headers))

    return app
