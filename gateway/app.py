"""FastAPI proxy app for the TAP-aware Gateway (spec §4.3).

The Gateway terminates the TAP handshake for an upstream tool that has never heard
of TAP: it answers ``tap_hello`` [TAP-NEGOTIATE], verifies the inbound Passport,
enforces scope/policy and replay defense (all via ``TAPServer.attest``), forwards
the request unchanged to the real upstream, observes the real result, and signs a
server-attested Event echoing the caller's ``action_ref`` [TAP-ASSURANCE]. To the
Signer it is indistinguishable from a TAP-aware Server — which is the point: it is
how a fleet gets two-sided assurance without every upstream tool being upgraded.

It implements exactly the server-leg contract ``TAPServer`` already provides for a
local Python handler; the Gateway just fronts a real HTTP upstream instead.

NOTE: ``/health`` is reserved for the Gateway's own liveness probe and is never
proxied — an upstream tool actually named "health" would need a different path.
"""
from __future__ import annotations

from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from tap_sdk.server import ServerDenied, TAPServer, UnattestedAction
from tap_sdk.core import digest, new_id
from tap_sdk.negotiate import authorization_from_headers, seq_from_headers

# The six fields an `authorization` record must carry [TAP-EVT-AUTHORIZATION,
# §9.2]. `X-TAP-Authorization` is unsigned, untrusted inbound data at this
# point — a caller can send anything — so a shape that's missing one of these
# degrades to "no authorization claimed" rather than crashing the request,
# same discipline `from_header` already applies to malformed JSON.
_AUTHORIZATION_FIELDS = {
    "authz_id", "authority_state_version", "target_state_digest",
    "nbf", "exp", "issuer_kid",
}

def _well_formed_authorization(parsed: dict | None) -> dict | None:
    if not parsed or not _AUTHORIZATION_FIELDS <= parsed.keys():
        return None
    return parsed

# Stripped both directions: hop-by-hop headers (RFC 7230 §6.1) plus TAP's own
# carriage headers (the upstream tool knows nothing about TAP) plus
# content-length (recomputed by the ASGI server from the actual body either way).
_STRIP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "host", "content-length",
    "x-agent-passport", "x-tap-action-ref", "x-tap-authorization",
    "x-tap-hello", "x-tap-hello-ack", "x-tap-seq",
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
        authorization = _well_formed_authorization(authorization_from_headers(request.headers))
        # The caller's `(aid, seq)` slot for this action (§11.1). This is the only
        # protocol-guaranteed unique value at an action edge — a Passport is
        # legitimately presented on every action of a record, so `jti` is not one
        # — and without it `TAPServer` reports replay defense as unenforceable
        # rather than inventing a guarantee [TAP-REPLAY].
        caller_seq = seq_from_headers(request.headers)
        # Answer the handshake if one was offered [TAP-NEGOTIATE]. The ack rides
        # back on every response it applies to, so a Signer learns the negotiated
        # outcome before it binds `nego` into its first Event. A caller that sent
        # no hello gets no ack, and correctly binds nothing.
        tap_headers = tap_server.hello_ack_headers(request.headers)
        # Simplest default (spec §4.3): the request path IS the tool
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
            # enter the signed envelope [TAP-EVT-ENVELOPE]. The real httpx.Response
            # (the actual bytes and headers the caller needs back) is stashed in
            # `captured` for the proxy handler below instead.
            return {"status_code": resp.status_code, "body_digest": digest(resp.content)}

        try:
            tap_server.attest(tool=tool, passport_jwt=passport_jwt, action_ref=action_ref,
                              execute=do_forward, authorization=authorization,
                              seq=caller_seq)
        except UnattestedAction as exc:
            return JSONResponse({"error": "unattested_action", "detail": str(exc)},
                                status_code=401, headers=tap_headers)
        except ServerDenied as exc:
            return JSONResponse({"error": exc.code, "detail": str(exc)},
                                status_code=403, headers=tap_headers)
        except Exception as exc:  # upstream network failure inside do_forward()
            return JSONResponse({"error": "UPSTREAM_ERROR", "detail": str(exc)},
                                status_code=502, headers=tap_headers)

        resp = captured["resp"]
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={**_strip_headers(resp.headers), **tap_headers})

    return app
