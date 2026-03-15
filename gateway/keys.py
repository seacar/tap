"""JWKS fetch-and-cache resolver for the Gateway.

The Gateway needs to resolve an inbound agent's public key from the Verifier's
published JWKS in order to verify Passports (TAP-spec §3.2). No client-side JWKS
cache exists elsewhere in the repo — the Verifier only ever serves its own JWKS.
"""
from __future__ import annotations

import threading
import time

import httpx

class JWKSCache:
    """Fetch-and-cache ``kid -> public JWK`` against a Verifier's
    ``/.well-known/jwks.json``. Exposes :meth:`resolve`, the ``KeyResolver``
    shape :class:`server.TAPServer` expects.

    Fails open: if a refresh fails (network error), stale cache entries are
    still served rather than raising — an unknown ``kid`` still safely resolves
    to ``None``, which :class:`server.TAPServer` already turns into
    :class:`server.UnattestedAction` rather than a crash.
    """

    def __init__(self, verifier_url: str, *, ttl_s: float = 60.0,
                 client: httpx.Client | None = None) -> None:
        self._url = verifier_url.rstrip("/") + "/.well-known/jwks.json"
        self._ttl_s = ttl_s
        self._client = client or httpx.Client(timeout=10.0)
        self._lock = threading.Lock()
        self._keys: dict[str, dict] = {}
        self._fetched_at: float = 0.0

    def _refresh(self) -> None:
        try:
            resp = self._client.get(self._url)
            resp.raise_for_status()
            jwks = resp.json()
            self._keys = {k["kid"]: k for k in jwks.get("keys", []) if k.get("kid")}
            self._fetched_at = time.monotonic()
        except Exception:
            # Fail open: keep serving whatever's cached; a genuinely unknown kid
            # still safely resolves to None.
            pass

    def resolve(self, kid: str) -> dict | None:
        with self._lock:
            stale = (time.monotonic() - self._fetched_at) >= self._ttl_s
            if stale or kid not in self._keys:
                self._refresh()
            return self._keys.get(kid)
