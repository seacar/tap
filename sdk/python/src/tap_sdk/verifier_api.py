"""Typed client for the TAPClient Verifier REST API.

    from tap_sdk import VerifierAPI
    api = VerifierAPI("https://your-verifier.example.com", api_key="tap_live_...")
    report = api.verify(passport=passport.compact, events=[...])
    record = api.get_record(aid)
"""
from __future__ import annotations

from typing import Any

import httpx


class VerifierAPI:
    def __init__(self, endpoint: str = "http://localhost:8000", *,
                 api_key: str | None = None, admin_token: str | None = None,
                 client_id: str | None = None, timeout: float = 10.0) -> None:
        self.base = endpoint.rstrip("/")
        self._http = httpx.Client(timeout=timeout)
        self._headers: dict[str, str] = {}
        if api_key:
            self._headers["X-API-Key"] = api_key
        if admin_token and client_id:  # the console/admin read path
            self._headers["X-Admin-Token"] = admin_token
            self._headers["X-Client-Id"] = client_id

    def jwks(self) -> dict:
        return self._http.get(f"{self.base}/.well-known/jwks.json").raise_for_status().json()

    def report_events(self, events: list[dict], passport: str | None = None) -> dict:
        payload: dict[str, Any] = {"events": events}
        if passport:
            payload["passport"] = passport
        r = self._http.post(f"{self.base}/v1/events", json=payload, headers=self._headers)
        return r.raise_for_status().json()

    def verify(self, *, passport: str, events: list[dict]) -> dict:
        r = self._http.post(f"{self.base}/v1/verify",
                            json={"passport": passport, "events": events},
                            headers=self._headers)
        return r.raise_for_status().json()

    def get_record(self, aid: str) -> dict | None:
        r = self._http.get(f"{self.base}/v1/records/{aid}", headers=self._headers)
        if r.status_code == 404:
            return None
        return r.raise_for_status().json()

    def recent_records(self) -> list[dict]:
        r = self._http.get(f"{self.base}/v1/records", headers=self._headers)
        return r.raise_for_status().json().get("records", [])

    def register_agent(self, *, agent_id: str, public_jwk: dict | None = None) -> dict:
        payload: dict[str, Any] = {"agent_id": agent_id}
        if public_jwk is not None:
            payload["public_jwk"] = public_jwk
        r = self._http.post(f"{self.base}/v1/agents/register", json=payload, headers=self._headers)
        return r.raise_for_status().json()

    def close(self) -> None:
        self._http.close()
