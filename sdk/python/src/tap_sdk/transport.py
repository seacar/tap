"""Async, buffered, fail-open event transport (MVP build spec §6).

The Signer MUST NOT block the agent's hot path on reporting availability
(TAP-spec §10.3). Signing happens on the calling thread (cheap with Ed25519);
only the network POST is deferred. A single background thread drains a bounded
queue and POSTs batches of up to ``batch_size`` events, or every
``flush_interval_s`` seconds — whichever comes first. If the Verifier is down,
events buffer; on overflow the oldest are dropped with a counter.

The actual HTTP send is injected (``post_fn``) so the same buffer works with the
stdlib sender below, with ``httpx`` in production, or with a FastAPI TestClient
in tests. Delivery is idempotent: the Verifier dedupes on ``event_id``.
"""
from __future__ import annotations

import json
import queue
import threading
import time
import urllib.request
from typing import Callable

# A sender takes the reporting URL, a batch payload dict, and request headers;
# returns nothing and raises on transport failure (so the worker can retry/buffer).
PostFn = Callable[[str, dict, dict], None]


def urllib_post(url: str, payload: dict, headers: dict) -> None:
    """Zero-dependency POST. Production deployments swap in httpx; the contract
    (raise on failure) is identical."""
    data = json.dumps(payload).encode()
    hdrs = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=data, headers=hdrs, method="POST")
    with urllib.request.urlopen(req, timeout=5) as resp:  # raises URLError on failure
        resp.read()


class EventReporter:
    """Bounded queue + background flusher. Fail-open by construction."""

    def __init__(
        self,
        endpoint: str,
        *,
        post_fn: PostFn | None = None,
        api_key: str | None = None,
        batch_size: int = 50,
        flush_interval_s: float = 2.0,
        max_buffer: int = 10_000,
    ) -> None:
        self._url = endpoint.rstrip("/") + "/v1/events"
        self._post = post_fn or urllib_post
        self._headers: dict[str, str] = {"X-API-Key": api_key} if api_key else {}
        self._batch_size = batch_size
        self._flush_interval = flush_interval_s
        self._q: queue.Queue[dict] = queue.Queue(maxsize=max_buffer)
        self._passport_jwt: str | None = None
        self._stop = threading.Event()
        self.dropped = 0  # overflow counter (surfaced for diagnostics)
        self._worker = threading.Thread(target=self._run, name="tap-reporter", daemon=True)
        self._worker.start()

    def set_passport(self, compact_jwt: str) -> None:
        """Carry the passport so the Verifier can cache it on first sight and
        record drift checks (its scope is needed). Sent alongside the next batch."""
        self._passport_jwt = compact_jwt

    def submit(self, event: dict) -> None:
        try:
            self._q.put_nowait(event)
        except queue.Full:
            # Drop oldest, keep newest — never block the agent.
            try:
                self._q.get_nowait()
                self.dropped += 1
                self._q.put_nowait(event)
            except queue.Empty:
                pass

    def _drain(self, limit: int) -> list[dict]:
        batch: list[dict] = []
        while len(batch) < limit:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _send(self, batch: list[dict]) -> None:
        payload: dict = {"events": batch}
        if self._passport_jwt:
            payload["passport"] = self._passport_jwt
        try:
            self._post(self._url, payload, self._headers)
        except Exception:
            # Re-queue (best effort) and try again next tick. Fail-open: the
            # agent keeps running regardless of Verifier availability.
            for ev in batch:
                self.submit(ev)

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            batch = self._drain(self._batch_size)
            if batch:
                self._send(batch)

    def flush(self) -> None:
        """Synchronously drain everything currently queued (used at shutdown
        and in tests)."""
        while True:
            batch = self._drain(self._batch_size)
            if not batch:
                return
            self._send(batch)

    def close(self) -> None:
        self.flush()
        self._stop.set()
