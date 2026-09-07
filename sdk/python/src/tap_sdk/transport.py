"""Async, buffered, fail-open event transport (spec §11.3).

The Signer MUST NOT block the agent's hot path on reporting availability
(spec §11.3). Signing happens on the calling thread (cheap with Ed25519);
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
        # Each item is an (event, annex | None) pair. The annex is the unsigned
        # plaintext companion to a digest-only signed body [TAP-EVT-ANNEX]; it
        # rides in the same batch so the Verifier can index it without a second
        # round-trip, and can be shredded later without touching the signed chain.
        self._q: queue.Queue[tuple[dict, dict | None]] = queue.Queue(maxsize=max_buffer)
        self._passport_jwt: str | None = None
        self._stop = threading.Event()
        self.dropped = 0  # overflow counter (surfaced for diagnostics)
        # Batches the Verifier did not accept. Fail-open means the agent keeps
        # running, not that nobody can tell delivery failed — checkpoints
        # (§6.3) are what make undelivered events detectable downstream, and
        # this is what makes them visible locally.
        self.failed_sends = 0
        self._worker = threading.Thread(target=self._run, name="tap-reporter", daemon=True)
        self._worker.start()

    def set_passport(self, compact_jwt: str) -> None:
        """Carry the passport so the Verifier can cache it on first sight and
        record drift checks (its scope is needed). Sent alongside the next batch."""
        self._passport_jwt = compact_jwt

    def submit(self, event: dict, annex: dict | None = None) -> None:
        try:
            self._q.put_nowait((event, annex))
        except queue.Full:
            # Drop oldest, keep newest — never block the agent.
            try:
                self._q.get_nowait()
                self.dropped += 1
                self._q.put_nowait((event, annex))
            except queue.Empty:
                pass

    def _drain(self, limit: int) -> list[tuple[dict, dict | None]]:
        batch: list[tuple[dict, dict | None]] = []
        while len(batch) < limit:
            try:
                batch.append(self._q.get_nowait())
            except queue.Empty:
                break
        return batch

    def _send(self, batch: list[tuple[dict, dict | None]]) -> None:
        payload: dict = {"events": [ev for ev, _ in batch]}
        annexes = [ax for _, ax in batch if ax is not None]
        if annexes:
            payload["annexes"] = annexes  # spec §11.3
        if self._passport_jwt:
            payload["passport"] = self._passport_jwt
        try:
            self._post(self._url, payload, self._headers)
        except Exception:
            # Re-queue (best effort) and try again next tick. Fail-open: the
            # agent keeps running regardless of Verifier availability.
            self.failed_sends += 1
            for pair in batch:
                self.submit(*pair)

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._flush_interval)
            batch = self._drain(self._batch_size)
            if batch:
                self._send(batch)

    def flush(self, *, timeout_s: float | None = 5.0) -> None:
        """Attempt one delivery pass over everything currently queued.

        Bounded on purpose. The obvious loop — drain, send, repeat until empty —
        never terminates when the Verifier is unreachable, because ``_send``
        re-queues the batch it failed to deliver and the next drain hands the
        same items straight back. That turns a down Verifier into a hot spin at
        shutdown, which is exactly what §11.3's "a Signer MUST NOT block
        execution on reporting availability" forbids.

        So this makes at most one pass over the items present when it was
        called: undelivered events stay queued for the background worker (or the
        next flush), ``failed_sends`` records that delivery did not happen, and
        the caller gets control back. ``timeout_s`` bounds it in wall-clock terms
        too, for a Verifier that accepts connections but answers slowly; pass
        ``None`` to bound by queue contents alone.
        """
        deadline = None if timeout_s is None else time.monotonic() + timeout_s
        # Snapshot the backlog size first: anything `_send` re-queues below lands
        # behind this bound rather than inside it.
        remaining = self._q.qsize()
        while remaining > 0:
            if deadline is not None and time.monotonic() >= deadline:
                return
            batch = self._drain(min(self._batch_size, remaining))
            if not batch:
                return
            remaining -= len(batch)
            self._send(batch)

    def close(self, *, timeout_s: float | None = 5.0) -> None:
        """Stop the worker after one bounded delivery attempt.

        The worker is stopped even when delivery failed: a shutdown path that
        waits for an unreachable Verifier is a hang, not durability.
        """
        self.flush(timeout_s=timeout_s)
        self._stop.set()
