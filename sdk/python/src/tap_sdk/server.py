"""TAPServer — server-attested provenance middleware [TAP-ASSURANCE].

A tool/resource operator wraps their handler with :meth:`TAPServer.attest`. On each
inbound call the middleware, **before executing**:

  1. verifies the caller's Passport (signature, freshness) against the JWKS,
  2. enforces ``scope_used ⊆ passport.scope`` (drift) and the policy (§9.4),
  3. rejects a duplicate ``(aid, action_ref)`` (replay defense, [TAP-REPLAY]),

then records the handler and signs a **server-attested** Event (``attestor:"server"``)
echoing the caller's ``action_ref`` so the Verifier can join the two legs.

The server signs with its **own** key — that is the whole point: the execution
attestation is independent of (and not forgeable by) the agent.
"""
from __future__ import annotations

import base64
import json
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .core import (
    DEFAULT_ISSUER,
    DEFAULT_TTL_S,
    SPEC_VERSION,
    digest,
    json_digest,
    load_signer,
    new_id,
    now_ts,
    scope_satisfied,
    sign_event,
    text_digest,
    verify_passport,
)
from .negotiate import (
    NegotiationFailed,
    ack_headers,
    hello_from_headers,
    select,
)
from .policy import (
    PolicyDecision,
    PolicyRequest,
    evaluate as evaluate_policy,
)
from .transport import EventReporter, PostFn

KeyResolver = Callable[[str], dict | None]  # kid -> public JWK


class UnattestedAction(RuntimeError):
    """The inbound Passport is missing/invalid — the action is unattested and the
    server MUST NOT infer authority from it ([TAP-SIG-ALG], downgrade defense)."""


class ServerDenied(RuntimeError):
    """The server refused the action *before executing* it (scope or policy).

    Carries the signed server-attested ``denied`` event as evidence."""

    def __init__(self, reason: str, *, code: str, event: dict,
                 decision: PolicyDecision | None = None) -> None:
        self.code = code
        self.event = event
        self.decision = decision
        super().__init__(reason)


def _result_digest(value: Any) -> str | None:
    """A privacy-safe digest of an execution result (for live-replay baselines)."""
    if value is None:
        return None
    try:
        canon = json.dumps(value, separators=(",", ":"), sort_keys=True, default=str).encode()
    except Exception:
        canon = repr(value).encode()
    return digest(canon)


def _peek_kid(compact_jwt: str) -> str | None:
    try:
        h_b64 = compact_jwt.split(".", 1)[0]
        pad = "=" * (-len(h_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(h_b64 + pad)).get("kid")
    except Exception:
        return None


class TAPServer:
    """A TAP-aware Server (the §13 conformance class) that emits server-attested
    Events. Reuses the shared crypto and policy engine, so its decisions are
    byte-for-byte reproducible by the Verifier."""

    def __init__(
        self,
        *,
        server_id: str,
        private_key_hex: str,
        kid: str,
        resolve_key: KeyResolver,
        issuer: str = DEFAULT_ISSUER,
        policy: dict | None = None,
        enforce: bool = True,
        env: str | None = None,
        endpoint: str = "http://localhost:8000",
        api_key: str | None = None,
        post_fn: PostFn | None = None,
        clock_skew_s: int = 60,
        flush_interval_s: float = 2.0,
        replay_ttl_s: int | None = None,
        attests: bool = True,
    ) -> None:
        self.server_id = server_id
        self.kid = kid
        self.issuer = issuer
        self.resolve_key = resolve_key
        self.policy = policy
        self.enforce = enforce
        self.env = env
        self.clock_skew_s = clock_skew_s
        # Whether this server actually signs execution legs. Answering
        # `attestation:"server"` in a handshake and then not signing one produces
        # exactly the `conflicting` state a Verifier holds against the AGENT
        # [TAP-ASSURANCE], so the answer has to come from what we really do.
        self.attests = attests
        self._sk = load_signer(private_key_hex)
        # flush_interval_s: how often the background reporter batches server-attested
        # events to the Verifier (fail-open, [TAP-RESULT-CODES]). Production keeps the
        # default; a lower value trades a little efficiency for a snappier caller-visible
        # two-sided result (e.g. a demo polling for the server leg to land).
        self._reporter = EventReporter(endpoint, post_fn=post_fn, api_key=api_key,
                                       flush_interval_s=flush_interval_s)
        self._seq: dict[str, int] = {}        # per-aid server seq space [TAP-EVT-SEQ]
        # Replay cache [TAP-REPLAY]: keyed on the values whose uniqueness the
        # protocol actually guarantees — the passport `jti` and `(aid, seq)`. It
        # was previously keyed on `action_ref`, which a replayer simply regenerates,
        # so it rejected nothing an attacker could not trivially route around.
        #
        # Entries expire (default: max passport TTL + skew), because a cache that
        # only ever grows is a memory-exhaustion surface reachable by anyone able
        # to mint identifiers — which, on an inbound edge, is everyone.
        self._replay_ttl_s = replay_ttl_s if replay_ttl_s is not None else DEFAULT_TTL_S + clock_skew_s
        self._seen: dict[tuple[str, Any], float] = {}
        self._lock = threading.RLock()  # reentrant: attest() holds it across _emit()

    # --- passport verification -----------------------------------------------

    def _verify_passport(self, passport_jwt: str | None) -> dict:
        if not passport_jwt:
            raise UnattestedAction("no passport on inbound call")
        kid = _peek_kid(passport_jwt)
        jwk = self.resolve_key(kid) if kid else None
        if jwk is None:
            raise UnattestedAction(f"unknown signing key (kid={kid})")
        try:
            return verify_passport(jwk, passport_jwt, now=int(time.time()))
        except Exception as exc:  # invalid signature / expired / wrong typ
            raise UnattestedAction(f"passport invalid: {exc}") from exc

    # --- seq / event construction --------------------------------------------

    def _next_seq(self, aid: str) -> int:
        with self._lock:
            self._seq[aid] = self._seq.get(aid, 0) + 1
            return self._seq[aid]

    def _emit(
        self,
        claims: dict,
        *,
        kind: str,
        intent: str,
        tool: str,
        scope_used: str | None,
        action_ref: str,
        args: Any = None,
        status: str,
        code: str,
        latency_ms: int | None = None,
        error: str | None = None,
        policy_decision: dict | None = None,
        result_digest: str | None = None,
    ) -> dict:
        # Digest-only, exactly like the agent leg [TAP-EVT-ENVELOPE]: the server
        # leg is a peer Event in the same record, not a second format. Raw intent
        # text here would put plaintext — possibly personal data — inside a signed
        # body that survives every erasure request, which is precisely what the
        # annex exists to prevent.
        action: dict[str, Any] = {
            "kind": kind,
            "intent_digest": text_digest(intent),
            "tool": tool,
            "scope_used": scope_used,
        }
        if args is not None:
            # JCS, the same canonicalization the agent leg uses. Sorting keys with
            # json.dumps is NOT the same function: the two legs of one action would
            # digest identical arguments differently, and the correlation that makes
            # two-sided attestation worth anything would silently never match.
            action["args_digest"] = json_digest(args)
        result: dict[str, Any] = {"status": status, "code": code, "error": error}
        if latency_ms is not None:
            result["latency_ms"] = latency_ms
        # The server attests a digest of what it actually returned — the grounded
        # baseline that lets live/shadow replay detect environment drift later.
        if result_digest is not None:
            result["result_digest"] = result_digest

        # Absent optionals are OMITTED, never null [TAP-EVT-OMIT] — `null` and
        # absent are different signed bytes, and the two legs must agree on the
        # envelope shape or their checkpoints will not.
        body: dict[str, Any] = {
            "v": SPEC_VERSION,
            "event_id": new_id("evt"),
            "passport_jti": claims["jti"],
            "aid": claims["aid"],
            "cid": claims["cid"],
            "seq": self._next_seq(claims["aid"]),
            "ts": now_ts(),
            "action": action,
            "result": result,
            "attestor": "server",            # the execution leg [TAP-ASSURANCE]
            "action_ref": action_ref,        # echoed -> correlates with the agent leg
            "kid": self.kid,                 # the SERVER's key, not the agent's
        }
        if policy_decision is not None:
            body["policy_decision"] = policy_decision
        event = sign_event(self._sk, body)
        # The plaintext the digests stand for travels in the unsigned annex
        # [TAP-EVT-ANNEX], where it can be crypto-shredded independently.
        annex: dict[str, Any] = {"event_id": body["event_id"], "intent": intent}
        if args is not None:
            annex["args"] = args
        self._reporter.submit(event, annex)
        return event

    # --- replay defense [TAP-REPLAY] -----------------------------------------

    def _check_replay(self, claims: dict, *, seq: int | None) -> str | None:
        """Return a rejection reason for a replayed inbound call, or None.

        Two independent guarantees, per [TAP-REPLAY]:

        * ``jti`` uniqueness — one passport, one presentation at this edge;
        * ``(aid, seq)`` monotonicity — a sequence slot is used once.

        ``seq`` is optional because a caller need not have told us its sequence
        number; when it is absent the `jti` check still stands on its own. What we
        must NOT do is fall back to `action_ref`, which the caller picks freely.
        """
        now = time.time()
        with self._lock:
            # Expire first, so the cache stays bounded by TTL rather than by uptime.
            if len(self._seen) > 1024:
                cutoff = now - self._replay_ttl_s
                self._seen = {k: v for k, v in self._seen.items() if v > cutoff}

            keys: list[tuple[str, Any]] = [("jti", claims["jti"])]
            if seq is not None:
                keys.append((claims["aid"], seq))

            for key in keys:
                seen_at = self._seen.get(key)
                if seen_at is not None and (now - seen_at) <= self._replay_ttl_s:
                    label = ("passport jti" if key[0] == "jti"
                             else f"(aid, seq) slot {key[1]}")
                    return f"replayed {label}"
            for key in keys:
                self._seen[key] = now
        return None

    # --- handshake [TAP-NEGOTIATE] -------------------------------------------

    def hello_ack(self, hello: dict[str, Any] | None) -> dict[str, Any] | None:
        """Answer a Signer's ``tap_hello``.

        Returns the ack to carry back (``X-TAP-Hello-Ack`` or
        ``_meta.tap.hello_ack``), or None when there was no hello to answer.
        Returns None rather than raising when nothing is mutually supported: per
        [TAP-NEGOTIATE] the parties fall back to unattested operation, and the
        Signer's missing `nego` binding is what makes that visible downstream.
        """
        try:
            return select(hello, attests=self.attests)
        except NegotiationFailed:
            return None

    def hello_ack_headers(self, headers: Any) -> dict[str, str]:
        """Read a hello from inbound HTTP headers and build the response headers."""
        return ack_headers(self.hello_ack(hello_from_headers(headers)))

    # --- the middleware entry point ------------------------------------------

    def attest(
        self,
        *,
        tool: str,
        passport_jwt: str | None,
        action_ref: str,
        execute: Callable[[], Any],
        scope_used: str | None = None,
        arguments: Any = None,
        intent: str | None = None,
        seq: int | None = None,
    ) -> Any:
        """Verify → enforce (pre-execution) → record → sign the execution attestation.

        Returns the handler's result. Raises :class:`UnattestedAction` if the
        passport is missing/invalid, or :class:`ServerDenied` if scope/policy
        blocks the action before it records (the blocked attempt is still recorded
        as a signed server ``denied`` event)."""
        claims = self._verify_passport(passport_jwt)
        scope_used = scope_used if scope_used is not None else f"call:{tool}"
        intent = intent or f"Execute {tool}"

        # Replay defense [TAP-REPLAY]: `jti` uniqueness and (aid, seq) monotonicity.
        replayed = self._check_replay(claims, seq=seq)
        if replayed is not None:
            raise ServerDenied(
                replayed, code="VALIDATION_ERROR",
                event=self._emit(
                    claims, kind="denied", intent=intent, tool=tool,
                    scope_used=scope_used, action_ref=action_ref, args=arguments,
                    status="denied", code="VALIDATION_ERROR", error=replayed),
            )

        # Drift: scope_used must be authorized by the passport ([TAP-SCOPE-MATCH]).
        if self.enforce and not scope_satisfied(scope_used, claims.get("scope", [])):
            ev = self._emit(
                claims, kind="denied", intent=intent, tool=tool, scope_used=scope_used,
                action_ref=action_ref, args=arguments, status="denied",
                code="DENIED_SCOPE", error="scope not in passport")
            raise ServerDenied(f"scope {scope_used!r} not in passport",
                               code="DENIED_SCOPE", event=ev)

        # Policy (§9.4) evaluated at the server leg — pre-execution prevention.
        pd: PolicyDecision | None = None
        if self.policy is not None:
            meta = claims.get("meta") or {}
            req = PolicyRequest(
                tool=tool, scope_used=scope_used, kind="tool_call",
                agent_name=meta.get("agent_name"),
                args=arguments if isinstance(arguments, dict) else None, env=self.env,
            )
            pd = evaluate_policy(self.policy, req)
            if pd.denied and self.enforce:
                ev = self._emit(
                    claims, kind="denied", intent=intent, tool=tool, scope_used=scope_used,
                    action_ref=action_ref, args=arguments, status="denied",
                    code="DENIED_POLICY", policy_decision=pd.to_record())
                raise ServerDenied(f"policy denied {tool!r}", code="DENIED_POLICY",
                                   event=ev, decision=pd)

        # Permitted → execute and attest the real outcome.
        t0 = time.monotonic()
        status, code, error, result = "success", "OK", None, None
        try:
            result = execute()
            return result
        except Exception as exc:
            status, code, error = "failure", "TOOL_ERROR", str(exc)
            raise
        finally:
            self._emit(
                claims, kind="tool_call", intent=intent, tool=tool,
                scope_used=scope_used, action_ref=action_ref, args=arguments,
                status=status, code=code, error=error,
                latency_ms=round((time.monotonic() - t0) * 1000),
                policy_decision=pd.to_record() if pd is not None else None,
                result_digest=_result_digest(result) if status == "success" else None,
            )

    def flush(self) -> None:
        self._reporter.flush()

    def close(self) -> None:
        self._reporter.close()
