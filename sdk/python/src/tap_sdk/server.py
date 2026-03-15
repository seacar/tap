"""TAPServer — server-attested provenance middleware (build spec §9.1).

A tool/resource operator wraps their handler with :meth:`TAPServer.attest`. On each
inbound call the middleware, **before executing**:

  1. verifies the caller's Passport (signature, freshness) against the JWKS,
  2. enforces ``scope_used ⊆ passport.scope`` (drift) and the policy (§9.4),
  3. rejects a duplicate ``(aid, action_ref)`` (replay defense, TAP-spec §7.2),

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
    SPEC_VERSION,
    digest,
    load_signer,
    new_id,
    now_ts,
    scope_satisfied,
    sign_event,
    verify_passport,
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
    server MUST NOT infer authority from it (TAP-spec §12, downgrade defense)."""


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
    ) -> None:
        self.server_id = server_id
        self.kid = kid
        self.issuer = issuer
        self.resolve_key = resolve_key
        self.policy = policy
        self.enforce = enforce
        self.env = env
        self.clock_skew_s = clock_skew_s
        self._sk = load_signer(private_key_hex)
        # flush_interval_s: how often the background reporter batches server-attested
        # events to the Verifier (fail-open, TAP-spec §10). Production keeps the
        # default; a lower value trades a little efficiency for a snappier caller-visible
        # two-sided result (e.g. a demo polling for the server leg to land).
        self._reporter = EventReporter(endpoint, post_fn=post_fn, api_key=api_key,
                                       flush_interval_s=flush_interval_s)
        self._seq: dict[str, int] = {}        # per-aid server seq space (TAP-spec §5.3/§6)
        self._seen: set[tuple[str, str]] = set()  # (aid, action_ref) replay cache
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
        action: dict[str, Any] = {
            "kind": kind, "intent": intent, "tool": tool, "scope_used": scope_used,
        }
        if args is not None:
            canon = json.dumps(args, separators=(",", ":"), sort_keys=True).encode()
            action["args_digest"] = digest(canon)
        result: dict[str, Any] = {"status": status, "code": code,
                                  "latency_ms": latency_ms, "error": error}
        # The server attests a digest of what it actually returned — the grounded
        # baseline that lets live/shadow replay detect environment drift later.
        if result_digest is not None:
            result["result_digest"] = result_digest
        body: dict[str, Any] = {
            "v": SPEC_VERSION,
            "event_id": new_id("evt"),
            "passport_jti": claims["jti"],
            "aid": claims["aid"],
            "cid": claims["cid"],
            "seq": self._next_seq(claims["aid"]),
            "ts": now_ts(),
            "action": action,
            "evidence": {"reasoning": None, "model_output_digest": None},
            "result": result,
            "attestor": "server",            # the execution leg (TAP-spec §6)
            "action_ref": action_ref,        # echoed → correlates with the agent leg
            "parent_event_id": None,
            "policy_decision": policy_decision,
            "kid": self.kid,                 # the SERVER's key, not the agent's
        }
        event = sign_event(self._sk, body)
        self._reporter.submit(event)
        return event

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
    ) -> Any:
        """Verify → enforce (pre-execution) → record → sign the execution attestation.

        Returns the handler's result. Raises :class:`UnattestedAction` if the
        passport is missing/invalid, or :class:`ServerDenied` if scope/policy
        blocks the action before it records (the blocked attempt is still recorded
        as a signed server ``denied`` event)."""
        claims = self._verify_passport(passport_jwt)
        scope_used = scope_used if scope_used is not None else f"call:{tool}"
        intent = intent or f"Execute {tool}"

        # Replay defense (TAP-spec §7.2): reject a duplicate (aid, action_ref).
        key = (claims["aid"], action_ref)
        with self._lock:
            if key in self._seen:
                raise ServerDenied(
                    f"replayed action_ref {action_ref}", code="VALIDATION_ERROR",
                    event=self._emit(
                        claims, kind="denied", intent=intent, tool=tool,
                        scope_used=scope_used, action_ref=action_ref, args=arguments,
                        status="denied", code="VALIDATION_ERROR",
                        error="duplicate action_ref (replay)"),
                )
            self._seen.add(key)

        # Drift: scope_used must be authorized by the passport (TAP-spec §8).
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
