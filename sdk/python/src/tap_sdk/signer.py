"""The TAPClient signer SDK — mint passports, sign provenance events & decisions.

    from tap_sdk import TAPClient

    signer = TAPClient(agent_id="support-triage", private_key_hex=SEED, kid=KID,
                  api_key="tap_live_...", endpoint="https://your-verifier.example.com")
    passport = signer.issue_passport(task_prompt=request, scope=["read:database"])

    @signer.trace(tool="db_query", scope="read:database")
    def db_query(table, limit): ...

    signer.decision(question="...", options=[...], chosen="refund")
"""
from __future__ import annotations

import base64
import functools
import json
import queue
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable

from .core import (
    DEFAULT_ISSUER,
    DEFAULT_TTL_S,
    SPEC_VERSION,
    checkpoint_root,
    cid_from_prompt,
    digest,
    json_digest,
    load_signer,
    new_id,
    new_nonce,
    now_ts,
    sign_event,
    public_jwk,
    sign_passport,
    suite_for_jwk,
    text_digest,
    verify_passport,
)
from .negotiate import (
    Negotiated,
    hello_headers,
    offer as build_hello,
    read_ack,
)
from .policy import PolicyDecision, PolicyRequest, evaluate as _evaluate_policy
from .authority import Authorization, AuthorityExpired, check_authority_window

PostFn = Callable[[str, dict, dict], None]

_VALID_ATTESTATION = {"requested", "server", "none"}


def _suite_id() -> str:
    """The suite this build signs with [TAP-SUITE-DISPATCH]. v0.1 has exactly one."""
    return "tap-ed25519"


class DelegationRejected(RuntimeError):
    """Raised when a receiving agent refuses an inbound A2A delegation — a bad
    signature, an expired or forged passport, or a replay (spec §8, [TAP-REPLAY]).

    A2A's base spec accepts delegated work without verifying the sender. This
    rejection *is* the guarantee TAP adds: a broken handoff breaks the chain
    visibly rather than being silently bridged."""


def _peek_jwt_kid(compact_jwt: str) -> str | None:
    """Read the ``kid`` from a compact JWT header **without** verifying it.

    Used only to look up which key to verify *with* — never to make a trust
    decision. The header is attacker-controlled until the signature checks out.
    """
    try:
        h_b64 = compact_jwt.split(".", 1)[0]
        pad = "=" * (-len(h_b64) % 4)
        return json.loads(base64.urlsafe_b64decode(h_b64 + pad)).get("kid")
    except Exception:
        return None


class PolicyDenied(RuntimeError):
    """Raised when inline enforcement blocks an action before it executes
    [TAP-POLICY-RECORD]. The blocked attempt is still recorded as a signed
    ``denied`` event — TAPClient stops the action *and* keeps the evidence."""

    def __init__(self, decision: PolicyDecision, *, tool: str) -> None:
        self.decision = decision
        self.tool = tool
        super().__init__(
            f"action on {tool!r} denied by policy "
            f"(rule={decision.rule_id}, policy_version={decision.policy_version})"
        )


def _urllib_post(url: str, payload: dict, headers: dict) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=data, method="POST",
        headers={"Content-Type": "application/json", **headers},
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        resp.read()


class _Reporter:
    """Async, buffered, fail-open event transport (never blocks the agent).

    Each queued item is a ``(event, annex | None)`` pair. Annexes are the
    unsigned plaintext companions to digest-only signed bodies ([TAP-EVT-ANNEX],
    spec §11.3). They travel in the same HTTP batch as their events so the Verifier
    can index them without a second round-trip.
    """

    def __init__(self, endpoint: str, *, api_key: str | None, post_fn: PostFn | None,
                 batch_size: int = 50, flush_interval_s: float = 2.0) -> None:
        self._url = endpoint.rstrip("/") + "/v1/events"
        self._post = post_fn or _urllib_post
        self._headers = {"X-API-Key": api_key} if api_key else {}
        self._batch = batch_size
        self._interval = flush_interval_s
        self._q: queue.Queue[tuple[dict, dict | None]] = queue.Queue(maxsize=10_000)
        self._passport_jwt: str | None = None
        self._stop = threading.Event()
        self.dropped = 0
        threading.Thread(target=self._run, name="tap-reporter", daemon=True).start()

    def set_passport(self, jwt: str) -> None:
        self._passport_jwt = jwt

    def submit(self, event: dict, annex: dict | None = None) -> None:
        try:
            self._q.put_nowait((event, annex))
        except queue.Full:
            try:
                self._q.get_nowait(); self.dropped += 1; self._q.put_nowait((event, annex))
            except queue.Empty:
                pass

    def _drain(self) -> list[tuple[dict, dict | None]]:
        out: list[tuple[dict, dict | None]] = []
        while len(out) < self._batch:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                break
        return out

    def _send(self, batch: list[tuple[dict, dict | None]]) -> None:
        events = [ev for ev, _ in batch]
        annexes = [ax for _, ax in batch if ax is not None]
        payload: dict = {"events": events}
        if annexes:
            payload["annexes"] = annexes  # spec §11.3
        if self._passport_jwt:
            payload["passport"] = self._passport_jwt
        try:
            self._post(self._url, payload, self._headers)
        except Exception:
            for pair in batch:
                self.submit(*pair)  # re-queue on failure; fail-open

    def _run(self) -> None:
        while not self._stop.is_set():
            time.sleep(self._interval)
            batch = self._drain()
            if batch:
                self._send(batch)

    def flush(self) -> None:
        while True:
            batch = self._drain()
            if not batch:
                return
            self._send(batch)

    def close(self) -> None:
        self.flush(); self._stop.set()


@dataclass
class Passport:
    compact: str
    claims: dict
    # The assurance level asserted for this record. When a real handshake happens
    # this is overwritten by the observed `tap_hello_ack` (see `record_ack`);
    # otherwise it is what the caller asserted at mint time [TAP-NEGO-BINDING].
    attestation: str = "none"
    #: The observed handshake outcome, when there was one. Preferred over
    #: `attestation` for the `nego` binding, because it is evidence rather than
    #: configuration.
    negotiated: Negotiated | None = None
    _seq: int = field(default=0, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    # Tracks event_ids emitted since the last checkpoint for Merkle construction
    # [TAP-EVT-CHECKPOINT].
    _event_ids: list[str] = field(default_factory=list, repr=False)
    _last_cp_count: int = field(default=0, repr=False)
    _last_cp_through_seq: int = field(default=0, repr=False)
    _nego_emitted: bool = field(default=False, repr=False)

    @property
    def jti(self) -> str: return self.claims["jti"]
    @property
    def aid(self) -> str: return self.claims["aid"]
    @property
    def cid(self) -> str: return self.claims["cid"]
    @property
    def scope(self) -> list[str]: return self.claims["scope"]

    def next_seq(self) -> int:
        with self._lock:
            self._seq += 1
            return self._seq

    def _track_event(self, event_id: str) -> None:
        """Record an emitted event_id for checkpoint Merkle construction (§6.3)."""
        with self._lock:
            self._event_ids.append(event_id)

    def record_ack(self, ack: dict[str, Any] | None) -> Negotiated | None:
        """Record the ``tap_hello_ack`` observed from a TAP-aware Server.

        This is the honest input to the anti-downgrade binding: what the Signer
        was actually told, as opposed to what its operator hoped for. An absent or
        unusable ack leaves the passport unnegotiated, which is itself the correct
        signal — a stripped handshake produces no ack, so no `nego` is bound, and
        the record is labelled intent-only [TAP-NEGO-BINDING].
        """
        outcome = read_ack(ack)
        if outcome is not None:
            with self._lock:
                self.negotiated = outcome
                self.attestation = outcome.attestation
        return outcome

    def nego(self) -> dict[str, str] | None:
        """The value to bind into ``evidence.nego``, or None to bind nothing.

        Prefers an observed handshake outcome over an asserted one. Returns None
        for ``attestation:"none"``, so an unnegotiated record stays silent rather
        than claiming intent-only assurance it was never promised."""
        if self.negotiated is not None:
            return self.negotiated.as_nego()
        if self.attestation == "none":
            return None
        return {"version": SPEC_VERSION, "suite": _suite_id(),
                "attestation": self.attestation}

    def http_headers(self, action_ref: str | None = None, *,
                     hello: dict[str, Any] | None = None) -> dict[str, str]:
        """Passport carriage for HTTP transport (spec §11.1).

        Sits alongside any ``Authorization`` header — TAP adds provenance, it
        does not replace access control. Pass ``hello`` on the first request of a
        session to carry the handshake [TAP-NEGOTIATE]."""
        h = {"X-Agent-Passport": self.compact}
        if action_ref:
            h["X-TAP-Action-Ref"] = action_ref
        if hello:
            h.update(hello_headers(hello))
        return h

    def meta(self, action_ref: str | None = None, *,
             hello: dict[str, Any] | None = None) -> dict[str, Any]:
        """Passport carriage for JSON-RPC ``_meta`` transport (spec §11.2).

        The binding for stdio MCP and A2A Tasks/Messages, where no HTTP headers
        exist. The same signed bytes verify identically either way. ``hello`` is
        included only on the first request of a session."""
        tap: dict[str, Any] = {"passport": self.compact}
        if action_ref:
            tap["action_ref"] = action_ref
        if hello:
            tap["hello"] = hello
        return {"tap": tap}


class TAPClient:
    def __init__(self, *, agent_id: str, private_key_hex: str, kid: str,
                 endpoint: str = "http://localhost:8000", issuer: str = DEFAULT_ISSUER,
                 api_key: str | None = None, framework: str | None = None,
                 model: str | None = None, capture_previews: bool = False,
                 post_fn: PostFn | None = None, policy: dict | None = None,
                 enforce: bool = False, env: str | None = None) -> None:
        self.agent_id = agent_id
        self.kid = kid
        self.issuer = issuer
        self.framework = framework
        self.model = model
        self.capture_previews = capture_previews
        # Policy-as-code [TAP-POLICY-RECORD]: ``enforce`` denies before acting.
        self.policy = policy
        self.enforce = enforce
        self.env = env
        self._sk = load_signer(private_key_hex)
        # Cache the negotiated crypto suite once ([TAP-SUITE-DISPATCH]) — the shape
        # bound into evidence.nego on the first event of each record (§4.1).
        self._suite = suite_for_jwk(public_jwk(self._sk, self.kid))
        self._reporter = _Reporter(endpoint, api_key=api_key, post_fn=post_fn)
        self._passport: Passport | None = None
        # Inbound-delegation replay cache [TAP-REPLAY]: (sender jti, action_ref).
        self._a2a_seen: set[tuple[str, Any]] = set()
        self._a2a_lock = threading.Lock()

    # --- passport -------------------------------------------------------------

    def issue_passport(self, *, task_prompt: str, scope: list[str],
                       ttl_s: int = DEFAULT_TTL_S, attestation: str = "none",
                       cid: str | None = None) -> Passport:
        """Mint a passport at the start of a record ([TAP-PASSPORT-LIFECYCLE]).

        ``attestation`` declares the assurance level this record expects to
        achieve — ``"server"`` when a TAPServer/Gateway sits in front of the
        tools, ``"requested"`` when one was merely asked for, or the default
        ``"none"`` for intent-only operation. It is bound into ``evidence.nego``
        on the first Event of the record (§4.1) so a Verifier can detect a
        downgrade: a Signer that claimed ``"server"`` but for which no server
        leg ever arrives is flagged identically to a conflicting attestation
        (§7). The default is conservative because nothing here can observe
        whether a real handshake occurred — claiming ``"server"`` is an explicit
        opt-in by the caller, not inferred.

        Pass ``cid`` to join an existing record rather than open a new one —
        this is how a receiving agent shares the delegator's context id so both
        sides of an A2A handoff land in a single verifiable chain (§8).
        """
        if attestation not in _VALID_ATTESTATION:
            raise ValueError(
                f"attestation must be one of {sorted(_VALID_ATTESTATION)}, got {attestation!r}"
            )
        now = int(time.time())
        claims = {
            "iss": self.issuer, "iat": now, "exp": now + ttl_s,
            "jti": new_id("psp"), "aid": new_id("agt"),
            # nonce ≥128 bits — §3.3: prevents cid collision and oracle attacks
            "cid": cid or cid_from_prompt(task_prompt, new_nonce()),
            "scope": list(scope),
            "meta": {k: v for k, v in {"framework": self.framework, "model": self.model,
                                       "agent_name": self.agent_id}.items() if v is not None},
        }
        passport = Passport(compact=sign_passport(self._sk, self.kid, claims), claims=claims,
                            attestation=attestation)
        self._passport = passport
        self._reporter.set_passport(passport.compact)
        return passport

    # --- handshake [TAP-NEGOTIATE] -------------------------------------------

    def hello(self, *, attestation: str = "requested") -> dict[str, Any]:
        """Build the ``tap_hello`` to send on the first request of a session.

        Carry it with ``passport.http_headers(hello=...)`` or
        ``passport.meta(hello=...)``, then feed whatever comes back to
        :meth:`negotiate`.
        """
        return build_hello(kid=self.kid, attestation=attestation)

    def negotiate(self, ack: dict[str, Any] | None,
                  passport: Passport | None = None) -> Negotiated | None:
        """Record the Server's ``tap_hello_ack`` against the current record.

        Returns the negotiated outcome, or None when no usable ack arrived — the
        case a stripped handshake produces. Callers do not need to branch on it:
        an unnegotiated record simply binds no ``nego`` and is labelled
        intent-only, which is the honest outcome [TAP-NEGO-BINDING].
        """
        return self._require(passport).record_ack(ack)

    def _require(self, p: Passport | None) -> Passport:
        p = p or self._passport
        if p is None:
            raise RuntimeError("no passport — call issue_passport() first")
        return p

    # --- policy [TAP-POLICY-RECORD] ---------------------------------------

    def set_policy(self, policy: dict | None, *, enforce: bool | None = None) -> None:
        self.policy = policy
        if enforce is not None:
            self.enforce = enforce

    def _decide(self, *, kind: str, tool: str, scope_used: str | None,
                args: Any) -> PolicyDecision | None:
        if self.policy is None:
            return None
        req = PolicyRequest(
            tool=tool, scope_used=scope_used, kind=kind,
            agent_name=self.agent_id, agent_id=self.agent_id,
            args=args if (self.capture_previews and isinstance(args, dict)) else None,
            env=self.env,
        )
        return _evaluate_policy(self.policy, req)

    # --- authority binding [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL] ---------
    # Stateless half only: minting an approval and checking its validity window.
    # Revocation and single-use enforcement are stateful and live on the
    # Verifier, not here — see tap_sdk.authority's module docstring.

    def authorize(self, *, target_state: dict, authority_state: dict,
                  ttl_s: int = DEFAULT_TTL_S, issuer_kid: str | None = None,
                  authz_id: str | None = None) -> Authorization:
        """Mint a bound approval for an action not yet taken.

        ``target_state`` is the expected resulting state (digested here, never
        signed in the raw); ``authority_state`` is the policy/permission state
        this approval was granted under (digested the same way
        ``policy_version`` digests a policy set). Pass the returned
        :class:`Authorization` to :meth:`trace` via its ``authorize=`` kwarg.
        """
        now = int(time.time())
        return Authorization.grant(
            target_state=target_state, authority_state=authority_state,
            nbf=now, exp=now + ttl_s,
            issuer_kid=issuer_kid or self.kid, authz_id=authz_id,
        )

    # --- event signing --------------------------------------------------------

    def _emit(self, passport: Passport, *, kind: str, intent: str, tool: str,
              scope_used: str | None, args: Any = None, reasoning: str | None = None,
              model_output: str | None = None, status: str = "success", code: str = "OK",
              latency_ms: int | None = None, error: str | None = None,
              action_ref: str | None = None, attestor: str = "agent",
              parent_event_id: str | None = None, decision: dict | None = None,
              policy_decision: dict | None = None,
              authorization: dict | None = None, effect_digest: str | None = None,
              extra_annex: dict | None = None) -> dict:
        """Sign one event with a digest-only body ([TAP-EVT-ENVELOPE]).

        Plaintext ``intent``, ``args``, and ``reasoning`` go into an unsigned,
        crypto-shreddable annex (§6.1.1) rather than the signed body. Only their
        SHA-256 digests are signed, so annexes can be deleted for GDPR erasure
        without breaking the provenance chain.
        """
        event_id = new_id("evt")

        # Digest-only action block — no plaintext in the signed body
        action: dict[str, Any] = {
            "kind": kind,
            "intent_digest": text_digest(intent),
            "tool": tool,
            "scope_used": scope_used,
        }

        # Annex: unsigned plaintext companion, keyed by event_id (§6.1.1)
        annex: dict[str, Any] = {"event_id": event_id, "intent": intent}

        if args is not None:
            action["args_digest"] = json_digest(args)
            annex["args"] = args  # plaintext in annex only — never in signed body

        evidence: dict[str, Any] = {}
        if reasoning is not None:
            evidence["reasoning_digest"] = text_digest(reasoning)
            annex["reasoning"] = reasoning
        if model_output is not None:
            evidence["model_output_digest"] = text_digest(model_output)

        # Bind the negotiated outcome into the FIRST Event of the record, once
        # [TAP-NEGO-BINDING]. Guarded by the same lock next_seq() uses, so
        # "assign my seq" and "claim the nego slot" happen atomically —
        # concurrent emitters can't both think they're first.
        #
        # `passport.nego()` prefers the ack actually observed from the Server over
        # anything the caller asserted at mint time, and returns None when there is
        # nothing honest to say. A stripped handshake therefore yields no binding
        # at all, which is exactly the signal a Verifier needs.
        nego = passport.nego()
        if nego is not None:
            with passport._lock:
                if not passport._nego_emitted:
                    passport._nego_emitted = True
                    evidence["nego"] = nego

        if extra_annex:
            annex.update(extra_annex)

        # Absent optional fields are OMITTED, never emitted as explicit nulls —
        # the reference implementation's envelope shape, and the only rule that
        # keeps the canonical form deterministic. `null` and absent are different
        # signed bytes, so two Signers that disagree here produce structurally
        # different events for logically identical actions.
        result: dict[str, Any] = {"status": status, "code": code, "error": error}
        if latency_ms is not None:
            result["latency_ms"] = latency_ms
        if effect_digest is not None:
            # [TAP-AUTHORITY-EFFECT, §9.2, provisional] — omit when unmeasured,
            # never null, matching every other optional field's omit discipline.
            result["effect_digest"] = effect_digest

        body: dict[str, Any] = {
            "v": SPEC_VERSION, "event_id": event_id, "passport_jti": passport.jti,
            "aid": passport.aid, "cid": passport.cid, "seq": passport.next_seq(),
            "ts": now_ts(), "action": action,
            "result": result,
            "attestor": attestor, "action_ref": action_ref or new_id("act"),
            "kid": self.kid,
        }
        if evidence:
            body["evidence"] = evidence
        if parent_event_id is not None:
            body["parent_event_id"] = parent_event_id
        if policy_decision is not None:
            body["policy_decision"] = policy_decision
        if authorization is not None:
            # [TAP-EVT-AUTHORIZATION, §9.2, provisional]
            body["authorization"] = authorization
        if decision is not None:
            body["decision"] = decision
        event = sign_event(self._sk, body)
        passport._track_event(event_id)
        # Only ship the annex when it has content beyond the event_id marker
        has_annex_content = len(annex) > 1
        self._reporter.submit(event, annex if has_annex_content else None)
        return event

    # Public alias for the signing path. Tooling that composes its own events
    # (the Inspector, test harnesses, custom framework adapters) should go
    # through this rather than reimplementing the envelope — there must be
    # exactly one place that decides what a signed Event looks like.
    emit_event = _emit

    # --- public surface -------------------------------------------------------

    def trace(self, *, tool: str, scope: str, kind: str = "tool_call",
              intent: str | None = None, authorize: Authorization | None = None,
              effect_of: Callable[[Any], Any] | None = None):
        """Wrap ``fn`` in a signed provenance record.

        ``authorize`` binds this call to a pre-declared expected effect
        [TAP-EVT-AUTHORIZATION, §9.2, provisional]: its validity window is
        checked *before* ``fn`` runs — an expired approval blocks the call
        exactly like a policy denial does — and if ``effect_of`` is given, the
        digest of ``effect_of(fn's return value)`` is compared against the
        approval's declared ``target_state_digest`` and recorded as
        ``result.effect_digest``. Omit ``effect_of`` to still bind and validate
        the approval without asserting a specific effect (the Event is then
        labeled ``unverified_authority`` downstream).
        """
        def deco(fn: Callable) -> Callable:
            @functools.wraps(fn)
            def wrap(*a, **kw):
                p = self._require(None)
                call_args = {"args": list(a), "kwargs": kw}

                # Enforcement point: deny *before acting* [TAP-POLICY-RECORD].
                pd = self._decide(kind=kind, tool=tool, scope_used=scope, args=kw)
                if pd is not None and pd.denied and self.enforce:
                    self._emit(p, kind="denied", intent=intent or f"Call {tool}",
                               tool=tool, scope_used=scope, args=call_args,
                               status="denied", code="DENIED_POLICY",
                               policy_decision=pd.to_record())
                    raise PolicyDenied(pd, tool=tool)

                # Second, independent enforcement point: deny *before acting*
                # when the bound approval has expired [TAP-AUTHORITY-VALIDITY].
                # Revocation/reuse are NOT checked here — they are stateful and
                # belong to the Verifier (§9.2, provisional).
                if authorize is not None:
                    try:
                        check_authority_window(authorize, now=int(time.time()))
                    except AuthorityExpired:
                        self._emit(p, kind="denied", intent=intent or f"Call {tool}",
                                   tool=tool, scope_used=scope, args=call_args,
                                   status="denied", code="DENIED_AUTHORITY_EXPIRED",
                                   policy_decision=pd.to_record() if pd is not None else None,
                                   authorization=authorize.to_record())
                        raise

                t0 = time.monotonic()
                status, code, error = "success", "OK", None
                effect_digest = None
                try:
                    ret = fn(*a, **kw)
                    if authorize is not None and effect_of is not None:
                        effect_digest = json_digest(effect_of(ret))
                    return ret
                except Exception as exc:
                    status, code, error = "failure", "TOOL_ERROR", str(exc)
                    raise
                finally:
                    self._emit(p, kind=kind, intent=intent or f"Call {tool}", tool=tool,
                               scope_used=scope, args=call_args,
                               status=status, code=code, error=error,
                               latency_ms=round((time.monotonic() - t0) * 1000),
                               policy_decision=pd.to_record() if pd is not None else None,
                               authorization=authorize.to_record() if authorize is not None else None,
                               effect_digest=effect_digest)
            return wrap
        return deco

    def decision(self, *, question: str, options: list[dict], chosen: str,
                 scope_used: str | None = None, selection: str | None = None,
                 reasoning: str | None = None, decision_key: str = "decision",
                 passport: Passport | None = None) -> dict:
        """Record a decision AND the alternatives not taken ([TAP-EVT-DECISION]).

        The signed body carries only digests; plaintext question and option
        rationale/reason go to the annex. Scores MUST be strings (§3.4).
        """
        p = self._require(passport)
        if chosen not in [o["id"] for o in options]:
            raise ValueError(f"chosen={chosen!r} not among options")

        norm: list[dict[str, Any]] = []
        annex_options: list[dict[str, Any]] = []

        for o in options:
            is_chosen = o["id"] == chosen
            item: dict[str, Any] = {"id": o["id"], "chosen": is_chosen}

            # Score MUST be a string per §3.4 (no fractional numbers in signed body)
            if o.get("score") is not None:
                item["score"] = str(o["score"])

            annex_opt: dict[str, Any] = {"id": o["id"]}
            if o.get("summary"):
                annex_opt["summary"] = o["summary"]
            if is_chosen:
                text = o.get("rationale") or o.get("reason")
                if text:
                    item["rationale_digest"] = text_digest(text)
                    annex_opt["rationale"] = text
            else:
                reason = o.get("reason")
                if reason:
                    item["reason_digest"] = text_digest(reason)
                    annex_opt["reason"] = reason

            norm.append(item)
            if len(annex_opt) > 1:
                annex_options.append(annex_opt)

        block: dict[str, Any] = {
            "question_digest": text_digest(question),
            "chosen": chosen,
            "options": norm,
            "options_digest": json_digest(norm),  # MUST per §6.4
        }
        if selection:
            block["selection"] = selection

        # Plaintext question + option text → annex (erasable, §6.1.1)
        extra_annex: dict[str, Any] = {}
        if annex_options:
            extra_annex["decision"] = {"question": question, "options": annex_options}

        return self._emit(p, kind="decision", intent=question, tool=decision_key,
                          scope_used=scope_used, reasoning=reasoning, decision=block,
                          extra_annex=extra_annex or None)

    def emit_checkpoint(self, passport: Passport | None = None) -> dict:
        """Emit a signed checkpoint event sealing the current record segment ([TAP-EVT-CHECKPOINT]).

        Builds the Merkle root over all event_ids emitted since the previous
        checkpoint (or since the passport was issued). The signed ``checkpoint``
        block lets verifiers distinguish provably-deleted events from benign
        sequence gaps — turning fail-open reporting safe.
        """
        p = self._require(passport)
        with p._lock:
            interval_ids = p._event_ids[p._last_cp_count:]
            from_seq = p._last_cp_through_seq   # exclusive lower bound; 0 for the first
            through_seq = p._seq                # highest seq before this checkpoint
            count = len(interval_ids)
            p._last_cp_count = len(p._event_ids)
            p._last_cp_through_seq = through_seq

        root = checkpoint_root(interval_ids)
        cp_seq = p.next_seq()

        body: dict[str, Any] = {
            "v": SPEC_VERSION,
            "event_id": new_id("evt"),
            "passport_jti": p.jti,
            "aid": p.aid,
            "cid": p.cid,
            "seq": cp_seq,
            "ts": now_ts(),
            "action": {"kind": "checkpoint", "tool": None, "scope_used": None},
            "checkpoint": {
                # The interval is half-open and self-describing: (from_seq,
                # through_seq]. Carrying the lower bound in the signed body is what
                # lets a Verifier reconcile this checkpoint alone, without
                # reconstructing the state of whichever checkpoint preceded it —
                # and without mis-scoping the interval when an earlier checkpoint
                # was lost or suppressed [TAP-EVT-CHECKPOINT].
                "from_seq": from_seq,
                "through_seq": through_seq,
                "event_id_root": root,
                "count": count,
            },
            "result": {"status": "success", "code": "OK", "error": None},
            "attestor": "agent",
            "kid": self.kid,
        }
        event = sign_event(self._sk, body)
        self._reporter.submit(event, None)  # checkpoints carry no annex
        return event

    def record_output(
        self,
        *,
        output: Any,
        intent: str = "Agent response",
        scope_used: str | None = None,
        reasoning: str | None = None,
        passport: Passport | None = None,
    ) -> dict:
        """Sign a model-response event (output digest + optional reasoning)."""
        p = self._require(passport)
        text = output if isinstance(output, str) else json.dumps(output, default=str)
        return self._emit(
            p,
            kind="model_response",
            intent=intent,
            tool="agent.record",
            scope_used=scope_used,
            reasoning=reasoning,
            model_output=text,
        )

    # --- MCP: instrument an existing client (spec §11.2) ------------------

    def instrument_mcp(self, mcp_client: Any, *, passport: Passport | None = None) -> Any:
        """Wrap an MCP client's ``call_tool`` so every ``tools/call`` attaches
        the passport and emits a signed ``tool_call`` event.

        Wraps the common ``call_tool(name, arguments)`` shape; real MCP clients
        vary, so pin the exact method per client if yours differs. The signing
        path is identical to :meth:`trace` — this is a convenience seam, not a
        second implementation.
        """
        p = self._require(passport)
        original = getattr(mcp_client, "call_tool", None)
        if original is None or not callable(original):
            raise TypeError("mcp_client has no callable call_tool(name, arguments)")

        @functools.wraps(original)
        def wrapped(name: str, arguments: dict | None = None, *a, **kw):
            action_ref = new_id("act")
            scope_used = f"call:{name}"

            # Enforcement point: deny *before* the tool runs.
            pd = self._decide(kind="tool_call", tool=name,
                              scope_used=scope_used, args=arguments)
            if pd is not None and pd.denied and self.enforce:
                self._emit(p, kind="denied", intent=f"Call MCP tool {name}",
                           tool=name, scope_used=scope_used, args=arguments or {},
                           status="denied", code="DENIED_POLICY",
                           action_ref=action_ref, policy_decision=pd.to_record())
                raise PolicyDenied(pd, tool=name)

            t0 = time.monotonic()
            status, code, error = "success", "OK", None
            try:
                return original(name, arguments, *a, **kw)
            except Exception as exc:
                status, code, error = "failure", "TOOL_ERROR", str(exc)
                raise
            finally:
                self._emit(p, kind="tool_call", intent=f"Call MCP tool {name}",
                           tool=name, scope_used=scope_used, args=arguments or {},
                           status=status, code=code, error=error,
                           latency_ms=round((time.monotonic() - t0) * 1000),
                           action_ref=action_ref,
                           policy_decision=pd.to_record() if pd is not None else None)

        mcp_client.call_tool = wrapped  # type: ignore[attr-defined]
        return mcp_client

    # --- A2A: outbound delegation (spec §8.1) ---------------------------------

    def sign_a2a_delegation(self, *, target_agent: str, intent: str,
                            scope_used: str = "delegate:agent", task_payload: Any = None,
                            passport: Passport | None = None) -> tuple[dict, dict]:
        """Sign an outbound A2A delegation.

        Returns ``(event, meta)`` — the signed ``agent_delegate`` event, and the
        ``_meta`` block to attach to the A2A Task/Message. The carriage conveys
        the ``cid`` and this event's id so the receiver can mint a same-``cid``
        passport and link its ``received_delegation`` via ``parent_event_id``,
        joining both sides into one chain (§8).
        """
        p = self._require(passport)
        action_ref = new_id("act")
        event = self._emit(p, kind="agent_delegate", intent=intent, tool=target_agent,
                           scope_used=scope_used, args=task_payload,
                           action_ref=action_ref)
        meta = p.meta(action_ref=action_ref)
        meta["tap"]["parent_event_id"] = event["event_id"]
        meta["tap"]["cid"] = p.cid
        return event, meta

    # --- A2A: inbound delegation, verified before the work starts -------------

    def accept_a2a_delegation(
        self,
        *,
        meta: dict,
        sender_passport_jwt: str,
        resolve_key: Callable[[str], dict | None],
        scope: list[str],
        intent: str | None = None,
        task_prompt: str = "",
        now: int | None = None,
        attestation: str = "none",
    ) -> Passport:
        """Verify and accept an inbound A2A delegation, then attest acceptance.

        This closes the gap A2A leaves open: the receiving specialist verifies
        *who* delegated, and that the delegation is fresh and not replayed,
        **before** doing the work. On success it mints its own passport sharing
        the delegator's ``cid`` and emits a signed ``received_delegation`` event
        linked via ``parent_event_id`` — so the two sides of the handoff are
        cryptographically joined rather than merely adjacent in a log.

        Raises :class:`DelegationRejected` on a bad signature, expiry, unknown
        key, or replay. The rejection is the point: a handoff that cannot be
        verified must break the chain visibly (§8).
        """
        tap = (meta or {}).get("tap") or {}

        # 1. Verify the sender's passport against the JWKS (signature + freshness).
        kid = _peek_jwt_kid(sender_passport_jwt)
        jwk = resolve_key(kid) if kid else None
        if jwk is None:
            raise DelegationRejected(f"unknown sender key (kid={kid})")
        try:
            sender_claims = verify_passport(jwk, sender_passport_jwt,
                                            now=now or int(time.time()))
        except Exception as exc:
            raise DelegationRejected(f"sender passport invalid: {exc}") from exc

        # 2. Replay defense (§8): reject a duplicate (jti, action_ref).
        action_ref = tap.get("action_ref")
        replay_key = (sender_claims["jti"], action_ref)
        with self._a2a_lock:
            if replay_key in self._a2a_seen:
                raise DelegationRejected(
                    f"replayed delegation (jti={sender_claims['jti']})"
                )
            self._a2a_seen.add(replay_key)

        # 3. Accept: mint our own passport on the SAME cid to join the chain.
        # This is a new record with its own assurance expectation, independent
        # of whatever the delegator claimed.
        receiver = self.issue_passport(
            task_prompt=task_prompt,
            scope=scope,
            cid=tap.get("cid") or sender_claims.get("cid"),
            attestation=attestation,
        )

        # 4. Attest acceptance, linked to the orchestrator's agent_delegate event.
        self._emit(
            receiver,
            kind="received_delegation",
            intent=intent or f"Accept delegation from {sender_claims['aid']}",
            tool=sender_claims["aid"],
            scope_used="delegate:agent",
            action_ref=action_ref,
            parent_event_id=tap.get("parent_event_id"),
        )
        return receiver

    def flush(self) -> None:
        self._reporter.flush()

    def close(self) -> None:
        self._reporter.close()
