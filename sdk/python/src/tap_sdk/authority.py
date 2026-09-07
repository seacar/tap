"""Authority binding — bind one Event to a pre-declared expected effect
[TAP-EVT-AUTHORIZATION, §9.2, **PROVISIONAL**].

``policy_decision`` (policy.py) proves a *class* of action was permitted under
the rules in force. It does not prove a specific, authentically-signed instance
stayed within what was actually approved *for that instance* — a Signer holding
a validly-scoped Passport and a compliant policy decision can still take an
authentic action nobody approved for that particular case. Authority binding is
that missing claim: it binds one Event to one pre-declared expected outcome,
under a specific version of the authority that granted it, valid only for a
bounded window. ``policy_decision`` and ``authorization`` compose freely — an
Event MAY carry either, both, or neither.

**Provisional.** The wire shape and the two STATELESS checks here
(``check_authority_window``, ``authority_effect_label``) have a reference
implementation in ``tap_ref.py`` as of protocol v0.1.4, with a fixed vector in
``test-vectors.json -> authorization``. ``[TAP-AUTHORITY-REVOKE]`` and
``[TAP-AUTHORITY-REUSE]`` are STATEFUL (a registry of revoked/consumed
``authz_id``s) and are therefore a Verifier/Service-Profile concern, not this
client SDK's — no production Verifier enforces them yet. Track status in
``tap/CHANGELOG.md``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jcs  # RFC 8785 — same canonicalizer the signatures use

from .core import digest, json_digest, new_id

__all__ = [
    "AuthorityError",
    "AuthorityExpired",
    "AuthorityMalformed",
    "AuthorityRevoked",
    "Authorization",
    "authority_state_version",
    "check_authority_window",
    "check_authority_not_revoked",
    "authority_effect_label",
]


class AuthorityError(ValueError):
    """Base class for authority-binding errors."""


class AuthorityMalformed(AuthorityError):
    """The ``authorization`` block is present but is not a usable approval.

    Raised only by the *enforcement* path (``check_authority_window``), which is
    reached with attacker-supplied input from ``X-TAP-Authorization`` /
    ``_meta.tap.authorization`` and must fail closed. The *labeling* path
    (``authority_effect_label``) never raises — it is a verifier reading records
    it did not choose, where one poisoned block must not end the report.
    """


class AuthorityExpired(AuthorityError):
    """The current time falls outside an authorization's validity window
    [TAP-AUTHORITY-VALIDITY], with the same +/-60s skew allowance as Passport
    freshness [TAP-PASSPORT-VALIDATE]."""

    def __init__(self, authorization: "Authorization", *, now: int) -> None:
        self.authorization = authorization
        self.now = now
        super().__init__(
            f"authorization {authorization.authz_id!r} outside validity window: "
            f"nbf={authorization.nbf} exp={authorization.exp} now={now}"
        )


def authority_state_version(state: dict) -> str:
    """Content-hash an authority/policy state to its version digest.

    The SAME construction as ``policy.policy_version`` — ``sha256(JCS(state))``
    — scoped to one approval rather than the whole active policy set, so an
    auditor can prove *which* authority state governed a specific approval.
    """
    return digest(jcs.canonicalize(state))


@dataclass(frozen=True)
class Authorization:
    """A bound approval [TAP-EVT-AUTHORIZATION, §9.2]: one action, one
    pre-declared expected effect, one version of the authority that granted
    it, valid only for a bounded window.

    The signed body never carries the raw expected state — only its digest,
    matching the digest-only discipline of the rest of the envelope
    [TAP-EVT-ENVELOPE]. Plaintext, where retained, belongs in the annex.
    """

    authz_id: str
    authority_state_version: str
    target_state_digest: str
    nbf: int
    exp: int
    issuer_kid: str

    @classmethod
    def grant(cls, *, target_state: dict, authority_state: dict, nbf: int, exp: int,
              issuer_kid: str, authz_id: str | None = None) -> "Authorization":
        """Mint a new approval binding ``target_state`` under ``authority_state``.

        ``target_state`` and ``authority_state`` are digested here, once, so
        every other layer only ever sees the digest — a caller cannot
        accidentally leak the raw state into a signed body.
        """
        return cls(
            authz_id=authz_id or new_id("auz"),
            authority_state_version=authority_state_version(authority_state),
            target_state_digest=json_digest(target_state),
            nbf=nbf,
            exp=exp,
            issuer_kid=issuer_kid,
        )

    def to_record(self) -> dict[str, Any]:
        """The exact JSON stamped onto an Event's ``authorization`` field."""
        return {
            "authz_id": self.authz_id,
            "authority_state_version": self.authority_state_version,
            "target_state_digest": self.target_state_digest,
            "nbf": self.nbf,
            "exp": self.exp,
            "issuer_kid": self.issuer_kid,
        }

    @classmethod
    def from_record(cls, record: dict) -> "Authorization":
        return cls(
            authz_id=record["authz_id"],
            authority_state_version=record["authority_state_version"],
            target_state_digest=record["target_state_digest"],
            nbf=record["nbf"],
            exp=record["exp"],
            issuer_kid=record["issuer_kid"],
        )


def check_authority_window(authorization: Authorization | dict, *, now: int) -> None:
    """Enforce the validity window [TAP-AUTHORITY-VALIDITY]:

        nbf - 60 <= now < exp + 60

    the same inequality and skew allowance as Passport freshness
    [TAP-PASSPORT-VALIDATE]. Raises :class:`AuthorityExpired` outside it, and
    :class:`AuthorityMalformed` when the block is not a usable approval at all.

    This is an enforcement point reached with untrusted input (the unsigned
    ``X-TAP-Authorization`` header, §11.1), so a malformed block fails closed
    rather than raising a raw ``KeyError``/``TypeError`` out of a request path.
    """
    if isinstance(authorization, Authorization):
        rec = authorization
    elif isinstance(authorization, dict):
        try:
            rec = Authorization.from_record(authorization)
        except (KeyError, TypeError) as exc:
            raise AuthorityMalformed(f"authorization block is not a usable approval: {exc}") from exc
    else:
        raise AuthorityMalformed(
            f"authorization must be an object, got {type(authorization).__name__}")
    if not isinstance(rec.nbf, int) or not isinstance(rec.exp, int):
        raise AuthorityMalformed("authorization nbf/exp must be integer epoch seconds")
    if not (rec.nbf - 60 <= now < rec.exp + 60):
        raise AuthorityExpired(rec, now=now)


class AuthorityRevoked(AuthorityError):
    """``authz_id`` or ``authority_state_version`` names a revoked approval
    [TAP-AUTHORITY-REVOKE], and this record is timestamped (by its own signed
    ``ts``) at or after the revocation boundary — the same effective-time-boundary
    mechanism as key revocation [TAP-KEY-REVOCATION], applied to an approval
    instead of a signing key."""

    def __init__(self, *, revoked_id: str, revoked_at: int, signed_ts: int) -> None:
        self.revoked_id = revoked_id
        self.revoked_at = revoked_at
        self.signed_ts = signed_ts
        super().__init__(
            f"{revoked_id!r} revoked at {revoked_at}; record is timestamped {signed_ts}"
        )


def check_authority_not_revoked(
    authz_id: str, authority_state_version: str, revoked_at: int | None, *, signed_ts: int,
) -> None:
    """Enforce the revocation boundary [TAP-AUTHORITY-REVOKE].

    ``revoked_at`` is an ALREADY-RESOLVED boundary for whichever of ``authz_id``
    or ``authority_state_version`` the caller looked up — this function performs
    no lookup itself and holds no registry. Publication format and query
    interface are a Service Profile concern (spec §9.2, §15); this is only the
    comparison. Pass ``None`` when nothing is known to be revoked (the common
    case): a Verifier with no revocation resource wired in should call this with
    ``revoked_at=None`` rather than skip the call, so the "nothing revoked" path
    is exercised the same way as every other outcome.

    Raises :class:`AuthorityRevoked` when ``signed_ts >= revoked_at`` — an
    effective-time boundary, not blanket repudiation: a record signed before
    the boundary stays valid, same as key revocation.
    """
    if revoked_at is None:
        return
    if signed_ts >= revoked_at:
        revoked_id = authz_id or authority_state_version
        raise AuthorityRevoked(revoked_id=revoked_id, revoked_at=revoked_at, signed_ts=signed_ts)


def authority_effect_label(authorization: Authorization | dict | None, result: dict) -> str | None:
    """Label an Event's authority-binding outcome [TAP-AUTHORITY-EFFECT] by
    comparing ``result.effect_digest`` against ``authorization.target_state_digest``.

    Returns ``None`` when no ``authorization`` is present (the label does not
    apply); otherwise one of ``"authorized_match"`` / ``"authorized_mismatch"``
    / ``"unverified_authority"`` / ``"malformed_authority"`` (the block is
    present and signed, but is not a usable approval — reported, never raised;
    see the shape note in the body). Reported ALONGSIDE two-sided assurance
    [TAP-ASSURANCE], never in place of it — an Event can be independently
    two-sided (execution attested by an independent key) and simultaneously
    ``authorized_mismatch`` (the attested execution did something other than
    what was approved). That combination is exactly the failure two-sided
    attestation alone cannot see, because it only asks who signed, never what
    was approved.
    """
    if authorization is None:
        return None
    # `authorization` arrives from a signed body, and a valid signature says
    # nothing about a block's SHAPE — a hostile or buggy Signer can sign
    # `"authorization": {}` or `"authorization": "hello"` just as validly. A
    # verifier that raises on those is a verifier one poisoned event can take
    # down, which is why this returns a label rather than propagating.
    if isinstance(authorization, Authorization):
        target = authorization.target_state_digest
    elif isinstance(authorization, dict):
        target = authorization.get("target_state_digest")
    else:
        return "malformed_authority"
    if not isinstance(target, str):
        return "malformed_authority"
    effect = result.get("effect_digest") if isinstance(result, dict) else None
    if effect is None:
        return "unverified_authority"
    return "authorized_match" if effect == target else "authorized_mismatch"
