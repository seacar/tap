"""TAP SDK — sign and verify TAP agent provenance (passports, events, decisions).

The signer (`TAPClient`) mints passports, negotiates the TAP handshake, and signs
provenance events, including the counterfactual decision ledger
(`signer.decision(...)`, [TAP-EVT-DECISION]). The verification layer
(`tap_sdk.verify`) needs only a public key, so anyone can re-verify a transcript
without trusting the platform that stored it — which is the whole claim.

Comments throughout cite the specification's stable `[TAP-...]` anchor tags rather
than section numbers, which move between revisions and leave citations quietly
wrong. See TAP-spec-v0.1.md.
"""
from .core import (
    SPEC_VERSION,
    InvalidRecord,
    PassportExpired,
    RevokedKey,
    UnknownSuite,
    b64u,
    b64u_dec,
    digest,
    load_signer,
    public_jwk,
    sign_event,
    sign_passport,
    verify_event,
    verify_passport,
)
from .policy import (
    EMPTY_POLICY,
    PolicyDecision,
    PolicyError,
    PolicyRequest,
    evaluate as evaluate_policy,
    policy_version,
)
from .authority import (
    Authorization,
    AuthorityError,
    AuthorityExpired,
    AuthorityRevoked,
    authority_effect_label,
    authority_state_version,
    check_authority_window,
    check_authority_not_revoked,
)
from .agent_id import resolve_agent_id
from .signer import DelegationRejected, Passport, PolicyDenied, TAPClient
from .tracer import TAPTracer, Tenant, TraceSession

__version__ = "0.1.3"

# `VerifierAPI` is the only part of this package that talks HTTP, and `httpx` is an
# OPTIONAL dependency (`pip install traceable-agent-protocol[http]`). Importing it
# eagerly here made `from tap_sdk import TAPClient` — the first line of the
# quickstart — fail outright on a default install.
#
# Signing and verifying need no network at all, and keeping them importable without
# one is the point: a relying party re-verifying an archived transcript should not
# have to install an HTTP client to do it. So the symbol is resolved on first
# access (PEP 562) and raises something that explains itself.
_LAZY = {"VerifierAPI": ".verifier_api"}


def __getattr__(name: str):
    module = _LAZY.get(name)
    if module is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    from importlib import import_module
    try:
        value = getattr(import_module(module, __name__), name)
    except ImportError as exc:
        raise ImportError(
            f"tap_sdk.{name} needs the optional HTTP extra: "
            f"pip install 'traceable-agent-protocol[http]' ({exc})"
        ) from exc
    globals()[name] = value  # cache, so the cost is paid once
    return value


def __dir__() -> list[str]:
    return sorted([*globals(), *_LAZY])

__all__ = [
    "TAPClient", "Passport", "DelegationRejected", "VerifierAPI", "TAPTracer", "TraceSession",
    "resolve_agent_id",
    "sign_event", "verify_event", "sign_passport", "verify_passport",
    "public_jwk", "load_signer", "digest", "b64u", "b64u_dec", "SPEC_VERSION",
    # Verification failures, raised (never asserted) so `python -O` cannot
    # strip them [TAP-PASSPORT-VALIDATE], [TAP-EVT-VERIFY].
    "InvalidRecord", "PassportExpired", "RevokedKey", "UnknownSuite",
    # policy-as-code [TAP-POLICY-RECORD]
    "PolicyDenied", "PolicyDecision", "PolicyRequest", "PolicyError",
    "evaluate_policy", "policy_version", "EMPTY_POLICY",
    # authority binding [TAP-EVT-AUTHORIZATION, §9.2, provisional]
    "Authorization", "AuthorityError", "AuthorityExpired", "AuthorityRevoked",
    "authority_state_version", "check_authority_window", "check_authority_not_revoked",
    "authority_effect_label",
]
