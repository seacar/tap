"""TAP SDK — sign and verify TAP agent provenance (passports, events, decisions).

The signer (`TAPClient`) mints passports and signs provenance events, including the
counterfactual decision ledger (`signer.decision(...)`, TAP-spec §5.7). The
verification primitives need only a public key, so anyone can re-verify a TAPClient
transcript without trusting the platform.
"""
from .core import (
    SPEC_VERSION,
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
from .agent_id import resolve_agent_id
from .verifier_api import VerifierAPI
from .signer import DelegationRejected, Passport, PolicyDenied, TAPClient
from .tracer import TAPTracer, Tenant, TraceSession

__version__ = "0.1.0"

__all__ = [
    "TAPClient", "Passport", "DelegationRejected", "VerifierAPI", "TAPTracer", "TraceSession",
    "resolve_agent_id",
    "sign_event", "verify_event", "sign_passport", "verify_passport",
    "public_jwk", "load_signer", "digest", "b64u", "b64u_dec", "SPEC_VERSION",
    # policy-as-code (build spec §9.4)
    "PolicyDenied", "PolicyDecision", "PolicyRequest", "PolicyError",
    "evaluate_policy", "policy_version", "EMPTY_POLICY",
]
