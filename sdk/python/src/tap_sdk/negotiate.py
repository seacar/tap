"""The TAP capability handshake — `tap_hello` / `tap_hello_ack` [TAP-NEGOTIATE].

A Signer offers the versions and crypto suites it supports and whether it wants
server attestation; a TAP-aware Server or Gateway answers with its selection. The
selected outcome is then bound into the first Event of the record as
``evidence.nego`` [TAP-NEGO-BINDING], which is what makes a stripped handshake
*detectable*: the handshake itself rides in plaintext metadata and can be removed
by any intermediary, but the Signer's signed claim about it cannot.

That binding is only worth something if the value bound is an outcome the Signer
actually obtained. This module exists so that obtaining one is the easy path —
see :func:`offer` on the Signer side and :func:`select` on the Server side.

Carriage is defined in spec §11 and implemented here for both bindings:

  * HTTP           — ``X-TAP-Hello`` / ``X-TAP-Hello-Ack`` headers
  * JSON-RPC       — ``_meta.tap.hello`` / ``_meta.tap.hello_ack``

The same JSON object travels either way.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Iterable

from .core import SPEC_VERSION

HELLO_HEADER = "X-TAP-Hello"
ACK_HEADER = "X-TAP-Hello-Ack"

#: Wire versions this implementation can speak, best first.
SUPPORTED_VERSIONS: tuple[str, ...] = (SPEC_VERSION,)

#: Crypto suites this implementation can speak [TAP-SUITE-DISPATCH].
SUPPORTED_SUITES: tuple[str, ...] = ("tap-ed25519",)

#: What a Signer may ask for. ``requested`` is an offer, never a selection.
OFFERABLE_ATTESTATION = frozenset({"none", "requested"})

#: What a Server may select.
SELECTABLE_ATTESTATION = frozenset({"none", "server"})


class NegotiationFailed(RuntimeError):
    """No mutually supported wire version or suite.

    Not fatal by itself: per [TAP-NEGOTIATE] the parties fall back to unattested
    operation and the Signer labels the record accordingly. It is raised so that
    the fallback is a decision the caller makes, not one that happens silently.
    """


@dataclass(frozen=True)
class Negotiated:
    """The outcome of a handshake — exactly the shape bound into ``evidence.nego``."""

    version: str
    suite: str
    attestation: str

    def as_nego(self) -> dict[str, str]:
        """The signed-body form. Key order is irrelevant (JCS sorts), but the key
        NAMES are part of the contract: ``suite``, carrying a TAP suite id, not
        ``alg`` carrying a JOSE value."""
        return {"version": self.version, "suite": self.suite,
                "attestation": self.attestation}


# --- Signer side --------------------------------------------------------------

def offer(*, kid: str, attestation: str = "requested",
          versions: Iterable[str] = SUPPORTED_VERSIONS,
          suites: Iterable[str] = SUPPORTED_SUITES) -> dict[str, Any]:
    """Build the ``tap_hello`` a Signer sends on the first request of a session."""
    if attestation not in OFFERABLE_ATTESTATION:
        raise ValueError(
            f"a Signer may offer {sorted(OFFERABLE_ATTESTATION)}, not {attestation!r}; "
            "'server' is a Server's selection, not something a Signer can claim"
        )
    return {"versions": list(versions), "suites": list(suites),
            "attestation": attestation, "kid": kid}


def read_ack(ack: dict[str, Any] | None) -> Negotiated | None:
    """Interpret a ``tap_hello_ack``. Returns None when there was no usable ack —
    which is the honest input to "emit no ``nego`` at all"."""
    if not ack:
        return None
    version = ack.get("version")
    # `suite` is the field name; `alg` is accepted on input only, because early
    # drafts of §4.1 showed a JOSE `alg` here. We never emit it.
    suite = ack.get("suite") or _suite_for_legacy_alg(ack.get("alg"))
    attestation = ack.get("attestation")
    if version not in SUPPORTED_VERSIONS or suite not in SUPPORTED_SUITES:
        return None
    if attestation not in SELECTABLE_ATTESTATION:
        return None
    return Negotiated(version=version, suite=suite, attestation=attestation)


def _suite_for_legacy_alg(alg: Any) -> str | None:
    return "tap-ed25519" if alg == "EdDSA" else None


# --- Server side --------------------------------------------------------------

def select(hello: dict[str, Any] | None, *, attests: bool) -> dict[str, Any] | None:
    """Choose the session parameters and build the ``tap_hello_ack``.

    ``attests`` says whether this Server will actually emit server-attested
    Events. It is deliberately a property of the Server, not something the
    caller's ``hello`` can influence: answering ``attestation:"server"`` to a
    Signer and then not signing an execution leg produces exactly the
    ``conflicting`` state [TAP-ASSURANCE] that a Verifier will hold against the
    *agent*.

    Returns None when there was no hello to answer. Raises NegotiationFailed when
    a hello arrived but shares no version or suite with us.
    """
    if not hello:
        return None
    offered_versions = hello.get("versions") or []
    offered_suites = hello.get("suites") or _legacy_suites(hello.get("algs"))

    version = _highest_mutual(offered_versions, SUPPORTED_VERSIONS)
    suite = _highest_mutual(offered_suites, SUPPORTED_SUITES)
    if version is None or suite is None:
        raise NegotiationFailed(
            f"no mutually supported version/suite: offered "
            f"versions={offered_versions!r} suites={offered_suites!r}"
        )
    return {"version": version, "suite": suite,
            "attestation": "server" if attests else "none",
            "checkpoints": "supported"}


def _legacy_suites(algs: Any) -> list[str]:
    if not algs:
        return []
    return [s for s in (_suite_for_legacy_alg(a) for a in algs) if s]


def _highest_mutual(offered: Iterable[str], supported: Iterable[str]) -> str | None:
    """Our preference order wins, not theirs: `supported` is ordered best-first,
    so we pick the best thing WE can do that they also do."""
    offered_set = set(offered)
    for candidate in supported:
        if candidate in offered_set:
            return candidate
    return None


# --- carriage -----------------------------------------------------------------

def to_header(obj: dict[str, Any]) -> str:
    """Serialize a hello/ack for an HTTP header: compact JSON, no raw newlines."""
    return json.dumps(obj, separators=(",", ":"))


def from_header(raw: str | None) -> dict[str, Any] | None:
    """Parse a hello/ack header. Malformed input is treated as absent rather than
    raising: a broken handshake degrades to unattested, which the `nego` binding
    then makes visible. It must never take down the request path."""
    if not raw:
        return None
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return None
    return parsed if isinstance(parsed, dict) else None


def hello_headers(hello: dict[str, Any]) -> dict[str, str]:
    return {HELLO_HEADER: to_header(hello)}


def ack_headers(ack: dict[str, Any] | None) -> dict[str, str]:
    return {ACK_HEADER: to_header(ack)} if ack else {}


def hello_from_headers(headers: Any) -> dict[str, Any] | None:
    """Read a hello from any case-insensitive header mapping (Starlette, httpx,
    a plain dict)."""
    return from_header(_get_header(headers, HELLO_HEADER))


def ack_from_headers(headers: Any) -> dict[str, Any] | None:
    return from_header(_get_header(headers, ACK_HEADER))


def _get_header(headers: Any, name: str) -> str | None:
    if headers is None:
        return None
    try:
        value = headers.get(name)
        if value is None:
            value = headers.get(name.lower())
        return value
    except AttributeError:
        return None


def hello_meta(hello: dict[str, Any]) -> dict[str, Any]:
    """`_meta` carriage for stdio MCP / A2A, where no HTTP headers exist."""
    return {"tap": {"hello": hello}}


def hello_from_meta(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    return ((meta or {}).get("tap") or {}).get("hello")


def ack_from_meta(meta: dict[str, Any] | None) -> dict[str, Any] | None:
    return ((meta or {}).get("tap") or {}).get("hello_ack")
