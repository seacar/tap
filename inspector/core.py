"""TAP Inspector — shared logic layer (whitepaper §15).

A local developer tool to mint test Passports, sign/verify Events, and
visualize a record's chain — analogous to the MCP Inspector. Every function
here is a thin wrapper over existing primitives (`tap_sdk`, `verifier.verify`); nothing in this module invents new crypto or verification
logic. Both the CLI (`inspector.cli`) and the local web UI (`inspector.app`)
import only from here, so they can never diverge in behavior.
"""
from __future__ import annotations

import base64
import json
import secrets
import sys
from pathlib import Path
from typing import Callable

# inspector/ lives in distribution/, but the primitives it wraps (shared,

import httpx

from tap_sdk.core import DEFAULT_TTL_S, load_signer, public_jwk
from tap_sdk.signer import Passport, TAPClient
import tap_sdk.verify as V

KeyResolver = Callable[[str], dict | None]

# --- keys --------------------------------------------------------------------

def generate_key(kid: str | None = None) -> dict:
    """Mint a fresh Ed25519 test identity.

    Mirrors the key-generation branch inline in `verifier/app.py::register_agent`
    (secrets -> load_signer -> public_jwk), reimplemented standalone here rather
    than imported, so the Inspector never depends on the Verifier's FastAPI app
    or its multi-tenant backend — just the crypto primitives.
    """
    from tap_sdk.core import new_id

    seed_hex = secrets.token_bytes(32).hex()
    kid = kid or new_id("key")
    sk = load_signer(seed_hex)
    jwk = public_jwk(sk, kid)
    return {"private_key_hex": seed_hex, "kid": kid, "public_jwk": jwk}

def _throwaway_client(private_key_hex: str, kid: str, *, agent_id: str = "inspector") -> TAPClient:
    """A TAPClient wired to a no-op transport — signing happens locally and
    immediately; nothing is ever posted anywhere unless the caller explicitly
    submits to a live Verifier (a separate, explicit action)."""
    return TAPClient(agent_id=agent_id, private_key_hex=private_key_hex, kid=kid,
                     post_fn=lambda url, payload, headers: None)

# --- minting / signing ---------------------------------------------------------

def mint_passport(
    *, private_key_hex: str, kid: str, task_prompt: str, scope: list[str],
    ttl_s: int = DEFAULT_TTL_S, cid: str | None = None, attestation: str = "none",
    agent_id: str | None = None, framework: str | None = None, model: str | None = None,
) -> Passport:
    """Mint a test Passport. Thin wrapper over `TAPClient.issue_passport`."""
    client = _throwaway_client(private_key_hex, kid, agent_id=agent_id or "inspector")
    client.framework = framework
    client.model = model
    return client.issue_passport(task_prompt=task_prompt, scope=scope, ttl_s=ttl_s, cid=cid,
                                 attestation=attestation)

def sign_event_for_passport(*, private_key_hex: str, kid: str, passport: Passport, **emit_kwargs) -> dict:
    """Sign a test Event for a passport. Thin wrapper over the public
    `TAPClient.emit_event` alias (the same method `trace`/`instrument_mcp` use).
    ``emit_kwargs`` accepts the same keywords as ``TAPClient._emit`` (kind,
    intent, tool, scope_used, args, status, code, action_ref, attestor, ...)."""
    agent_id = (passport.claims.get("meta") or {}).get("agent_name") or "inspector"
    client = _throwaway_client(private_key_hex, kid, agent_id=agent_id)
    return client.emit_event(passport, **emit_kwargs)

def _decode_claims(compact_jwt: str) -> dict:
    """Decode (NOT verify) a compact JWT's claims segment. The Inspector is a
    single-operator local tool re-using its own or a pasted-in credential, not
    a trust boundary — this must never be mistaken for a security check."""
    parts = compact_jwt.split(".")
    if len(parts) < 2:
        raise ValueError("not a compact JWT")
    pad = "=" * (-len(parts[1]) % 4)
    return json.loads(base64.urlsafe_b64decode(parts[1] + pad))

def load_passport(compact_or_path: str) -> Passport:
    """Build a Passport from a previously-minted ``{"compact":..., "claims":...,
    "attestation":...}`` JSON blob (file path or literal JSON string), or from a
    bare compact JWT (claims decoded, not re-verified — see `_decode_claims`)."""
    text = compact_or_path
    # A compact JWT is longer than any filesystem path component, so probing it
    # as a path raises ENAMETOOLONG rather than returning False. Guard the probe
    # instead of trusting it: this input is whatever the operator pasted in.
    try:
        path = Path(compact_or_path)
        if path.exists():
            text = path.read_text()
    except (OSError, ValueError):
        pass  # not a usable path — treat the input as literal text
    text = text.strip()
    if text.startswith("{"):
        data = json.loads(text)
        compact = data["compact"]
        claims = data.get("claims") or _decode_claims(compact)
        return Passport(compact=compact, claims=claims, attestation=data.get("attestation", "none"))
    return Passport(compact=text, claims=_decode_claims(text))

# --- verification ---------------------------------------------------------------

def make_resolver(jwks_source: str) -> KeyResolver:
    """``jwks_source`` is an http(s) Verifier base URL (JWKS fetched once), a
    local JSON file, or literal JWKS/JWK JSON text (detected the same way
    `load_passport` detects literal JSON vs. a file path) — either a JWKS
    ``{"keys": [...]}`` or a single JWK dict. Returns a ``{kid: jwk}.get``-style
    resolver — the exact KeyResolver shape `verifier.verify`'s functions
    already expect."""
    jwks_source = jwks_source.strip()
    if jwks_source.startswith("http://") or jwks_source.startswith("https://"):
        url = jwks_source.rstrip("/")
        if not url.endswith("/.well-known/jwks.json"):
            url += "/.well-known/jwks.json"
        resp = httpx.get(url, timeout=10.0)
        resp.raise_for_status()
        data = resp.json()
    elif jwks_source.startswith("{"):
        data = json.loads(jwks_source)
    else:
        data = json.loads(Path(jwks_source).read_text())

    if "keys" in data:
        keys = {k["kid"]: k for k in data["keys"] if k.get("kid")}
    elif "kid" in data:
        keys = {data["kid"]: data}
    else:
        keys = {}
    return keys.get

def verify(*, jwks_source: str, passport_compact: str | None = None,
          events: list[dict] | None = None) -> dict:
    """Dispatch to `verifier.verify`'s existing functions — no new verification
    logic. Passport + events -> Audit-in-a-Box report; passport only -> passport
    validity; events only -> per-event signature/drift evaluation."""
    resolve_key = make_resolver(jwks_source)
    events = events or []
    if passport_compact and events:
        return V.verify_transcript(passport_compact, events, resolve_key=resolve_key)
    if passport_compact:
        return V.check_passport(passport_compact, resolve_key=resolve_key)
    if events:
        results = [
            V.evaluate_event(e, resolve_key=resolve_key, passport_claims=None, last_seq=None)
            for e in events
        ]
        return {"events": results}
    raise ValueError("verify() needs a passport and/or events to check")

def build_record_from_local(*, passport_claims: dict | None, events: list[dict],
                            resolve_key: KeyResolver) -> dict:
    """Assemble the same record shape `verifier.store.InMemoryStore.get_record`
    produces, from local passport+events instead of a database, so
    `V.annotate_assurance` can run over it unmodified — the offline chain view
    produces identical labels to a live Verifier, since it's the same function."""
    ordered = sorted(events, key=lambda e: e.get("seq", 0))
    stored: list[dict] = []
    last_seq_by_attestor: dict[str, int] = {}
    for ev in ordered:
        attestor = ev.get("attestor", "agent")
        res = V.evaluate_event(ev, resolve_key=resolve_key, passport_claims=passport_claims,
                               last_seq=last_seq_by_attestor.get(attestor))
        stored.append({
            "raw": ev, "sig_valid": res["sig_valid"], "drift": res["drift"],
            "drift_reason": res["drift_reason"], "integrity": res["integrity"],
        })
        if isinstance(ev.get("seq"), int):
            last_seq_by_attestor[attestor] = ev["seq"]

    aid = ordered[0].get("aid") if ordered else (passport_claims or {}).get("aid")
    return {
        "aid": aid,
        "passport": passport_claims,
        "events": stored,
        "flags": {
            "drift": any(r["drift"] for r in stored),
            "invalid_sig": any(not r["sig_valid"] for r in stored),
            "integrity": [r["integrity"] for r in stored if r["integrity"]],
        },
    }

# --- chain visualization ---------------------------------------------------------

def _render_record_lines(record: dict) -> str:
    lines = [f"record aid={record.get('aid')}"]
    assurance = record.get("assurance") or {}
    if assurance.get("counts"):
        lines.append(f"  counts: {assurance['counts']}")
    flags = record.get("flags") or {}
    if flags:
        lines.append(f"  flags: {flags}")
    for rec in record.get("events", []):
        raw = rec.get("raw", {})
        mark = "✓" if rec.get("sig_valid") else "✗"
        level = rec.get("assurance", "?")
        nego = " NEGO-MISMATCH" if rec.get("nego_mismatch") else ""
        action = raw.get("action") or {}
        lines.append(
            f"  [{raw.get('seq')}] {mark} {action.get('kind'):<20} "
            f"tool={action.get('tool')!r} attestor={raw.get('attestor'):<6} "
            f"assurance={level}{nego}"
        )
    return "\n".join(lines)

def render_chain_ascii(record_or_chain: dict) -> str:
    """Pure formatting over `V.annotate_assurance`/`V.build_chain`'s output — no
    verification logic here, only reads of fields those functions computed."""
    if "records" in record_or_chain and "edges" in record_or_chain:
        lines = [
            f"chain cid={record_or_chain.get('cid')} "
            f"intact={record_or_chain.get('chain_intact')} "
            f"nego_mismatch={record_or_chain.get('nego_mismatch')}"
        ]
        for rec in record_or_chain["records"]:
            lines.append(_render_record_lines(rec))
        for edge in record_or_chain.get("edges", []):
            status = "verified" if edge["verified"] else ("BROKEN" if edge["broken"] else "unverified")
            lines.append(f"  edge {edge['parent_aid']} -> {edge['child_aid']} [{status}]")
        return "\n".join(lines)
    return _render_record_lines(record_or_chain)
