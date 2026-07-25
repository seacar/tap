"""Local agent identity storage and Verifier registration.

Developers identify agents in code (``agent_id="finance-bot-v1"``). The SDK
generates an Ed25519 keypair on first use, persists it under ``~/.tap``, and
registers the public key with the Verifier via ``POST /v1/agents/register``.
No console step is required.
"""
from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

import httpx

from typing import Callable

from .core import generate_signer, load_signer, new_id, public_jwk

RegisterFn = Callable[..., str]

_REGISTRY_LOCK = threading.Lock()
_IDENTITY_CACHE: dict[str, AgentIdentity] = {}


@dataclass(frozen=True)
class AgentIdentity:
    agent_id: str
    kid: str
    seed_hex: str


def default_identity_dir() -> Path:
    override = os.environ.get("TAP_IDENTITY_DIR")
    if override:
        return Path(override).expanduser()
    return Path.home() / ".tap" / "identities"


def _namespace(api_key: str | None, endpoint: str) -> str:
    digest = hashlib.sha256(f"{endpoint}\0{api_key or ''}".encode()).hexdigest()
    return digest[:16]


def _cache_key(namespace: str, agent_id: str) -> str:
    return f"{namespace}:{agent_id}"


def _identity_file(identity_dir: Path, namespace: str, agent_id: str) -> Path:
    safe = agent_id.replace("/", "_").replace("\\", "_")
    return identity_dir / namespace / f"{safe}.json"


def _load_file(path: Path) -> AgentIdentity | None:
    if not path.is_file():
        return None
    data = json.loads(path.read_text())
    return AgentIdentity(
        agent_id=data["agent_id"],
        kid=data["kid"],
        seed_hex=data["seed_hex"],
    )


def _save_file(path: Path, identity: AgentIdentity) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(
            {
                "agent_id": identity.agent_id,
                "kid": identity.kid,
                "seed_hex": identity.seed_hex,
            },
            indent=2,
        )
        + "\n",
    )
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def _from_env(agent_id: str) -> AgentIdentity | None:
    env_agent = os.environ.get("TAP_AGENT_ID") or os.environ.get("TAP_AGENT_ID")
    seed = os.environ.get("TAP_PRIVATE_KEY") or os.environ.get("TAP_PRIVATE_KEY_HEX")
    kid = os.environ.get("TAP_KID")
    if not seed or not kid:
        return None
    if env_agent and env_agent != agent_id:
        return None
    return AgentIdentity(agent_id=agent_id, kid=kid, seed_hex=seed.replace("0x", ""))


def register_with_verifier(
    *,
    endpoint: str,
    api_key: str | None,
    agent_id: str,
    public_jwk_dict: dict,
    timeout: float = 10.0,
    post: RegisterFn | None = None,
) -> str:
    if post is not None:
        return post(
            endpoint=endpoint,
            api_key=api_key,
            agent_id=agent_id,
            public_jwk_dict=public_jwk_dict,
            timeout=timeout,
        )
    headers: dict[str, str] = {}
    if api_key:
        headers["X-API-Key"] = api_key
    with httpx.Client(timeout=timeout) as http:
        resp = http.post(
            f"{endpoint.rstrip('/')}/v1/agents/register",
            json={"agent_id": agent_id, "public_jwk": public_jwk_dict},
            headers=headers,
        )
        resp.raise_for_status()
        return resp.json()["kid"]


def ensure_agent_identity(
    *,
    agent_id: str,
    api_key: str | None,
    endpoint: str,
    identity_dir: Path | None = None,
    register: bool = True,
    register_fn: RegisterFn | None = None,
) -> AgentIdentity:
    """Load or create a signing identity for ``agent_id`` and register it with TAPClient."""
    id_dir = identity_dir or default_identity_dir()
    ns = _namespace(api_key, endpoint)
    ck = _cache_key(ns, agent_id)

    with _REGISTRY_LOCK:
        cached = _IDENTITY_CACHE.get(ck)
        if cached:
            return cached

        from_env = _from_env(agent_id)
        if from_env:
            if register:
                sk = load_signer(from_env.seed_hex)
                kid = register_with_verifier(
                    endpoint=endpoint,
                    api_key=api_key,
                    agent_id=agent_id,
                    public_jwk_dict=public_jwk(sk, from_env.kid),
                    post=register_fn,
                )
                from_env = AgentIdentity(agent_id=agent_id, kid=kid, seed_hex=from_env.seed_hex)
            _IDENTITY_CACHE[ck] = from_env
            return from_env

        path = _identity_file(id_dir, ns, agent_id)
        existing = _load_file(path)
        if existing:
            sk = load_signer(existing.seed_hex)
            kid = existing.kid
            if register:
                kid = register_with_verifier(
                    endpoint=endpoint,
                    api_key=api_key,
                    agent_id=agent_id,
                    public_jwk_dict=public_jwk(sk, existing.kid),
                    post=register_fn,
                )
            identity = AgentIdentity(agent_id=agent_id, kid=kid, seed_hex=existing.seed_hex)
            _IDENTITY_CACHE[ck] = identity
            return identity

        sk, seed_hex = generate_signer()
        kid = new_id("key")
        if register:
            kid = register_with_verifier(
                endpoint=endpoint,
                api_key=api_key,
                agent_id=agent_id,
                public_jwk_dict=public_jwk(sk, kid),
                post=register_fn,
            )
        identity = AgentIdentity(agent_id=agent_id, kid=kid, seed_hex=seed_hex)
        _save_file(path, identity)
        _IDENTITY_CACHE[ck] = identity
        return identity
