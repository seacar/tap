"""High-level SDK entrypoint — trace agent records from code without console setup.

    from tap_sdk import TAPTracer

    tap = TAPTracer(api_key=os.environ["TAP_API_KEY"], endpoint="https://your-verifier.example.com")

    with signer.trace(agent_id="finance-bot-v1", task=prompt, scope=["read:database"]) as session:
        response = agent.run(prompt)
        session.record_output(response)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

from .agent_id import resolve_agent_id
from .signer import Passport, TAPClient
from .identity import AgentIdentity, ensure_agent_identity
from .instance_suffix import get_or_create_instance_suffix


class TraceSession:
    """An active traced record. Created by ``TAPTracer.trace()``; do not construct directly."""

    def __init__(self, signer: TAPClient, passport: Passport, identity: AgentIdentity) -> None:
        self._signer = signer
        self.passport = passport
        self.identity = identity

    @property
    def agent_id(self) -> str:
        return self._signer.agent_id

    @property
    def kid(self) -> str:
        return self.identity.kid

    def record_output(
        self,
        output: Any,
        *,
        intent: str = "Agent response",
        scope_used: str | None = None,
        reasoning: str | None = None,
    ) -> dict:
        return self._signer.record_output(
            output=output,
            intent=intent,
            scope_used=scope_used,
            reasoning=reasoning,
            passport=self.passport,
        )

    def decision(self, **kwargs: Any) -> dict:
        return self._signer.decision(passport=self.passport, **kwargs)

    def trace(self, **kwargs: Any) -> Callable:
        return self._signer.trace(**kwargs)

    def sign_a2a_delegation(self, **kwargs: Any) -> dict:
        return self._signer.sign_a2a_delegation(passport=self.passport, **kwargs)

    def close(self) -> None:
        self._signer.close()


class _TraceContext:
    def __init__(
        self,
        tenant: "TAPTracer",
        *,
        agent_id: str,
        task: str,
        scope: list[str],
        ttl_s: int | None,
    ) -> None:
        self._tenant = tenant
        self._agent_id = agent_id
        self._task = task
        self._scope = scope
        self._ttl_s = ttl_s
        self._session: TraceSession | None = None

    def __enter__(self) -> TraceSession:
        instance_suffix = get_or_create_instance_suffix(self._tenant.identity_dir)
        resolved_id = resolve_agent_id(self._agent_id, instance_suffix=instance_suffix)
        identity = ensure_agent_identity(
            agent_id=resolved_id,
            api_key=self._tenant.api_key,
            endpoint=self._tenant.endpoint,
            identity_dir=self._tenant.identity_dir,
            register_fn=self._tenant.register_fn,
        )
        signer = TAPClient(
            agent_id=resolved_id,
            private_key_hex=identity.seed_hex,
            kid=identity.kid,
            endpoint=self._tenant.endpoint,
            api_key=self._tenant.api_key,
            framework=self._tenant.framework,
            model=self._tenant.model,
            capture_previews=self._tenant.capture_previews,
            post_fn=self._tenant.post_fn,
        )
        passport = signer.issue_passport(
            task_prompt=self._task,
            scope=self._scope,
            ttl_s=self._ttl_s or 3600,
        )
        self._session = TraceSession(signer, passport, identity)
        return self._session

    def __exit__(self, exc_type, exc, tb) -> bool:
        if self._session:
            self._session.close()
        return False


class TAPTracer:
    """Connects your application to TAPClient using only an API key."""

    def __init__(
        self,
        *,
        api_key: str,
        endpoint: str = "http://localhost:8000",
        identity_dir: Path | str | None = None,
        framework: str | None = None,
        model: str | None = None,
        capture_previews: bool = False,
        post_fn: Callable[[str, dict, dict], None] | None = None,
        register_fn: Callable[..., str] | None = None,
    ) -> None:
        self.api_key = api_key
        self.endpoint = endpoint.rstrip("/")
        self.identity_dir = Path(identity_dir).expanduser() if identity_dir else None
        self.framework = framework
        self.model = model
        self.capture_previews = capture_previews
        self.post_fn = post_fn
        self.register_fn = register_fn

    @classmethod
    def from_env(cls) -> "TAPTracer":
        api_key = os.environ.get("TAP_API_KEY") or os.environ.get("TAP_API_KEY")
        if not api_key:
            raise ValueError("Set TAP_API_KEY or TAP_API_KEY")
        endpoint = (
            os.environ.get("TAP_ENDPOINT")
            or os.environ.get("TAP_ENDPOINT")
            or os.environ.get("VERIFIER_URL")
            or "http://localhost:8000"
        )
        identity_dir = os.environ.get("TAP_IDENTITY_DIR")
        return cls(
            api_key=api_key,
            endpoint=endpoint,
            identity_dir=identity_dir,
            framework=os.environ.get("TAP_FRAMEWORK"),
            model=os.environ.get("TAP_MODEL"),
        )

    def trace(
        self,
        *,
        agent_id: str,
        task: str | None = None,
        task_prompt: str | None = None,
        prompt: str | None = None,
        scope: list[str] | None = None,
        ttl_s: int | None = None,
    ) -> _TraceContext:
        """Start a traced agent record. Registers the agent identity on first use."""
        run_task = task or task_prompt or prompt
        if not run_task:
            raise ValueError("trace() requires task= (or task_prompt= / prompt=)")
        return _TraceContext(
            self,
            agent_id=agent_id,
            task=run_task,
            scope=scope or ["agent:record"],
            ttl_s=ttl_s,
        )


# Backward-compatible alias — prefer TAPTracer and ``signer.trace(...)``.
Tenant = TAPTracer
