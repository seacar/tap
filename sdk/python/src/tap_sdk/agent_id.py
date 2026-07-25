"""Resolve logical agent names with an optional per-install instance suffix."""
from __future__ import annotations

from .instance_suffix import is_instance_suffix_disabled


def resolve_agent_id(agent_id: str, *, instance_suffix: str | None = None) -> str:
    """Resolve the agent name used for registration and signing.

    When an instance suffix is present (from ``get_or_create_instance_suffix``),
    returns ``{agent_id}-{suffix}``. Disable suffixing with
    ``TAP_DISABLE_INSTANCE_SUFFIX=1`` (or deprecated
    ``TAP_DISABLE_LOCAL_AGENT_SUFFIX=1``). Override the suffix with
    ``TAP_INSTANCE_SUFFIX``.
    """
    if is_instance_suffix_disabled() or not instance_suffix:
        return agent_id

    safe = instance_suffix.replace("/", "_").replace("\\", "_")
    return f"{agent_id}-{safe}"
