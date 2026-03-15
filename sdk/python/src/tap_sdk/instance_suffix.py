"""Persisted 6-char instance suffix for unique agent registration names."""
from __future__ import annotations

import json
import os
import secrets
from pathlib import Path

_cached_suffix: str | None | object = object()
_UNSET = _cached_suffix


def is_instance_suffix_disabled() -> bool:
    env = os.environ.get("TAP_DISABLE_INSTANCE_SUFFIX") or os.environ.get(
        "TAP_DISABLE_LOCAL_AGENT_SUFFIX", ""
    )
    return env.strip().lower() in ("1", "true", "yes")


def _default_instance_file(identity_dir: Path | str | None = None) -> Path:
    explicit = os.environ.get("TAP_INSTANCE_FILE", "").strip()
    if explicit:
        return Path(explicit).expanduser()

    if identity_dir:
        base = Path(identity_dir).expanduser().resolve().parent
    else:
        base = Path.home() / ".tap"
    return base / "instance.json"


def _generate_suffix() -> str:
    return secrets.token_hex(3)


def _load_file(file_path: Path) -> str | None:
    try:
        data = json.loads(file_path.read_text(encoding="utf-8"))
        suffix = str(data.get("suffix", "")).strip()
        return suffix or None
    except (OSError, json.JSONDecodeError, TypeError):
        return None


def _save_file(file_path: Path, suffix: str) -> None:
    file_path.parent.mkdir(parents=True, exist_ok=True)
    file_path.write_text(f"{json.dumps({'suffix': suffix}, indent=2)}\n", encoding="utf-8")
    try:
        file_path.chmod(0o600)
    except OSError:
        pass


def get_or_create_instance_suffix(identity_dir: Path | str | None = None) -> str | None:
    global _cached_suffix

    if is_instance_suffix_disabled():
        return None

    explicit = os.environ.get("TAP_INSTANCE_SUFFIX", "").strip()
    if explicit:
        return explicit

    if _cached_suffix is not _UNSET:
        return _cached_suffix  # type: ignore[return-value]

    file_path = _default_instance_file(identity_dir)
    existing = _load_file(file_path)
    if existing:
        _cached_suffix = existing
        return existing

    suffix = _generate_suffix()
    _save_file(file_path, suffix)
    _cached_suffix = suffix
    return suffix


def clear_instance_suffix_cache() -> None:
    global _cached_suffix
    _cached_suffix = _UNSET
