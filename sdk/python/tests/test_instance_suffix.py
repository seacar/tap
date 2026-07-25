#!/usr/bin/env python3
"""Unit tests for instance suffix and agent name resolution."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import types
from pathlib import Path

_src = Path(__file__).resolve().parents[1] / "src"
_pkg_dir = _src / "tap_sdk"
sys.path.insert(0, str(_src))
_pkg = types.ModuleType("tap_sdk")
_pkg.__path__ = [str(_pkg_dir)]
sys.modules["tap_sdk"] = _pkg

from tap_sdk.agent_id import resolve_agent_id
from tap_sdk.instance_suffix import (
    clear_instance_suffix_cache,
    get_or_create_instance_suffix,
    is_instance_suffix_disabled,
)


def test_resolve_agent_id_with_suffix() -> None:
    assert resolve_agent_id("finance-bot-v1", instance_suffix="a3f2b1") == "finance-bot-v1-a3f2b1"
    assert resolve_agent_id("finance-bot-v1") == "finance-bot-v1"


def test_disable_instance_suffix() -> None:
    prev = os.environ.pop("TAP_DISABLE_INSTANCE_SUFFIX", None)
    prev_legacy = os.environ.pop("TAP_DISABLE_LOCAL_AGENT_SUFFIX", None)
    try:
        os.environ["TAP_DISABLE_INSTANCE_SUFFIX"] = "1"
        clear_instance_suffix_cache()
        assert is_instance_suffix_disabled()
        assert resolve_agent_id("finance-bot-v1", instance_suffix="a3f2b1") == "finance-bot-v1"
    finally:
        clear_instance_suffix_cache()
        if prev is None:
            os.environ.pop("TAP_DISABLE_INSTANCE_SUFFIX", None)
        else:
            os.environ["TAP_DISABLE_INSTANCE_SUFFIX"] = prev
        if prev_legacy is not None:
            os.environ["TAP_DISABLE_LOCAL_AGENT_SUFFIX"] = prev_legacy


def test_instance_suffix_override() -> None:
    prev = os.environ.get("TAP_INSTANCE_SUFFIX")
    try:
        os.environ["TAP_INSTANCE_SUFFIX"] = "ci0001"
        clear_instance_suffix_cache()
        with tempfile.TemporaryDirectory(prefix="tap-instance-test-") as tmp:
            identity_dir = Path(tmp) / "identities"
            suffix = get_or_create_instance_suffix(identity_dir)
            assert suffix == "ci0001"
            assert resolve_agent_id("claims-adjuster", instance_suffix=suffix) == "claims-adjuster-ci0001"
    finally:
        clear_instance_suffix_cache()
        if prev is None:
            os.environ.pop("TAP_INSTANCE_SUFFIX", None)
        else:
            os.environ["TAP_INSTANCE_SUFFIX"] = prev


def test_instance_suffix_persistence() -> None:
    prev = os.environ.pop("TAP_INSTANCE_SUFFIX", None)
    prev_disable = os.environ.pop("TAP_DISABLE_INSTANCE_SUFFIX", None)
    try:
        clear_instance_suffix_cache()
        with tempfile.TemporaryDirectory(prefix="tap-instance-test-") as tmp:
            identity_dir = Path(tmp) / "identities"
            instance_file = Path(tmp) / "instance.json"

            first = get_or_create_instance_suffix(identity_dir)
            assert first
            assert len(first) == 6
            assert all(c in "0123456789abcdef" for c in first)

            second = get_or_create_instance_suffix(identity_dir)
            assert second == first

            on_disk = json.loads(instance_file.read_text(encoding="utf-8"))
            assert on_disk["suffix"] == first
    finally:
        clear_instance_suffix_cache()
        if prev is None:
            os.environ.pop("TAP_INSTANCE_SUFFIX", None)
        else:
            os.environ["TAP_INSTANCE_SUFFIX"] = prev
        if prev_disable is None:
            os.environ.pop("TAP_DISABLE_INSTANCE_SUFFIX", None)
        else:
            os.environ["TAP_DISABLE_INSTANCE_SUFFIX"] = prev_disable


def main() -> None:
    test_resolve_agent_id_with_suffix()
    test_disable_instance_suffix()
    test_instance_suffix_override()
    test_instance_suffix_persistence()
    print("ok - instance suffix tests passed")


if __name__ == "__main__":
    main()
