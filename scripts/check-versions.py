#!/usr/bin/env python3
"""Assert SDK package versions share a single source: VERSION at the repo root."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _toml_version(text: str) -> str:
    for line in text.splitlines():
        if line.startswith("version"):
            return line.split("=", 1)[1].strip().strip('"')
    raise SystemExit("no version in pyproject.toml")


def main() -> int:
    expected = (ROOT / "VERSION").read_text().strip()
    pyproject = _toml_version((ROOT / "sdk/python/pyproject.toml").read_text())
    package = json.loads((ROOT / "sdk/js/package.json").read_text())["version"]
    init = (ROOT / "sdk/python/src/tap_sdk/__init__.py").read_text()
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', init, re.M)
    if not match:
        print("::error::__version__ missing from tap_sdk/__init__.py", file=sys.stderr)
        return 1
    init_ver = match.group(1)
    found = {
        "VERSION": expected,
        "sdk/python/pyproject.toml": pyproject,
        "sdk/js/package.json": package,
        "tap_sdk.__version__": init_ver,
    }
    disagree = {k: v for k, v in found.items() if v != expected}
    if disagree:
        print("::error::package versions disagree (expected %s): %s" % (expected, found),
              file=sys.stderr)
        return 1
    print("ok - all package versions are", expected)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
