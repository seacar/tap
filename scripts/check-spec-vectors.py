#!/usr/bin/env python3
"""The specification's published values must match the conformance vectors.

TAP-spec-v0.1.md §6.6 quotes live signatures and JCS signing-input hashes, and §14
quotes the reference seed and JWK. Those values are load-bearing: an implementer
reading the document takes them as the contract.

They were also, until v0.1.2, wrong. The `tool_call` row published a signature that
did not match the committed vectors, and nothing noticed, because nothing compared
the two. A specification whose stated reference values are stale is worse than one
that states none — it sends implementers chasing a mismatch that is the document's
fault, in exactly the area where they have least reason to doubt it.

So CI compares them now.

Run:  python scripts/check-spec-vectors.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "TAP-spec-v0.1.md"
VECTORS = ROOT / "test-vectors.json"

# spec table row -> vectors key
CASES = {
    "event": "tool_call",
    "decision": "decision",
    "checkpoint": "checkpoint",
    "canonicalization": "canonicalization",
}


def main() -> int:
    spec = SPEC.read_text(encoding="utf-8")
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    failures: list[str] = []

    # 1. Every signing-input hash and signature the spec quotes must appear in the
    #    vectors. Checked by presence rather than by parsing the table, so the table
    #    can be reformatted without breaking the check.
    for key in CASES:
        case = vectors[key]
        for label, value in (
            ("signing-input sha256", case["canonical_signing_input_sha256"]),
            ("signature", case["signed_event"]["sig"]),
        ):
            if value not in spec:
                failures.append(
                    f"{key}: the {label} in test-vectors.json ({value[:24]}...) does not "
                    f"appear anywhere in {SPEC.name} — the §6.6 table is stale"
                )

    # 2. Conversely, every 64-hex signing-input hash quoted in the spec's §6.6 table
    #    must be a real one. This is the direction that actually caught the bug: a
    #    leftover value from an earlier regeneration.
    live_hashes = {vectors[k]["canonical_signing_input_sha256"] for k in CASES}
    table = _section(spec, "### 6.6")
    for quoted in re.findall(r"`([0-9a-f]{64})`", table):
        if quoted not in live_hashes:
            failures.append(
                f"§6.6 quotes signing-input hash {quoted} which no vector produces — "
                f"regenerate the vectors or fix the table"
            )

    # 3. The seed and public key quoted in §14 must be the ones in the vectors.
    for label, value in (
        ("public JWK x", vectors["jwks"]["keys"][0]["x"]),
        ("kid", vectors["jwks"]["keys"][0]["kid"]),
    ):
        if value not in spec:
            failures.append(f"§14: the {label} ({value}) does not appear in {SPEC.name}")
    seed = vectors["ed25519_private_seed_hex"]
    if seed[:6] not in spec:
        failures.append(f"§14: the reference seed prefix {seed[:6]} does not appear in {SPEC.name}")

    # 4. The document version and the vectors' recorded spec version must agree.
    doc_version = re.search(r"\*\*Version:\*\* ([0-9]+\.[0-9]+\.[0-9]+)", spec)
    if doc_version and vectors.get("_spec_version") != doc_version.group(1):
        failures.append(
            f"version drift: the spec says {doc_version.group(1)}, the vectors say "
            f"{vectors.get('_spec_version')}"
        )

    # 5. The vectors file must stay pure ASCII: the canonicalization cases carry
    #    non-BMP characters as \\u escapes precisely so no editor, terminal, or
    #    transport can silently mangle the contract.
    raw = VECTORS.read_bytes()
    if any(b > 127 for b in raw):
        failures.append("test-vectors.json contains raw non-ASCII bytes; regenerate with ensure_ascii")

    if failures:
        print("spec/vectors mismatch:\n")
        for f in failures:
            print(f"  - {f}")
        print("\nRegenerate with `python3 tap_ref.py`, then update the §6.6 and §14 tables.")
        return 1

    print(f"ok - {SPEC.name} agrees with {VECTORS.name} "
          f"({len(CASES)} cases, seed, JWK, version, ASCII-safe)")
    return 0


def _section(text: str, heading: str) -> str:
    start = text.find(heading)
    if start == -1:
        return ""
    end = text.find("\n## ", start)
    return text[start : end if end != -1 else len(text)]


if __name__ == "__main__":
    sys.exit(main())
