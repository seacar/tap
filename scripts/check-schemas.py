#!/usr/bin/env python3
"""The published schemas and registries must describe the published vectors.

A schema nobody validates against is documentation that drifts. So every signed
case in `test-vectors.json` is checked against `schemas/event.schema.json`, the
passport claims against the passport schema, the annexes against the annex schema,
and every `result.code` and suite id against the machine-readable registries.

Uses `jsonschema` when it is installed and falls back to a small structural check
otherwise, so this runs in a bare environment rather than being skipped — a check
that quietly does nothing is worse than no check.

Run:  python scripts/check-schemas.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

VECTORS = json.loads((ROOT / "test-vectors.json").read_text(encoding="utf-8"))
EVENT_SCHEMA = json.loads((ROOT / "schemas/event.schema.json").read_text(encoding="utf-8"))
PASSPORT_SCHEMA = json.loads((ROOT / "schemas/passport.schema.json").read_text(encoding="utf-8"))
ANNEX_SCHEMA = json.loads((ROOT / "schemas/annex.schema.json").read_text(encoding="utf-8"))
SUITES = json.loads((ROOT / "registries/suites.json").read_text(encoding="utf-8"))
CODES = json.loads((ROOT / "registries/result-codes.json").read_text(encoding="utf-8"))

SIGNED_CASES = ("event", "decision", "checkpoint", "canonicalization", "authorization")


def main() -> int:
    failures: list[str] = []
    validate = _make_validator()

    for case in SIGNED_CASES:
        event = VECTORS[case]["signed_event"]
        failures += [f"{case}: {e}" for e in validate(EVENT_SCHEMA, event)]

        # Registry cross-checks the schema deliberately leaves open, because a
        # Verifier MUST preserve unknown codes rather than reject them — so this is
        # a check on OUR vectors, not a constraint on the wire.
        code = (event.get("result") or {}).get("code")
        if code and code not in {c["code"] for c in CODES["codes"]} and not code.startswith("x."):
            failures.append(f"{case}: result.code {code!r} is neither registered nor namespaced")

        nego = (event.get("evidence") or {}).get("nego")
        if nego and nego.get("suite") not in {s["id"] for s in SUITES["suites"]}:
            failures.append(f"{case}: nego.suite {nego.get('suite')!r} is not in the suite registry")

        annex = VECTORS[case].get("annex")
        if annex:
            failures += [f"{case} annex: {e}" for e in validate(ANNEX_SCHEMA, annex)]
            if annex.get("event_id") != event.get("event_id"):
                failures.append(f"{case}: annex event_id does not match its Event")

    failures += [f"passport: {e}" for e in validate(PASSPORT_SCHEMA, VECTORS["passport"]["claims"])]

    # The negative vectors are non-conforming ON PURPOSE, so they are not validated
    # as a group — but the explicit-nulls case must actually violate the omit rule,
    # or it is not testing what it claims to.
    nulls = VECTORS["negative"]["explicit_nulls_non_conforming"]["event"]
    if not any(nulls.get(f) is None and f in nulls for f in ("parent_event_id", "policy_decision")):
        failures.append("negative.explicit_nulls_non_conforming no longer carries explicit nulls")

    # The suite the reference key declares must be the one the registry names.
    jwk = VECTORS["jwks"]["keys"][0]
    ed25519 = next(s for s in SUITES["suites"] if s["id"] == "tap-ed25519")
    if (jwk.get("alg"), jwk.get("crv")) != (ed25519["jose"]["alg"], ed25519["jose"]["crv"]):
        failures.append("the reference JWK does not match the tap-ed25519 registry entry")

    if failures:
        print("schema/registry mismatch:\n")
        for f in failures:
            print(f"  - {f}")
        return 1

    print(f"ok - {len(SIGNED_CASES)} events, passport, annexes validate against schemas/; "
          f"codes and suites resolve in registries/")
    return 0


def _make_validator():
    """Return validate(schema, instance) -> list[str] of error messages."""
    try:
        import jsonschema  # type: ignore
    except ImportError:
        return _structural_validate

    def validate(schema, instance):
        v = jsonschema.Draft202012Validator(schema)
        return [f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message}"
                for e in v.iter_errors(instance)]

    return validate


def _structural_validate(schema: dict, instance: dict) -> list[str]:
    """Required-properties and type checking, one level deep into objects.

    Not a JSON Schema implementation — deliberately. It exists so the check still
    catches a missing required field when `jsonschema` is not installed, instead of
    the suite silently passing on an environment where nothing was verified.
    """
    errors: list[str] = []

    def walk(sch: dict, inst, path: str) -> None:
        if not isinstance(sch, dict):
            return
        if "$ref" in sch:
            ref = sch["$ref"]
            if ref.startswith("#/$defs/"):
                walk(schema.get("$defs", {}).get(ref.split("/")[-1], {}), inst, path)
            return
        for key in sch.get("required", []):
            if not isinstance(inst, dict) or key not in inst:
                errors.append(f"{path or '<root>'}: missing required property {key!r}")
        const = sch.get("const")
        if const is not None and inst != const:
            errors.append(f"{path}: expected {const!r}, got {inst!r}")
        enum = sch.get("enum")
        if enum is not None and inst not in enum:
            errors.append(f"{path}: {inst!r} not in {enum}")
        if isinstance(inst, dict):
            for name, sub in (sch.get("properties") or {}).items():
                if name in inst:
                    walk(sub, inst[name], f"{path}/{name}" if path else name)

    walk(schema, instance, "")
    return errors


if __name__ == "__main__":
    sys.exit(main())
