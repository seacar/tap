"""Typed decisions: decider provenance and confidence gates (§6.4.1, provisional).

A §6.4 decision records what was chosen and what else was considered. v0.1.7
adds two OPTIONAL blocks inside ``decision`` so a record can also say *who*
chose, and whether a low-confidence answer was acted on or escalated:

* ``decider`` [TAP-EVT-DECIDER] — the model, rule, or human that made the
  decision, its version, the typed output contract it was held to, and how to
  read its scores.
* ``gate`` [TAP-EVT-GATE] — the confidence threshold the decision was held to,
  and whether it cleared it (``accept``) or fell back (``fallback``).

Everything here is a pure function, like checkpoint reconciliation and the
authority-binding checks: no registry, no network. Gate arithmetic is exact
decimal arithmetic on integer millionths [TAP-EVT-GATE-DECIMAL] — never a
float, because two Verifiers that disagree about a score sitting exactly on the
threshold disagree exactly where it matters.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .core import json_digest

DECIDER_KINDS = ("model", "rule", "human")
SCORE_SEMANTICS = ("calibrated_probability", "probability", "uncalibrated")
GATED_SCORE_SEMANTICS = ("calibrated_probability", "probability")
GATE_OUTCOMES = ("accept", "fallback")

GateLabel = str  # "gate_consistent" | "gate_inconsistent" | "gate_unscorable"

_GATE_DECIMAL = re.compile(r"^(?:0(?:\.[0-9]{1,6})?|1(?:\.0{1,6})?)$")


class DeciderError(ValueError):
    """A decider or gate block that cannot be signed as a conforming record."""


def gate_decimal_micros(value: Any) -> int:
    """Parse a gate decimal to integer millionths, exactly [TAP-EVT-GATE-DECIMAL].

    Accepts only strings matching ``0``, ``1``, ``0.d{1,6}`` or ``1.0{1,6}``.
    Raises ``ValueError`` on anything else, including floats: a float has
    already lost the exactness this rule exists to keep."""
    if not isinstance(value, str) or not _GATE_DECIMAL.match(value):
        raise ValueError(f"not a gate decimal in [0, 1] with <= 6 places: {value!r}")
    whole, _, frac = value.partition(".")
    return int(whole) * 1_000_000 + int((frac + "000000")[:6])


def gate_outcome(score: str, threshold: str) -> str:
    """``"accept"`` iff ``score >= threshold`` as exact decimals, else ``"fallback"``."""
    return "accept" if gate_decimal_micros(score) >= gate_decimal_micros(threshold) else "fallback"


def decision_gate_label(decision: dict | None) -> GateLabel | None:
    """Label a decision's confidence gate [TAP-EVT-GATE, §6.4.1].

    ``None`` when there is no gate (the label does not apply). Otherwise
    ``gate_consistent`` / ``gate_inconsistent`` / ``gate_unscorable`` — see the
    spec's table. Mirrors ``tap_ref.decision_gate_label`` exactly."""
    if not isinstance(decision, dict) or "gate" not in decision:
        return None
    gate = decision.get("gate") or {}
    decider = decision.get("decider") or {}
    if not isinstance(gate, dict) or not isinstance(decider, dict):
        return "gate_unscorable"
    if decider.get("score_semantics") not in GATED_SCORE_SEMANTICS:
        return "gate_unscorable"
    chosen = [o for o in decision.get("options") or []
              if isinstance(o, dict) and o.get("chosen") is True]
    if len(chosen) != 1 or chosen[0].get("id") != decision.get("chosen"):
        return "gate_unscorable"
    try:
        expected = gate_outcome(chosen[0].get("score"), gate.get("threshold"))
    except ValueError:
        return "gate_unscorable"
    if gate.get("outcome") not in GATE_OUTCOMES:
        return "gate_unscorable"
    return "gate_consistent" if gate["outcome"] == expected else "gate_inconsistent"


def check_output_schema(decision: dict, annex_decision: dict | None) -> dict:
    """Check a decider's annexed output schema against the signed record.

    Returns ``{"schema_present", "schema_digest_valid", "labels_permitted"}``.
    A missing annex is an informational gap, never an integrity failure
    [TAP-EVT-ANNEX] — so every field is ``None`` when there is nothing to check.
    ``labels_permitted`` is evaluated only for schemas whose ``label`` (or
    top-level) property is an ``enum``; otherwise it is ``None``."""
    out: dict[str, Any] = {"schema_present": False, "schema_digest_valid": None,
                           "labels_permitted": None}
    decider = (decision or {}).get("decider") or {}
    signed = decider.get("output_schema_digest")
    schema = (annex_decision or {}).get("output_schema")
    if schema is None or signed is None:
        return out
    out["schema_present"] = True
    out["schema_digest_valid"] = json_digest(schema) == signed
    enum = None
    if isinstance(schema, dict):
        enum = schema.get("enum")
        props = schema.get("properties")
        if enum is None and isinstance(props, dict) and isinstance(props.get("label"), dict):
            enum = props["label"].get("enum")
    if isinstance(enum, list):
        ids = {o.get("id") for o in decision.get("options") or [] if isinstance(o, dict)}
        out["labels_permitted"] = ids <= set(enum)
    return out


@dataclass(frozen=True)
class Decider:
    """The component behind a decision [TAP-EVT-DECIDER].

    ``output_schema`` is the plaintext typed contract; only its digest is
    signed, and the plaintext goes to the annex (erasable, §6.1.2)."""
    kind: str
    id: str
    version: str | None = None
    output_schema: Any = None
    score_semantics: str | None = None
    version_digest: str | None = None

    def block(self, *, scored: bool) -> dict[str, Any]:
        """The signed ``decider`` block, validated, with absent fields omitted."""
        if self.kind not in DECIDER_KINDS:
            raise DeciderError(f"decider.kind must be one of {DECIDER_KINDS}, got {self.kind!r}")
        if not self.id:
            raise DeciderError("decider.id is REQUIRED")
        if self.kind in ("model", "rule") and not self.version:
            raise DeciderError(f"decider.version is REQUIRED for kind {self.kind!r}")
        if self.kind == "model" and self.output_schema is None:
            raise DeciderError("decider.output_schema is REQUIRED for kind 'model'")
        if self.score_semantics is not None and self.score_semantics not in SCORE_SEMANTICS:
            raise DeciderError(f"score_semantics must be one of {SCORE_SEMANTICS}")
        if scored and self.score_semantics is None:
            raise DeciderError("score_semantics is REQUIRED when any option carries a score")
        b: dict[str, Any] = {"kind": self.kind, "id": self.id}
        if self.version:
            b["version"] = self.version
        if self.version_digest:
            b["version_digest"] = self.version_digest
        if self.output_schema is not None:
            b["output_schema_digest"] = json_digest(self.output_schema)
        if self.score_semantics is not None:
            b["score_semantics"] = self.score_semantics
        return b


def build_gate(*, score: str | None, threshold: str, decider_block: dict,
               fallback_to: str | None = None) -> dict[str, Any]:
    """Compute a signed ``gate`` block. The outcome is DERIVED, never passed in:
    a caller cannot record ``accept`` for a score below its own threshold."""
    if decider_block.get("score_semantics") not in GATED_SCORE_SEMANTICS:
        raise DeciderError("a gate needs a decider whose score_semantics is a probability")
    if score is None:
        raise DeciderError("a gate needs a score on the chosen option")
    try:
        outcome = gate_outcome(score, threshold)
    except ValueError as exc:
        raise DeciderError(str(exc)) from exc
    g: dict[str, Any] = {"threshold": threshold, "outcome": outcome}
    if fallback_to:
        g["fallback_to"] = fallback_to
    return g


def unresolved_fallbacks(events: list[dict]) -> list[str]:
    """event_ids of fallback-gated decisions no delivered ``decision`` supersedes.

    Informational, like an uncovered sequence gap [TAP-EVT-GATE]: the
    superseding decision may simply not have arrived yet."""
    fallback_ids = [
        e.get("event_id") for e in events
        if (e.get("action") or {}).get("kind") == "decision"
        and ((e.get("decision") or {}).get("gate") or {}).get("outcome") == "fallback"
    ]
    parents = {e.get("parent_event_id") for e in events
               if (e.get("action") or {}).get("kind") == "decision"}
    return [eid for eid in fallback_ids if eid not in parents]
