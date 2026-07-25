"""Merge signed TAP events with their plaintext annexes for human-readable display.

The signed body carries digests only (§6.1); summaries, questions, and
rationale/reason text live in the unsigned annex (§6.1.1). Storage and API
responses must join the two before dashboards or exports render them.
"""
from __future__ import annotations

from typing import Any


def merge_decision(signed: dict | None, annex: dict | None) -> dict | None:
    """Build a display-ready decision block from signed structure + annex plaintext."""
    if not signed:
        return None

    annex_dec = (annex or {}).get("decision") or {}
    annex_opts = {o["id"]: o for o in annex_dec.get("options") or [] if o.get("id")}

    # Legacy transcripts may still embed plaintext in the signed body.
    if signed.get("question") and any(o.get("summary") for o in signed.get("options") or []):
        return {
            "question": signed.get("question"),
            "chosen": signed.get("chosen"),
            "selection": signed.get("selection"),
            "options": [
                {
                    "id": o.get("id"),
                    "chosen": o.get("chosen"),
                    "score": o.get("score"),
                    "summary": o.get("summary") or o.get("id"),
                    "rationale": o.get("rationale"),
                    "reason": o.get("reason"),
                }
                for o in signed.get("options") or []
            ],
        }

    question = annex_dec.get("question") or (annex or {}).get("intent") or signed.get("question")
    out: dict[str, Any] = {
        "chosen": signed.get("chosen"),
        "options": [],
    }
    if question:
        out["question"] = question
    if signed.get("selection"):
        out["selection"] = signed.get("selection")

    for o in signed.get("options") or []:
        oid = o.get("id")
        ao = annex_opts.get(oid) or {}
        chosen = o.get("chosen")
        rationale = ao.get("rationale") or o.get("rationale")
        reason = ao.get("reason") or o.get("reason")
        if chosen and not rationale:
            rationale = reason
        out["options"].append({
            "id": oid,
            "chosen": chosen,
            "score": o.get("score"),
            "summary": ao.get("summary") or o.get("summary") or oid,
            "rationale": rationale,
            "reason": reason if not chosen else None,
        })
    return out


def merge_decision_column(signed: dict | None, annex: dict | None) -> dict | None:
    """Denormalized decision payload for the events.decision column."""
    return merge_decision(signed, annex)


def hydrate_event_record(rec: dict) -> dict:
    """Attach a ``decision`` view (and plaintext intent/reasoning hints) on the event envelope."""
    annex = rec.get("annex") or {}
    raw = rec.get("raw") or {}
    action = raw.get("action") or {}
    evidence = raw.get("evidence") or {}

    view: dict[str, Any] = {}
    if not action.get("intent") and annex.get("intent"):
        view["intent"] = annex["intent"]
    if not evidence.get("reasoning") and annex.get("reasoning"):
        view["reasoning"] = annex["reasoning"]

    decision = merge_decision(raw.get("decision"), annex)
    if decision:
        view["decision"] = decision

    if view:
        rec["view"] = view
        # Convenience for clients that read a top-level hydrated decision block.
        if decision:
            rec["decision"] = decision
    return rec


def hydrate_record(record: dict | None) -> dict | None:
    if record is None:
        return None
    for rec in record.get("events") or []:
        hydrate_event_record(rec)
    return record
