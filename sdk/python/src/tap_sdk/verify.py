"""Verification logic: signatures, drift, sequence integrity, assurance.

This is the Verifier conformance class ([TAP-CONFORMANCE]): §3 signature checks, §4.3
passport validation, §5.4 event verification, §6 assurance labeling, §7 chain
join + replay signals, §9 code preservation. It is pure(ish) — it takes records
and a key resolver and returns evaluations — so it is equally usable by the
ingest hot path and the offline ``/v1/verify`` report.
"""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any, Callable

from .display import hydrate_record

from .core import (
    RevokedKey,
    checkpoint_root,
    key_revoked_at,
    scope_satisfied,
    verify_event,
    verify_passport,
)
from .policy import (
    PolicyRequest,
    evaluate as evaluate_policy,
    policy_version,
)

# kid -> public JWK dict
KeyResolver = Callable[[str], dict | None]


def _parse_event_ts(ts: str | None) -> int | None:
    """Parse an RFC 3339 ``ts`` string to epoch-seconds; return None on failure."""
    if not ts:
        return None
    try:
        import datetime
        dt = datetime.datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return int(dt.timestamp())
    except Exception:
        return None


def evaluate_event(
    event: dict,
    *,
    resolve_key: KeyResolver,
    passport_claims: dict | None,
    last_seq: int | None,
) -> dict:
    """Evaluate one event. Returns sig validity, drift, and integrity signals.

    An invalid signature is itself evidence — it is recorded, never silently
    dropped ([TAP-EVT-ENVELOPE]).
    """
    kid = event.get("kid")
    jwk = resolve_key(kid) if kid else None

    sig_valid = False
    revoked_key = False
    if jwk is not None:
        # verify_event enforces suite dispatch and the revocation boundary itself
        # [TAP-EVT-VERIFY]; RevokedKey is separated out here only so the report can
        # say *why* — "this key was retired" is a different operational story from
        # "this signature is wrong".
        try:
            sig_valid = verify_event(jwk, event)
        except RevokedKey:
            revoked_key = True
        except Exception:
            sig_valid = False

    if revoked_key:
        return {
            "event_id": event.get("event_id"),
            "sig_valid": False,
            "drift": False,
            "drift_reason": "key_revoked",
            "integrity": {},
            "policy_decision": None,
            "denied": False,
        }

    # Drift: scope_used ⊆ passport.scope ([TAP-SCOPE-MATCH]). Only meaningful once the
    # signature is valid and we know the governing passport.
    drift = False
    drift_reason = None
    if sig_valid and passport_claims is not None:
        scope_used = event.get("action", {}).get("scope_used")
        if not scope_satisfied(scope_used, passport_claims.get("scope", [])):
            drift = True
            drift_reason = "scope_escalation"

    # Sequence integrity ([TAP-EVT-SEQ]): gaps and duplicates are signals.
    integrity: dict[str, Any] = {}
    seq = event.get("seq")
    if isinstance(seq, int) and last_seq is not None:
        if seq <= last_seq:
            integrity["seq_duplicate"] = seq
        elif seq > last_seq + 1:
            integrity["seq_gap"] = list(range(last_seq + 1, seq))

    # Policy decision stamped at enforcement time [TAP-POLICY-RECORD]. The Verifier
    # records it as-signed; a denial is itself audit evidence.
    pd = event.get("policy_decision") if sig_valid else None

    return {
        "event_id": event.get("event_id"),
        "sig_valid": sig_valid,
        "drift": drift,
        "drift_reason": drift_reason,
        "integrity": integrity,
        "policy_decision": pd,
        "denied": bool(pd and pd.get("decision") == "deny"),
    }


def check_passport(
    compact_jwt: str, *, resolve_key: KeyResolver, now: int | None = None
) -> dict:
    """Validate a passport per [TAP-PASSPORT-VALIDATE]. Returns claims + validity flags."""
    now = now or int(time.time())
    try:
        header_kid = _peek_kid(compact_jwt)
        jwk = resolve_key(header_kid) if header_kid else None
        if jwk is None:
            return {"valid": False, "expired": False, "reason": "unknown kid", "claims": None}
        claims = verify_passport(jwk, compact_jwt, now=now)
        return {"valid": True, "expired": False, "claims": claims}
    except AssertionError as exc:
        expired = "expired" in str(exc)
        return {"valid": False, "expired": expired, "reason": str(exc), "claims": None}
    except Exception as exc:
        return {"valid": False, "expired": False, "reason": str(exc), "claims": None}


def peek_kid(compact_jwt: str) -> str | None:
    """Read the `kid` from a compact JWT header without verifying (the kid is in
    the JOSE header, not the claims)."""
    import base64
    import json

    try:
        h_b64 = compact_jwt.split(".", 1)[0]
        pad = "=" * (-len(h_b64) % 4)
        header = json.loads(base64.urlsafe_b64decode(h_b64 + pad))
        return header.get("kid")
    except Exception:
        return None


_peek_kid = peek_kid  # backward-compatible alias


def reconcile_checkpoint(checkpoint: dict, events: list[dict]) -> dict:
    """Reconcile one signed checkpoint against the Events actually delivered
    [TAP-EVT-CHECKPOINT].

    The interval is half-open and **self-describing**: `(from_seq, through_seq]`,
    both carried in the signed body. Reading the lower bound from the checkpoint
    rather than inferring it from whichever earlier checkpoints happened to arrive
    is what keeps reconciliation correct when one of them was lost or suppressed —
    inferring it makes every checkpoint after a missing one report a mismatch
    caused by the verifier's own bookkeeping.

    Two signals, deliberately kept apart:

    * ``root_mismatch`` — the delivered set is not the sealed set. An integrity
      failure, but on its own it does not say which Event is missing, or whether
      one was *added*.
    * ``provably_deleted`` — specific ``event_id``s the Signer committed to and
      never delivered. This is the strong claim, and it is only available when the
      checkpoint enumerates its leaves (``reconciliation.event_ids``), which the
      conformance vectors do and a bare wire checkpoint does not.

    Reporting a mismatch *as* provable deletion overstates the evidence, and
    overstating evidence is the one thing an audit tool must never do.
    """
    cp = checkpoint.get("checkpoint") or {}
    through_seq = cp.get("through_seq")
    # from_seq is REQUIRED as of v0.1.2. Absent, the safest reading of a legacy
    # checkpoint is "from the start of the record", which is what the interval
    # meant before the bound was explicit.
    from_seq = cp.get("from_seq", 0) or 0
    claimed_root = cp.get("event_id_root")

    delivered = [
        e for e in events
        if isinstance(e.get("seq"), int)
        and from_seq < e["seq"] <= (through_seq if isinstance(through_seq, int) else -1)
    ]
    delivered_ids = [e.get("event_id", "") for e in sorted(delivered, key=lambda e: e["seq"])]
    actual_root = checkpoint_root(delivered_ids)
    root_valid = actual_root == claimed_root

    # Only computable when the committed leaves are known; a wire checkpoint
    # carries the root alone, by design (the root is the commitment).
    committed_ids = (checkpoint.get("reconciliation") or {}).get("event_ids")
    missing = ([eid for eid in committed_ids if eid not in set(delivered_ids)]
               if isinstance(committed_ids, list) else [])

    count_claimed = cp.get("count")
    return {
        "from_seq": from_seq,
        "through_seq": through_seq,
        "count_claimed": count_claimed,
        "count_received": len(delivered_ids),
        "count_matches": count_claimed is None or count_claimed == len(delivered_ids),
        "root_valid": root_valid,
        "root_mismatch": not root_valid,
        "computed_root": actual_root,
        "claimed_root": claimed_root,
        "provably_deleted": missing,
        "sig_valid": True,
    }


def assurance_level(legs: list[dict]) -> str:
    """Two-sided attestation labeling per [TAP-ASSURANCE] — full consistency predicate.

    Returns intent-only / two-sided / conflicting. The consistency predicate is
    normative: both legs must agree on cid, action.tool, action.kind, and their
    results must not contradict. A status or code contradiction raises conflicting.
    """
    agent = [e for e in legs if e.get("attestor") == "agent"]
    server = [e for e in legs if e.get("attestor") == "server"]
    if not server:
        return "intent-only"

    for a in agent:
        for s in server:
            a_act = a.get("action") or {}
            s_act = s.get("action") or {}
            a_res = a.get("result") or {}
            s_res = s.get("result") or {}

            # cid, tool, and kind must all match (§7 consistency predicate)
            if (a.get("cid") != s.get("cid")
                    or a_act.get("tool") != s_act.get("tool")
                    or a_act.get("kind") != s_act.get("kind")):
                return "conflicting"

            # Result contradiction: server denied/failed what agent claimed succeeded
            a_status = a_res.get("status")
            s_status = s_res.get("status")
            if s_status in ("denied", "failure") and a_status == "success":
                return "conflicting"

            # Differing non-OK result codes are a contradiction
            a_code = a_res.get("code")
            s_code = s_res.get("code")
            if (a_code and s_code
                    and a_code not in ("OK", None) and s_code not in ("OK", None)
                    and a_code != s_code):
                return "conflicting"

    return "two-sided"


def nego_violation(legs: list[dict]) -> bool:
    """True iff any leg's ``evidence.nego`` claims ``attestation:"server"`` while
    this action's own correlated legs contain no ``server`` attestor at all
    ([TAP-NEGO-BINDING] anti-downgrade). A network intermediary that strips the
    handshake removes the server leg, but the Signer's own signed claim
    survives — this is exactly that scenario, and per §4.1 it MUST be flagged
    identically to a conflicting attestation.

    Deliberately does not re-check result agreement: when a server leg *is*
    present but disagrees, `assurance_level`'s existing consistency predicate
    already returns "conflicting" on its own. This only catches the case that
    would otherwise read as plain "intent-only" despite the claim."""
    claims_server = any(
        ((leg.get("evidence") or {}).get("nego") or {}).get("attestation") == "server"
        for leg in legs
    )
    if not claims_server:
        return False
    return not any(leg.get("attestor") == "server" for leg in legs)


def _levels_for_groups(groups: dict[str, list[dict]]) -> dict[str, str]:
    """Per-action_ref assurance level for pre-grouped legs, folding the nego
    anti-downgrade check into the same "conflicting" bucket the spec requires.
    Shared by `annotate_assurance` (read-time record view) and
    `verify_transcript` (Audit-in-a-Box report) so the two can't diverge."""
    levels: dict[str, str] = {}
    for ref, legs in groups.items():
        level = assurance_level(legs)
        if level != "conflicting" and nego_violation(legs):
            level = "conflicting"
        levels[ref] = level
    return levels


def annotate_assurance(record: dict | None) -> dict | None:
    """Enrich a reconstructed record with two-sided attestation state ([TAP-EVT-ENVELOPE]).

    Correlates the agent leg (``attestor:"agent"``) and the server leg
    (``attestor:"server"``) of each action on their shared ``action_ref``, stamps
    every event record with its ``assurance`` (intent-only / two-sided /
    conflicting), and raises a record-level ``flags.conflicting`` when any action's
    legs disagree — the integrity alert that proves "decided ≠ did". This is the
    sharpest, least-copyable edge: an intent-only proxy can never reach two-sided.
    """
    if record is None:
        return None
    records = record.get("events", [])

    # Group raw legs by action_ref (only sig-valid legs count toward assurance).
    groups: dict[str, list[dict]] = {}
    for rec in records:
        raw = rec.get("raw", {})
        ref = raw.get("action_ref")
        if ref and rec.get("sig_valid"):
            groups.setdefault(ref, []).append(raw)

    levels = _levels_for_groups(groups)

    conflicting = False
    nego_mismatch_any = False
    for rec in records:
        ref = rec.get("raw", {}).get("action_ref")
        level = levels.get(ref, "intent-only") if ref else "intent-only"
        rec["assurance"] = level
        mismatch = bool(ref and nego_violation(groups.get(ref, [])))
        rec["nego_mismatch"] = mismatch
        if level == "conflicting":
            conflicting = True
        if mismatch:
            nego_mismatch_any = True

    counts = {"intent-only": 0, "two-sided": 0, "conflicting": 0}
    for level in levels.values():
        counts[level] = counts.get(level, 0) + 1

    flags = record.setdefault("flags", {})
    flags["conflicting"] = conflicting
    flags["nego_mismatch"] = nego_mismatch_any
    record["assurance"] = {"by_action_ref": levels, "counts": counts}
    return hydrate_record(record)


def build_chain(cid: str, records: list[dict]) -> dict:
    """Stitch a multi-agent delegation chain (spec §8.1).

    Real agent systems are trees: orchestrator → specialist → tools. All records in
    one chain share a ``cid``; each ``received_delegation`` event references the
    delegating ``agent_delegate`` event via ``parent_event_id``. We join them into
    a DAG, label every record with its two-sided assurance, and mark each handoff
    edge ``verified`` only when **both** legs' signatures check out — so a broken
    or unverified handoff breaks the chain visibly rather than silently. This
    cross-protocol (A2A + MCP) chain of custody is the wedge a single-LLM-call
    model can't hold as systems go multi-agent."""
    records = [annotate_assurance(r) for r in records if r is not None]

    # Index every event_id -> its owning aid, and capture each event's validity.
    owner: dict[str, str] = {}
    valid: dict[str, bool] = {}
    for record in records:
        for rec in record.get("events", []):
            eid = rec.get("raw", {}).get("event_id")
            if eid:
                owner[eid] = record["aid"]
                valid[eid] = bool(rec.get("sig_valid"))

    edges: list[dict] = []
    children: set[str] = set()
    for record in records:
        for rec in record.get("events", []):
            raw = rec.get("raw", {})
            if raw.get("action", {}).get("kind") != "received_delegation":
                continue
            parent_eid = raw.get("parent_event_id")
            child_eid = raw.get("event_id")
            parent_aid = owner.get(parent_eid) if parent_eid else None
            resolved = parent_aid is not None
            edges.append({
                "parent_event_id": parent_eid,
                "parent_aid": parent_aid,
                "child_event_id": child_eid,
                "child_aid": record["aid"],
                # The handoff is verified only if both legs are signed AND linked.
                "verified": resolved and valid.get(parent_eid, False) and valid.get(child_eid, False),
                "broken": not resolved,  # dangling parent ⇒ chain breaks visibly
            })
            children.add(record["aid"])

    roots = [r["aid"] for r in records if r["aid"] not in children]
    return {
        "cid": cid,
        "records": records,
        "edges": edges,
        "roots": roots,
        "chain_intact": all(e["verified"] for e in edges),
        "nego_mismatch": any(r.get("flags", {}).get("nego_mismatch") for r in records),
    }


def verify_transcript(
    passport_jwt: str,
    events: list[dict],
    *,
    resolve_key: KeyResolver,
    now: int | None = None,
) -> dict:
    """Audit-in-a-Box report ([TAP-CONFORMANCE]) — the artifact an auditor wants."""
    pp = check_passport(passport_jwt, resolve_key=resolve_key, now=now)
    claims = pp.get("claims")

    ordered = sorted(events, key=lambda e: e.get("seq", 0))

    # Split checkpoint events from regular action events (§6.3)
    checkpoints = [e for e in ordered if (e.get("action") or {}).get("kind") == "checkpoint"]
    regular = [e for e in ordered if (e.get("action") or {}).get("kind") != "checkpoint"]

    valid_sig = 0
    drift: list[dict] = []
    denials: list[dict] = []
    last_seq: int | None = None
    seq_gaps: list[int] = []
    duplicates: list[int] = []
    # Sig-valid legs grouped by action_ref — the same shape annotate_assurance()
    # groups, so verify_transcript() can surface identical assurance/nego signals
    # in the Audit-in-a-Box report ([TAP-NEGO-BINDING], §7).
    action_groups: dict[str, list[dict]] = {}

    for ev in regular:
        res = evaluate_event(
            ev, resolve_key=resolve_key, passport_claims=claims, last_seq=last_seq
        )
        if res["sig_valid"]:
            valid_sig += 1
            ref = ev.get("action_ref")
            if ref:
                action_groups.setdefault(ref, []).append(ev)
        if res["drift"]:
            drift.append({
                "event_id": res["event_id"],
                "scope_used": ev.get("action", {}).get("scope_used"),
                "reason": "not in passport scope",
            })
        if res["denied"]:
            pd = res["policy_decision"] or {}
            denials.append({
                "event_id": res["event_id"],
                "rule_id": pd.get("rule_id"),
                "policy_version": pd.get("policy_version"),
            })
        seq_gaps.extend(res["integrity"].get("seq_gap", []))
        if "seq_duplicate" in res["integrity"]:
            duplicates.append(res["integrity"]["seq_duplicate"])
        seq = ev.get("seq")
        if isinstance(seq, int):
            last_seq = seq if last_seq is None else max(last_seq, seq)

    # Checkpoint reconciliation [TAP-EVT-CHECKPOINT].
    checkpoint_results: list[dict] = []
    for cp in checkpoints:
        cp_res = evaluate_event(
            cp, resolve_key=resolve_key, passport_claims=claims, last_seq=None
        )
        if cp_res["sig_valid"]:
            checkpoint_results.append(
                reconcile_checkpoint(cp, regular)
            )

    total = len(regular) + len(checkpoints)
    invalid_sig = len(regular) - valid_sig
    # A record with a sound signature on every event but a checkpoint that does not
    # reconcile is NOT verified: the checkpoint is the only thing standing between
    # fail-open reporting and undetectable suppression [TAP-EVT-CHECKPOINT].
    verified = (
        pp["valid"] and not pp.get("expired") and invalid_sig == 0 and not drift
        and all(c["root_valid"] and c["count_matches"] for c in checkpoint_results)
    )

    # Assurance per action_ref ([TAP-ASSURANCE]) + nego anti-downgrade folding (§4.1) —
    # the same computation annotate_assurance() runs at read time, reused here so
    # the audit report and the live record view never disagree.
    assurance_by_ref = _levels_for_groups(action_groups)
    nego_mismatches = [ref for ref, legs in action_groups.items() if nego_violation(legs)]

    parts = []
    parts.append("All signatures valid." if invalid_sig == 0 else f"{invalid_sig} invalid signature(s).")
    if seq_gaps:
        parts.append(f"{len(seq_gaps)} sequence gap(s) at {seq_gaps}.")
    if drift:
        parts.append(f"{len(drift)} scope drift detected.")
    if denials:
        parts.append(f"{len(denials)} action(s) denied by policy.")
    if checkpoints:
        parts.append(f"{len(checkpoints)} checkpoint(s) present.")
    bad_roots = [c for c in checkpoint_results if c["root_mismatch"]]
    deleted = [eid for c in checkpoint_results for eid in c["provably_deleted"]]
    if bad_roots:
        parts.append(
            f"{len(bad_roots)} checkpoint root mismatch(es) — the delivered events "
            f"are not the sealed set."
        )
    if deleted:
        parts.append(f"{len(deleted)} event(s) provably deleted: {deleted}.")
    if nego_mismatches:
        parts.append(f"{len(nego_mismatches)} action(s) show conflicting/downgraded assurance.")
    if not pp["valid"]:
        parts.append(f"Passport invalid ({pp.get('reason')}).")

    return {
        "verified": verified,
        "passport": {"valid": pp["valid"], "expired": pp.get("expired", False)},
        "events": {"total": total, "valid_sig": valid_sig, "invalid_sig": invalid_sig},
        "integrity": {"seq_gaps": seq_gaps, "duplicates": duplicates},
        "checkpoints": checkpoint_results,
        "drift": drift,
        "denials": denials,
        "assurance": {"by_action_ref": assurance_by_ref, "nego_mismatches": nego_mismatches},
        "summary": " ".join(parts),
    }


def backtest_policy(
    events: list[dict],
    policy: dict,
    *,
    passport_claims: dict | None = None,
    env: str | None = None,
) -> dict:
    """Re-evaluate a historical transcript against a policy version [TAP-POLICY-RECORD].

    This is two things at once:

    * **Compliance proof.** Re-running each event against its *stamped*
      ``policy_version`` must reproduce the original decision byte-for-byte —
      turning "we had a policy" into "here is the reproducible proof of the
      decision that ran." A mismatch (``reproduced: false``) is an integrity alert.
    * **Policy backtest.** Run a *different* (e.g. proposed) policy over real
      historical actions to see what *would* have been denied — the parity
      capability against replay-style tools, but over what the agent *actually
      did*, not a model re-decision.

    Returns per-event decisions and a count of would-be denials under ``policy``.
    """
    target_version = policy_version(policy)
    ordered = sorted(events, key=lambda e: e.get("seq", 0))
    results: list[dict] = []
    would_deny = 0
    reproduced_all = True

    for ev in ordered:
        req = PolicyRequest.from_event(ev, passport_claims=passport_claims, env=env)
        decision = evaluate_policy(policy, req)
        stamped = ev.get("policy_decision") or {}
        # "Reproduced" only compares against a decision stamped under the SAME
        # policy version — otherwise we are backtesting a different policy, and a
        # differing outcome is the expected, useful signal (not a tamper alert).
        same_version = stamped.get("policy_version") == target_version
        reproduced = (not same_version) or (
            stamped.get("decision") == decision.decision
            and stamped.get("rule_id") == decision.rule_id
        )
        if same_version and not reproduced:
            reproduced_all = False
        if decision.denied:
            would_deny += 1
        results.append({
            "event_id": ev.get("event_id"),
            "tool": (ev.get("action") or {}).get("tool"),
            "decision": decision.decision,
            "rule_id": decision.rule_id,
            "stamped": stamped or None,
            "reproduced": reproduced if same_version else None,
        })

    return {
        "policy_version": target_version,
        "events": len(ordered),
        "would_deny": would_deny,
        "reproduced_all": reproduced_all,
        "decisions": results,
    }
