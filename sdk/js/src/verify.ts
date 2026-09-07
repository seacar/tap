// The Verifier conformance class, in TypeScript [TAP-CONFORMANCE].
//
// Until v0.1.2 this did not exist: the TypeScript SDK could sign but not verify,
// so half the protocol's central claim — "any relying party can re-verify with
// only a public key" — was reachable only from Python. A verifier that a browser
// cannot run is not "anyone can check this"; it is "anyone with a Python
// environment can check this", which is a materially smaller promise.
//
// This module is therefore deliberately browser-safe: no Node built-ins, no
// filesystem, no network. Give it records and a key resolver and it returns
// evaluations, so it serves an ingest hot path and an offline audit report alike.

import {
  PassportExpired,
  RevokedKey,
  b64uToBytes,
  checkpointRoot,
  parseTs,
  scopeSatisfied,
  verifyEvent,
  verifyPassport,
  type Jwk,
} from "./tap.js";
import { AuthorityRevoked, authorityEffectLabel, checkAuthorityNotRevoked } from "./authority.js";

/**
 * (authzId, authorityStateVersion) -> revoked_at (epoch seconds), or
 * null/undefined when neither is known to be revoked [TAP-AUTHORITY-REVOKE,
 * §9.2, provisional]. This SDK ships no default resolver/registry —
 * publication format and query interface are a Service Profile concern (spec
 * §9.2, §15); a caller (Sworn, or a self-hoster) supplies one. Mirrors
 * VerifyKeyResolver's shape deliberately.
 */
export type AuthorityRevocationResolver = (
  authzId: string,
  authorityStateVersion: string,
) => number | null | undefined | Promise<number | null | undefined>;

/**
 * kid -> public JWK, or null when the key is unknown.
 *
 * Named distinctly from the server leg's synchronous `KeyResolver` because this
 * one may be async: a relying party re-verifying in a browser fetches JWKS over
 * the network, which the server-side resolver never has to do.
 */
export type VerifyKeyResolver = (kid: string) => Jwk | null | Promise<Jwk | null>;

/**
 * kid -> true iff this key is one the deployment recognizes as belonging to a
 * TAP-aware Server or Gateway, and therefore permitted to sign a leg claiming
 * `attestor: "server"` [TAP-ASSURANCE-KEY]. There is no protocol-level way to
 * derive this: "independent attestation" is a trust relationship a Verifier holds
 * out of band, exactly as it holds the JWKS it resolves keys against. Omitted, the
 * structural floor in `assuranceLevel` still applies.
 */
export type ServerKeyPredicate = (kid: string) => boolean;

export type Assurance = "intent-only" | "two-sided" | "conflicting";

export interface EventEvaluation {
  event_id: unknown;
  sig_valid: boolean;
  drift: boolean;
  drift_reason: string | null;
  integrity: { seq_gap?: number[]; seq_duplicate?: number };
  policy_decision: Record<string, unknown> | null;
  denied: boolean;
  /** [TAP-EVT-AUTHORIZATION, §9.2, provisional] — the Event's authorization block, as signed. */
  authorization: Record<string, unknown> | null;
  /** [TAP-AUTHORITY-EFFECT, §9.2, provisional] — null when no `authorization` is present. */
  authority_effect: ReturnType<typeof authorityEffectLabel>;
  /** [TAP-AUTHORITY-REVOKE, §9.2, provisional] — always false unless a
   * `resolveAuthorityRevocation` was supplied and flagged this record. */
  authority_revoked: boolean;
}

type Ev = Record<string, any>;

/**
 * Evaluate one Event: signature validity, scope drift, and sequence integrity.
 *
 * An invalid signature is itself evidence — it is recorded, never silently
 * dropped [TAP-EVT-VERIFY].
 */
export async function evaluateEvent(
  event: Ev,
  opts: {
    resolveKey: VerifyKeyResolver;
    passportClaims?: Record<string, any> | null;
    lastSeq?: number | null;
    /** [TAP-AUTHORITY-REVOKE, §9.2, provisional] — optional; see
     * {@link AuthorityRevocationResolver}. Omitted, `authority_revoked` stays
     * false — this function ships no default registry. */
    resolveAuthorityRevocation?: AuthorityRevocationResolver;
  },
): Promise<EventEvaluation> {
  const kid = event.kid as string | undefined;
  const jwk = kid ? await opts.resolveKey(kid) : null;

  let sigValid = false;
  let revokedKey = false;
  if (jwk) {
    // verifyEvent enforces suite dispatch and the revocation boundary itself;
    // RevokedKey is separated out only so a report can say *why* — "this key was
    // retired" is a different operational story from "this signature is wrong".
    try {
      sigValid = await verifyEvent(jwk, event);
    } catch (e) {
      if (e instanceof RevokedKey) revokedKey = true;
      else sigValid = false;
    }
  }

  if (revokedKey) {
    return {
      event_id: event.event_id,
      sig_valid: false,
      drift: false,
      drift_reason: "key_revoked",
      integrity: {},
      policy_decision: null,
      denied: false,
      authorization: null,
      authority_effect: null,
      authority_revoked: false,
    };
  }

  // Drift: scope_used must be authorized by the governing passport
  // [TAP-SCOPE-MATCH]. Only meaningful once the signature checks out.
  let drift = false;
  let driftReason: string | null = null;
  const claims = opts.passportClaims;
  if (sigValid && claims) {
    const scopeUsed = event.action?.scope_used ?? null;
    if (!scopeSatisfied(scopeUsed, (claims.scope as string[]) ?? [])) {
      drift = true;
      driftReason = "scope_escalation";
    }
  }

  // Sequence integrity [TAP-EVT-SEQ]: gaps and duplicates are signals, not errors.
  const integrity: EventEvaluation["integrity"] = {};
  const seq = event.seq;
  const lastSeq = opts.lastSeq;
  if (typeof seq === "number" && typeof lastSeq === "number") {
    if (seq <= lastSeq) {
      integrity.seq_duplicate = seq;
    } else if (seq > lastSeq + 1) {
      integrity.seq_gap = Array.from({ length: seq - lastSeq - 1 }, (_, i) => lastSeq + 1 + i);
    }
  }

  const pd = sigValid ? ((event.policy_decision as Record<string, unknown>) ?? null) : null;
  // [TAP-EVT-AUTHORIZATION / TAP-AUTHORITY-EFFECT, §9.2, provisional]. Labeled
  // ALONGSIDE policy_decision and two-sided assurance, never in place of
  // either. Only meaningful once the signature checks out — an unverified
  // leg's claimed authorization is not evidence. Single-use is NOT checked
  // here: batch-local reuse is verifyTranscript's job (it needs the whole
  // batch); cross-session reuse needs a live registry this pure function
  // does not have.
  const authorization = sigValid ? ((event.authorization as Record<string, unknown>) ?? null) : null;
  const authorityEffect = authorization ? authorityEffectLabel(authorization as any, event.result) : null;

  // Revocation [TAP-AUTHORITY-REVOKE, §9.2, provisional]: kept separate from
  // authority_effect on purpose — a revoked-but-matching Event is a worse
  // signal than a mismatch, not a non-signal — and it does NOT flip
  // sig_valid: the signature is still authentic, only the claimed authority
  // is void, the same distinction this codebase already draws between "wrong
  // signature" and "denied by policy".
  let authorityRevoked = false;
  if (authorization && opts.resolveAuthorityRevocation) {
    const signedTs = typeof event.ts === "string" ? parseTs(event.ts) : NaN;
    if (Number.isFinite(signedTs)) {
      const revokedAt = await opts.resolveAuthorityRevocation(
        authorization.authz_id as string, authorization.authority_state_version as string);
      try {
        checkAuthorityNotRevoked(
          authorization.authz_id as string, authorization.authority_state_version as string,
          revokedAt, signedTs);
      } catch (e) {
        if (e instanceof AuthorityRevoked) authorityRevoked = true;
        else throw e;
      }
    }
  }

  return {
    event_id: event.event_id,
    sig_valid: sigValid,
    drift,
    drift_reason: driftReason,
    integrity,
    policy_decision: pd,
    denied: Boolean(pd && pd.decision === "deny"),
    authorization,
    authority_effect: authorityEffect,
    authority_revoked: authorityRevoked,
  };
}

/** Read the `kid` from a compact JWT header WITHOUT verifying it. */
export function peekKid(compactJwt: string): string | null {
  try {
    const header = JSON.parse(
      new TextDecoder().decode(b64uToBytes(compactJwt.split(".", 1)[0])),
    );
    return header.kid ?? null;
  } catch {
    return null;
  }
}

export interface PassportCheck {
  valid: boolean;
  expired: boolean;
  reason?: string;
  claims: Record<string, any> | null;
}

/** Validate a Passport [TAP-PASSPORT-VALIDATE]. */
export async function checkPassport(
  compactJwt: string,
  opts: { resolveKey: VerifyKeyResolver; now?: number },
): Promise<PassportCheck> {
  const now = opts.now ?? Math.floor(Date.now() / 1000);
  try {
    const kid = peekKid(compactJwt);
    const jwk = kid ? await opts.resolveKey(kid) : null;
    if (!jwk) return { valid: false, expired: false, reason: "unknown kid", claims: null };
    const claims = await verifyPassport(jwk, compactJwt, now);
    return { valid: true, expired: false, claims: claims as Record<string, any> };
  } catch (e) {
    const reason = (e as Error).message;
    // A typed error, not a substring match on a message [TAP-PASSPORT-VALIDATE].
    return { valid: false, expired: e instanceof PassportExpired, reason, claims: null };
  }
}

export interface CheckpointReconciliation {
  from_seq: number;
  through_seq: unknown;
  count_claimed: unknown;
  count_received: number;
  count_matches: boolean;
  root_valid: boolean;
  root_mismatch: boolean;
  computed_root: string;
  claimed_root: unknown;
  provably_deleted: string[];
  sig_valid: boolean;
}

/**
 * Reconcile one signed checkpoint against the Events actually delivered
 * [TAP-EVT-CHECKPOINT].
 *
 * The interval is half-open and self-describing: `(from_seq, through_seq]`, both
 * carried in the signed body. Reading the lower bound from the checkpoint rather
 * than inferring it from whichever earlier checkpoints happened to arrive is what
 * keeps reconciliation correct when one of them was lost or suppressed.
 *
 * Two signals, deliberately kept apart:
 *
 *  - `root_mismatch` — the delivered set is not the sealed set. An integrity
 *    failure, but on its own it identifies neither which Event is missing nor
 *    whether one was *added*.
 *  - `provably_deleted` — specific `event_id`s the Signer committed to and never
 *    delivered. The strong claim, available only when the checkpoint enumerates
 *    its leaves. Reporting a mismatch *as* provable deletion overstates the
 *    evidence, and overstating evidence is the one thing an audit tool must not do.
 */
export function reconcileCheckpoint(checkpoint: Ev, events: Ev[]): CheckpointReconciliation {
  const cp = (checkpoint.checkpoint ?? {}) as Record<string, any>;
  const throughSeq = cp.through_seq;
  // from_seq is REQUIRED as of v0.1.2. Absent, the safest reading of a legacy
  // checkpoint is "from the start of the record", which is what it used to mean.
  const fromSeq: number = cp.from_seq ?? 0;
  const claimedRoot = cp.event_id_root;

  const delivered = events
    .filter(
      (e) =>
        typeof e.seq === "number" &&
        typeof throughSeq === "number" &&
        e.seq > fromSeq &&
        e.seq <= throughSeq,
    )
    .sort((a, b) => (a.seq as number) - (b.seq as number));
  const deliveredIds = delivered.map((e) => (e.event_id as string) ?? "");
  const computedRoot = checkpointRoot(deliveredIds);
  const rootValid = computedRoot === claimedRoot;

  // Only computable when the committed leaves are known; a wire checkpoint carries
  // the root alone, by design (the root IS the commitment).
  const committed = checkpoint.reconciliation?.event_ids;
  const deliveredSet = new Set(deliveredIds);
  const missing: string[] = Array.isArray(committed)
    ? committed.filter((eid: string) => !deliveredSet.has(eid))
    : [];

  const countClaimed = cp.count;
  return {
    from_seq: fromSeq,
    through_seq: throughSeq,
    count_claimed: countClaimed,
    count_received: deliveredIds.length,
    count_matches: countClaimed === undefined || countClaimed === deliveredIds.length,
    root_valid: rootValid,
    root_mismatch: !rootValid,
    computed_root: computedRoot,
    claimed_root: claimedRoot,
    provably_deleted: missing,
    sig_valid: true,
  };
}

/**
 * Two-sided attestation labelling [TAP-ASSURANCE], with the full normative
 * consistency predicate: both legs must agree on `cid`, `action.tool` and
 * `action.kind`, and their results must not contradict.
 */
export function assuranceLevel(legs: Ev[], isServerKey?: ServerKeyPredicate): Assurance {
  const agent = legs.filter((e) => e.attestor === "agent");
  const server = legs.filter((e) => e.attestor === "server");
  if (server.length === 0) return "intent-only";

  // Key independence, before any content comparison [TAP-ASSURANCE-KEY].
  // `attestor` is a self-declared string inside a signed body, so a Signer can
  // simply write "server" on a leg it signed itself. Taking it at face value
  // would let any agent mint `two-sided` with one key — the exact property §7
  // claims cannot be forged. Without `isServerKey` we apply the structural
  // floor (a server leg may not share an agent leg's kid); with it, a server
  // leg must be signed by a key the deployment recognizes as a server's.
  const agentKids = new Set(agent.map((a) => a.kid));
  for (const s of server) {
    const sKid = s.kid as string | undefined;
    if (!sKid || agentKids.has(sKid)) return "conflicting";
    if (isServerKey && !isServerKey(sKid)) return "conflicting";
  }

  for (const a of agent) {
    for (const s of server) {
      const aAct = a.action ?? {};
      const sAct = s.action ?? {};
      const aRes = a.result ?? {};
      const sRes = s.result ?? {};

      if (a.cid !== s.cid || aAct.tool !== sAct.tool || aAct.kind !== sAct.kind) {
        return "conflicting";
      }
      // The server denied or failed what the agent claimed succeeded.
      if ((sRes.status === "denied" || sRes.status === "failure") && aRes.status === "success") {
        return "conflicting";
      }
      // Differing non-OK result codes contradict each other.
      const aCode = aRes.code;
      const sCode = sRes.code;
      if (aCode && sCode && aCode !== "OK" && sCode !== "OK" && aCode !== sCode) {
        return "conflicting";
      }
    }
  }
  return "two-sided";
}

/**
 * True iff a leg's `evidence.nego` claims `attestation:"server"` while this
 * action's correlated legs contain no server attestor at all
 * [TAP-NEGO-BINDING] — the signature of a stripped handshake, which removes the
 * server leg but cannot remove the Signer's own signed claim about it.
 *
 * Deliberately does not re-check result agreement: when a server leg IS present
 * but disagrees, `assuranceLevel` already returns "conflicting" on its own. This
 * catches only the case that would otherwise read as plain "intent-only" despite
 * the claim.
 */
export function negoViolation(legs: Ev[]): boolean {
  const claimsServer = legs.some((leg) => leg.evidence?.nego?.attestation === "server");
  if (!claimsServer) return false;
  return !legs.some((leg) => leg.attestor === "server");
}

function levelsForGroups(
  groups: Map<string, Ev[]>,
  isServerKey?: ServerKeyPredicate,
): Map<string, Assurance> {
  const levels = new Map<string, Assurance>();
  for (const [ref, legs] of groups) {
    let level = assuranceLevel(legs, isServerKey);
    // The spec requires a broken nego binding to be flagged identically to legs
    // that disagree, so it folds into the same bucket rather than a softer one.
    if (level !== "conflicting" && negoViolation(legs)) level = "conflicting";
    levels.set(ref, level);
  }
  return levels;
}

export interface AnnotatedRecord {
  aid: string;
  events: { raw: Ev; sig_valid?: boolean; assurance?: Assurance; nego_mismatch?: boolean }[];
  flags?: Record<string, boolean>;
  assurance?: { by_action_ref: Record<string, Assurance>; counts: Record<string, number> };
}

/**
 * Enrich a reconstructed record with two-sided attestation state
 * [TAP-ASSURANCE]: correlates the agent and server legs of each action on their
 * shared `action_ref`, stamps every event with its assurance, and raises a
 * record-level `flags.conflicting` when any action's legs disagree.
 */
export function annotateAssurance(
  record: AnnotatedRecord | null,
  isServerKey?: ServerKeyPredicate,
): AnnotatedRecord | null {
  if (!record) return null;
  const records = record.events ?? [];

  // Only signature-valid legs count toward assurance: an unverified leg is not
  // evidence of anything, and letting one raise a record to "two-sided" would
  // mean an attacker could manufacture assurance by injecting a junk leg.
  const groups = new Map<string, Ev[]>();
  for (const rec of records) {
    const ref = rec.raw?.action_ref as string | undefined;
    if (ref && rec.sig_valid) {
      const list = groups.get(ref) ?? [];
      list.push(rec.raw);
      groups.set(ref, list);
    }
  }

  const levels = levelsForGroups(groups, isServerKey);
  let conflicting = false;
  let negoMismatchAny = false;

  for (const rec of records) {
    const ref = rec.raw?.action_ref as string | undefined;
    const level = (ref && levels.get(ref)) || "intent-only";
    rec.assurance = level;
    const mismatch = Boolean(ref && negoViolation(groups.get(ref) ?? []));
    rec.nego_mismatch = mismatch;
    if (level === "conflicting") conflicting = true;
    if (mismatch) negoMismatchAny = true;
  }

  const counts: Record<string, number> = { "intent-only": 0, "two-sided": 0, conflicting: 0 };
  for (const level of levels.values()) counts[level] = (counts[level] ?? 0) + 1;

  record.flags = { ...(record.flags ?? {}), conflicting, nego_mismatch: negoMismatchAny };
  record.assurance = { by_action_ref: Object.fromEntries(levels), counts };
  return record;
}

export interface ChainEdge {
  parent_event_id: string | null;
  parent_aid: string | null;
  child_event_id: string | null;
  child_aid: string;
  verified: boolean;
  broken: boolean;
}

/**
 * Stitch a multi-agent delegation chain (spec §8.1).
 *
 * All records in one chain share a `cid`; each `received_delegation` references
 * the delegating `agent_delegate` via `parent_event_id`. A handoff edge is marked
 * `verified` only when BOTH legs' signatures check out, so a broken or unverified
 * handoff breaks the chain visibly rather than being silently bridged.
 */
export function buildChain(
  cid: string,
  records: (AnnotatedRecord | null)[],
  isServerKey?: ServerKeyPredicate,
) {
  const annotated = records
    .filter((r): r is AnnotatedRecord => r !== null)
    .map((r) => annotateAssurance(r, isServerKey)!) ;

  const owner = new Map<string, string>();
  const valid = new Map<string, boolean>();
  for (const record of annotated) {
    for (const rec of record.events ?? []) {
      const eid = rec.raw?.event_id as string | undefined;
      if (eid) {
        owner.set(eid, record.aid);
        valid.set(eid, Boolean(rec.sig_valid));
      }
    }
  }

  const edges: ChainEdge[] = [];
  const children = new Set<string>();
  for (const record of annotated) {
    for (const rec of record.events ?? []) {
      const raw = rec.raw ?? {};
      if (raw.action?.kind !== "received_delegation") continue;
      const parentEid = (raw.parent_event_id as string) ?? null;
      const childEid = (raw.event_id as string) ?? null;
      const parentAid = parentEid ? owner.get(parentEid) ?? null : null;
      const resolved = parentAid !== null;
      edges.push({
        parent_event_id: parentEid,
        parent_aid: parentAid,
        child_event_id: childEid,
        child_aid: record.aid,
        verified:
          resolved &&
          Boolean(parentEid && valid.get(parentEid)) &&
          Boolean(childEid && valid.get(childEid)),
        broken: !resolved, // a dangling parent breaks the chain, visibly
      });
      children.add(record.aid);
    }
  }

  return {
    cid,
    records: annotated,
    edges,
    roots: annotated.filter((r) => !children.has(r.aid)).map((r) => r.aid),
    chain_intact: edges.every((e) => e.verified),
    nego_mismatch: annotated.some((r) => r.flags?.nego_mismatch),
  };
}

/** The audit report a relying party actually wants [TAP-CONFORMANCE]. */
export async function verifyTranscript(
  passportJwt: string,
  events: Ev[],
  opts: {
    resolveKey: VerifyKeyResolver;
    now?: number;
    /** [TAP-AUTHORITY-REVOKE, §9.2, provisional] — optional; see {@link evaluateEvent}. */
    resolveAuthorityRevocation?: AuthorityRevocationResolver;
    /** [TAP-ASSURANCE-KEY] — optional; see {@link assuranceLevel}. */
    isServerKey?: ServerKeyPredicate;
  },
) {
  const pp = await checkPassport(passportJwt, opts);
  const claims = pp.claims;

  const ordered = [...events].sort((a, b) => ((a.seq as number) ?? 0) - ((b.seq as number) ?? 0));
  const checkpoints = ordered.filter((e) => e.action?.kind === "checkpoint");
  const regular = ordered.filter((e) => e.action?.kind !== "checkpoint");

  let validSig = 0;
  const drift: Record<string, unknown>[] = [];
  const denials: Record<string, unknown>[] = [];
  const seqGaps: number[] = [];
  const duplicates: number[] = [];
  const actionGroups = new Map<string, Ev[]>();
  let lastSeq: number | null = null;
  // [TAP-AUTHORITY-REVOKE / TAP-AUTHORITY-REUSE, §9.2, provisional].
  const authorityRevoked: Record<string, unknown>[] = [];
  const authorityReuse: Record<string, unknown>[] = [];
  // authzId -> the first sig-valid event_id it was seen on, for the
  // batch-local reuse scan below.
  const seenAuthz = new Map<string, string>();

  for (const ev of regular) {
    const res = await evaluateEvent(ev, {
      resolveKey: opts.resolveKey,
      passportClaims: claims,
      lastSeq,
      resolveAuthorityRevocation: opts.resolveAuthorityRevocation,
    });
    if (res.sig_valid) {
      validSig += 1;
      const ref = ev.action_ref as string | undefined;
      if (ref) {
        const list = actionGroups.get(ref) ?? [];
        list.push(ev);
        actionGroups.set(ref, list);
      }
      // Batch-local single-use scan [TAP-AUTHORITY-REUSE]: a duplicate
      // authz_id across two DIFFERENT sig-valid events in this batch — only
      // meaningful once the signature checks out, same discipline as every
      // other authority-binding signal here.
      const authBlock = res.authorization;
      const authzId =
        authBlock && typeof authBlock === "object" && !Array.isArray(authBlock)
          ? (authBlock as Record<string, unknown>).authz_id
          : undefined;
      if (typeof authzId === "string" && authzId) {
        const firstEventId = seenAuthz.get(authzId);
        if (firstEventId !== undefined && firstEventId !== res.event_id) {
          authorityReuse.push({
            authz_id: authzId,
            first_event_id: firstEventId,
            reused_event_id: res.event_id,
          });
        } else {
          seenAuthz.set(authzId, res.event_id as string);
        }
      }
    }
    if (res.drift) {
      drift.push({
        event_id: res.event_id,
        scope_used: ev.action?.scope_used,
        reason: "not in passport scope",
      });
    }
    if (res.denied) {
      denials.push({
        event_id: res.event_id,
        rule_id: res.policy_decision?.rule_id,
        policy_version: res.policy_decision?.policy_version,
      });
    }
    if (res.authority_revoked) {
      authorityRevoked.push({ event_id: res.event_id, authz_id: res.authorization?.authz_id });
    }
    if (res.integrity.seq_gap) seqGaps.push(...res.integrity.seq_gap);
    if (res.integrity.seq_duplicate !== undefined) duplicates.push(res.integrity.seq_duplicate);
    if (typeof ev.seq === "number") lastSeq = lastSeq === null ? ev.seq : Math.max(lastSeq, ev.seq);
  }

  const checkpointResults: CheckpointReconciliation[] = [];
  for (const cp of checkpoints) {
    const res = await evaluateEvent(cp, {
      resolveKey: opts.resolveKey,
      passportClaims: claims,
      lastSeq: null,
    });
    if (res.sig_valid) checkpointResults.push(reconcileCheckpoint(cp, regular));
  }

  const invalidSig = regular.length - validSig;
  const assuranceByRef = levelsForGroups(actionGroups, opts.isServerKey);
  const negoMismatches = [...actionGroups.entries()]
    .filter(([, legs]) => negoViolation(legs))
    .map(([ref]) => ref);

  // A record whose every signature is sound but whose checkpoint does not
  // reconcile is NOT verified: the checkpoint is the only thing standing between
  // fail-open reporting and undetectable suppression [TAP-EVT-CHECKPOINT].
  // A `conflicting` action is an integrity alert, not a footnote: legs that
  // disagree, or a "server" leg signed by a key that cannot be an independent
  // attestation [TAP-ASSURANCE-KEY]. Reporting `verified: true` over one would
  // assert exactly the property that failed.
  const verified =
    pp.valid &&
    !pp.expired &&
    invalidSig === 0 &&
    drift.length === 0 &&
    checkpointResults.every((c) => c.root_valid && c.count_matches) &&
    [...assuranceByRef.values()].every((level) => level !== "conflicting");

  const parts: string[] = [];
  parts.push(invalidSig === 0 ? "All signatures valid." : `${invalidSig} invalid signature(s).`);
  if (seqGaps.length) parts.push(`${seqGaps.length} sequence gap(s) at ${seqGaps}.`);
  if (drift.length) parts.push(`${drift.length} scope drift detected.`);
  if (denials.length) parts.push(`${denials.length} action(s) denied by policy.`);
  if (checkpoints.length) parts.push(`${checkpoints.length} checkpoint(s) present.`);
  const badRoots = checkpointResults.filter((c) => c.root_mismatch);
  const deleted = checkpointResults.flatMap((c) => c.provably_deleted);
  if (badRoots.length) {
    parts.push(
      `${badRoots.length} checkpoint root mismatch(es) — the delivered events are not the sealed set.`,
    );
  }
  if (deleted.length) parts.push(`${deleted.length} event(s) provably deleted: ${deleted}.`);
  if (negoMismatches.length) {
    parts.push(`${negoMismatches.length} action(s) show conflicting/downgraded assurance.`);
  }
  const conflictingRefs = [...assuranceByRef.entries()]
    .filter(([, level]) => level === "conflicting")
    .map(([ref]) => ref);
  if (conflictingRefs.length) {
    parts.push(
      `${conflictingRefs.length} action(s) labeled conflicting — legs disagree, or a ` +
        `'server' leg was not independently attested [TAP-ASSURANCE-KEY].`,
    );
  }
  if (duplicates.length) {
    parts.push(`${duplicates.length} duplicate (aid, seq) slot(s) at ${duplicates}.`);
  }
  if (authorityRevoked.length) {
    parts.push(`${authorityRevoked.length} event(s) named a revoked authority binding.`);
  }
  if (authorityReuse.length) {
    parts.push(`${authorityReuse.length} authz_id reuse(s) detected.`);
  }
  if (!pp.valid) parts.push(`Passport invalid (${pp.reason}).`);

  return {
    verified,
    passport: { valid: pp.valid, expired: pp.expired },
    events: { total: regular.length + checkpoints.length, valid_sig: validSig, invalid_sig: invalidSig },
    integrity: { seq_gaps: seqGaps, duplicates },
    checkpoints: checkpointResults,
    drift,
    denials,
    authority_revoked: authorityRevoked,
    authority_reuse: authorityReuse,
    assurance: {
      by_action_ref: Object.fromEntries(assuranceByRef),
      nego_mismatches: negoMismatches,
    },
    summary: parts.join(" "),
  };
}
