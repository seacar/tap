// Typed decisions: decider provenance and confidence gates [TAP-EVT-DECIDER,
// TAP-EVT-GATE, §6.4.1, PROVISIONAL]. TypeScript port of
// sdk/python/src/tap_sdk/decider.py — keep the two in step.
//
// Gate arithmetic is exact decimal arithmetic on integer millionths
// [TAP-EVT-GATE-DECIMAL]. Never Number(score) >= Number(threshold): two
// Verifiers that disagree about a score sitting exactly on the threshold
// disagree exactly where it matters.

import { jsonDigest } from "./tap.js";

export const DECIDER_KINDS = ["model", "rule", "human"] as const;
export const SCORE_SEMANTICS = ["calibrated_probability", "probability", "uncalibrated"] as const;
export const GATED_SCORE_SEMANTICS = ["calibrated_probability", "probability"] as const;

export type DeciderKind = (typeof DECIDER_KINDS)[number];
export type ScoreSemantics = (typeof SCORE_SEMANTICS)[number];
export type GateOutcome = "accept" | "fallback";
export type GateLabel = "gate_consistent" | "gate_inconsistent" | "gate_unscorable";

const GATE_DECIMAL = /^(?:0(?:\.[0-9]{1,6})?|1(?:\.0{1,6})?)$/;

export class DeciderError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeciderError";
  }
}

/** Parse a gate decimal to integer millionths, exactly. Throws on anything outside the grammar. */
export function gateDecimalMicros(value: unknown): number {
  if (typeof value !== "string" || !GATE_DECIMAL.test(value)) {
    throw new RangeError(`not a gate decimal in [0, 1] with <= 6 places: ${JSON.stringify(value)}`);
  }
  const [whole, frac = ""] = value.split(".");
  return Number(whole) * 1_000_000 + Number((frac + "000000").slice(0, 6));
}

/** "accept" iff score >= threshold as exact decimals, else "fallback". */
export function gateOutcome(score: string, threshold: string): GateOutcome {
  return gateDecimalMicros(score) >= gateDecimalMicros(threshold) ? "accept" : "fallback";
}

type Obj = Record<string, any>;
const isObj = (v: unknown): v is Obj => v !== null && typeof v === "object" && !Array.isArray(v);

/** Label a decision's confidence gate. null when there is no gate. Mirrors tap_ref.decision_gate_label. */
export function decisionGateLabel(decision: unknown): GateLabel | null {
  if (!isObj(decision) || !("gate" in decision)) return null;
  const gate = decision.gate ?? {};
  const decider = decision.decider ?? {};
  if (!isObj(gate) || !isObj(decider)) return "gate_unscorable";
  if (!(GATED_SCORE_SEMANTICS as readonly string[]).includes(decider.score_semantics)) {
    return "gate_unscorable";
  }
  const options = Array.isArray(decision.options) ? decision.options : [];
  const chosen = options.filter((o: unknown) => isObj(o) && o.chosen === true);
  if (chosen.length !== 1 || chosen[0].id !== decision.chosen) return "gate_unscorable";
  let expected: GateOutcome;
  try {
    expected = gateOutcome(chosen[0].score, gate.threshold);
  } catch {
    return "gate_unscorable";
  }
  if (gate.outcome !== "accept" && gate.outcome !== "fallback") return "gate_unscorable";
  return gate.outcome === expected ? "gate_consistent" : "gate_inconsistent";
}

export interface OutputSchemaCheck {
  schema_present: boolean;
  schema_digest_valid: boolean | null;
  labels_permitted: boolean | null;
}

/** Check an annexed output schema against the signed record. A missing annex is an informational gap. */
export function checkOutputSchema(decision: Obj, annexDecision?: Obj | null): OutputSchemaCheck {
  const out: OutputSchemaCheck = { schema_present: false, schema_digest_valid: null, labels_permitted: null };
  const signed = decision?.decider?.output_schema_digest;
  const schema = annexDecision?.output_schema;
  if (schema === undefined || schema === null || signed === undefined) return out;
  out.schema_present = true;
  out.schema_digest_valid = jsonDigest(schema) === signed;
  let en: unknown = isObj(schema) ? schema.enum : undefined;
  if (en === undefined && isObj(schema) && isObj(schema.properties) && isObj(schema.properties.label)) {
    en = schema.properties.label.enum;
  }
  if (Array.isArray(en)) {
    const ids = (decision.options ?? []).filter(isObj).map((o: Obj) => o.id);
    out.labels_permitted = ids.every((id: unknown) => (en as unknown[]).includes(id));
  }
  return out;
}

/** The component behind a decision [TAP-EVT-DECIDER]. `outputSchema` is plaintext; only its digest is signed. */
export interface Decider {
  kind: DeciderKind;
  id: string;
  version?: string;
  outputSchema?: unknown;
  scoreSemantics?: ScoreSemantics;
  versionDigest?: string;
}

/** The signed `decider` block, validated, with absent fields omitted. */
export function deciderBlock(d: Decider, scored: boolean): Obj {
  if (!(DECIDER_KINDS as readonly string[]).includes(d.kind)) {
    throw new DeciderError(`decider.kind must be one of ${DECIDER_KINDS.join(", ")}, got ${d.kind}`);
  }
  if (!d.id) throw new DeciderError("decider.id is REQUIRED");
  if ((d.kind === "model" || d.kind === "rule") && !d.version) {
    throw new DeciderError(`decider.version is REQUIRED for kind '${d.kind}'`);
  }
  if (d.kind === "model" && d.outputSchema === undefined) {
    throw new DeciderError("decider.outputSchema is REQUIRED for kind 'model'");
  }
  if (d.scoreSemantics !== undefined && !(SCORE_SEMANTICS as readonly string[]).includes(d.scoreSemantics)) {
    throw new DeciderError(`scoreSemantics must be one of ${SCORE_SEMANTICS.join(", ")}`);
  }
  if (scored && d.scoreSemantics === undefined) {
    throw new DeciderError("scoreSemantics is REQUIRED when any option carries a score");
  }
  const b: Obj = { kind: d.kind, id: d.id };
  if (d.version) b.version = d.version;
  if (d.versionDigest) b.version_digest = d.versionDigest;
  if (d.outputSchema !== undefined) b.output_schema_digest = jsonDigest(d.outputSchema);
  if (d.scoreSemantics !== undefined) b.score_semantics = d.scoreSemantics;
  return b;
}

/** Compute a signed `gate` block. The outcome is DERIVED, never passed in. */
export function buildGate(args: {
  score: string | undefined;
  threshold: string;
  deciderBlock: Obj;
  fallbackTo?: string;
}): Obj {
  if (!(GATED_SCORE_SEMANTICS as readonly string[]).includes(args.deciderBlock.score_semantics)) {
    throw new DeciderError("a gate needs a decider whose score_semantics is a probability");
  }
  if (args.score === undefined) throw new DeciderError("a gate needs a score on the chosen option");
  let outcome: GateOutcome;
  try {
    outcome = gateOutcome(args.score, args.threshold);
  } catch (e) {
    throw new DeciderError((e as Error).message);
  }
  const g: Obj = { threshold: args.threshold, outcome };
  if (args.fallbackTo) g.fallback_to = args.fallbackTo;
  return g;
}

/** event_ids of fallback-gated decisions that no delivered decision supersedes (informational). */
export function unresolvedFallbacks(events: Obj[]): string[] {
  const decisions = events.filter((e) => e.action?.kind === "decision");
  const parents = new Set(decisions.map((e) => e.parent_event_id));
  return decisions
    .filter((e) => e.decision?.gate?.outcome === "fallback")
    .map((e) => e.event_id as string)
    .filter((id) => !parents.has(id));
}
