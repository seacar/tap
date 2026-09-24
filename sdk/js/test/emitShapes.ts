// Emit normalized envelope shapes for every event kind this SDK composes.
//
// Half of a cross-language contract. `sdk/python/tests/emit_shapes.py` is the
// other half, and `scripts/check-envelope-parity.py` diffs the two and validates
// both against `schemas/event.schema.json`.
//
// See the Python file's header for why the comparison lives outside both SDKs.
// In short: every divergence that actually happened was invisible from inside
// one language, and the test named "the two SDKs compose identical envelopes"
// asserted a rule about one SDK's output rather than comparing the two.
//
//   npx tsx test/emitShapes.ts

import { TAPClient } from "../src/client.js";

const SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KID = "key_2026_ref01";

// Values that legitimately differ every run. Normalized to a marker so a diff
// reports envelope-shape drift and nothing else.
const VOLATILE = new Set([
  "event_id", "action_ref", "passport_jti", "aid", "cid", "ts", "sig",
  "intent_digest", "args_digest", "reasoning_digest", "model_output_digest",
  "question_digest", "rationale_digest", "reason_digest", "options_digest",
  "event_id_root", "kid", "parent_event_id",
]);

function normalize(value: unknown, key?: string): unknown {
  if (key && VOLATILE.has(key)) return `<${key}>`;
  // A measured latency is a real integer whose value is timing noise; the
  // contract is that the key is PRESENT when measured and ABSENT when not.
  if (key === "latency_ms") return "<measured>";
  if (Array.isArray(value)) return value.map((v) => normalize(v));
  if (value !== null && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const k of Object.keys(value as object).sort()) {
      out[k] = normalize((value as Record<string, unknown>)[k], k);
    }
    return out;
  }
  return value;
}

const captured: Record<string, any>[] = [];
const tap = new TAPClient({
  agentId: "parity", privateKeyHex: SEED, kid: KID,
  post: async (_u, p: any) => { captured.push(...(p.events ?? [])); },
});
await tap.issuePassport({ taskPrompt: "parity", scope: ["read:database"] });
await tap.traceTool(
  { tool: "db_query", scope: "read:database", intent: "Call db_query", args: { table: "users", limit: 50 } },
  async () => ({ rows: 1 }),
);
await tap.decision({
  question: "Refund?",
  chosen: "refund",
  options: [
    { id: "refund", score: "0.71", rationale: "policy allows" },
    { id: "deny", score: "0.10", reason: "would breach policy" },
  ],
});
// typed decisions (§6.4.1, provisional): gate accepted, gate fell back, and the
// superseding decision — must match sdk/python/tests/emit_shapes.py exactly.
const schema = { type: "object", properties: { label: { enum: ["approve", "review"] } } };
const fast = {
  kind: "model" as const, id: "example.com/typed-decider", version: "2026-09-15",
  outputSchema: schema, scoreSemantics: "calibrated_probability" as const,
};
await tap.typedDecision({
  question: "Route?", labels: ["approve", "review"], chosen: "approve",
  score: "0.97", scores: { review: "0.03" }, decider: fast, threshold: "0.90",
  input: { invoice: "INV-1" },
});
const fb = await tap.typedDecision({
  question: "Route?", labels: ["approve", "review"], chosen: "approve",
  score: "0.72", decider: fast, threshold: "0.90", fallbackTo: "llm",
  input: { invoice: "INV-2" },
});
await tap.decision({
  question: "Route?", chosen: "review", input: { invoice: "INV-2" },
  options: [
    { id: "approve", reason: "no PO match" },
    { id: "review", rationale: "unusual total" },
  ],
  decider: { kind: "model", id: "example.com/frontier-llm", version: "2026-06-01", outputSchema: schema },
  parentEventId: fb.event_id as string, actionRef: fb.action_ref as string,
});
await tap.recordOutput({ output: "done" });
await tap.emitCheckpoint();
await tap.flush();

// Sorted top-level keys so the two languages' JSON is directly comparable as text.
const byKind = new Map<string, unknown>();
// One key per distinct envelope shape — typed decisions split by gate outcome.
const shapeKey = (ev: Record<string, any>): string => {
  let key = ev.action.kind as string;
  const d = ev.decision ?? {};
  if ("gate" in d) key += ":gated-" + d.gate.outcome;
  else if ("decider" in d) key += ":typed";
  return key;
};
for (const ev of captured) byKind.set(shapeKey(ev), normalize(ev));
const shapes: Record<string, unknown> = {};
for (const kind of [...byKind.keys()].sort()) shapes[kind] = byKind.get(kind);
process.stdout.write(JSON.stringify(shapes, null, 2) + "\n");
