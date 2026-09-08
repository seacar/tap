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
  "event_id_root", "kid",
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
await tap.recordOutput({ output: "done" });
await tap.emitCheckpoint();
await tap.flush();

// Sorted top-level keys so the two languages' JSON is directly comparable as text.
const byKind = new Map<string, unknown>();
for (const ev of captured) byKind.set(ev.action.kind, normalize(ev));
const shapes: Record<string, unknown> = {};
for (const kind of [...byKind.keys()].sort()) shapes[kind] = byKind.get(kind);
process.stdout.write(JSON.stringify(shapes, null, 2) + "\n");
