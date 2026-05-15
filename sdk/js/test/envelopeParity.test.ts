// Envelope parity: for one logically identical action, the TypeScript SDK and the
// Python SDK must produce the SAME signed bytes.
//
// This is the property the conformance vectors alone cannot establish. A vector
// proves an implementation can re-sign a body someone else composed. It says
// nothing about the body this SDK *composes on its own* — and that is where the two
// diverged: TypeScript emitted `parent_event_id: null`, `policy_decision: null` and
// `evidence: null` where Python omitted them. Both signed correctly. Both verified.
// Their checkpoint roots would never have matched, because a Merkle commitment is
// over `event_id`s of events whose bodies differ.
//
// So this test composes an event through the SDK's own emit path, freezes the
// varying fields (ids, timestamps), and asserts the resulting shape against the
// rule [TAP-EVT-OMIT] rather than against a recorded hash — a recorded hash would
// just move the problem.
//
//   npx tsx test/envelopeParity.test.ts

import { writeFileSync } from "node:fs";

import { TAPClient } from "../src/client.js";
import { signingInput } from "../src/tap.js";

const SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KID = "key_2026_ref01";

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

async function emitOne(): Promise<Record<string, any>> {
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
  await tap.flush();
  return captured[0];
}

test("a composed tool_call omits absent optionals", async () => {
  const ev = await emitOne();
  for (const absent of ["parent_event_id", "policy_decision", "decision", "checkpoint"]) {
    assert(!(absent in ev), `${absent} must be omitted when absent, not null`);
  }
  // `evidence` is omitted entirely when empty, rather than sent as null.
  assert(!("evidence" in ev) || Object.keys(ev.evidence).length > 0,
    "an empty evidence block must be omitted, not null");
  // `result.error` is explicitly nullable and MUST be present.
  assert("error" in ev.result && ev.result.error === null,
    "result.error is nullable and present");
  // `latency_ms` is optional; when measured it is an integer, never fractional.
  if ("latency_ms" in ev.result) {
    assert(Number.isInteger(ev.result.latency_ms), "latency_ms must be an integer");
  }
});

test("a composed checkpoint carries a self-describing interval", async () => {
  const captured: Record<string, any>[] = [];
  const tap = new TAPClient({
    agentId: "parity", privateKeyHex: SEED, kid: KID,
    post: async (_u, p: any) => { captured.push(...(p.events ?? [])); },
  });
  const p = await tap.issuePassport({ taskPrompt: "parity", scope: ["call:tool"] });
  await tap.traceTool({ tool: "a", scope: "call:tool" }, async () => 1);
  await tap.traceTool({ tool: "b", scope: "call:tool" }, async () => 2);
  await tap.emitCheckpoint(p);
  await tap.traceTool({ tool: "c", scope: "call:tool" }, async () => 3);
  await tap.emitCheckpoint(p);
  await tap.flush();

  const cps = captured.filter((e) => e.action?.kind === "checkpoint");
  assert(cps.length === 2, "two checkpoints emitted");

  // First seals (0, 2]; second seals (3, 5] — the first checkpoint itself consumed
  // seq 3. The bounds must chain without overlap, or a verifier double-counts.
  assert(cps[0].checkpoint.from_seq === 0, "the first checkpoint starts at 0");
  assert(cps[0].checkpoint.count === 2, "the first seals two events");
  assert(cps[1].checkpoint.from_seq === cps[0].checkpoint.through_seq,
    "each checkpoint starts where the previous one ended");
  assert(cps[1].checkpoint.count === 1, "the second seals one event");

  // A checkpoint action has no intent and no args — omitted, not nulled.
  assert(!("intent_digest" in cps[0].action), "a checkpoint action has no intent_digest");
  assert(!("args_digest" in cps[0].action), "a checkpoint action has no args_digest");
  assert(cps[0].action.tool === null && cps[0].action.scope_used === null,
    "tool and scope_used are explicitly nullable here");
});

test("the composed body is written out for the Python side to compare", async () => {
  // Emitted as an artifact so the cross-language CI job can assert that Python,
  // composing the same logical action, produces byte-identical canonical input.
  const ev = await emitOne();
  const frozen = freeze(ev);
  writeFileSync("/tmp/tap-js-envelope.json", JSON.stringify({
    frozen,
    canonical: new TextDecoder().decode(signingInput(frozen)),
  }));
  assert(typeof frozen.event_id === "string", "artifact written");
});

/** Replace the fields that legitimately vary per run, so two runs are comparable. */
function freeze(ev: Record<string, any>): Record<string, any> {
  const { sig: _drop, ...body } = ev;
  return {
    ...body,
    event_id: "evt_FROZEN",
    passport_jti: "psp_FROZEN",
    aid: "agt_FROZEN",
    cid: "sha256:" + "00".repeat(32),
    ts: "2026-01-01T00:00:00.000Z",
    action_ref: "act_FROZEN",
    result: { ...body.result, latency_ms: 0 },
  };
}

async function main() {
  console.log(`1..${tests.length}`);
  for (const [name, fn] of tests) {
    try {
      await fn();
    } catch (e) {
      console.log(`not ok ${++n} - ${name}`);
      console.log(`  # ${(e as Error).message}`);
      process.exit(1);
    }
    console.log(`ok ${++n} - ${name}`);
  }
  console.log("# composed envelopes match the omit rule ✓");
}

main();
