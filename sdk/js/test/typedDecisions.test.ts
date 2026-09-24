// Typed decisions in TypeScript [TAP-EVT-DECIDER, TAP-EVT-GATE, §6.4.1, PROVISIONAL],
// mirroring sdk/python/tests/test_typed_decisions.py.
//
//   npx tsx test/typedDecisions.test.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  checkOutputSchema,
  DeciderError,
  decisionGateLabel,
  gateDecimalMicros,
  gateOutcome,
  type Decider,
} from "../src/decider.js";
import { jsonDigest, signEvent, verifyEvent } from "../src/tap.js";
import { TAPClient } from "../src/client.js";
import { evaluateEvent, verifyTranscript } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"));
const jwk = vectors.jwks.keys[0];
const SEED = vectors.ed25519_private_seed_hex as string;
const CASES = ["typed_decision", "typed_decision_fallback", "typed_decision_resolution"];
const SCHEMA = { type: "object", properties: { label: { enum: ["approve", "review"] } } };
const FAST: Decider = {
  kind: "model", id: "example.com/typed-decider", version: "2026-09-15",
  outputSchema: SCHEMA, scoreSemantics: "calibrated_probability",
};
const resolveKey = async (kid: string) => (kid === jwk.kid ? jwk : null);

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};
const throwsDecider = async (fn: () => Promise<unknown>, why: string) => {
  try {
    await fn();
  } catch (e) {
    if (e instanceof DeciderError) return;
    throw new Error(`${why}: expected DeciderError, got ${(e as Error).message}`);
  }
  throw new Error(`${why}: expected DeciderError`);
};

async function client(captured: any[]): Promise<TAPClient> {
  const c = new TAPClient({
    agentId: "bot", privateKeyHex: "44".repeat(32), kid: "key_test",
    post: async (_u, p: any) => { captured.push(p); },
  });
  await c.issuePassport({ taskPrompt: "route invoices", scope: ["call:tool"] });
  return c;
}

test("the three typed-decision vectors reproduce and verify", async () => {
  for (const c of CASES) {
    const ev = vectors[c].signed_event;
    assert(await verifyEvent(jwk, ev), `${c}: must verify`);
    const { sig, ...body } = ev;
    const resigned = await signEvent(SEED, body);
    assert(resigned.sig === sig, `${c}: TS must reproduce the reference sig`);
  }
});

test("gate labels match the vectors", async () => {
  assert(decisionGateLabel(vectors.typed_decision.signed_event.decision) === "gate_consistent", "accept");
  assert(decisionGateLabel(vectors.typed_decision_fallback.signed_event.decision) === "gate_consistent", "fallback");
  assert(decisionGateLabel(vectors.typed_decision_resolution.signed_event.decision) === null, "no gate");
  assert(decisionGateLabel(vectors.decision.signed_event.decision) === null, "plain decision");
  const neg = vectors.negative.gate_outcome_inconsistent;
  assert(decisionGateLabel(neg.event.decision) === neg.expected_label, "negative case must flag");
});

test("gate arithmetic agrees with every decision_gate row", async () => {
  for (const row of vectors.decision_gate.outcomes) {
    assert(gateOutcome(row.score, row.threshold) === row.outcome, JSON.stringify(row));
  }
  for (const bad of [...vectors.decision_gate.malformed, 0.9, null, 1]) {
    let threw = false;
    try { gateDecimalMicros(bad); } catch { threw = true; }
    assert(threw, `${JSON.stringify(bad)} must be rejected`);
  }
});

test("annexed output schema re-hashes and permits every label", async () => {
  for (const c of CASES) {
    const chk = checkOutputSchema(vectors[c].signed_event.decision, vectors[c].annex.decision);
    assert(chk.schema_present && chk.schema_digest_valid === true && chk.labels_permitted === true, c);
  }
  const d = vectors.typed_decision.signed_event.decision;
  assert(checkOutputSchema(d, { output_schema: { enum: ["x"] } }).schema_digest_valid === false, "tamper");
  assert(checkOutputSchema(d, null).schema_present === false, "shredded annex is a gap");
});

test("typedDecision() derives the gate and keeps plaintext in the annex", async () => {
  const captured: any[] = [];
  const c = await client(captured);
  const ok = await c.typedDecision({
    question: "Route?", labels: ["approve", "review"], chosen: "approve",
    score: "0.97", scores: { review: "0.03" }, decider: FAST, threshold: "0.90",
    input: { invoice: "INV-1" },
  }) as any;
  const fb = await c.typedDecision({
    question: "Route?", labels: ["approve", "review"], chosen: "approve",
    score: "0.72", decider: FAST, threshold: "0.9", fallbackTo: "human",
  }) as any;
  const edge = await c.typedDecision({
    question: "Route?", labels: ["approve", "review"], chosen: "approve",
    score: "0.9", decider: FAST, threshold: "0.900000",
  }) as any;
  assert(JSON.stringify(ok.decision.gate) === JSON.stringify({ threshold: "0.90", outcome: "accept" }), "accept gate");
  assert(fb.decision.gate.outcome === "fallback" && fb.decision.gate.fallback_to === "human", "fallback gate");
  assert(edge.decision.gate.outcome === "accept", "on the threshold is accept");
  for (const ev of [ok, fb, edge]) {
    assert(decisionGateLabel(ev.decision) === "gate_consistent", "consistent");
    assert(!JSON.stringify(ev).includes("enum"), "plaintext schema must stay out of the body");
    assert(ev.decision.decider.output_schema_digest === jsonDigest(SCHEMA), "schema digest");
  }
  assert(ok.action.args_digest === jsonDigest({ invoice: "INV-1" }), "input -> args_digest");
  assert(ok.decision.options[1].score === "0.03", "distribution carried");
  assert(!("score" in fb.decision.options[1]), "unscored labels omit score");
  await c.flush();
  const annexes = captured.flatMap((p) => p.annexes ?? []);
  const ann = annexes.find((a: any) => a.event_id === ok.event_id);
  assert(ann && JSON.stringify(ann.decision.output_schema) === JSON.stringify(SCHEMA), "schema in annex");
});

test("decider validation refuses non-conforming records", async () => {
  const c = await client([]);
  const opts = [{ id: "a", score: "0.5" }, { id: "b", score: "0.5" }];
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: opts,
    decider: { kind: "model", id: "m", version: "1" } }), "model needs outputSchema");
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: opts,
    decider: { kind: "rule", id: "r" } as Decider }), "rule needs version");
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: opts,
    decider: { ...FAST, scoreSemantics: "uncalibrated" }, threshold: "0.9" }), "gate over rankings");
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: opts,
    decider: FAST, threshold: "0.95000001" }), "threshold grammar");
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: opts,
    threshold: "0.9" }), "gate needs a decider");
  await throwsDecider(() => c.decision({ question: "q", chosen: "a", options: [{ id: "a", score: "0.5" }],
    decider: { kind: "rule", id: "r", version: "1" } }), "scores need scoreSemantics");
  const human = await c.decision({ question: "q", chosen: "a", options: [{ id: "a" }, { id: "b" }],
    decider: { kind: "human", id: "reviewer:ap-team" } }) as any;
  assert(JSON.stringify(human.decision.decider) === JSON.stringify({ kind: "human", id: "reviewer:ap-team" }),
    "human decider needs no version or schema");
});

test("verifyTranscript surfaces inconsistent and unresolved gates", async () => {
  const passport = vectors.passport.compact_jwt;
  const now = vectors.passport.claims.iat + 1;
  const neg = vectors.negative.gate_outcome_inconsistent.event;
  const ok = vectors.typed_decision.signed_event;
  const fb = vectors.typed_decision_fallback.signed_event;
  const res = vectors.typed_decision_resolution.signed_event;

  const full = await verifyTranscript(passport, [ok, fb, res], { resolveKey, now });
  assert(JSON.stringify(full.decision_gates) === JSON.stringify({ inconsistent: [], unscorable: [], unresolved: [] }),
    "a resolved chain carries no gate signals");
  const open = await verifyTranscript(passport, [ok, fb], { resolveKey, now });
  assert(open.decision_gates.unresolved[0] === fb.event_id, "unsuperseded fallback is reported");
  const bad = await verifyTranscript(passport, [ok, neg], { resolveKey, now });
  assert(bad.decision_gates.inconsistent[0] === neg.event_id, "self-contradicting gate is reported");
  assert(bad.verified === open.verified, "provisional: not folded into verified");

  const one = await evaluateEvent(neg, { resolveKey });
  assert(one.sig_valid && one.decision_gate === "gate_inconsistent", "evaluateEvent labels it");
  const forged = { ...neg, decision: { ...neg.decision, chosen: "manual_review" } };
  assert((await evaluateEvent(forged, { resolveKey })).decision_gate === null, "no label without a valid sig");
});

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
  console.log("# typed decisions match tap_ref.py / Python SDK (provisional, §6.4.1) ✓");
}

main();
