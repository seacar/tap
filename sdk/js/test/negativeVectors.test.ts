// The `negative` half of the conformance contract [TAP-CONFORMANCE], in TypeScript.
//
// Reproducing the published signatures proves this SDK can *sign* like the
// reference. It says nothing about whether it *refuses* what the reference
// refuses — and a verifier that accepts everything reproduces every vector
// perfectly.
//
// Each entry in test-vectors.json -> negative declares its own expected outcome,
// so this is a loop rather than a pile of hand-written cases: adding a case to the
// vectors adds it to this suite and to the Python one at the same time.
//
//   npx tsx test/negativeVectors.test.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { sha256 } from "@noble/hashes/sha2.js";

import { checkpointRoot, signingInput, verifyEvent, verifyPassport, type Jwk } from "../src/tap.js";
import { reconcileCheckpoint } from "../src/verify.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"));

const negative: Record<string, any> = Object.fromEntries(
  Object.entries(vectors.negative).filter(([k]) => !k.startsWith("_")),
);
const NOW = vectors.passport.claims.iat + 1;
const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

async function attempt(c: any): Promise<boolean> {
  if ("compact_jwt" in c) {
    await verifyPassport(c.jwk as Jwk, c.compact_jwt, NOW);
    return true;
  }
  return verifyEvent(c.jwk as Jwk, c.event);
}

test("every negative case behaves as declared", async () => {
  assert(Object.keys(negative).length > 0, "the vectors must carry negative cases");
  for (const [name, c] of Object.entries(negative)) {
    if (c.expect === "reject") {
      let rejected = false;
      try {
        await attempt(c);
      } catch {
        rejected = true;
      }
      assert(rejected, `${name}: MUST be rejected (${c.reason}) — ${c.spec}`);
    } else if (c.expect === "accept") {
      assert(await attempt(c), `${name}: MUST verify (${c.reason})`);
    } else if (c.expect === "flag") {
      // A "flag" case is validly signed on purpose: the signal lives above the
      // signature check, so an implementation that only checks signatures waves
      // it straight through.
      if (c.events) {
        for (const ev of c.events) assert(await verifyEvent(c.jwk as Jwk, ev), `${name}: legs verify`);
      } else {
        assert(await attempt(c), `${name}: MUST verify (the flag is not a sig failure)`);
      }
    } else {
      throw new Error(`${name}: unknown expect ${JSON.stringify(c.expect)}`);
    }
  }
});

test("explicit nulls diverge structurally from the reference", async () => {
  // [TAP-EVT-OMIT]. The point of the rule: this record is validly signed, so no
  // amount of signature checking catches it — but its signing input differs from
  // the reference for a logically identical action, so two conforming Signers
  // would disagree on the bytes and their checkpoints would not match.
  const c = negative.explicit_nulls_non_conforming;
  assert(await verifyEvent(c.jwk as Jwk, c.event), "the non-conforming record still verifies");
  const got = hex(sha256(signingInput(c.event)));
  assert(got === c.canonical_signing_input_sha256, "matches the recorded divergent hash");
  assert(got !== hex(sha256(signingInput(vectors.event.signed_event))),
    "explicit nulls must produce different signed bytes — that is the whole problem");
  for (const field of c.diverges_on) {
    assert(field in c.event && c.event[field] === null, `${field} is an explicit null here`);
    assert(!(field in vectors.event.signed_event), "the reference omits absent optionals");
  }
});

test("duplicate (aid, seq) is detectable despite valid signatures", async () => {
  const c = negative.duplicate_aid_seq;
  const [a, b] = c.events;
  assert(await verifyEvent(c.jwk as Jwk, a), "first leg verifies");
  assert(await verifyEvent(c.jwk as Jwk, b), "second leg verifies");
  assert(a.aid === b.aid && a.seq === b.seq, "same (aid, seq)");
  assert(a.event_id !== b.event_id, "different content under the same sequence slot");
});

test("a checkpoint omitting a delivered event fails reconciliation", async () => {
  const c = negative.checkpoint_omits_delivered_event;
  assert(await verifyEvent(c.jwk as Jwk, c.event), "the checkpoint itself is validly signed");

  const delivered = [vectors.event.signed_event, vectors.decision.signed_event];
  const result = reconcileCheckpoint(c.event, delivered);
  assert(result.root_mismatch, "recomputing the root over delivered ids must mismatch");
  assert(!result.count_matches, "the claimed count is short too");
  assert(checkpointRoot(c.committed_event_ids) === c.event.checkpoint.event_id_root,
    "the short root is internally consistent");
});

test("reconciliation uses the signed lower bound", async () => {
  // The bug this replaced: reconciliation that ignores `from_seq` and sweeps every
  // event with seq <= through_seq reports a mismatch on any record whose earlier
  // checkpoint is missing — a false accusation manufactured by the verifier itself.
  const checkpoint = vectors.checkpoint.signed_event;
  const delivered = [vectors.event.signed_event, vectors.decision.signed_event];
  const earlier = { ...vectors.event.signed_event, seq: 3, event_id: "evt_from_a_previous_segment" };

  const clean = reconcileCheckpoint(checkpoint, delivered);
  assert(clean.root_valid && clean.count_matches, "the honest record reconciles");

  const withEarlier = reconcileCheckpoint(checkpoint, [...delivered, earlier]);
  assert(withEarlier.root_valid, "an event below from_seq must be excluded, not counted as a mismatch");
  assert(withEarlier.from_seq === 6 && withEarlier.count_received === 2, "interval respected");
});

test("a root mismatch is not reported as provable deletion", async () => {
  // A mismatch says the delivered set is wrong. It does not identify which Event is
  // missing, or whether one was added. Only an enumerated commitment supports the
  // stronger claim — and overstating evidence is the one thing an audit tool must
  // not do.
  const c = negative.checkpoint_omits_delivered_event;
  const delivered = [vectors.event.signed_event, vectors.decision.signed_event];
  const result = reconcileCheckpoint(c.event, delivered);
  assert(result.root_mismatch, "mismatch detected");
  assert(result.provably_deleted.length === 0,
    "no leaf enumeration on the wire => no provable-deletion claim");

  const enumerated = {
    ...vectors.checkpoint.signed_event,
    reconciliation: { event_ids: vectors.checkpoint.reconciliation.event_ids },
  };
  const partial = reconcileCheckpoint(enumerated, [vectors.event.signed_event]);
  assert(partial.provably_deleted[0] === vectors.decision.signed_event.event_id,
    "with the leaves enumerated, the suppressed id becomes provable");
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
  console.log(`# ${Object.keys(negative).length} negative vectors enforced ✓`);
}

main();
