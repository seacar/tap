// The @traceableagent/sdk (TypeScript) reproduces the TAP conformance vectors
// byte-for-byte — a JS-signed passport/event is identical to the Python
// reference, so a JS signer interoperates with any TAP verifier.
//
// Every published vector is exercised, not just the headline one:
// [TAP-CONFORMANCE] makes the fractional-score decision case, the checkpoint
// Merkle case and the canonicalization case mandatory, and this suite used to
// check none of them.
//
// Rejection behaviour lives in negativeVectors.test.ts. Both halves count.
//
//   npx tsx test/conformance.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { sha256 } from "@noble/hashes/sha2.js";

import {
  checkpointRoot,
  digest,
  jsonDigest,
  signEvent,
  signPassport,
  signingInput,
  textDigest,
  verifyEvent,
  verifyPassport,
  type Jwk,
} from "../src/tap.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"));

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

const SIGNED_CASES = ["event", "decision", "checkpoint", "canonicalization"] as const;

let n = 0;
const ok = (label: string) => console.log(`ok ${++n} - ${label}`);
const fail = (label: string, detail = "") => {
  console.log(`not ok ${++n} - ${label}`);
  if (detail) console.log(`  # ${detail}`);
  process.exit(1);
};
const check = (cond: unknown, label: string, detail = "") => {
  if (!cond) fail(label, detail);
};

async function main() {
  // "TAP version 13" is the Test Anything Protocol header — an unrelated TAP.
  console.log("TAP version 13");
  console.log("1..8");

  const seed: string = vectors.ed25519_private_seed_hex;
  const jwk: Jwk = vectors.jwks.keys[0];
  const kid: string = jwk.kid;

  // 1. passport reproduces byte-for-byte
  const passport = await signPassport(seed, kid, vectors.passport.claims);
  check(passport === vectors.passport.compact_jwt,
    "passport reproduces reference vector", "compact JWT differs from Python");
  ok("passport reproduces reference vector (identical to Python)");

  // 2. every signed case reproduces its signature AND its JCS signing input
  for (const c of SIGNED_CASES) {
    const signed = vectors[c].signed_event;
    const { sig: _omit, ...body } = signed;
    const reSigned = await signEvent(seed, body);
    check(reSigned.sig === signed.sig, `${c}: signature reproduces`, "sig differs from Python");
    check(hex(sha256(signingInput(signed))) === vectors[c].canonical_signing_input_sha256,
      `${c}: JCS input matches`);
  }
  ok(`all ${SIGNED_CASES.length} signed cases reproduce sig + JCS input (identical to Python)`);

  // 3. verification accepts every reference record
  await verifyPassport(jwk, vectors.passport.compact_jwt, vectors.passport.claims.iat + 1);
  for (const c of SIGNED_CASES) await verifyEvent(jwk, vectors[c].signed_event);
  ok("verifies reference passport + every reference event");

  // 4. tamper on any signed field is rejected
  const signed = vectors.event.signed_event;
  try {
    await verifyEvent(jwk, { ...signed, action: { ...signed.action, tool: "drop_table" } });
    fail("tamper rejected", "verifyEvent did not throw");
  } catch {
    ok("tamper rejected");
  }

  // 5. the fractional-score rule [TAP-CANON-NUMBERS]
  const dec = vectors.decision.signed_event.decision;
  for (const opt of dec.options) {
    check(typeof opt.score === "string", "decision scores are strings",
      `got ${typeof opt.score} for ${opt.id}`);
  }
  assertNoFloats(vectors.decision.signed_event);
  const chosen = dec.options.filter((o: any) => o.chosen);
  check(chosen.length === 1 && chosen[0].id === dec.chosen,
    "exactly one option is chosen and decision.chosen names it");
  ok("decision: string scores, no fractional numbers, one chosen option");

  // 6. checkpoint Merkle reconciliation [TAP-EVT-CHECKPOINT] — the construction
  //    the entire fail-open story rests on, and previously never tested here
  const rec = vectors.checkpoint.reconciliation;
  const cp = vectors.checkpoint.signed_event.checkpoint;
  check(checkpointRoot(rec.event_ids) === rec.event_id_root
    && rec.event_id_root === cp.event_id_root,
    "recomputed Merkle root matches the signed root");
  check(checkpointRoot([]) === rec.empty_interval_root
    && rec.empty_interval_root === digest(new Uint8Array(0)),
    "the empty interval has a defined root");
  check(cp.from_seq === rec.from_seq && cp.through_seq === rec.through_seq,
    "the sealed interval is self-describing");
  check(cp.count === rec.event_ids.length, "count equals the committed leaf count");
  check(checkpointRoot([...rec.event_ids].reverse()) !== rec.event_id_root,
    "leaf order is part of the commitment");
  ok("checkpoint Merkle root, empty interval, interval bounds, leaf order");

  // 7. canonicalization [TAP-CANON-JCS] — the half of RFC 8785 that pure-ASCII
  //    vectors miss, and where JS is most likely to diverge from Python: it stores
  //    strings as UTF-16, so surrogate pairs and member ordering are live risks.
  const canon = vectors.canonicalization;
  const args = canon.member_ordering.args;
  const order: string[] = canon.member_ordering.jcs_member_order;
  check(jsonDigest(args) === canon.member_ordering.args_digest,
    "JCS digest over the torture object matches the reference");
  check(order[0] === "", "the empty key sorts first");
  check(order.indexOf("\u{1f511}") < order.indexOf("\ufb03"),
    "a non-BMP key orders by its leading surrogate, BELOW U+FB03");
  // NFD ('e' + U+0301) and NFC (U+00E9) are DIFFERENT keys — JCS does not normalize.
  check("e\u0301" in args && "\u00e9" in args,
    "NFD and NFC keys both survive as distinct members");
  check(textDigest(canon.annex.reasoning) === canon.signed_event.evidence.reasoning_digest,
    "UTF-8 digest of mixed-script plaintext matches across implementations");
  ok("canonicalization: escaping, non-BMP, UTF-16 ordering, NFC/NFD");

  // 8. annex digests verify, and nothing leaked into a signed body
  const ev = vectors.event;
  check(textDigest(ev.annex.intent) === ev.signed_event.action.intent_digest,
    "annex intent verifies against the signed digest");
  check(jsonDigest(ev.annex.args_preview) === ev.signed_event.action.args_digest,
    "annex args verify against the signed digest");
  for (const c of SIGNED_CASES) {
    const body = vectors[c].signed_event;
    for (const forbidden of ["intent", "args", "args_preview", "reasoning"]) {
      check(!(forbidden in (body.action ?? {})), `${c}: no ${forbidden} in signed action`);
      check(!(forbidden in (body.evidence ?? {})), `${c}: no ${forbidden} in signed evidence`);
    }
    // absent optionals are omitted, never null [TAP-EVT-OMIT]
    for (const absent of ["parent_event_id", "policy_decision"]) {
      check(!(absent in body), `${c}: ${absent} must be omitted when absent, not null`);
    }
  }
  ok("annex digests verify; no plaintext and no explicit nulls in signed bodies");

  console.log("# @traceableagent/sdk is TAP-conformant across every published vector \u2713");
}

function assertNoFloats(value: unknown, path = ""): void {
  if (typeof value === "number") {
    if (!Number.isInteger(value)) fail("no fractional numbers in a signed body", `at ${path}`);
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => assertNoFloats(v, `${path}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(value)) assertNoFloats(v, `${path}.${k}`);
}

main();
