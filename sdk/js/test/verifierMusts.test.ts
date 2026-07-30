// Verifier MUST-behaviours that are easy to regress. Mirrors
// sdk/python/tests/test_verifier_musts.py.
//
// These guard the checks a conforming verifier cannot skip, all of which are part
// of verification itself rather than a layer above it:
//   * suite dispatch [TAP-SUITE-DISPATCH] — resolve the key's declared suite and
//     REJECT an unrecognized one rather than defaulting to Ed25519;
//   * key revocation [TAP-KEY-REVOCATION] — reject records signed at or after the
//     key's revoked_at, for EVENTS as well as passports, and keep accepting
//     records signed before it;
//   * exact scope matching [TAP-SCOPE-MATCH] — no wildcards, no prefix rule;
//   * the no-fractional-numbers rule [TAP-CANON-NUMBERS] — a Signer must REFUSE
//     to sign a body the spec forbids, which this SDK never did.
//
// Every one of these has been missing from some build of this SDK.
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  CanonicalizationError,
  RevokedKey,
  UnknownSuite,
  keyRevokedAt,
  parseTs,
  scopeSatisfied,
  signEvent,
  suiteForJwk,
  verifyEvent,
  verifyPassport,
  type Jwk,
} from "../src/tap.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"));

const JWK: Jwk = vectors.jwks.keys[0];
const EVENT = vectors.event.signed_event as Record<string, unknown>;
const PASSPORT = vectors.passport.compact_jwt as string;
const IAT = vectors.passport.claims.iat as number;

const tests: Array<[string, () => Promise<void>]> = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);

test("known suite resolves", async () => {
  if (suiteForJwk(JWK) !== "tap-ed25519") throw new Error("expected tap-ed25519");
});

test("unknown suite rejected, not defaulted", async () => {
  const hostileKeys = [
    { alg: "RS256", crv: "P-256" },
    { alg: "none", crv: "Ed25519" },
    { alg: "HS256", crv: undefined },
  ];
  for (const bad of hostileKeys) {
    const jwk = { ...JWK, ...bad } as Jwk;
    for (const call of [
      () => verifyEvent(jwk, EVENT),
      () => verifyPassport(jwk, PASSPORT, IAT + 1),
    ]) {
      let rejected = false;
      try {
        await call();
      } catch (err) {
        rejected = err instanceof UnknownSuite;
      }
      if (!rejected) throw new Error(`unknown suite ${JSON.stringify(bad)} was not rejected`);
    }
  }
});

test("revoked key rejects a passport", async () => {
  if (keyRevokedAt(JWK) !== null) throw new Error("reference key should not be revoked");
  const revoked = { ...JWK, revoked_at: IAT - 1 } as Jwk; // revoked before issuance
  let rejected = false;
  try {
    await verifyPassport(revoked, PASSPORT, IAT + 1);
  } catch (e) {
    rejected = e instanceof RevokedKey;
  }
  if (!rejected) throw new Error("passport signed by a revoked key was accepted");
});

test("revoked key rejects an event", async () => {
  // The gap that mattered: revocation was enforced for passports only, so the
  // documented event-verification primitive accepted records signed by a key its
  // owner had already reported compromised.
  const eventTs = parseTs(EVENT.ts as string);
  let rejected = false;
  try {
    await verifyEvent({ ...JWK, revoked_at: eventTs - 1 } as Jwk, EVENT);
  } catch (e) {
    rejected = e instanceof RevokedKey;
  }
  if (!rejected) throw new Error("event signed by a revoked key was accepted");
});

test("revocation is a boundary, not blanket repudiation", async () => {
  // Records signed BEFORE the boundary stay valid — otherwise revoking a key would
  // retroactively destroy every record it ever signed, the opposite of what an
  // evidence system should do.
  const eventTs = parseTs(EVENT.ts as string);
  await verifyEvent({ ...JWK, revoked_at: eventTs + 3600 } as Jwk, EVENT);
  await verifyPassport({ ...JWK, revoked_at: IAT + 10_000 } as Jwk, PASSPORT, IAT + 1);
});

test("an undated record under a revoked key is rejected", async () => {
  // A record that cannot place itself in time cannot prove it predates the
  // revocation, so it must not get the benefit of the doubt.
  const { ts: _drop, ...undated } = EVENT as Record<string, unknown>;
  let rejected = false;
  try {
    await verifyEvent({ ...JWK, revoked_at: IAT } as Jwk, undated);
  } catch (e) {
    rejected = e instanceof RevokedKey;
  }
  if (!rejected) throw new Error("undated record under a revoked key was accepted");
});

test("scope matching is exact", async () => {
  // [TAP-SCOPE-MATCH]. A looser rule here would be privilege escalation in the one
  // check TAP performs itself.
  const granted = ["read:database", "call:tool"];
  if (!scopeSatisfied("read:database", granted)) throw new Error("exact match must succeed");
  if (!scopeSatisfied(null, granted)) throw new Error("no scope exercised must succeed");
  for (const denied of ["read:*", "*", "read:database.users", "READ:DATABASE", "read:", "read:databas"]) {
    if (scopeSatisfied(denied, granted)) throw new Error(`${denied} must not match`);
  }
});

test("a Signer refuses to sign a body with fractional numbers", async () => {
  // [TAP-CANON-NUMBERS]. Without this guard a TS signer silently emitted records
  // the spec forbids: each verified against its own signature, so the divergence
  // only surfaced later, as a checkpoint that would not reconcile.
  const seed: string = vectors.ed25519_private_seed_hex;
  for (const bad of [
    { v: "tap/0.1", event_id: "evt_x", seq: 1, score: 0.71, kid: JWK.kid },
    { v: "tap/0.1", event_id: "evt_x", seq: 1, big: Number.MAX_SAFE_INTEGER + 2, kid: JWK.kid },
    { v: "tap/0.1", event_id: "evt_x", seq: 1, nested: { a: [1, 2.5] }, kid: JWK.kid },
  ]) {
    let rejected = false;
    try {
      await signEvent(seed, bad);
    } catch (e) {
      rejected = e instanceof CanonicalizationError;
    }
    if (!rejected) throw new Error(`signed a forbidden body: ${JSON.stringify(bad)}`);
  }
  // ... and still signs a legal one, with the score as a string
  await signEvent(seed, { v: "tap/0.1", event_id: "evt_x", seq: 1, score: "0.71", kid: JWK.kid });
});

test("reference vectors still verify unchanged", async () => {
  await verifyEvent(JWK, EVENT);
  await verifyPassport(JWK, PASSPORT, IAT + 1);
});

const main = async () => {
  console.log(`1..${tests.length}`);
  let i = 0;
  for (const [name, fn] of tests) {
    await fn();
    console.log(`ok ${++i} - ${name}`);
  }
  console.log("# verifier MUST-behaviours enforced ✓");
};

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
