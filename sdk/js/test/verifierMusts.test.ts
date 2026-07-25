// Verifier MUST-behaviours that are easy to regress (spec §3.2, §3.6, §15).
//
// Mirrors sdk/python/tests/test_verifier_musts.py. Two checks a conforming
// verifier cannot skip:
//   * algorithm-driven dispatch — resolve the key's declared suite and REJECT an
//     unrecognized one rather than defaulting to Ed25519;
//   * key revocation — reject records signed at or after the key's revoked_at.
//
// Both are MUST in the spec and both were missing from an earlier build of this
// SDK's core while the reference implementation had them.
import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

import {
  UnknownSuite,
  keyRevokedAt,
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

test("revoked key rejected", async () => {
  if (keyRevokedAt(JWK) !== null) throw new Error("reference key should not be revoked");
  const revoked = { ...JWK, revoked_at: IAT - 1 } as Jwk; // revoked before issuance
  let rejected = false;
  try {
    await verifyPassport(revoked, PASSPORT, IAT + 1);
  } catch {
    rejected = true;
  }
  if (!rejected) throw new Error("passport signed by a revoked key was accepted");
});

test("key valid before revocation still verifies", async () => {
  const stillOk = { ...JWK, revoked_at: IAT + 10_000 } as Jwk;
  await verifyPassport(stillOk, PASSPORT, IAT + 1);
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
