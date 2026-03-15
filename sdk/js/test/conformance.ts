// The @traceableagent/sdk (TypeScript) reproduces the TAP conformance vectors
// byte-for-byte — i.e. a JS-signed passport/event is identical to the Python
// reference, so a JS signer interoperates with the Python Verifier.
//
//   npx tsx test/conformance.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import { sha256 } from "@noble/hashes/sha2.js";

import { signEvent, signPassport, signingInput, verifyEvent, verifyPassport, type Jwk } from "../src/tap.js";

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(
  readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"),
);

const hex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

let n = 0;
const ok = (label: string) => console.log(`ok ${++n} - ${label}`);
const fail = (label: string, detail = "") => {
  console.log(`not ok ${++n} - ${label}`);
  if (detail) console.log(`  # ${detail}`);
  process.exit(1);
};

async function main() {
  console.log("TAP version 13");
  console.log("1..4");

  const seed: string = vectors.ed25519_private_seed_hex;
  const jwk: Jwk = vectors.jwks.keys[0];
  const kid: string = jwk.kid;

  // 1. passport reproduces byte-for-byte
  const passport = await signPassport(seed, kid, vectors.passport.claims);
  if (passport !== vectors.passport.compact_jwt)
    fail("passport reproduces reference vector", "compact JWT differs from Python");
  ok("passport reproduces reference vector (identical to Python)");

  // 2. event signature + JCS input reproduce
  const signed = vectors.event.signed_event;
  const { sig: _omit, ...body } = signed;
  const reSigned = await signEvent(seed, body);
  if (reSigned.sig !== signed.sig) fail("event signature reproduces", "sig differs");
  const jcsHash = hex(sha256(signingInput(signed)));
  if (jcsHash !== vectors.event.canonical_signing_input_sha256)
    fail("JCS canonical input matches", `got ${jcsHash}`);
  ok("event signature + JCS input reproduce reference vector (identical to Python)");

  // 3. verify accepts the reference records
  await verifyPassport(jwk, vectors.passport.compact_jwt, vectors.passport.claims.iat + 1);
  await verifyEvent(jwk, signed);
  ok("verifies reference passport + event");

  // 4. tamper rejected
  const tampered = { ...signed, action: { ...signed.action, tool: "drop_table" } };
  try {
    await verifyEvent(jwk, tampered);
    fail("tamper rejected", "verifyEvent did not throw");
  } catch {
    ok("tamper rejected");
  }
  console.log("# @traceableagent/sdk is TAP-conformant — cross-language interop with Python ✓");
}

main();
