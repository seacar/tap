// The handshake and the anti-downgrade binding in TypeScript [TAP-NEGOTIATE],
// mirroring sdk/python/tests/test_handshake.py and test_nego.py.
//
// Neither existed here before v0.1.2: `nego` appeared nowhere in the TypeScript
// tree, so a TS-produced record was indistinguishable from one whose handshake had
// been stripped — the exact confusion the binding exists to prevent — and the two
// SDKs disagreed on a spec MUST.
//
//   npx tsx test/nego.test.ts

import {
  ACK_HEADER,
  HELLO_HEADER,
  NegotiationFailed,
  ackFromHeaders,
  helloFromHeaders,
  offer,
  readAck,
  select,
} from "../src/negotiate.js";
import { TAPClient } from "../src/client.js";
import { SPEC_VERSION, publicJwk, verifyEvent } from "../src/tap.js";
import { assuranceLevel, negoViolation } from "../src/verify.js";

const SEED = "66".repeat(32);
const KID = "key_nego_ts_test";

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

function client(): { tap: TAPClient; captured: Record<string, unknown>[] } {
  const captured: Record<string, unknown>[] = [];
  const tap = new TAPClient({
    agentId: "nego-ts-test",
    privateKeyHex: SEED,
    kid: KID,
    post: async (_url, payload: any) => {
      captured.push(...(payload.events ?? []));
    },
  });
  return { tap, captured };
}

test("offer and select agree", async () => {
  const hello = offer({ kid: KID });
  assert(hello.versions[0] === SPEC_VERSION, "offers the current wire version");
  assert(hello.suites[0] === "tap-ed25519", "suites carry TAP suite ids, not JOSE algs");

  const ack = select(hello, { attests: true })!;
  assert(ack.suite === "tap-ed25519" && ack.attestation === "server", "server attests");
  const outcome = readAck(ack)!;
  assert(outcome.version === SPEC_VERSION && outcome.attestation === "server", "outcome read back");
});

test("a Signer cannot offer 'server'", async () => {
  // `server` is the Server's selection. A Signer offering it would be claiming an
  // outcome it is not in a position to grant.
  for (const bad of ["server", "two-sided", "yes"]) {
    let threw = false;
    try {
      offer({ kid: KID, attestation: bad });
    } catch {
      threw = true;
    }
    assert(threw, `a Signer must not be able to offer ${bad}`);
  }
});

test("a non-attesting server says so", async () => {
  const ack = select(offer({ kid: KID }), { attests: false })!;
  assert(ack.attestation === "none", "a server that will not sign a leg must not answer 'server'");
});

test("no mutual version fails loudly", async () => {
  let threw = false;
  try {
    select({ versions: ["tap/9.9"], suites: ["tap-ed25519"] }, { attests: true });
  } catch (e) {
    threw = e instanceof NegotiationFailed;
  }
  assert(threw, "a version mismatch must not silently succeed");
});

test("header carriage round-trips", async () => {
  const hello = offer({ kid: KID });
  assert(JSON.stringify(helloFromHeaders({ [HELLO_HEADER]: JSON.stringify(hello) })) ===
    JSON.stringify(hello), "hello round-trips");
  assert(helloFromHeaders({ [HELLO_HEADER.toLowerCase()]: JSON.stringify(hello) }) !== null,
    "header lookup is case-insensitive");
  // A malformed header degrades to "no handshake" rather than taking down the request.
  assert(helloFromHeaders({ [HELLO_HEADER]: "{not json" }) === null, "malformed input is absent");
  assert(ackFromHeaders({}) === null, "absent ack is null");
  assert(ACK_HEADER === "X-TAP-Hello-Ack", "ack header name");
});

test("the negotiated outcome is what gets bound", async () => {
  const { tap, captured } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  const ack = select(tap.hello(), { attests: true });
  const outcome = tap.negotiate(ack, p)!;
  assert(outcome.attestation === "server", "negotiated server attestation");

  await tap.traceTool({ tool: "x", scope: "call:tool" }, async () => 1);
  await tap.flush();

  const nego = (captured[0] as any).evidence?.nego;
  assert(nego?.version === SPEC_VERSION && nego?.suite === "tap-ed25519"
    && nego?.attestation === "server", `first event must carry the outcome, got ${JSON.stringify(nego)}`);
});

test("nego appears exactly once per record", async () => {
  const { tap, captured } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  tap.negotiate(select(tap.hello(), { attests: true }), p);
  await tap.traceTool({ tool: "first", scope: "call:tool" }, async () => 1);
  await tap.traceTool({ tool: "second", scope: "call:tool" }, async () => 2);
  await tap.flush();
  assert((captured[0] as any).evidence?.nego, "first event carries it");
  assert(!(captured[1] as any).evidence?.nego, "the second must not");
});

test("a stripped handshake binds nothing", async () => {
  // The attack the binding exists for. An intermediary drops the hello, so no ack
  // comes back; the Signer has nothing honest to claim and says nothing, and the
  // record degrades visibly to intent-only instead of asserting assurance nobody
  // promised.
  const { tap, captured } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  assert(tap.negotiate(null, p) === null, "no ack, no outcome");
  await tap.traceTool({ tool: "x", scope: "call:tool" }, async () => 1);
  await tap.flush();
  assert(!(captured[0] as any).evidence?.nego, "with no observed ack there is nothing truthful to bind");
  assert(assuranceLevel([captured[0]]) === "intent-only", "labelled honestly");
});

test("an unusable ack is treated as no ack", async () => {
  const { tap } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  for (const bad of [
    { version: "tap/9.9", suite: "tap-ed25519", attestation: "server" },
    { version: SPEC_VERSION, suite: "tap-pq-9", attestation: "server" },
    { version: SPEC_VERSION, suite: "tap-ed25519", attestation: "requested" },
  ]) {
    assert(tap.negotiate(bad, p) === null, `${JSON.stringify(bad)} should be unusable`);
  }
});

test("a claim without a server leg is a violation", async () => {
  const { tap, captured } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  tap.negotiate(select(tap.hello(), { attests: true }), p);
  await tap.traceTool({ tool: "x", scope: "call:tool" }, async () => 1);
  await tap.flush();
  assert(negoViolation([captured[0]]), "a claimed server leg that never arrives is a violation");
});

test("the binding is inside the signature", async () => {
  // The binding is worthless unless the signature covers it.
  const { tap, captured } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  tap.negotiate(select(tap.hello(), { attests: true }), p);
  await tap.traceTool({ tool: "x", scope: "call:tool" }, async () => 1);
  await tap.flush();

  const jwk = await publicJwk(SEED, KID);
  const event = captured[0] as any;
  assert(await verifyEvent(jwk, event), "the signed event verifies as-is");

  const downgraded = {
    ...event,
    evidence: { ...event.evidence, nego: { ...event.evidence.nego, attestation: "none" } },
  };
  let threw = false;
  try {
    await verifyEvent(jwk, downgraded);
  } catch {
    threw = true;
  }
  assert(threw, "downgrading nego after signing must break verification");
});

test("a legacy `alg` field is accepted on input only", async () => {
  const ack = select({ versions: [SPEC_VERSION], algs: ["EdDSA"] } as any, { attests: true })!;
  assert(!("alg" in ack) && ack.suite === "tap-ed25519", "we read `alg` but never emit it");
  assert(readAck({ version: SPEC_VERSION, alg: "EdDSA", attestation: "server" } as any)?.suite ===
    "tap-ed25519", "an older peer still interoperates");
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
  console.log("# handshake negotiated, bound, and downgrade-detectable ✓");
}

main();
