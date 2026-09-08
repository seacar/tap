// Defects that shipped once, with the property each one violated.
//
// The TypeScript half of sdk/python/tests/test_regressions.py. Both SDKs share
// the verifier's assurance and passport-validation logic in shape but not in
// code, so a fix landing in only one language is the normal failure mode here —
// which is exactly how the `latency_ms: null` divergence survived for a release.
//
//   npx tsx test/regressions.test.ts

import * as ed from "@noble/ed25519";

import { TAPClient } from "../src/client.js";
import { PassportExpired, b64u, publicJwk, signEvent, verifyPassport } from "../src/tap.js";
import { assuranceLevel, checkPassport, evaluateEvent, verifyTranscript } from "../src/verify.js";
import { AuthorityMalformed, checkAuthorityWindow } from "../src/authority.js";

const utf8 = (s: string) => new TextEncoder().encode(s);
const fromHex = (h: string) =>
  Uint8Array.from(h.match(/.{2}/g)!.map((b) => parseInt(b, 16)));
const nowTs = () => new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");

const AGENT_SEED = "11".repeat(32);
const SERVER_SEED = "22".repeat(32);
const AGENT_KID = "kid_agent";
const SERVER_KID = "kid_server";

const KEYS: Record<string, any> = {
  [AGENT_KID]: await publicJwk(AGENT_SEED, AGENT_KID),
  [SERVER_KID]: await publicJwk(SERVER_SEED, SERVER_KID),
};
const resolveKey = async (kid: string) => KEYS[kid] ?? null;

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

function client(): { tap: TAPClient; events: Record<string, any>[] } {
  const events: Record<string, any>[] = [];
  const tap = new TAPClient({
    agentId: "regress", privateKeyHex: AGENT_SEED, kid: AGENT_KID,
    post: async (_u, p: any) => { events.push(...(p.events ?? [])); },
  });
  return { tap, events };
}

// --- §7: a Signer cannot forge independent attestation [TAP-ASSURANCE-KEY] ---

test("an agent signing both legs with its own key cannot reach two-sided", async () => {
  const { tap } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: ["call:x"] });
  const leg = (attestor: string, seq: number) =>
    signEvent(AGENT_SEED, {
      v: "tap/0.1", event_id: `evt_${attestor}`, passport_jti: p.claims.jti,
      aid: p.claims.aid, cid: p.claims.cid, seq, ts: nowTs(),
      action: { kind: "tool_call", intent_digest: "sha256:" + "00".repeat(32),
                tool: "x", scope_used: "call:x" },
      result: { status: "success", code: "OK", error: null },
      attestor, action_ref: "r1", kid: AGENT_KID,
    });
  const events = [await leg("agent", 1), await leg("server", 2)];
  // Both legs verify. The forgery is not a bad signature — it is a leg claiming
  // to be independent while signed by the very key it claims independence from.
  assert(new Set(events.map((e) => e.kid)).size === 1, "one key signed both legs");
  const report = await verifyTranscript(p.compact, events, { resolveKey });
  assert(
    report.assurance.by_action_ref.r1 === "conflicting",
    `expected conflicting, got ${report.assurance.by_action_ref.r1}`,
  );
  assert(report.verified === false, "a forged server leg must not verify");
});

test("assuranceLevel reaches two-sided only across independent keys", async () => {
  const base = {
    cid: "sha256:" + "00".repeat(32),
    action: { kind: "tool_call", tool: "x", scope_used: "call:x" },
    result: { status: "success", code: "OK", error: null },
  };
  const agentLeg = { ...base, attestor: "agent", kid: AGENT_KID };
  assert(
    assuranceLevel([agentLeg, { ...base, attestor: "server", kid: AGENT_KID }]) === "conflicting",
    "a server leg sharing the agent's kid is conflicting",
  );
  assert(
    assuranceLevel([agentLeg, { ...base, attestor: "server", kid: SERVER_KID }]) === "two-sided",
    "an independent kid reaches two-sided",
  );
  // "Different key" is only a floor: an agent holding two keys still clears it.
  // A deployment that knows WHICH keys may attest as a server says so.
  assert(
    assuranceLevel(
      [agentLeg, { ...base, attestor: "server", kid: SERVER_KID }],
      (kid) => kid === "some_other_gateway",
    ) === "conflicting",
    "a trust anchor rejects an unrecognized server key",
  );
});

// --- §3.1/§5.3: verification checks the field attacks actually target -------

test("a JOSE header of alg:none is rejected [TAP-SIG-ALG]", async () => {
  const now = Math.floor(Date.now() / 1000);
  const hdr = { alg: "none", typ: "tap-passport+jwt", kid: AGENT_KID };
  const claims = {
    iss: "x", iat: now, exp: now + 60, jti: "j", aid: "a",
    cid: "sha256:" + "0".repeat(64), scope: [],
  };
  const enc = (o: unknown) => b64u(utf8(JSON.stringify(o)));
  const seg = `${enc(hdr)}.${enc(claims)}`;
  const sig = await ed.signAsync(utf8(seg), fromHex(AGENT_SEED));
  // The signature is a perfectly good Ed25519 signature. The header still lies
  // about the algorithm, and §3.1 says that MUST NOT be accepted — checking the
  // JWK's suite alone leaves the field alg-confusion attacks actually target.
  let rejected = false;
  try {
    await verifyPassport(KEYS[AGENT_KID], `${seg}.${b64u(sig)}`);
  } catch (e) {
    rejected = (e as Error).message.includes("alg");
  }
  assert(rejected, "alg:none in the JOSE header must be rejected");
});

test("expiry is a typed error, not a substring of a message", async () => {
  const { tap } = client();
  const p = await tap.issuePassport({ taskPrompt: "t", scope: [], ttlS: 1 });
  const res = await checkPassport(p.compact, {
    resolveKey, now: Math.floor(Date.now() / 1000) + 10_000,
  });
  assert(res.expired === true && res.valid === false, "an aged-out passport reports expired");
  let typed = false;
  try {
    await verifyPassport(KEYS[AGENT_KID], p.compact, Math.floor(Date.now() / 1000) + 10_000);
  } catch (e) {
    typed = e instanceof PassportExpired;
  }
  assert(typed, "expiry must raise PassportExpired, not a generic Error");
});

// --- a verifier must not be crashable by a record it is asked to read -------

test("a malformed authorization block is labeled, never thrown", async () => {
  for (const bad of [{}, { authz_id: "a" }, "a string", [1, 2], 7]) {
    const event = await signEvent(AGENT_SEED, {
      v: "tap/0.1", event_id: "evt_1", passport_jti: "p", aid: "a",
      cid: "sha256:" + "00".repeat(32), seq: 1, ts: nowTs(),
      action: { kind: "tool_call", tool: "t", scope_used: null },
      result: { status: "success", code: "OK", error: null },
      attestor: "agent", kid: AGENT_KID, authorization: bad,
    });
    // The signature is valid; a valid signature says nothing about SHAPE.
    // One poisoned event must not end the whole audit report.
    const res = await evaluateEvent(event, { resolveKey, passportClaims: null, lastSeq: null });
    assert(
      res.authority_effect === "malformed_authority",
      `expected malformed_authority for ${JSON.stringify(bad)}, got ${res.authority_effect}`,
    );
  }
});

test("the authority ENFORCEMENT path fails closed on a malformed block", async () => {
  // The labeling path never throws; the enforcement path must never wave one
  // through, because it reads the unsigned X-TAP-Authorization header (§11.1).
  const bad: unknown[] = [
    {},
    { nbf: "x", exp: 1, authz_id: "a", authority_state_version: "v",
      target_state_digest: "d", issuer_kid: "k" },
    "str",
    [1],
  ];
  for (const b of bad) {
    let closed = false;
    try {
      checkAuthorityWindow(b as any, 0);
    } catch (e) {
      closed = e instanceof AuthorityMalformed;
    }
    assert(closed, `expected AuthorityMalformed for ${JSON.stringify(b)}`);
  }
});

// --- §4.1: nego binds an outcome, never an aspiration [TAP-NEGO-BINDING] ----

test("a record with no observed ack binds no nego", async () => {
  const { tap, events } = client();
  await tap.issuePassport({ taskPrompt: "t", scope: ["read:db"] });
  await tap.traceTool({ tool: "db", scope: "read:db", intent: "i" }, async () => 1);
  await tap.flush();
  const nego = events[0]?.evidence?.nego;
  assert(nego === undefined, `an unnegotiated record must bind no nego, got ${JSON.stringify(nego)}`);
});

// --- §6.1.1: absent optionals are omitted, never null [TAP-EVT-OMIT] --------

test("no composed event carries an explicit null where the rule says omit", async () => {
  const { tap, events } = client();
  await tap.issuePassport({ taskPrompt: "t", scope: ["read:db"] });
  await tap.traceTool({ tool: "db", scope: "read:db", intent: "i" }, async () => 1);
  await tap.decision({
    question: "q", chosen: "a",
    options: [{ id: "a", score: "0.9" }, { id: "b", score: "0.1", reason: "no" }],
  });
  await tap.recordOutput({ output: "x" });
  await tap.emitCheckpoint();
  await tap.flush();
  // `result.error` and `action.tool`/`action.scope_used` are the ONLY nullable
  // fields. Everything else absent must be absent, because `null` and omitted
  // are different signed bytes and two Signers that disagree produce
  // structurally different events for the same action.
  const NULLABLE = new Set(["error", "tool", "scope_used"]);
  for (const ev of events) {
    const walk = (o: any, path: string) => {
      if (o === null || typeof o !== "object") return;
      for (const [k, v] of Object.entries(o)) {
        const at = path ? `${path}.${k}` : k;
        assert(
          v !== null || NULLABLE.has(k),
          `${ev.action.kind}: ${at} is an explicit null; [TAP-EVT-OMIT] says omit`,
        );
        walk(v, at);
      }
    };
    walk(ev, "");
  }
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
  console.log("# regressions: forged attestation, alg confusion, crashable verifier, omit rule ✓");
}

main();
