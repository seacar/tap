// Authority binding in TypeScript [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL],
// mirroring sdk/python/tests/test_authority.py.
//
// Before this, `authorization`/`authority_state_version`/`target_state_digest`
// appeared nowhere in the TypeScript tree — only tap_ref.py and the Python SDK
// implemented the stateless half of §9.2, so a TS Signer could not bind an
// Event to a declared approval, and a TS Verifier could not label the outcome.
//
//   npx tsx test/authority.test.ts

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

import {
  Authorization,
  AuthorityExpired,
  AuthorityRevoked,
  authorityEffectLabel,
  authorityStateVersion,
  checkAuthorityWindow,
  checkAuthorityNotRevoked,
} from "../src/authority.js";
import { jsonDigest, newId, publicJwk, signEvent, signPassport, textDigest } from "../src/tap.js";
import { TAPClient } from "../src/client.js";
import { evaluateEvent, verifyTranscript } from "../src/verify.js";

const AUTHORITY_STATE = { policy: "refund-v3", rules: ["max_refund_cents:10000"] };
const TARGET_STATE = { ticket: "8842", status: "refunded", refund_cents: 5000 };

const here = dirname(fileURLToPath(import.meta.url));
const vectors = JSON.parse(readFileSync(resolve(here, "../../../test-vectors.json"), "utf8"));

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

test("authorityStateVersion is the same JCS-digest construction as jsonDigest", async () => {
  // Same construction as the Python SDK's authority_state_version / policy_version:
  // sha256(JCS(state)) — jsonDigest already performs exactly that.
  assert(
    authorityStateVersion(AUTHORITY_STATE) === jsonDigest(AUTHORITY_STATE),
    "authorityStateVersion must equal jsonDigest for the same input",
  );
});

test("grant() and toRecord()/fromRecord() round-trip", async () => {
  const auth = Authorization.grant({
    targetState: TARGET_STATE,
    authorityState: AUTHORITY_STATE,
    nbf: 1000,
    exp: 2000,
    issuerKid: "key_admin",
  });
  const record = auth.toRecord();
  assert(
    record.authority_state_version === authorityStateVersion(AUTHORITY_STATE),
    "authority_state_version must match",
  );
  assert(record.target_state_digest === jsonDigest(TARGET_STATE), "target_state_digest must match");
  assert(record.nbf === 1000 && record.exp === 2000, "nbf/exp must round-trip");
  assert(record.issuer_kid === "key_admin", "issuer_kid must round-trip");
  const back = Authorization.fromRecord(record);
  assert(JSON.stringify(back.toRecord()) === JSON.stringify(record), "fromRecord must round-trip exactly");
});

test("checkAuthorityWindow enforces the +/-60s skew boundary", async () => {
  const auth = Authorization.grant({
    targetState: TARGET_STATE,
    authorityState: AUTHORITY_STATE,
    nbf: 1000,
    exp: 2000,
    issuerKid: "key_admin",
  });
  checkAuthorityWindow(auth, 1500); // mid-window: must not throw
  checkAuthorityWindow(auth, 1000 - 60); // inclusive lower skew edge: must not throw
  for (const badNow of [1000 - 61, 2000 + 61]) {
    let threw = false;
    try {
      checkAuthorityWindow(auth, badNow);
    } catch (e) {
      threw = e instanceof AuthorityExpired;
      if (threw) {
        assert((e as AuthorityExpired).authorization.authz_id === auth.authzId, "authz_id carried on the error");
        assert((e as AuthorityExpired).now === badNow, "now carried on the error");
      }
    }
    assert(threw, `expected AuthorityExpired at now=${badNow}`);
  }
});

test("authorityEffectLabel matches/mismatches/unverifies correctly", async () => {
  const auth = Authorization.grant({
    targetState: TARGET_STATE,
    authorityState: AUTHORITY_STATE,
    nbf: 1000,
    exp: 2000,
    issuerKid: "key_admin",
  });
  assert(authorityEffectLabel(null, { effect_digest: "x" }) === null, "no authorization -> null");
  assert(authorityEffectLabel(auth, {}) === "unverified_authority", "no effect_digest -> unverified");
  assert(
    authorityEffectLabel(auth, { effect_digest: jsonDigest(TARGET_STATE) }) === "authorized_match",
    "matching effect_digest -> authorized_match",
  );
  const other = { ...TARGET_STATE, refund_cents: 7500 };
  assert(
    authorityEffectLabel(auth, { effect_digest: jsonDigest(other) }) === "authorized_mismatch",
    "differing effect_digest -> authorized_mismatch",
  );
  // record form (as it appears on a decoded wire Event) works identically to the class instance
  assert(
    authorityEffectLabel(auth.toRecord(), { effect_digest: jsonDigest(TARGET_STATE) }) === "authorized_match",
    "record form behaves identically to the class instance",
  );
});

test("reproduces test-vectors.json -> authorization's fixed validity_window and effect_check", async () => {
  // The vector's own _about note: "fixture data for the validity-window
  // boundaries and the match/mismatch/unverified effect labels, so other
  // implementations have fixed numbers to test against without needing their
  // own seed." Cross-checking against these SAME numbers (not just our own
  // freely-chosen nbf/exp) is what actually proves TS and Python agree on
  // [TAP-AUTHORITY-VALIDITY] and [TAP-AUTHORITY-EFFECT], not merely that each
  // independently satisfies its own logic.
  const av = vectors.authorization;
  const auth = Authorization.fromRecord(av.signed_event.authorization);
  const vw = av.validity_window;

  checkAuthorityWindow(auth, vw.accepted_now); // must not throw

  for (const badNow of [vw.rejected_now_not_yet_valid, vw.rejected_now_expired]) {
    let threw = false;
    try {
      checkAuthorityWindow(auth, badNow);
    } catch (e) {
      threw = e instanceof AuthorityExpired;
    }
    assert(threw, `vector's rejected_now=${badNow} must raise AuthorityExpired`);
  }

  const ec = av.effect_check;
  assert(
    authorityEffectLabel(auth, { effect_digest: ec.authorized_match_effect_digest }) === "authorized_match",
    "the vector's authorized_match_effect_digest must label authorized_match",
  );
  assert(
    authorityEffectLabel(auth, { effect_digest: ec.authorized_mismatch_effect_digest }) === "authorized_mismatch",
    "the vector's authorized_mismatch_effect_digest must label authorized_mismatch",
  );
  assert(
    authorityEffectLabel(auth, {}) === "unverified_authority",
    "an absent effect_digest must label unverified_authority",
  );
});

test("traceTool binds authorization and stamps effect_digest", async () => {
  const captured: Record<string, unknown>[] = [];
  const tap = new TAPClient({
    agentId: "bot",
    privateKeyHex: "44".repeat(32),
    kid: "key_test",
    post: async (_url, payload: any) => {
      captured.push(...(payload.events ?? []));
    },
  });
  await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  const auth = tap.authorize({ targetState: TARGET_STATE, authorityState: AUTHORITY_STATE, ttlS: 3600 });

  await tap.traceTool(
    { tool: "issue_refund", scope: "call:tool", authorize: auth, effectOf: () => TARGET_STATE },
    async () => TARGET_STATE,
  );
  await tap.flush();

  const ev = captured[0] as any;
  assert(ev.authorization.authz_id === auth.authzId, "event carries the bound authz_id");
  assert(ev.result.effect_digest === jsonDigest(TARGET_STATE), "event carries the stamped effect_digest");
  assert(
    authorityEffectLabel(ev.authorization, ev.result) === "authorized_match",
    "the stamped Event labels as authorized_match",
  );
});

test("traceTool blocks before acting on an expired authorization", async () => {
  // Same inline-enforcement shape as a policy denial: the wrapped fn never
  // runs, and a signed `denied` event with DENIED_AUTHORITY_EXPIRED is still emitted.
  const captured: Record<string, unknown>[] = [];
  const tap = new TAPClient({
    agentId: "bot",
    privateKeyHex: "44".repeat(32),
    kid: "key_test",
    post: async (_url, payload: any) => {
      captured.push(...(payload.events ?? []));
    },
  });
  await tap.issuePassport({ taskPrompt: "t", scope: ["call:tool"] });
  const now = Math.floor(Date.now() / 1000);
  const expired = tap.authorize({
    targetState: TARGET_STATE,
    authorityState: AUTHORITY_STATE,
    ttlS: 1,
    issuerKid: "key_test",
  });
  // force well outside the skew window (Authorization fields are readonly by
  // design — reconstruct rather than mutate, matching the intent of the guard)
  const forcedExpired = Authorization.fromRecord({ ...expired.toRecord(), exp: now - 3600 });

  let ran = false;
  let threw = false;
  try {
    await tap.traceTool(
      { tool: "issue_refund", scope: "call:tool", authorize: forcedExpired },
      async () => {
        ran = true;
        return TARGET_STATE;
      },
    );
  } catch (e) {
    threw = e instanceof AuthorityExpired;
  }

  await tap.flush();
  assert(threw, "expected AuthorityExpired to propagate");
  assert(!ran, "the wrapped function must not run");
  assert((captured[0] as any).action.kind === "denied", "a denied event is emitted");
  assert((captured[0] as any).result.code === "DENIED_AUTHORITY_EXPIRED", "denied with the correct code");
  assert(
    (captured[0] as any).authorization.authz_id === forcedExpired.authzId,
    "the denied event still carries the authz_id",
  );
});

test("checkAuthorityNotRevoked enforces the effective-time boundary", async () => {
  checkAuthorityNotRevoked("auz_x", "sha256:v", null, 1500); // nothing revoked: must not throw
  checkAuthorityNotRevoked("auz_x", "sha256:v", 2000, 1999); // before boundary: must not throw
  for (const badTs of [2000, 2001]) {
    let threw = false;
    try {
      checkAuthorityNotRevoked("auz_x", "sha256:v", 2000, badTs);
    } catch (e) {
      threw = e instanceof AuthorityRevoked;
      if (threw) {
        const err = e as AuthorityRevoked;
        assert(err.revokedId === "auz_x" && err.revokedAt === 2000 && err.signedTs === badTs, "error fields carried");
      }
    }
    assert(threw, `expected AuthorityRevoked at signedTs=${badTs}`);
  }
});

const REVOKE_SEED = "88".repeat(32);
const REVOKE_KID = "key_revoke_ts_test";

async function signedAuthorizedEvent(args: { authzId: string; eventId: string; seq: number; actionRef: string }) {
  const jwk = await publicJwk(REVOKE_SEED, REVOKE_KID);
  const passportClaims = {
    iss: "https://verifier.example.com", iat: 1000, exp: 2000,
    jti: newId("psp"), aid: "agt_revoke_ts_test",
    cid: "sha256:" + "0".repeat(64), scope: ["call:tool"], meta: {},
  };
  const passportJwt = await signPassport(REVOKE_SEED, REVOKE_KID, passportClaims);
  const auth = Authorization.grant({
    targetState: TARGET_STATE, authorityState: AUTHORITY_STATE,
    nbf: 1000, exp: 999999999, issuerKid: REVOKE_KID, authzId: args.authzId,
  });
  const body = {
    v: "tap/0.1", event_id: args.eventId, passport_jti: passportClaims.jti,
    aid: passportClaims.aid, cid: passportClaims.cid, seq: args.seq,
    ts: new Date().toISOString(),
    action: { kind: "tool_call", intent_digest: textDigest("t"), tool: "issue_refund", scope_used: "call:tool" },
    authorization: auth.toRecord(),
    result: { status: "success", code: "OK", error: null },
    attestor: "agent", action_ref: args.actionRef, kid: REVOKE_KID,
  };
  const event = await signEvent(REVOKE_SEED, body);
  return { event, passportJwt, jwk };
}

test("evaluateEvent surfaces revocation via a supplied resolver", async () => {
  const { event, jwk } = await signedAuthorizedEvent(
    { authzId: "auz_revoke_1", eventId: "evt_revoke_1", seq: 1, actionRef: "act_revoke_1" });

  // No resolver supplied: the revocation signal stays false, not an error.
  let res = await evaluateEvent(event, { resolveKey: async () => jwk, passportClaims: null, lastSeq: null });
  assert(res.sig_valid && res.authority_revoked === false, "no resolver -> not revoked");

  // A resolver that knows about this authz_id, revoked in the past: flagged.
  res = await evaluateEvent(event, {
    resolveKey: async () => jwk, passportClaims: null, lastSeq: null,
    resolveAuthorityRevocation: async (authzId) => (authzId === "auz_revoke_1" ? 1 : null),
  });
  assert(res.authority_revoked === true, "resolver flags revocation");
  assert(res.sig_valid === true, "revocation must not flip sig_valid");

  // A resolver that has never heard of this id: not flagged.
  res = await evaluateEvent(event, {
    resolveKey: async () => jwk, passportClaims: null, lastSeq: null,
    resolveAuthorityRevocation: async () => null,
  });
  assert(res.authority_revoked === false, "unknown to the resolver -> not revoked");
});

test("verifyTranscript detects batch-local authz_id reuse", async () => {
  const { event: ev1, passportJwt, jwk } = await signedAuthorizedEvent(
    { authzId: "auz_reused", eventId: "evt_reuse_1", seq: 1, actionRef: "act_reuse_1" });
  const { event: ev2 } = await signedAuthorizedEvent(
    { authzId: "auz_reused", eventId: "evt_reuse_2", seq: 2, actionRef: "act_reuse_2" });

  let report = await verifyTranscript(passportJwt, [ev1, ev2], { resolveKey: async () => jwk });
  assert(report.authority_reuse.length === 1, "one reuse detected");
  const reuse = report.authority_reuse[0] as any;
  assert(reuse.authz_id === "auz_reused");
  assert(
    new Set([reuse.first_event_id, reuse.reused_event_id]).size === 2 &&
      [reuse.first_event_id, reuse.reused_event_id].includes("evt_reuse_1") &&
      [reuse.first_event_id, reuse.reused_event_id].includes("evt_reuse_2"),
    "both event ids named",
  );

  report = await verifyTranscript(passportJwt, [ev1], { resolveKey: async () => jwk });
  assert(report.authority_reuse.length === 0, "a single event carrying the id is not reuse");
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
  console.log("# authority binding matches tap_ref.py / Python SDK (provisional, §9.2) ✓");
}

main();
