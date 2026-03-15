// Live cross-language interop: the JS TAPClient client signs a FRESH passport +
// decision event (not a fixed vector), and emits JSON for the Python SDK to
// verify. Run:  npx tsx test/interop.ts > /tmp/js_event.json
//
// (Uses the public reference seed so both sides share the keypair.)

import { TAPClient } from "../src/client.js";
import { publicJwk, verifyEvent, verifyPassport } from "../src/tap.js";

const SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const KID = "key_2026_ref01";

async function main() {
  const captured: Record<string, unknown>[] = [];
  const client = new TAPClient({
    agentId: "js-agent",
    privateKeyHex: SEED,
    kid: KID,
    capturePreviews: true,
    post: async (_url, payload) => {
      captured.push(...(payload as { events: Record<string, unknown>[] }).events);
    },
  });

  const passport = await client.issuePassport({
    taskPrompt: "refund ticket #8842",
    scope: ["read:database"],
  });
  await client.decision({
    question: "How to resolve refund?",
    chosen: "refund",
    selection: "argmax",
    options: [
      { id: "refund", summary: "Refund", score: 0.71, reason: "in policy" },
      { id: "deny", summary: "Deny", score: 0.1, reason: "violates policy v3" },
    ],
  });
  await client.flush();

  const jwk = await publicJwk(SEED, KID);
  // Self-verify in JS first, then hand off to Python.
  await verifyPassport(jwk, passport.compact);
  await verifyEvent(jwk, captured[0]);

  process.stdout.write(
    JSON.stringify({ jwk, passport: passport.compact, event: captured[0] }),
  );
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
