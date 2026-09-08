// MCP client-side wrapper [spec §11.2], mirroring
// sdk/python/src/tap_sdk/signer.py's TAPClient.instrument_mcp — the only MCP
// surface this SDK ships. No @modelcontextprotocol/sdk dependency, no server,
// no key custody beyond the caller's own TAPClient.
//
//   npx tsx test/instrumentMcp.test.ts

import { instrumentMcp, type McpToolCaller } from "../src/instrumentMcp.js";
import { TAPClient } from "../src/client.js";
import { publicJwk, verifyEvent } from "../src/tap.js";

const SEED = "77".repeat(32);
const KID = "key_mcp_ts_test";

let n = 0;
const tests: [string, () => Promise<void>][] = [];
const test = (name: string, fn: () => Promise<void>) => tests.push([name, fn]);
const assert = (cond: unknown, msg: string) => {
  if (!cond) throw new Error(msg);
};

function client(): { tap: TAPClient; captured: Record<string, unknown>[] } {
  const captured: Record<string, unknown>[] = [];
  const tap = new TAPClient({
    agentId: "mcp-ts-test",
    privateKeyHex: SEED,
    kid: KID,
    post: async (_url, payload: any) => {
      captured.push(...(payload.events ?? []));
    },
  });
  return { tap, captured };
}

test("wraps callTool and emits a signed tool_call event, no MCP SDK involved", async () => {
  const { tap, captured } = client();
  await tap.issuePassport({ taskPrompt: "t", scope: ["call:db_query"] });

  let calledWith: [string, Record<string, unknown> | undefined] | null = null;
  const mcpClient: McpToolCaller = {
    async callTool(name, args) {
      calledWith = [name, args];
      return { rows: 3 };
    },
  };

  const wrapped = instrumentMcp(tap, mcpClient);
  assert(wrapped === mcpClient, "instrumentMcp returns the same client instance");

  const result = await wrapped.callTool("db_query", { table: "users" });
  assert((result as any).rows === 3, "the original call_tool's return value passes through");
  assert(calledWith !== null && calledWith[0] === "db_query", "original call_tool was invoked");

  await tap.flush();
  assert(captured.length === 1, "exactly one event was emitted");
  const ev = captured[0] as any;
  assert(ev.action.kind === "tool_call", "emits a tool_call event");
  assert(ev.action.tool === "db_query", "tool name carried");
  assert(ev.action.scope_used === "call:db_query", "scope derived as call:<name>");
  assert(ev.result.status === "success" && ev.result.code === "OK", "success recorded");
  assert(typeof ev.result.latency_ms === "number", "latency recorded");

  const jwk = await publicJwk(SEED, KID);
  assert(await verifyEvent(jwk, ev), "the emitted event verifies");
});

test("a thrown tool error is still signed and re-thrown", async () => {
  const { tap, captured } = client();
  await tap.issuePassport({ taskPrompt: "t", scope: ["call:flaky"] });

  const mcpClient: McpToolCaller = {
    async callTool() {
      throw new Error("boom");
    },
  };
  const wrapped = instrumentMcp(tap, mcpClient);

  let threw = false;
  try {
    await wrapped.callTool("flaky", {});
  } catch (e) {
    threw = (e as Error).message === "boom";
  }
  assert(threw, "the original error propagates");

  await tap.flush();
  const ev = captured[0] as any;
  assert(ev.result.status === "failure" && ev.result.code === "TOOL_ERROR", "failure recorded");
  assert(ev.result.error === "boom", "error message captured");
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
  console.log("# MCP client-side wrapper: signs, correlates, and re-throws faithfully ✓");
}

main();
