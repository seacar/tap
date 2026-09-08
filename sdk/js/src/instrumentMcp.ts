// MCP: instrument an existing client (spec §11.2), mirroring
// sdk/python/src/tap_sdk/signer.py's TAPClient.instrument_mcp.
//
// This is deliberately NOT an MCP server, has no @modelcontextprotocol/sdk
// dependency, and never custodies a key beyond the caller's own TAPClient. It
// duck-types the common `callTool(name, arguments)` shape and wraps it so
// every call attaches the passport and emits a signed tool_call event — the
// same signing path as traceTool(), not a second implementation. A hosted MCP
// server exposing TAP operations as callable tools is explicitly out of scope
// for this SDK; see docs/architecture.md.

import { newId } from "./tap.js";
import type { Passport, TAPClient } from "./client.js";

/** The minimal shape this wrapper needs from an MCP client. Real MCP clients
 * vary — pin the exact method on your client if it differs from this. */
export interface McpToolCaller {
  callTool(name: string, args?: Record<string, unknown>, ...rest: unknown[]): Promise<unknown>;
}

/**
 * Wrap an MCP client's `callTool` so every `tools/call` emits a signed
 * `tool_call` event via `tap`, correlated by a fresh `action_ref`.
 */
export function instrumentMcp<T extends McpToolCaller>(
  tap: TAPClient,
  mcpClient: T,
  opts?: { passport?: Passport },
): T {
  const original = mcpClient.callTool.bind(mcpClient);

  mcpClient.callTool = (async (
    name: string,
    args?: Record<string, unknown>,
    ...rest: unknown[]
  ) => {
    const actionRef = newId("act");
    const t0 = Date.now();
    let status = "success", code = "OK", error: string | null = null;
    try {
      return await original(name, args, ...rest);
    } catch (e) {
      status = "failure"; code = "TOOL_ERROR"; error = (e as Error).message;
      throw e;
    } finally {
      await tap.signToolCall({
        tool: name,
        scope: `call:${name}`,
        intent: `Call MCP tool ${name}`,
        argsValue: args ?? {},
        status, code, error,
        actionRef,
        passport: opts?.passport,
        latencyMs: Date.now() - t0,
      });
    }
  }) as T["callTool"];

  return mcpClient;
}
