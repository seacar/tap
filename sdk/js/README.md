# @traceableagent/sdk — Traceable Agent Protocol for TypeScript

Sign every action your agent takes, so anyone can verify what it did without trusting you.

Part of the [TAP monorepo](../../). See the [specification](../../TAP-spec-v0.1.md) for the wire contract.

```bash
npm install @traceableagent/sdk
```

Two entry points, so you only pull in the side you need:

```ts
import { TAPClient } from "@traceableagent/sdk/agent";   // signing agent
import { TAPServer } from "@traceableagent/sdk/server";  // attesting tool operator
```

## Sign an agent

```ts
const tap = new TAPClient({
  agentId: "support-triage",
  privateKeyHex: SEED,
  kid: "key_2026_01",
  endpoint: "https://your-verifier.example.com",
  apiKey: process.env.TAP_API_KEY,
});

const passport = await tap.issuePassport({
  taskPrompt: "Resolve support ticket #8842",
  scope: ["read:database", "call:tool"],
});

const rows = await tap.traceTool(
  { tool: "db_query", scope: "read:database" },
  () => runQuery("users", 50),          // your existing code, unchanged
);

await tap.flush();
```

Reporting is **asynchronous and fail-open** — your agent never blocks on the Verifier being reachable. Signed checkpoints make that safe: a verifier can distinguish a dropped batch from a deleted event.

## Record a decision, including the roads not taken

```ts
await tap.decision({
  question: "How should I resolve refund ticket #8842?",
  options: [
    { id: "refund",   score: "0.71", rationale: "Within policy; SLA breached" },
    { id: "escalate", score: "0.52", reason: "Higher cost; not required" },
    { id: "deny",     score: "0.10", reason: "Would violate refund policy v3" },
  ],
  chosen: "refund",
});
```

The full option set is inside the signature, so the agent can't later claim it weighed a different one. **Scores must be strings** — fractional numbers are forbidden in a signed body (spec §3.4), because float canonicalization is the most common cause of cross-language signature divergence.

## Attest the server side

```ts
const server = new TAPServer({
  privateKeyHex: SERVER_SEED,
  kid: "key_tool_01",
  endpoint: "https://your-verifier.example.com",
  resolveKey: (kid) => jwks[kid],
});

const result = await server.attest({
  passport: req.headers["x-agent-passport"],
  actionRef: req.headers["x-tap-action-ref"],
  tool: "db_query",
  scopeUsed: "read:database",
  handler: () => runQuery(req.body),
});
```

The agent attests *intent*; the server attests *execution* with its own independent key. A compromised agent can lie about what it meant to do — it cannot forge the server's signature over what actually happened. For upstreams that don't speak TAP, put the [Gateway](../../gateway) in front instead.

## Carriage

The same signed bytes verify identically across transports.

```ts
// HTTP — alongside your existing Authorization header, not instead of it
await fetch(url, { headers: { ...passport.httpHeaders(actionRef), ...auth } });

// JSON-RPC (stdio MCP, A2A tasks) — TAP metadata rides in _meta
{ _meta: { tap: { passport: passport.compact, action_ref: actionRef } } }
```

TAP adds provenance. It does not replace access control.

## Runtime

ESM, Node 20+. Crypto via `@noble/ed25519` and `@noble/hashes`; canonicalization via `canonicalize` (RFC 8785). No other runtime dependencies — implementers audit this code, so dependency-light is deliberate.

## Conformance

```bash
npm test        # reproduces the reference vectors + unit tests
npm run build   # type check and emit
```

This SDK reproduces [`test-vectors.json`](../../test-vectors.json) byte-for-byte, as does the [Python SDK](../python) — from the same fixed seed, to the same signature. That cross-language agreement is the contract the whole protocol rests on.

Apache-2.0.
