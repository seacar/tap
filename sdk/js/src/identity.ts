/**
 * Local agent identity storage and Verifier registration (Node.js).
 * Browser runtimes must inject TAP_PRIVATE_KEY + TAP_KID or pass identityDir
 * to a Node-compatible storage backend.
 */
import { createHash } from "node:crypto";
import { chmod, mkdir, readFile, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import path from "node:path";

import { generateSigner, newId, publicJwk, type Jwk } from "./tap.js";

export interface AgentIdentity {
  agentId: string;
  kid: string;
  seedHex: string;
}

const cache = new Map<string, AgentIdentity>();

export function defaultIdentityDir(): string {
  return process.env.TAP_IDENTITY_DIR?.trim() || path.join(homedir(), ".tap", "identities");
}

function namespace(apiKey: string | undefined, endpoint: string): string {
  return createHash("sha256").update(`${endpoint}\0${apiKey ?? ""}`).digest("hex").slice(0, 16);
}

function identityFile(identityDir: string, ns: string, agentId: string): string {
  const safe = agentId.replace(/\//g, "_").replace(/\\/g, "_");
  return path.join(identityDir, ns, `${safe}.json`);
}

function fromEnv(agentId: string): AgentIdentity | null {
  const envAgent = process.env.TAP_AGENT_ID ?? process.env.TAP_AGENT_ID;
  const seed = process.env.TAP_PRIVATE_KEY ?? process.env.TAP_PRIVATE_KEY_HEX;
  const kid = process.env.TAP_KID;
  if (!seed || !kid) return null;
  if (envAgent && envAgent !== agentId) return null;
  return { agentId, kid, seedHex: seed.replace(/^0x/, "") };
}

async function loadFile(filePath: string): Promise<AgentIdentity | null> {
  try {
    const data = JSON.parse(await readFile(filePath, "utf8")) as {
      agent_id: string;
      kid: string;
      seed_hex: string;
    };
    return { agentId: data.agent_id, kid: data.kid, seedHex: data.seed_hex };
  } catch {
    return null;
  }
}

async function saveFile(filePath: string, identity: AgentIdentity): Promise<void> {
  await mkdir(path.dirname(filePath), { recursive: true });
  await writeFile(
    filePath,
    `${JSON.stringify(
      { agent_id: identity.agentId, kid: identity.kid, seed_hex: identity.seedHex },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );
  try {
    await chmod(filePath, 0o600);
  } catch {
    /* windows */
  }
}

export type RegisterFn = (args: {
  endpoint: string;
  apiKey?: string;
  agentId: string;
  publicJwk: Jwk;
}) => Promise<string>;

export async function registerWithVerifier(args: {
  endpoint: string;
  apiKey?: string;
  agentId: string;
  publicJwk: Jwk;
  registerFn?: RegisterFn;
}): Promise<string> {
  if (args.registerFn) {
    return args.registerFn({
      endpoint: args.endpoint,
      apiKey: args.apiKey,
      agentId: args.agentId,
      publicJwk: args.publicJwk,
    });
  }
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (args.apiKey) headers["X-API-Key"] = args.apiKey;
  const res = await fetch(`${args.endpoint.replace(/\/$/, "")}/v1/agents/register`, {
    method: "POST",
    headers,
    body: JSON.stringify({ agent_id: args.agentId, public_jwk: args.publicJwk }),
  });
  if (!res.ok) throw new Error(`agent registration failed: ${res.status}`);
  const body = (await res.json()) as { kid: string };
  return body.kid;
}

export async function ensureAgentIdentity(args: {
  agentId: string;
  apiKey?: string;
  endpoint: string;
  identityDir?: string;
  register?: boolean;
  registerFn?: RegisterFn;
}): Promise<AgentIdentity> {
  const idDir = args.identityDir ?? defaultIdentityDir();
  const ns = namespace(args.apiKey, args.endpoint);
  const ck = `${ns}:${args.agentId}`;

  const cached = cache.get(ck);
  if (cached) return cached;

  const fromEnvIdentity = fromEnv(args.agentId);
  if (fromEnvIdentity) {
    let identity = fromEnvIdentity;
    if (args.register !== false) {
      const jwk = await publicJwk(identity.seedHex, identity.kid);
      const kid = await registerWithVerifier({
        endpoint: args.endpoint,
        apiKey: args.apiKey,
        agentId: args.agentId,
        publicJwk: jwk,
        registerFn: args.registerFn,
      });
      identity = { ...identity, kid };
    }
    cache.set(ck, identity);
    return identity;
  }

  const filePath = identityFile(idDir, ns, args.agentId);
  const existing = await loadFile(filePath);
  if (existing) {
    if (args.register !== false) {
      const jwk = await publicJwk(existing.seedHex, existing.kid);
      existing.kid = await registerWithVerifier({
        endpoint: args.endpoint,
        apiKey: args.apiKey,
        agentId: args.agentId,
        publicJwk: jwk,
        registerFn: args.registerFn,
      });
    }
    cache.set(ck, existing);
    return existing;
  }

  const { seedHex } = await generateSigner();
  let kid = newId("key");
  if (args.register !== false) {
    const jwk = await publicJwk(seedHex, kid);
    kid = await registerWithVerifier({
      endpoint: args.endpoint,
      apiKey: args.apiKey,
      agentId: args.agentId,
      publicJwk: jwk,
      registerFn: args.registerFn,
    });
  }
  const identity: AgentIdentity = { agentId: args.agentId, kid, seedHex };
  await saveFile(filePath, identity);
  cache.set(ck, identity);
  return identity;
}

/** Clear in-memory cache (tests). */
export function clearIdentityCache(): void {
  cache.clear();
}
