/**
 * TAP-aware server middleware — server-attested provenance ([TAP-EVT-ENVELOPE]).
 * Verifies inbound passports, enforces scope/policy before execute, signs execution legs.
 */
import canonicalize from "canonicalize";

import {
  b64uToBytes,
  digest,
  newId,
  scopeSatisfied,
  signEvent,
  SPEC_VERSION,
  verifyPassport,
  type Jwk,
} from "./tap.js";

function nowTs(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export type KeyResolver = (kid: string) => Jwk | null | undefined;

export interface PolicyRule {
  id: string;
  effect: "allow" | "deny";
  when: { tool?: string };
}

export interface Policy {
  default: "allow" | "deny";
  rules: PolicyRule[];
}

export interface PolicyDecision {
  decision: "allow" | "deny";
  rule_id: string | null;
  policy_version: string;
}

export class UnattestedAction extends Error {
  constructor(message = "missing or invalid passport") {
    super(message);
    this.name = "UnattestedAction";
  }
}

export class ServerDenied extends Error {
  readonly code: string;
  readonly event: Record<string, unknown>;

  constructor(message: string, args: { code: string; event: Record<string, unknown> }) {
    super(message);
    this.name = "ServerDenied";
    this.code = args.code;
    this.event = args.event;
  }
}

function policyVersion(policy: Policy): string {
  const canon = canonicalize(policy);
  if (canon === undefined) throw new Error("policy canonicalization failed");
  return digest(canon);
}

function evaluatePolicy(policy: Policy, tool: string): PolicyDecision {
  const version = policyVersion(policy);
  for (const rule of policy.rules) {
    if (rule.when.tool !== undefined && rule.when.tool === tool) {
      return { decision: rule.effect, rule_id: rule.id, policy_version: version };
    }
  }
  return { decision: policy.default, rule_id: null, policy_version: version };
}

function resultDigest(value: unknown): string | null {
  if (value === undefined || value === null) return null;
  try {
    return digest(JSON.stringify(value));
  } catch {
    return digest(String(value));
  }
}

function peekKid(compactJwt: string): string | null {
  try {
    const h = compactJwt.split(".")[0];
    if (!h) return null;
    const header = JSON.parse(new TextDecoder().decode(b64uToBytes(h))) as { kid?: string };
    return header.kid ?? null;
  } catch {
    return null;
  }
}

export type PostFn = (url: string, payload: unknown, headers: Record<string, string>) => Promise<void>;

export interface TAPServerOptions {
  serverId: string;
  privateKeyHex: string;
  kid: string;
  resolveKey: KeyResolver;
  issuer?: string;
  policy?: Policy;
  enforce?: boolean;
  endpoint?: string;
  apiKey?: string;
  post?: PostFn;
  clockSkewS?: number;
}

export class TAPServer {
  private readonly opts: Required<Pick<TAPServerOptions, "issuer" | "enforce" | "clockSkewS">> &
    TAPServerOptions;
  private readonly seq = new Map<string, number>();
  private readonly seen = new Set<string>();
  private readonly buffer: Record<string, unknown>[] = [];

  constructor(opts: TAPServerOptions) {
    this.opts = {
      issuer: "https://verifier.example.com",
      enforce: true,
      clockSkewS: 60,
      ...opts,
    };
  }

  private nextSeq(aid: string): number {
    const n = (this.seq.get(aid) ?? 0) + 1;
    this.seq.set(aid, n);
    return n;
  }

  private async submit(event: Record<string, unknown>): Promise<void> {
    this.buffer.push(event);
  }

  private async emit(args: {
    claims: Record<string, unknown>;
    kind: string;
    intent: string;
    tool: string;
    scopeUsed: string | null;
    actionRef: string;
    args?: unknown;
    status: string;
    code: string;
    latencyMs?: number | null;
    error?: string | null;
    policyDecision?: PolicyDecision | null;
    resultDigest?: string | null;
  }): Promise<Record<string, unknown>> {
    const action: Record<string, unknown> = {
      kind: args.kind,
      intent: args.intent,
      tool: args.tool,
      scope_used: args.scopeUsed,
    };
    if (args.args !== undefined) {
      action.args_digest = digest(JSON.stringify(args.args));
    }
    const result: Record<string, unknown> = {
      status: args.status,
      code: args.code,
      latency_ms: args.latencyMs ?? null,
      error: args.error ?? null,
    };
    if (args.resultDigest) result.result_digest = args.resultDigest;
    const body: Record<string, unknown> = {
      v: SPEC_VERSION,
      event_id: newId("evt"),
      passport_jti: args.claims.jti,
      aid: args.claims.aid,
      cid: args.claims.cid,
      seq: this.nextSeq(String(args.claims.aid)),
      ts: nowTs(),
      action,
      evidence: { reasoning: null, model_output_digest: null },
      result,
      attestor: "server",
      action_ref: args.actionRef,
      parent_event_id: null,
      policy_decision: args.policyDecision
        ? {
            decision: args.policyDecision.decision,
            rule_id: args.policyDecision.rule_id,
            policy_version: args.policyDecision.policy_version,
          }
        : null,
      kid: this.opts.kid,
    };
    const event = await signEvent(this.opts.privateKeyHex, body);
    await this.submit(event);
    return event;
  }

  private async verifyPassportJwt(passportJwt: string | null | undefined): Promise<Record<string, unknown>> {
    if (!passportJwt) throw new UnattestedAction();
    const kid = peekKid(passportJwt);
    if (!kid) throw new UnattestedAction("passport header unreadable");
    const jwk = this.opts.resolveKey(kid);
    if (!jwk) throw new UnattestedAction(`unknown passport kid ${kid}`);
    const now = Math.floor(Date.now() / 1000);
    return verifyPassport(jwk, passportJwt, now);
  }

  /** Verify → enforce → execute → sign the server-attested execution leg. */
  async attest<T>(args: {
    tool: string;
    passportJwt: string | null | undefined;
    actionRef: string;
    execute: () => T | Promise<T>;
    scopeUsed?: string | null;
    arguments?: unknown;
    intent?: string;
  }): Promise<T> {
    const claims = await this.verifyPassportJwt(args.passportJwt);
    const scopeUsed = args.scopeUsed ?? `call:${args.tool}`;
    const intent = args.intent ?? `Execute ${args.tool}`;
    const aid = String(claims.aid);
    const replayKey = `${aid}:${args.actionRef}`;
    if (this.seen.has(replayKey)) {
      const event = await this.emit({
        claims,
        kind: "denied",
        intent,
        tool: args.tool,
        scopeUsed,
        actionRef: args.actionRef,
        args: args.arguments,
        status: "denied",
        code: "VALIDATION_ERROR",
        error: "duplicate action_ref (replay)",
      });
      throw new ServerDenied(`replayed action_ref ${args.actionRef}`, {
        code: "VALIDATION_ERROR",
        event,
      });
    }
    this.seen.add(replayKey);

    const passportScope = (claims.scope as string[]) ?? [];
    if (this.opts.enforce && !scopeSatisfied(scopeUsed, passportScope)) {
      const event = await this.emit({
        claims,
        kind: "denied",
        intent,
        tool: args.tool,
        scopeUsed,
        actionRef: args.actionRef,
        args: args.arguments,
        status: "denied",
        code: "DENIED_SCOPE",
        error: "scope not in passport",
      });
      throw new ServerDenied(`scope ${scopeUsed} not in passport`, { code: "DENIED_SCOPE", event });
    }

    let policyDecision: PolicyDecision | null = null;
    if (this.opts.policy) {
      policyDecision = evaluatePolicy(this.opts.policy, args.tool);
      if (policyDecision.decision === "deny" && this.opts.enforce) {
        const event = await this.emit({
          claims,
          kind: "denied",
          intent,
          tool: args.tool,
          scopeUsed,
          actionRef: args.actionRef,
          args: args.arguments,
          status: "denied",
          code: "DENIED_POLICY",
          policyDecision,
        });
        throw new ServerDenied(`policy denied ${args.tool}`, { code: "DENIED_POLICY", event });
      }
    }

    const t0 = Date.now();
    let status = "success";
    let code = "OK";
    let error: string | null = null;
    let result: T | undefined;
    try {
      result = await args.execute();
      return result;
    } catch (exc) {
      status = "failure";
      code = "TOOL_ERROR";
      error = exc instanceof Error ? exc.message : String(exc);
      throw exc;
    } finally {
      await this.emit({
        claims,
        kind: "tool_call",
        intent,
        tool: args.tool,
        scopeUsed,
        actionRef: args.actionRef,
        args: args.arguments,
        status,
        code,
        error,
        latencyMs: Date.now() - t0,
        policyDecision,
        resultDigest: status === "success" ? resultDigest(result) : null,
      });
    }
  }

  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    const events = this.buffer.splice(0, this.buffer.length);
    const payload = { events };
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.opts.apiKey) headers["X-API-Key"] = this.opts.apiKey;
    const url = (this.opts.endpoint ?? "http://localhost:8000").replace(/\/$/, "") + "/v1/events";
    if (this.opts.post) {
      await this.opts.post(url, payload, headers);
      return;
    }
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload) });
    if (!res.ok) {
      this.buffer.unshift(...events);
      throw new Error(`verifier ${res.status}`);
    }
  }
}

/** Fetch JWKS from the Verifier and build a kid → JWK resolver. */
export async function jwksResolver(
  endpoint: string,
  apiKey?: string,
): Promise<KeyResolver> {
  const headers: Record<string, string> = {};
  if (apiKey) headers["X-API-Key"] = apiKey;
  const res = await fetch(`${endpoint.replace(/\/$/, "")}/.well-known/jwks.json`, { headers });
  if (!res.ok) throw new Error(`jwks fetch ${res.status}`);
  const body = (await res.json()) as { keys: Jwk[] };
  const map = new Map(body.keys.map((k) => [k.kid, k]));
  return (kid) => map.get(kid) ?? null;
}
