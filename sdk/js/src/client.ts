// The TAPClient signer SDK (TypeScript). Mints passports and signs provenance
// events + the counterfactual decision ledger (TAP-spec §5.7).

import {
  checkpointRoot,
  cidFromPrompt,
  digest,
  jsonDigest,
  newId,
  SPEC_VERSION,
  signEvent,
  signPassport,
  textDigest,
} from "./tap.js";

export interface TapCarriage {
  passport: string;
  actionRef: string;
  headers: Record<string, string>;
}

/** Passport carriage for HTTP transport (TAP-spec §10.1). */
export function passportHttpHeaders(passport: Passport, actionRef?: string): Record<string, string> {
  const headers: Record<string, string> = { "X-Agent-Passport": passport.compact };
  if (actionRef) headers["X-TAP-Action-Ref"] = actionRef;
  return headers;
}

/** Passport carriage for JSON-RPC ``_meta`` transport (TAP-spec §10.2). */
export function passportMeta(passport: Passport, actionRef?: string): Record<string, unknown> {
  const tap: Record<string, unknown> = { passport: passport.compact };
  if (actionRef) tap.action_ref = actionRef;
  return { tap };
}
function nowTs(): string {
  return new Date().toISOString().replace(/(\.\d{3})\d*Z$/, "$1Z");
}

export interface DecisionOption {
  id: string;
  /** Human-readable label for display (stored in annex only — not signed). */
  summary?: string;
  /** Score MUST be a string per TAP-spec §3.4 (no fractional numbers in signed bodies). */
  score?: string;
  reason?: string;
  rationale?: string;
}

export interface TAPClientOptions {
  agentId: string;
  privateKeyHex: string;
  kid: string;
  endpoint?: string;
  issuer?: string;
  apiKey?: string;
  framework?: string;
  model?: string;
  capturePreviews?: boolean;
  /** Override the HTTP sender (tests / custom transport). */
  post?: (url: string, payload: unknown, headers: Record<string, string>) => Promise<void>;
}

export interface Passport {
  compact: string;
  claims: Record<string, unknown>;
}

export class TAPClient {
  private opts: Required<Pick<TAPClientOptions, "endpoint" | "issuer">> & TAPClientOptions;
  private passport: Passport | null = null;
  private seq = 0;
  /** Each buffered item pairs the signed event with its optional plaintext annex (§6.1.1). */
  private buffer: { event: Record<string, unknown>; annex: Record<string, unknown> | null }[] = [];

  constructor(opts: TAPClientOptions) {
    this.opts = {
      endpoint: "http://localhost:8000",
      issuer: "https://verifier.example.com",
      ...opts,
    };
  }

  get agentId(): string {
    return this.opts.agentId;
  }

  async issuePassport(args: { taskPrompt: string; scope: string[]; ttlS?: number }): Promise<Passport> {
    const now = Math.floor(Date.now() / 1000);
    const meta: Record<string, string> = {};
    if (this.opts.framework) meta.framework = this.opts.framework;
    if (this.opts.model) meta.model = this.opts.model;
    meta.agent_name = this.opts.agentId;
    const claims: Record<string, unknown> = {
      iss: this.opts.issuer,
      iat: now,
      exp: now + (args.ttlS ?? 3600),
      jti: newId("psp"),
      aid: newId("agt"),
      // nonce ≥128 bits — §3.3: prevents cid collision and confirmation oracle attacks
      cid: cidFromPrompt(args.taskPrompt),
      scope: args.scope,
      meta,
    };
    const compact = await signPassport(this.opts.privateKeyHex, this.opts.kid, claims);
    this.passport = { compact, claims };
    this.seq = 0;
    return this.passport;
  }

  private requirePassport(): Passport {
    if (!this.passport) throw new Error("no passport — call issuePassport() first");
    return this.passport;
  }

  private async emit(args: {
    kind: string;
    intent: string;
    tool: string;
    scopeUsed: string | null;
    argsValue?: unknown;
    reasoning?: string | null;
    status?: string;
    code?: string;
    latencyMs?: number | null;
    error?: string | null;
    decision?: Record<string, unknown>;
    modelOutput?: string | null;
    passport?: Passport;
    actionRef?: string;
    attestor?: string;
    /** Extra plaintext fields merged into the annex (e.g. decision question/options). */
    extraAnnex?: Record<string, unknown>;
  }): Promise<Record<string, unknown>> {
    const p = args.passport ?? this.requirePassport();
    const eventId = newId("evt");

    // Digest-only action block — no plaintext in the signed body (TAP-spec §6.1)
    const action: Record<string, unknown> = {
      kind: args.kind,
      intent_digest: textDigest(args.intent),
      tool: args.tool,
      scope_used: args.scopeUsed,
    };

    // Annex: unsigned plaintext companion, keyed by event_id (§6.1.1)
    const annex: Record<string, unknown> = { event_id: eventId, intent: args.intent };

    if (args.argsValue !== undefined) {
      action.args_digest = jsonDigest(args.argsValue);
      annex.args = args.argsValue; // plaintext in annex only — never in signed body
    }

    const evidence: Record<string, unknown> = {};
    if (args.reasoning) {
      evidence.reasoning_digest = textDigest(args.reasoning);
      annex.reasoning = args.reasoning;
    }
    if (args.modelOutput) {
      evidence.model_output_digest = digest(args.modelOutput);
    }

    if (args.extraAnnex) {
      Object.assign(annex, args.extraAnnex);
    }

    const body: Record<string, unknown> = {
      v: SPEC_VERSION,
      event_id: eventId,
      passport_jti: p.claims.jti,
      aid: p.claims.aid,
      cid: p.claims.cid,
      seq: ++this.seq,
      ts: nowTs(),
      action,
      evidence: Object.keys(evidence).length > 0 ? evidence : null,
      result: {
        status: args.status ?? "success",
        code: args.code ?? "OK",
        latency_ms: args.latencyMs ?? null,
        error: args.error ?? null,
      },
      attestor: args.attestor ?? "agent",
      action_ref: args.actionRef ?? newId("act"),
      parent_event_id: null,
      policy_decision: null,
      kid: this.opts.kid,
    };
    if (args.decision) body.decision = args.decision;
    const event = await signEvent(this.opts.privateKeyHex, body);
    // Only ship the annex when it has content beyond the event_id marker
    const hasAnnexContent = Object.keys(annex).length > 1;
    this.buffer.push({ event, annex: hasAnnexContent ? annex : null });
    return event;
  }

  /** Wrap an async tool call: sign a tool_call event around it (intent-only). */
  async traceTool<T>(
    spec: { tool: string; scope: string; intent?: string; args?: unknown },
    fn: () => Promise<T>,
  ): Promise<T> {
    const t0 = Date.now();
    let status = "success", code = "OK", error: string | null = null;
    try {
      return await fn();
    } catch (e) {
      status = "failure"; code = "TOOL_ERROR"; error = (e as Error).message;
      throw e;
    } finally {
      await this.emit({
        kind: "tool_call",
        intent: spec.intent ?? `Call ${spec.tool}`,
        tool: spec.tool,
        scopeUsed: spec.scope,
        argsValue: spec.args ?? {},
        status, code, error,
        latencyMs: Date.now() - t0,
      });
    }
  }

  /**
   * Call a TAP-aware remote tool: stamps ``action_ref``, passes passport carriage on
   * the wire, and signs the agent leg correlated with the server's execution leg.
   */
  async traceAttestedTool<T>(
    spec: {
      tool: string;
      scope: string;
      intent?: string;
      args?: unknown;
      passport?: Passport;
      invoke: (carriage: TapCarriage) => Promise<T>;
    },
  ): Promise<{ result: T; actionRef: string }> {
    const p = spec.passport ?? this.requirePassport();
    const actionRef = newId("act");
    const carriage: TapCarriage = {
      passport: p.compact,
      actionRef,
      headers: passportHttpHeaders(p, actionRef),
    };
    const t0 = Date.now();
    let status = "success";
    let code = "OK";
    let error: string | null = null;
    let result: T;
    try {
      result = await spec.invoke(carriage);
      return { result, actionRef };
    } catch (e) {
      status = "failure";
      code = "TOOL_ERROR";
      error = (e as Error).message;
      throw e;
    } finally {
      await this.emit({
        kind: "tool_call",
        intent: spec.intent ?? `Call ${spec.tool}`,
        tool: spec.tool,
        scopeUsed: spec.scope,
        argsValue: spec.args ?? {},
        status,
        code,
        error,
        latencyMs: Date.now() - t0,
        passport: p,
        actionRef,
      });
    }
  }

  /** Sign an agent tool_call leg with an explicit outcome (for integrity demos). */
  async signToolCall(args: {
    tool: string;
    scope: string;
    intent?: string;
    argsValue?: unknown;
    status?: string;
    code?: string;
    error?: string | null;
    actionRef?: string;
    passport?: Passport;
  }): Promise<Record<string, unknown>> {
    return this.emit({
      kind: "tool_call",
      intent: args.intent ?? `Call ${args.tool}`,
      tool: args.tool,
      scopeUsed: args.scope,
      argsValue: args.argsValue ?? {},
      status: args.status ?? "success",
      code: args.code ?? "OK",
      error: args.error ?? null,
      passport: args.passport,
      actionRef: args.actionRef,
    });
  }

  /** Record a model output event (output digest + optional reasoning). */
  async recordOutput(args: {
    output: unknown;
    intent?: string;
    scopeUsed?: string | null;
    reasoning?: string | null;
    passport?: Passport;
  }): Promise<Record<string, unknown>> {
    const text =
      typeof args.output === "string" ? args.output : JSON.stringify(args.output);
    return this.emit({
      kind: "model_response",
      intent: args.intent ?? "Agent response",
      tool: "agent.record",
      scopeUsed: args.scopeUsed ?? null,
      reasoning: args.reasoning ?? null,
      modelOutput: text,
      passport: args.passport,
    });
  }

  /** Record a decision AND the alternatives not taken (TAP-spec §6.4).
   *
   * The signed body carries only digests; plaintext question and option
   * rationale/reason go to the annex. Scores MUST be strings (§3.4).
   */
  async decision(args: {
    question: string;
    options: DecisionOption[];
    chosen: string;
    scopeUsed?: string | null;
    selection?: string;
    reasoning?: string;
    decisionKey?: string;
    passport?: Passport;
  }): Promise<Record<string, unknown>> {
    if (!args.options.some((o) => o.id === args.chosen))
      throw new Error(`chosen=${args.chosen} not among options`);

    const norm: Record<string, unknown>[] = [];
    const annexOptions: Record<string, unknown>[] = [];

    for (const o of args.options) {
      const isChosen = o.id === args.chosen;
      const item: Record<string, unknown> = { id: o.id, chosen: isChosen };

      // Score MUST be a string per §3.4 (no fractional numbers in signed body)
      if (o.score !== undefined) item.score = String(o.score);

      const annexOpt: Record<string, unknown> = { id: o.id };
      if (o.summary) annexOpt.summary = o.summary; // display label — annex only, not signed
      if (isChosen) {
        const rationale = o.rationale ?? o.reason;
        if (rationale) {
          item.rationale_digest = textDigest(rationale);
          annexOpt.rationale = rationale;
        }
      } else {
        if (o.reason) {
          item.reason_digest = textDigest(o.reason);
          annexOpt.reason = o.reason;
        }
      }
      norm.push(item);
      if (Object.keys(annexOpt).length > 1) annexOptions.push(annexOpt);
    }

    const decision: Record<string, unknown> = {
      question_digest: textDigest(args.question),
      chosen: args.chosen,
      options: norm,
      options_digest: jsonDigest(norm),  // MUST per §6.4
    };
    if (args.selection) decision.selection = args.selection;

    const extraAnnex: Record<string, unknown> = {};
    if (annexOptions.length > 0) {
      extraAnnex.decision = { question: args.question, options: annexOptions };
    }

    return this.emit({
      kind: "decision",
      intent: args.question,
      tool: args.decisionKey ?? "decision",
      scopeUsed: args.scopeUsed ?? null,
      reasoning: args.reasoning,
      decision,
      passport: args.passport,
      extraAnnex: Object.keys(extraAnnex).length > 0 ? extraAnnex : undefined,
    });
  }

  /** Flush buffered events (and their annexes) to the Verifier (TAP-spec §11.3). */
  async flush(): Promise<void> {
    if (this.buffer.length === 0) return;
    const items = this.buffer;
    this.buffer = [];
    const events = items.map((i) => i.event);
    const annexes = items.map((i) => i.annex).filter(Boolean);
    const payload: Record<string, unknown> = { events };
    if (annexes.length > 0) payload.annexes = annexes;
    if (this.passport) payload.passport = this.passport.compact;
    const headers: Record<string, string> = { "Content-Type": "application/json" };
    if (this.opts.apiKey) headers["X-API-Key"] = this.opts.apiKey;
    const url = this.opts.endpoint.replace(/\/$/, "") + "/v1/events";

    if (this.opts.post) {
      await this.opts.post(url, payload, headers);
      return;
    }
    const res = await fetch(url, { method: "POST", headers, body: JSON.stringify(payload) });
    if (!res.ok) {
      this.buffer.unshift(...items); // fail-open: keep for retry
      throw new Error(`verifier ${res.status}`);
    }
  }
}
