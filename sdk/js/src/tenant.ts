/**
 * High-level SDK entrypoint — trace agent records with API key only.
 * Agent identities are generated locally and registered on first trace.
 */
import { resolveAgentId } from "./agentId.js";
import { TAPClient, type Passport, type DecisionOption } from "./client.js";
import { ensureAgentIdentity, type AgentIdentity, type RegisterFn } from "./identity.js";
import { getOrCreateInstanceSuffix } from "./instanceSuffix.js";

export interface TAPTracerOptions {
  apiKey: string;
  endpoint?: string;
  identityDir?: string;
  framework?: string;
  model?: string;
  capturePreviews?: boolean;
  post?: (url: string, payload: unknown, headers: Record<string, string>) => Promise<void>;
  registerFn?: RegisterFn;
}

export class TraceSession {
  constructor(
    private readonly client: TAPClient,
    readonly passport: Passport,
    readonly identity: AgentIdentity,
    readonly logicalAgentId: string,
  ) {}

  get agentId(): string {
    return this.identity.agentId;
  }

  get kid(): string {
    return this.identity.kid;
  }

  async recordOutput(args: {
    output: unknown;
    intent?: string;
    scopeUsed?: string | null;
    reasoning?: string | null;
  }): Promise<Record<string, unknown>> {
    return this.client.recordOutput({
      ...args,
      passport: this.passport,
    });
  }

  async decision(
    args: Omit<Parameters<TAPClient["decision"]>[0], "passport">,
  ): Promise<Record<string, unknown>> {
    return this.client.decision({ ...args, passport: this.passport });
  }

  traceTool<T>(
    spec: { tool: string; scope: string; intent?: string; args?: unknown },
    fn: () => Promise<T>,
  ): Promise<T> {
    return this.client.traceTool(spec, fn);
  }

  traceAttestedTool<T>(
    spec: {
      tool: string;
      scope: string;
      intent?: string;
      args?: unknown;
      invoke: (carriage: import("./client.js").TapCarriage) => Promise<T>;
    },
  ): Promise<{ result: T; actionRef: string }> {
    return this.client.traceAttestedTool({ ...spec, passport: this.passport });
  }

  signToolCall(
    args: Omit<Parameters<TAPClient["signToolCall"]>[0], "passport">,
  ): Promise<Record<string, unknown>> {
    return this.client.signToolCall({ ...args, passport: this.passport });
  }

  async flush(): Promise<void> {
    await this.client.flush();
  }
}

export class TAPTracer {
  readonly apiKey: string;
  readonly endpoint: string;
  readonly identityDir?: string;
  readonly framework?: string;
  readonly model?: string;
  readonly capturePreviews: boolean;
  readonly post?: TAPTracerOptions["post"];
  readonly registerFn?: RegisterFn;

  constructor(opts: TAPTracerOptions) {
    this.apiKey = opts.apiKey;
    this.endpoint = (opts.endpoint ?? "http://localhost:8000").replace(/\/$/, "");
    this.identityDir = opts.identityDir;
    this.framework = opts.framework;
    this.model = opts.model;
    this.capturePreviews = opts.capturePreviews ?? false;
    this.post = opts.post;
    this.registerFn = opts.registerFn;
  }

  static fromEnv(overrides?: Partial<TAPTracerOptions>): TAPTracer {
    const apiKey = process.env.TAP_API_KEY ?? process.env.TAP_API_KEY;
    if (!apiKey) {
      throw new Error("Set TAP_API_KEY or TAP_API_KEY");
    }
    const endpoint =
      process.env.TAP_ENDPOINT ??
      process.env.TAP_ENDPOINT ??
      process.env.VERIFIER_URL ??
      "http://localhost:8000";
    return new TAPTracer({
      apiKey,
      endpoint,
      identityDir: process.env.TAP_IDENTITY_DIR,
      framework: process.env.TAP_FRAMEWORK,
      model: process.env.TAP_MODEL ?? process.env.OLLAMA_MODEL,
      capturePreviews: process.env.TAP_CAPTURE_PREVIEWS === "1",
      ...overrides,
    });
  }

  async trace(args: {
    agentId: string;
    task?: string;
    taskPrompt?: string;
    prompt?: string;
    scope?: string[];
    ttlS?: number;
  }): Promise<TraceSession> {
    const runTask = args.task ?? args.taskPrompt ?? args.prompt;
    if (!runTask) throw new Error("trace() requires task= (or taskPrompt= / prompt=)");

    const logicalAgentId = args.agentId;
    const instanceSuffix = await getOrCreateInstanceSuffix(this.identityDir);
    const resolvedId = resolveAgentId(logicalAgentId, instanceSuffix);
    const identity = await ensureAgentIdentity({
      agentId: resolvedId,
      apiKey: this.apiKey,
      endpoint: this.endpoint,
      identityDir: this.identityDir,
      registerFn: this.registerFn,
    });

    const client = new TAPClient({
      agentId: resolvedId,
      privateKeyHex: identity.seedHex,
      kid: identity.kid,
      apiKey: this.apiKey,
      endpoint: this.endpoint,
      framework: this.framework,
      model: this.model,
      capturePreviews: this.capturePreviews,
      post: this.post,
    });

    const passport = await client.issuePassport({
      taskPrompt: runTask,
      scope: args.scope ?? ["agent:record"],
      ttlS: args.ttlS,
    });

    return new TraceSession(client, passport, identity, logicalAgentId);
  }
}

export type { DecisionOption };
