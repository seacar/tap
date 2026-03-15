/**
 * @traceableagent/sdk/server — high-level server SDK.
 * TAP-aware tool server with API-key-only setup; mirrors TAPTracer on the agent side.
 */
import { ensureAgentIdentity, type AgentIdentity, type RegisterFn } from "./identity.js";
import {
  jwksResolver,
  ServerDenied,
  TAPServer,
  UnattestedAction,
  type Policy,
  type PostFn,
} from "./server.js";

/** TAP HTTP carriage headers (TAP-spec §10.1). */
export const TAP_PASSPORT_HEADER = "X-Agent-Passport";
export const TAP_ACTION_REF_HEADER = "X-TAP-Action-Ref";

export interface TapRequestContext {
  passportJwt: string | null;
  actionRef: string | null;
}

export interface TapToolRequestBody {
  tool?: string;
  scope_used?: string;
  arguments?: Record<string, unknown>;
  intent?: string;
  /** Demo / deployment hook: select a server policy profile. */
  policy_mode?: string;
}

/** Read TAP carriage from a Fetch API ``Headers`` object. */
export function readTapHeaders(headers: Headers): TapRequestContext;
/** Read TAP carriage from a plain header map (Node / tests). */
export function readTapHeaders(
  headers: Record<string, string | null | undefined>,
): TapRequestContext;
export function readTapHeaders(
  headers: Headers | Record<string, string | null | undefined>,
): TapRequestContext {
  if (headers instanceof Headers) {
    return {
      passportJwt: headers.get(TAP_PASSPORT_HEADER.toLowerCase()) ?? headers.get(TAP_PASSPORT_HEADER),
      actionRef: headers.get(TAP_ACTION_REF_HEADER.toLowerCase()) ?? headers.get(TAP_ACTION_REF_HEADER),
    };
  }
  const lower = Object.fromEntries(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v ?? null]),
  );
  return {
    passportJwt: lower[TAP_PASSPORT_HEADER.toLowerCase()] ?? null,
    actionRef: lower[TAP_ACTION_REF_HEADER.toLowerCase()] ?? null,
  };
}

export function readTapHeadersFromRequest(req: Request): TapRequestContext {
  return readTapHeaders(req.headers);
}

export interface TAPToolServerOptions {
  serverId: string;
  apiKey: string;
  endpoint?: string;
  identityDir?: string;
  policy?: Policy;
  enforce?: boolean;
  post?: PostFn;
  registerFn?: RegisterFn;
}

export class TAPToolServer {
  readonly serverId: string;
  readonly apiKey: string;
  readonly endpoint: string;
  readonly identityDir?: string;
  readonly policy?: Policy;
  readonly enforce: boolean;
  readonly post?: PostFn;
  readonly registerFn?: RegisterFn;

  private identity: AgentIdentity | null = null;
  private tap: TAPServer | null = null;
  private readyPromise: Promise<void> | null = null;

  constructor(opts: TAPToolServerOptions) {
    this.serverId = opts.serverId;
    this.apiKey = opts.apiKey;
    this.endpoint = (opts.endpoint ?? "http://localhost:8000").replace(/\/$/, "");
    this.identityDir = opts.identityDir;
    this.policy = opts.policy;
    this.enforce = opts.enforce ?? true;
    this.post = opts.post;
    this.registerFn = opts.registerFn;
  }

  /** Configure from environment — parallel to ``TAPTracer.fromEnv()``. */
  static fromEnv(overrides?: Partial<TAPToolServerOptions>): TAPToolServer {
    const apiKey = overrides?.apiKey ?? process.env.TAP_API_KEY ?? process.env.TAP_API_KEY;
    if (!apiKey) {
      throw new Error("Set TAP_API_KEY or TAP_API_KEY");
    }
    const serverId =
      overrides?.serverId ??
      process.env.TAP_SERVER_ID ??
      process.env.TAP_SERVER_ID ??
      "tap-tool-server";
    const endpoint =
      overrides?.endpoint ??
      process.env.TAP_ENDPOINT ??
      process.env.TAP_ENDPOINT ??
      process.env.VERIFIER_URL ??
      "http://localhost:8000";
    return new TAPToolServer({
      serverId,
      apiKey,
      endpoint,
      identityDir: overrides?.identityDir ?? process.env.TAP_IDENTITY_DIR,
      policy: overrides?.policy,
      enforce: overrides?.enforce,
      post: overrides?.post,
      registerFn: overrides?.registerFn,
    });
  }

  get kid(): string {
    if (!this.identity) throw new Error("TAPToolServer not ready — call ready() or attest() first");
    return this.identity.kid;
  }

  /** Ensure server identity is registered and TAPServer is wired. */
  async ready(): Promise<void> {
    if (this.tap) return;
    if (!this.readyPromise) {
      this.readyPromise = (async () => {
        this.identity = await ensureAgentIdentity({
          agentId: this.serverId,
          apiKey: this.apiKey,
          endpoint: this.endpoint,
          identityDir: this.identityDir,
          registerFn: this.registerFn,
        });
        const resolveKey = await jwksResolver(this.endpoint, this.apiKey);
        this.tap = new TAPServer({
          serverId: this.serverId,
          privateKeyHex: this.identity.seedHex,
          kid: this.identity.kid,
          resolveKey,
          endpoint: this.endpoint,
          apiKey: this.apiKey,
          policy: this.policy,
          enforce: this.enforce,
          post: this.post,
        });
      })();
    }
    await this.readyPromise;
  }

  /** Verify passport → enforce → execute → sign server-attested leg. */
  async attest<T>(args: {
    tool: string;
    passportJwt: string | null | undefined;
    actionRef: string;
    execute: () => T | Promise<T>;
    scopeUsed?: string | null;
    arguments?: unknown;
    intent?: string;
  }): Promise<T> {
    await this.ready();
    return this.tap!.attest(args);
  }

  /**
   * Handle a standard TAP tool HTTP request (passport + action_ref headers, JSON body).
   * Returns the handler result; use ``toTapToolResponse`` to map errors to HTTP.
   */
  async handleToolRequest(req: Request, spec: {
    tool: string;
    scopeUsed: string;
    arguments?: Record<string, unknown>;
    intent?: string;
    execute: (args: Record<string, unknown>) => unknown | Promise<unknown>;
  }): Promise<unknown> {
    const { passportJwt, actionRef } = readTapHeadersFromRequest(req);
    if (!actionRef) throw new TapRequestError("X-TAP-Action-Ref required", 400);
    const body = (await req.json()) as TapToolRequestBody;
    const args = spec.arguments ?? body.arguments ?? {};
    return this.attest({
      tool: spec.tool,
      passportJwt,
      actionRef,
      scopeUsed: spec.scopeUsed ?? body.scope_used ?? `call:${spec.tool}`,
      arguments: args,
      intent: spec.intent ?? body.intent,
      execute: () => spec.execute(args),
    });
  }

  async flush(): Promise<void> {
    await this.ready();
    await this.tap!.flush();
  }
}

export class TapRequestError extends Error {
  readonly status: number;
  constructor(message: string, status: number) {
    super(message);
    this.name = "TapRequestError";
    this.status = status;
  }
}

function isNamedError(err: unknown, name: string): boolean {
  return err instanceof Error && err.name === name;
}

/** Map TAP server errors to HTTP ``Response`` objects for route handlers. */
export function toTapToolResponse(
  resultOrError: { ok: true; result: unknown } | { ok: false; error: unknown },
): Response {
  if (resultOrError.ok) {
    return Response.json({ ok: true, result: resultOrError.result });
  }
  const err = resultOrError.error;
  if (err instanceof TapRequestError) {
    return Response.json({ error: err.message }, { status: err.status });
  }
  if (err instanceof UnattestedAction || isNamedError(err, "UnattestedAction")) {
    return Response.json(
      { error: (err as Error).message, code: "UNATTESTED" },
      { status: 401 },
    );
  }
  if (err instanceof ServerDenied || isNamedError(err, "ServerDenied")) {
    const denied = err as ServerDenied;
    return Response.json(
      { error: denied.message, code: denied.code, event_id: denied.event.event_id },
      { status: 403 },
    );
  }
  const message = err instanceof Error ? err.message : "tool execution failed";
  return Response.json({ error: message }, { status: 500 });
}

/** Run a TAP tool handler and return a ready-made HTTP response. */
export async function respondToTapTool(
  server: TAPToolServer,
  req: Request,
  spec: Parameters<TAPToolServer["handleToolRequest"]>[1],
): Promise<Response> {
  try {
    const result = await server.handleToolRequest(req, spec);
    return toTapToolResponse({ ok: true, result });
  } catch (err) {
    return toTapToolResponse({ ok: false, error: err });
  }
}

/**
 * Factory for a Next.js / Fetch ``POST`` route that dispatches by ``body.tool``.
 * Each entry supplies ``scopeUsed`` and an ``execute`` handler for server attestation.
 */
export type TapToolRouterContext = { body: TapToolRequestBody };

export function createTapToolRouter(
  getServer: (ctx: TapToolRouterContext) => TAPToolServer | Promise<TAPToolServer>,
  tools: Record<
    string,
    {
      scopeUsed: string;
      intent?: string;
      execute: (args: Record<string, unknown>) => unknown | Promise<unknown>;
    }
  >,
): (req: Request) => Promise<Response> {
  return async (req: Request) => {
    try {
      const body = (await req.json()) as TapToolRequestBody;
      if (!body.tool) {
        return Response.json({ error: "tool is required" }, { status: 400 });
      }
      const toolSpec = tools[body.tool];
      if (!toolSpec) {
        return Response.json({ error: `unknown tool ${body.tool}` }, { status: 404 });
      }
      const server = await getServer({ body });
      const { passportJwt, actionRef } = readTapHeadersFromRequest(req);
      if (!actionRef) {
        return toTapToolResponse({ ok: false, error: new TapRequestError("X-TAP-Action-Ref required", 400) });
      }
      const args = body.arguments ?? {};
      const result = await server.attest({
        tool: body.tool,
        passportJwt,
        actionRef,
        scopeUsed: body.scope_used ?? toolSpec.scopeUsed,
        arguments: args,
        intent: body.intent ?? toolSpec.intent,
        execute: () => toolSpec.execute(args),
      });
      return toTapToolResponse({ ok: true, result });
    } catch (err) {
      return toTapToolResponse({ ok: false, error: err });
    }
  };
}
