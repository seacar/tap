// Typed client for the TAPClient Verifier REST API (isomorphic fetch).

export interface DecisionOptionView {
  id: string;
  summary: string;
  chosen: boolean;
  score?: number;
  rationale?: string;
  reason?: string;
}
export interface DecisionBlock {
  question: string;
  chosen: string;
  selection?: string;
  options: DecisionOptionView[];
}
export interface TapEventRaw {
  v: string;
  event_id: string;
  aid: string;
  cid: string;
  seq: number;
  ts: string;
  action: { kind: string; intent: string; tool: string; scope_used: string | null };
  evidence?: { reasoning?: string | null };
  result: { status: string; code: string; latency_ms?: number | null };
  decision?: DecisionBlock;
  kid: string;
  sig: string;
}
export interface EventRecord {
  raw: TapEventRaw;
  sig_valid: boolean;
  drift: boolean;
  drift_reason: string | null;
  integrity: Record<string, unknown>;
}
export interface AgentRecord {
  aid: string;
  passport: Record<string, unknown> | null;
  events: EventRecord[];
  flags: { drift: boolean; invalid_sig: boolean; integrity: unknown[] };
}
export interface RecordSummary {
  aid: string;
  cid: string | null;
  agent_name: string | null;
  scope: string[];
  event_count: number;
  drift: boolean;
  issued_at: number | string | null;
}

export interface ReplayReport {
  aid: string;
  actions: unknown[];
  summary: {
    intent_only_checked: number;
    skipped_two_sided: number;
    skipped_conflicting: number;
    drift_findings: number;
    env_drifts: number;
    decision_changes: number;
    human_overrides: number;
  };
  oversight?: unknown[];
  policy_backtest?: unknown;
}

export interface TrainingCorpus {
  aid: string;
  cid?: string;
  agent_name?: string;
  model?: string;
  framework?: string;
  scope: string[];
  summary: {
    samples: number;
    human_labeled: number;
    oversight_events: number;
    decisions: number;
    tool_calls: number;
  };
  samples: unknown[];
  oversight: unknown[];
}

export interface VerifierApiOptions {
  apiKey?: string;
  adminToken?: string; // console/admin read path
  clientId?: string;
}

async function verifierError(prefix: string, r: Response): Promise<Error> {
  let detail = "";
  try {
    const body = (await r.json()) as { detail?: string | { msg?: string }[] };
    if (typeof body.detail === "string") {
      detail = body.detail;
    } else if (Array.isArray(body.detail) && body.detail[0]?.msg) {
      detail = body.detail[0].msg;
    }
  } catch {
    // ignore non-JSON bodies
  }
  const message = detail ? `${prefix}: ${detail}` : `${prefix} ${r.status}`;
  const err = new Error(message);
  (err as Error & { status: number }).status = r.status;
  return err;
}

export class VerifierAPI {
  private base: string;
  private headers: Record<string, string>;

  constructor(endpoint = "http://localhost:8000", opts: VerifierApiOptions = {}) {
    this.base = endpoint.replace(/\/$/, "");
    this.headers = {};
    if (opts.apiKey) this.headers["X-API-Key"] = opts.apiKey;
    if (opts.adminToken && opts.clientId) {
      this.headers["X-Admin-Token"] = opts.adminToken;
      this.headers["X-Client-Id"] = opts.clientId;
    }
  }

  async jwks(): Promise<{ keys: unknown[] }> {
    const r = await fetch(`${this.base}/.well-known/jwks.json`);
    return r.json();
  }

  async verify(passport: string, events: TapEventRaw[]): Promise<unknown> {
    const r = await fetch(`${this.base}/v1/verify`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...this.headers },
      body: JSON.stringify({ passport, events }),
    });
    return r.json();
  }

  async getRecord(aid: string): Promise<AgentRecord | null> {
    const r = await fetch(`${this.base}/v1/records/${aid}`, { headers: this.headers, cache: "no-store" });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`verifier ${r.status}`);
    return r.json();
  }

  async recentRecords(): Promise<RecordSummary[]> {
    const r = await fetch(`${this.base}/v1/records`, { headers: this.headers, cache: "no-store" });
    if (!r.ok) return [];
    return (await r.json()).records ?? [];
  }

  async replay(aid: string, policy?: Record<string, unknown>, env?: string): Promise<ReplayReport> {
    const r = await fetch(`${this.base}/v1/replay`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...this.headers },
      body: JSON.stringify({ aid, policy, env }),
    });
    if (!r.ok) throw new Error(`verifier replay ${r.status}`);
    return r.json();
  }

  async exportCorpus(aid: string): Promise<TrainingCorpus> {
    const r = await fetch(`${this.base}/v1/records/${encodeURIComponent(aid)}/corpus`, {
      headers: this.headers,
      cache: "no-store",
    });
    if (!r.ok) throw new Error(`verifier corpus ${r.status}`);
    return r.json();
  }

  async submitOversight(args: {
    aid: string;
    target_event_id: string;
    decision: "approve" | "reject" | "override";
    justification?: string;
    actor: string;
    role?: string;
    event?: Record<string, unknown>;
  }): Promise<unknown> {
    const r = await fetch(`${this.base}/v1/oversight`, {
      method: "POST",
      headers: { "Content-Type": "application/json", ...this.headers },
      body: JSON.stringify(args),
    });
    if (!r.ok) throw await verifierError("verifier oversight", r);
    return r.json();
  }
}
