// The TAP capability handshake — `tap_hello` / `tap_hello_ack` [TAP-NEGOTIATE].
//
// A Signer offers the versions and crypto suites it supports and whether it wants
// server attestation; a TAP-aware Server or Gateway answers with its selection.
// The selected outcome is then bound into the first Event of the record as
// `evidence.nego` [TAP-NEGO-BINDING], which is what makes a stripped handshake
// *detectable*: the handshake rides in plaintext metadata and any intermediary can
// remove it, but the Signer's signed claim about it cannot be removed silently.
//
// That binding is only worth something if the value bound is an outcome the Signer
// actually obtained, so this module exists to make obtaining one the easy path.
//
// Carriage (spec §11), both bindings, same JSON object either way:
//   HTTP     — `X-TAP-Hello` / `X-TAP-Hello-Ack` headers
//   JSON-RPC — `_meta.tap.hello` / `_meta.tap.hello_ack`

import { SPEC_VERSION } from "./tap.js";

export const HELLO_HEADER = "X-TAP-Hello";
export const ACK_HEADER = "X-TAP-Hello-Ack";

/** Wire versions this implementation speaks, best first. */
export const SUPPORTED_VERSIONS: readonly string[] = [SPEC_VERSION];

/** Crypto suites this implementation speaks [TAP-SUITE-DISPATCH]. */
export const SUPPORTED_SUITES: readonly string[] = ["tap-ed25519"];

/** What a Signer may ask for. `requested` is an offer, never a selection. */
export const OFFERABLE_ATTESTATION = new Set(["none", "requested"]);

/** What a Server may select. */
export const SELECTABLE_ATTESTATION = new Set(["none", "server"]);

export interface Hello {
  versions: string[];
  suites: string[];
  attestation: string;
  kid: string;
}

export interface Ack {
  version: string;
  suite: string;
  attestation: string;
  checkpoints?: string;
}

/** The outcome of a handshake — exactly the shape bound into `evidence.nego`. */
export interface Negotiated {
  version: string;
  suite: string;
  attestation: string;
}

/**
 * No mutually supported wire version or suite.
 *
 * Not fatal by itself: per [TAP-NEGOTIATE] the parties fall back to unattested
 * operation and the Signer labels the record accordingly. It throws so that the
 * fallback is a decision the caller makes, not one that happens silently.
 */
export class NegotiationFailed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "NegotiationFailed";
  }
}

// --- Signer side -------------------------------------------------------------

/** Build the `tap_hello` a Signer sends on the first request of a session. */
export function offer(args: {
  kid: string;
  attestation?: string;
  versions?: readonly string[];
  suites?: readonly string[];
}): Hello {
  const attestation = args.attestation ?? "requested";
  if (!OFFERABLE_ATTESTATION.has(attestation)) {
    throw new Error(
      `a Signer may offer ${[...OFFERABLE_ATTESTATION].sort().join(", ")}, not ${JSON.stringify(attestation)}; ` +
        `"server" is a Server's selection, not something a Signer can claim`,
    );
  }
  return {
    versions: [...(args.versions ?? SUPPORTED_VERSIONS)],
    suites: [...(args.suites ?? SUPPORTED_SUITES)],
    attestation,
    kid: args.kid,
  };
}

/**
 * Interpret a `tap_hello_ack`. Returns null when there was no usable ack — which
 * is the honest input to "bind no `nego` at all".
 */
export function readAck(ack: Partial<Ack> | null | undefined): Negotiated | null {
  if (!ack) return null;
  const version = ack.version;
  // `suite` is the field name; `alg` is accepted on INPUT only, because early
  // drafts of the handshake showed a JOSE `alg` here. We never emit it.
  const suite = ack.suite ?? suiteForLegacyAlg((ack as Record<string, unknown>).alg);
  const attestation = ack.attestation;
  if (!version || !SUPPORTED_VERSIONS.includes(version)) return null;
  if (!suite || !SUPPORTED_SUITES.includes(suite)) return null;
  if (!attestation || !SELECTABLE_ATTESTATION.has(attestation)) return null;
  return { version, suite, attestation };
}

function suiteForLegacyAlg(alg: unknown): string | undefined {
  return alg === "EdDSA" ? "tap-ed25519" : undefined;
}

// --- Server side -------------------------------------------------------------

/**
 * Choose the session parameters and build the `tap_hello_ack`.
 *
 * `attests` says whether this Server will actually sign execution legs. It is
 * deliberately a property of the Server rather than something the caller's hello
 * can influence: answering `attestation:"server"` and then not signing one
 * produces exactly the `conflicting` state [TAP-ASSURANCE] that a Verifier will
 * hold against the *agent*.
 *
 * Returns null when there was no hello to answer; throws NegotiationFailed when a
 * hello arrived but shares no version or suite with us.
 */
export function select(
  hello: Partial<Hello> | null | undefined,
  opts: { attests: boolean },
): Ack | null {
  if (!hello) return null;
  const offeredVersions = hello.versions ?? [];
  const offeredSuites =
    hello.suites ?? legacySuites((hello as Record<string, unknown>).algs);

  const version = highestMutual(offeredVersions, SUPPORTED_VERSIONS);
  const suite = highestMutual(offeredSuites, SUPPORTED_SUITES);
  if (!version || !suite) {
    throw new NegotiationFailed(
      `no mutually supported version/suite: offered versions=${JSON.stringify(offeredVersions)} ` +
        `suites=${JSON.stringify(offeredSuites)}`,
    );
  }
  return {
    version,
    suite,
    attestation: opts.attests ? "server" : "none",
    checkpoints: "supported",
  };
}

function legacySuites(algs: unknown): string[] {
  if (!Array.isArray(algs)) return [];
  return algs.map(suiteForLegacyAlg).filter((s): s is string => Boolean(s));
}

/**
 * Our preference order wins, not theirs: `supported` is ordered best-first, so we
 * pick the best thing WE can do that they also do.
 */
function highestMutual(offered: readonly string[], supported: readonly string[]): string | null {
  const offeredSet = new Set(offered);
  for (const candidate of supported) {
    if (offeredSet.has(candidate)) return candidate;
  }
  return null;
}

// --- carriage ----------------------------------------------------------------

/** Serialize a hello/ack for an HTTP header: compact JSON, no raw newlines. */
export function toHeader(obj: unknown): string {
  return JSON.stringify(obj);
}

/**
 * Parse a hello/ack header. Malformed input is treated as absent rather than
 * throwing: a broken handshake degrades to unattested, which the `nego` binding
 * then makes visible. It must never take down the request path.
 */
export function fromHeader(raw: string | null | undefined): Record<string, unknown> | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function helloHeaders(hello: Hello): Record<string, string> {
  return { [HELLO_HEADER]: toHeader(hello) };
}

export function ackHeaders(ack: Ack | null): Record<string, string> {
  return ack ? { [ACK_HEADER]: toHeader(ack) } : {};
}

/** Read a hello from any case-insensitive header bag (Headers, a plain object). */
export function helloFromHeaders(headers: unknown): Record<string, unknown> | null {
  return fromHeader(getHeader(headers, HELLO_HEADER));
}

export function ackFromHeaders(headers: unknown): Record<string, unknown> | null {
  return fromHeader(getHeader(headers, ACK_HEADER));
}

function getHeader(headers: unknown, name: string): string | null {
  if (!headers) return null;
  const anyHeaders = headers as { get?: (k: string) => string | null } & Record<string, unknown>;
  if (typeof anyHeaders.get === "function") {
    return anyHeaders.get(name) ?? anyHeaders.get(name.toLowerCase()) ?? null;
  }
  const direct = anyHeaders[name] ?? anyHeaders[name.toLowerCase()];
  return typeof direct === "string" ? direct : null;
}

/** `_meta` carriage for stdio MCP / A2A, where no HTTP headers exist. */
export function helloMeta(hello: Hello): Record<string, unknown> {
  return { tap: { hello } };
}

export function helloFromMeta(meta: Record<string, any> | null | undefined): Record<string, unknown> | null {
  return meta?.tap?.hello ?? null;
}

export function ackFromMeta(meta: Record<string, any> | null | undefined): Record<string, unknown> | null {
  return meta?.tap?.hello_ack ?? null;
}
