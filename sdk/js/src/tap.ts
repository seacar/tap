// TAP v0.1 wire crypto in TypeScript — Ed25519 (EdDSA) over JCS-canonicalized
// event bodies and compact-JWS passports. Isomorphic (Node + browser): uses
// @noble/ed25519 + @noble/hashes and a pure-JS base64url. Reproduces
// tap/test-vectors.json byte-for-byte (see test/conformance.ts) — the contract
// that keeps this interoperable with the reference impl and the Python SDK.

import * as ed from "@noble/ed25519";
import { sha256 } from "@noble/hashes/sha2.js";
import canonicalize from "canonicalize";

export const SPEC_VERSION = "tap/0.1";
export const PASSPORT_TYP = "tap-passport+jwt";

// --- encoding (pure JS, isomorphic) -----------------------------------------

const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

export function b64u(bytes: Uint8Array): string {
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const b0 = bytes[i], b1 = bytes[i + 1], b2 = bytes[i + 2];
    out += B64[b0 >> 2];
    out += B64[((b0 & 3) << 4) | ((b1 ?? 0) >> 4)];
    if (b1 === undefined) break;
    out += B64[((b1 & 15) << 2) | ((b2 ?? 0) >> 6)];
    if (b2 === undefined) break;
    out += B64[b2 & 63];
  }
  return out;
}

export function b64uToBytes(s: string): Uint8Array {
  const lookup = new Map<string, number>();
  for (let i = 0; i < B64.length; i++) lookup.set(B64[i], i);
  const bytes: number[] = [];
  let bits = 0, value = 0;
  for (const ch of s) {
    const v = lookup.get(ch);
    if (v === undefined) continue;
    value = (value << 6) | v;
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >> bits) & 0xff);
    }
  }
  return Uint8Array.from(bytes);
}

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function utf8(s: string): Uint8Array {
  return new TextEncoder().encode(s);
}

const fromHex = (h: string): Uint8Array =>
  Uint8Array.from(h.match(/.{1,2}/g)!.map((b) => parseInt(b, 16)));

export function digest(data: Uint8Array | string): string {
  return "sha256:" + hex(sha256(typeof data === "string" ? utf8(data) : data));
}

/** Digest of a UTF-8 string — the value signed when plaintext lives in the annex (§6.1). */
export function textDigest(text: string): string {
  return digest(utf8(text));
}

/** Digest over JCS-canonical bytes of a JSON value — cross-language stable (§6.1). */
export function jsonDigest(obj: unknown): string {
  const canon = canonicalize(obj);
  if (canon === undefined) throw new Error("canonicalization failed");
  return digest(utf8(canon));
}

/**
 * cid = digest(utf8(prompt) ‖ nonce) — §3.3.
 * The nonce MUST carry ≥128 bits of entropy so identical prompts do not collide
 * and cid cannot serve as a confirmation oracle. If omitted, 16 random bytes are
 * generated via ``crypto.getRandomValues``.
 */
export function cidFromPrompt(prompt: string, nonce?: Uint8Array): string {
  const promptBytes = utf8(prompt);
  const n = nonce ?? crypto.getRandomValues(new Uint8Array(16));
  if (n.length < 16) throw new Error("cid nonce must be at least 16 bytes (128 bits)");
  const combined = new Uint8Array(promptBytes.length + n.length);
  combined.set(promptBytes);
  combined.set(n, promptBytes.length);
  return digest(combined);
}

/**
 * Merkle root over event_ids per §6.3 (normative construction, matches tap_ref.py).
 * Leaf = SHA-256(0x00 ‖ utf8(event_id))
 * Node = SHA-256(0x01 ‖ left ‖ right)
 * Odd  = final node promoted unchanged (no duplication)
 * Empty → SHA-256(empty bytes)
 */
export function checkpointRoot(eventIds: string[]): string {
  if (eventIds.length === 0) {
    return "sha256:" + hex(sha256(new Uint8Array(0)));
  }
  let level: Uint8Array[] = eventIds.map((eid) => {
    const eidBytes = utf8(eid);
    const m = new Uint8Array(1 + eidBytes.length);
    m[0] = 0x00;
    m.set(eidBytes, 1);
    return sha256(m);
  });
  while (level.length > 1) {
    const next: Uint8Array[] = [];
    for (let i = 0; i < level.length; i += 2) {
      if (i + 1 < level.length) {
        const combined = new Uint8Array(1 + level[i].length + level[i + 1].length);
        combined[0] = 0x01;
        combined.set(level[i], 1);
        combined.set(level[i + 1], 1 + level[i].length);
        next.push(sha256(combined));
      } else {
        next.push(level[i]); // promote odd node unchanged
      }
    }
    level = next;
  }
  return "sha256:" + hex(level[0]);
}

// --- keys --------------------------------------------------------------------

export interface Jwk {
  kty: "OKP";
  crv: "Ed25519";
  alg: "EdDSA";
  use: "sig";
  kid: string;
  x: string;
  /** Optional epoch-seconds revocation boundary (spec §3.2). */
  revoked_at?: number;
}

// --- crypto-suite dispatch & revocation [TAP-SUITE-DISPATCH], [TAP-KEY-REVOCATION] ---------------

/**
 * The key declares a crypto suite this implementation does not recognize.
 * A conforming verifier MUST reject it rather than fall back to a default
 * ([TAP-SUITE-DISPATCH]) — verification dispatches off the key's declared suite so that
 * future suites need no verifier rewrite.
 */
export class UnknownSuite extends Error {
  constructor(kid: string | undefined, alg: unknown, crv: unknown) {
    super(`unrecognized crypto suite for key ${JSON.stringify(kid)}: (${alg}, ${crv})`);
    this.name = "UnknownSuite";
  }
}

// v0.1 recognizes only Ed25519. Future suites are registry additions.
const SUITES = new Map<string, string>([["EdDSA|Ed25519", "tap-ed25519"]]);

/**
 * The Passport is outside its freshness window, skew allowance included.
 *
 * A distinct type so a caller can tell "this credential aged out" — routine,
 * renew and retry (§4.2) — from "this credential is malformed or was not issued
 * for this key". Deciding that by searching the error message for the substring
 * "expired" breaks the moment anyone rewords it.
 */
export class PassportExpired extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PassportExpired";
  }
}

/** Resolve a JWK's declared (alg, crv) to a TAP suite id, or throw. */
export function suiteForJwk(jwk: Partial<Jwk>): string {
  const suite = SUITES.get(`${jwk.alg}|${jwk.crv}`);
  if (suite === undefined) throw new UnknownSuite(jwk.kid, jwk.alg, jwk.crv);
  return suite;
}

/** Optional epoch-seconds revocation boundary for a key [TAP-KEY-REVOCATION]. */
export function keyRevokedAt(jwk: Partial<Jwk>): number | null {
  return jwk.revoked_at === undefined || jwk.revoked_at === null
    ? null
    : Number(jwk.revoked_at);
}

/** The signing key's revocation boundary excludes this record [TAP-KEY-REVOCATION]. */
export class RevokedKey extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RevokedKey";
  }
}

/** RFC 3339 UTC timestamp -> epoch seconds. NaN when unparseable. */
export function parseTs(ts: string): number {
  return Math.floor(Date.parse(ts) / 1000);
}

/**
 * Enforce a key's revocation boundary against the record's own timestamp
 * [TAP-KEY-REVOCATION].
 *
 * `signedAt` is an Event's `ts` or a Passport's `iat`. Both live INSIDE the
 * signing input, so a holder of a compromised key cannot backdate a record past
 * the boundary without breaking its signature — which is what makes this check
 * sound before the signature has been verified.
 *
 * Revocation is an effective-time boundary, not blanket repudiation: records
 * signed before it stay valid, or retiring a key would retroactively destroy
 * every record it ever signed. A record that cannot place itself in time, under a
 * key that IS revoked, is rejected: evidence that cannot prove its own effective
 * time is not evidence.
 */
export function checkNotRevoked(jwk: Partial<Jwk>, signedAt: string | number | undefined): void {
  const revoked = keyRevokedAt(jwk);
  if (revoked === null) return;
  if (signedAt === undefined || signedAt === null) {
    throw new RevokedKey("key is revoked and the record carries no timestamp to place it");
  }
  const at = typeof signedAt === "number" ? signedAt : parseTs(signedAt);
  if (!Number.isFinite(at)) {
    throw new RevokedKey("key is revoked and the record timestamp is unparseable");
  }
  if (at >= revoked) {
    throw new RevokedKey(`key revoked at ${revoked}; record is timestamped ${at}`);
  }
}

const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

function b32(value: number, length: number): string {
  let out = "";
  for (let i = 0; i < length; i++) {
    out = CROCKFORD[value % 32] + out;
    value = Math.floor(value / 32);
  }
  return out;
}

/**
 * Crockford base32 id with prefix, e.g. ``evt_01H...``
 *
 * The random half comes from `crypto.getRandomValues`, not `Math.random`: these
 * identifiers become `event_id`s and `action_ref`s, which correlate the two legs of
 * an attested action and are committed to by checkpoint Merkle roots. Predictable
 * identifiers let an attacker guess a slot before it is filled. The Python SDK has
 * always used a CSPRNG here; this one had not.
 */
export function newId(prefix: string): string {
  const ts = b32(Date.now(), 10);
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  let rand = "";
  for (let i = 0; i < 16; i++) rand += CROCKFORD[bytes[i] & 31];
  return `${prefix}_${ts}${rand}`;
}

export async function generateSigner(): Promise<{ seedHex: string }> {
  const priv = ed.utils.randomSecretKey();
  // `hex`, not Buffer — this module must stay browser-safe so a relying party
  // can re-verify a transcript client-side with no Node polyfills.
  return { seedHex: hex(priv) };
}

export async function publicJwk(seedHex: string, kid: string): Promise<Jwk> {
  const pub = await ed.getPublicKeyAsync(fromHex(seedHex));
  return { kty: "OKP", crv: "Ed25519", alg: "EdDSA", use: "sig", kid, x: b64u(pub) };
}

// --- passport (compact JWS / JWT) -------------------------------------------

export async function signPassport(
  seedHex: string,
  kid: string,
  claims: Record<string, unknown>,
): Promise<string> {
  const header = { alg: "EdDSA", typ: PASSPORT_TYP, kid };
  const seg = b64u(utf8(JSON.stringify(header))) + "." + b64u(utf8(JSON.stringify(claims)));
  const sig = await ed.signAsync(utf8(seg), fromHex(seedHex));
  return seg + "." + b64u(sig);
}

export async function verifyPassport(
  jwk: Jwk,
  token: string,
  now: number = Math.floor(Date.now() / 1000),
): Promise<Record<string, unknown>> {
  suiteForJwk(jwk); // dispatch off the declared suite; throws on unknown (§3.6, §15)
  const parts = token.split(".");
  if (parts.length !== 3)
    throw new Error("not a compact JWS: expected three dot-separated segments");
  const [h, p, s] = parts;
  const ok = await ed.verifyAsync(b64uToBytes(s), utf8(`${h}.${p}`), b64uToBytes(jwk.x));
  if (!ok) throw new Error("passport signature invalid");
  const header = JSON.parse(new TextDecoder().decode(b64uToBytes(h)));
  const claims = JSON.parse(new TextDecoder().decode(b64uToBytes(p)));
  // `alg` is pinned to the session suite [TAP-SIG-ALG]: `none` and the RS/HS
  // families MUST NOT be accepted. Checking the JWK's suite alone leaves the
  // JOSE header — the field every historical alg-confusion attack targets —
  // unvalidated, which is also what RFC 8725 requires be checked.
  if (header.alg !== "EdDSA")
    throw new Error(`unacceptable JOSE alg ${JSON.stringify(header.alg)}; v0.1 requires EdDSA`);
  if (header.typ !== PASSPORT_TYP) throw new Error("wrong token type");
  if (header.kid !== jwk.kid) throw new Error("kid mismatch");
  checkNotRevoked(jwk, claims.iat as number);
  // Freshness with the +/-60 s skew allowance, written as the spec's inequality so
  // the two cannot drift apart [TAP-PASSPORT-VALIDATE].
  if (!((claims.iat as number) - 60 <= now && now < (claims.exp as number) + 60))
    throw new PassportExpired(
      `passport expired / not yet valid: iat=${claims.iat} exp=${claims.exp} now=${now}`,
    );
  return claims;
}

// --- event (detached sig over JCS canonical body) ---------------------------

/**
 * No fractional numbers, and no integer outside the IEEE-754 safe range, anywhere
 * in a signed body [TAP-CANON-NUMBERS].
 *
 * RFC 8785's number canonicalization is correct, but non-integer floating point is
 * the single most common source of cross-language signature divergence, so TAP
 * forbids it outright: fractional quantities travel as strings ("0.71"). This
 * guard exists because the rule is only worth anything if a Signer REFUSES to sign
 * a violating body — a TypeScript signer without it silently emitted records the
 * specification forbids, which a Python verifier could still verify, leaving the
 * divergence to surface later as a checkpoint that would not reconcile.
 */
export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "CanonicalizationError";
  }
}

const MAX_SAFE = Number.MAX_SAFE_INTEGER; // 2^53 - 1

export function canonicalGuard(value: unknown, path = ""): void {
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new CanonicalizationError(`non-finite number in a signed body at ${path || "<root>"}`);
    }
    if (!Number.isInteger(value)) {
      throw new CanonicalizationError(
        `fractional numbers are forbidden in a signed body (at ${path || "<root>"}); encode as a string`,
      );
    }
    if (Math.abs(value) > MAX_SAFE) {
      throw new CanonicalizationError(
        `integer ${value} at ${path || "<root>"} exceeds the +/-(2^53-1) safe range`,
      );
    }
    return;
  }
  if (value === null || typeof value !== "object") return;
  if (Array.isArray(value)) {
    value.forEach((v, i) => canonicalGuard(v, `${path}[${i}]`));
    return;
  }
  for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
    canonicalGuard(v, `${path}.${k}`);
  }
}

export function signingInput(body: Record<string, unknown>): Uint8Array {
  const { sig: _omit, ...rest } = body as Record<string, unknown>;
  const canon = canonicalize(rest); // RFC 8785
  if (canon === undefined) throw new Error("canonicalization failed");
  return utf8(canon);
}

export async function signEvent<T extends Record<string, unknown>>(
  seedHex: string,
  body: T,
): Promise<T & { sig: string }> {
  const { sig: _omit, ...rest } = body as Record<string, unknown>;
  canonicalGuard(rest); // refuse to sign a body the spec forbids [TAP-CANON-NUMBERS]
  const sig = await ed.signAsync(signingInput(body), fromHex(seedHex));
  return { ...body, sig: b64u(sig) };
}

/**
 * Exact-match scope check [TAP-SCOPE-MATCH].
 *
 * v0.1 matches scope tokens by exact string equality: no wildcards, no prefix rule,
 * no case folding, and `read:database` does NOT cover `read:database.users`. This is
 * the narrowest possible rule on purpose — a matching semantics that grants more
 * than it literally says would be privilege escalation in the one check TAP performs
 * itself. Richer schemes belong in a Service Profile.
 */
export function scopeSatisfied(scopeUsed: string | null | undefined, passportScope: string[]): boolean {
  return scopeUsed == null || passportScope.includes(scopeUsed);
}

/**
 * Verify one Event [TAP-EVT-VERIFY].
 *
 * Suite dispatch and the revocation boundary are part of verification, not a layer
 * above it: a primitive that skips either does not conform, however faithfully a
 * caller might re-implement them elsewhere.
 */
export async function verifyEvent(jwk: Jwk, event: Record<string, unknown>): Promise<boolean> {
  suiteForJwk(jwk); // dispatch off the declared suite; throws on unknown [TAP-SUITE-DISPATCH]
  checkNotRevoked(jwk, event.ts as string | undefined);
  const ok = await ed.verifyAsync(
    b64uToBytes(event.sig as string),
    signingInput(event),
    b64uToBytes(jwk.x),
  );
  if (!ok) throw new Error("event signature invalid");
  if (event.kid !== jwk.kid) throw new Error("kid mismatch");
  return true;
}
