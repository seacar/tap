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

// --- crypto-suite dispatch & revocation (spec §3.2, §3.6, §15) ---------------

/**
 * The key declares a crypto suite this implementation does not recognize.
 * A conforming verifier MUST reject it rather than fall back to a default
 * (spec §15) — verification dispatches off the key's declared suite so that
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

/** Resolve a JWK's declared (alg, crv) to a TAP suite id, or throw. */
export function suiteForJwk(jwk: Partial<Jwk>): string {
  const suite = SUITES.get(`${jwk.alg}|${jwk.crv}`);
  if (suite === undefined) throw new UnknownSuite(jwk.kid, jwk.alg, jwk.crv);
  return suite;
}

/** Optional epoch-seconds revocation boundary for a key (spec §3.2). */
export function keyRevokedAt(jwk: Partial<Jwk>): number | null {
  return jwk.revoked_at === undefined || jwk.revoked_at === null
    ? null
    : Number(jwk.revoked_at);
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

/** Crockford base32 id with prefix, e.g. ``key_01H...`` */
export function newId(prefix: string): string {
  const ts = b32(Date.now(), 10);
  let rand = "";
  for (let i = 0; i < 16; i++) rand += CROCKFORD[Math.floor(Math.random() * 32)];
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
  const [h, p, s] = token.split(".");
  const ok = await ed.verifyAsync(b64uToBytes(s), utf8(`${h}.${p}`), b64uToBytes(jwk.x));
  if (!ok) throw new Error("passport signature invalid");
  const header = JSON.parse(new TextDecoder().decode(b64uToBytes(h)));
  const claims = JSON.parse(new TextDecoder().decode(b64uToBytes(p)));
  if (header.typ !== PASSPORT_TYP) throw new Error("wrong token type");
  if (header.kid !== jwk.kid) throw new Error("kid mismatch");
  const revoked = keyRevokedAt(jwk);
  if (revoked !== null && (claims.iat as number) >= revoked)
    throw new Error("key revoked as of iat");
  if (!((claims.iat as number) - 60 <= now && now < (claims.exp as number) + 60))
    throw new Error("passport expired / not yet valid");
  return claims;
}

// --- event (detached sig over JCS canonical body) ---------------------------

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
  const sig = await ed.signAsync(signingInput(body), fromHex(seedHex));
  return { ...body, sig: b64u(sig) };
}

/** True when ``scope_used`` is authorized by the passport scope list (TAP-spec §8). */
export function scopeSatisfied(scopeUsed: string | null | undefined, passportScope: string[]): boolean {
  return scopeUsed == null || passportScope.includes(scopeUsed);
}

export async function verifyEvent(jwk: Jwk, event: Record<string, unknown>): Promise<boolean> {
  suiteForJwk(jwk); // dispatch off the declared suite; throws on unknown (§3.6, §15)
  const ok = await ed.verifyAsync(
    b64uToBytes(event.sig as string),
    signingInput(event),
    b64uToBytes(jwk.x),
  );
  if (!ok) throw new Error("event signature invalid");
  if (event.kid !== jwk.kid) throw new Error("kid mismatch");
  return true;
}
