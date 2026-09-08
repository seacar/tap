// Authority binding — bind one Event to a pre-declared expected effect
// [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL].
//
// `policy_decision` proves a *class* of action was permitted under the rules
// in force. It does not prove a specific, authentically-signed instance stayed
// within what was actually approved *for that instance* — a Signer holding a
// validly-scoped Passport and a compliant policy decision can still take an
// authentic action nobody approved for that particular case. Authority
// binding is that missing claim: it binds one Event to one pre-declared
// expected outcome, under a specific version of the authority that granted
// it, valid only for a bounded window. `policy_decision` and `authorization`
// compose freely — an Event MAY carry either, both, or neither.
//
// PROVISIONAL. The wire shape and the two STATELESS checks here
// (`checkAuthorityWindow`, `authorityEffectLabel`) mirror the reference
// implementation in tap_ref.py and sdk/python/src/tap_sdk/authority.py as of
// protocol v0.1.4, reproducing the same `test-vectors.json -> authorization`
// vector. `[TAP-AUTHORITY-REVOKE]` and `[TAP-AUTHORITY-REUSE]` are STATEFUL (a
// registry of revoked/consumed authz_ids) and are therefore a
// Verifier/Service-Profile concern, not this SDK's — no production Verifier
// enforces them yet. Track status in tap/CHANGELOG.md.

import canonicalize from "canonicalize";
import { digest, jsonDigest, newId } from "./tap.js";

/** The exact JSON shape stamped onto an Event's `authorization` field. */
export interface AuthorizationRecord {
  authz_id: string;
  authority_state_version: string;
  target_state_digest: string;
  nbf: number;
  exp: number;
  issuer_kid: string;
}

/**
 * A bound approval [TAP-EVT-AUTHORIZATION, §9.2]: one action, one
 * pre-declared expected effect, one version of the authority that granted it,
 * valid only for a bounded window.
 *
 * The signed body never carries the raw expected state — only its digest,
 * matching the digest-only discipline of the rest of the envelope
 * [TAP-EVT-ENVELOPE]. Plaintext, where retained, belongs in the annex.
 */
export class Authorization {
  constructor(
    public readonly authzId: string,
    public readonly authorityStateVersion: string,
    public readonly targetStateDigest: string,
    public readonly nbf: number,
    public readonly exp: number,
    public readonly issuerKid: string,
  ) {}

  /**
   * Mint a new approval binding `targetState` under `authorityState`.
   *
   * `targetState` and `authorityState` are digested here, once, so every
   * other layer only ever sees the digest — a caller cannot accidentally leak
   * the raw state into a signed body.
   */
  static grant(args: {
    targetState: unknown;
    authorityState: unknown;
    nbf: number;
    exp: number;
    issuerKid: string;
    authzId?: string;
  }): Authorization {
    return new Authorization(
      args.authzId ?? newId("auz"),
      authorityStateVersion(args.authorityState),
      jsonDigest(args.targetState),
      args.nbf,
      args.exp,
      args.issuerKid,
    );
  }

  toRecord(): AuthorizationRecord {
    return {
      authz_id: this.authzId,
      authority_state_version: this.authorityStateVersion,
      target_state_digest: this.targetStateDigest,
      nbf: this.nbf,
      exp: this.exp,
      issuer_kid: this.issuerKid,
    };
  }

  static fromRecord(record: AuthorizationRecord): Authorization {
    return new Authorization(
      record.authz_id,
      record.authority_state_version,
      record.target_state_digest,
      record.nbf,
      record.exp,
      record.issuer_kid,
    );
  }
}

/**
 * Content-hash an authority/policy state to its version digest.
 *
 * The SAME construction as the Python SDK's `policy_version` /
 * `authority_state_version` — `sha256(JCS(state))` — scoped to one approval
 * rather than the whole active policy set, so an auditor can prove *which*
 * authority state governed a specific approval.
 */
export function authorityStateVersion(state: unknown): string {
  const canon = canonicalize(state);
  if (canon === undefined) throw new Error("canonicalization failed");
  return digest(canon);
}

/**
 * The current time falls outside an authorization's validity window
 * [TAP-AUTHORITY-VALIDITY], with the same +/-60s skew allowance as Passport
 * freshness [TAP-PASSPORT-VALIDATE].
 */
export class AuthorityExpired extends Error {
  constructor(
    public readonly authorization: AuthorizationRecord,
    public readonly now: number,
  ) {
    super(
      `authorization ${authorization.authz_id} outside validity window: ` +
        `nbf=${authorization.nbf} exp=${authorization.exp} now=${now}`,
    );
    this.name = "AuthorityExpired";
  }
}

/**
 * Enforce the validity window [TAP-AUTHORITY-VALIDITY]:
 *
 *     nbf - 60 <= now < exp + 60
 *
 * the same inequality and skew allowance as Passport freshness
 * [TAP-PASSPORT-VALIDATE]. Throws {@link AuthorityExpired} outside it, and
 * {@link AuthorityMalformed} when the block is not a usable approval at all.
 *
 * This is an enforcement point reached with untrusted input (the unsigned
 * `X-TAP-Authorization` header, §11.1), so a malformed block fails closed rather
 * than producing `NaN` comparisons that quietly evaluate to "outside the window"
 * for the right reason by accident, or "inside" for the wrong one.
 */
export function checkAuthorityWindow(
  authorization: Authorization | AuthorizationRecord,
  now: number,
): void {
  if (
    authorization === null ||
    typeof authorization !== "object" ||
    Array.isArray(authorization)
  ) {
    throw new AuthorityMalformed(
      `authorization must be an object, got ${Array.isArray(authorization) ? "array" : typeof authorization}`,
    );
  }
  const rec = authorization instanceof Authorization ? authorization.toRecord() : authorization;
  if (!Number.isInteger(rec.nbf) || !Number.isInteger(rec.exp)) {
    throw new AuthorityMalformed("authorization nbf/exp must be integer epoch seconds");
  }
  if (!(rec.nbf - 60 <= now && now < rec.exp + 60)) {
    throw new AuthorityExpired(rec, now);
  }
}

/**
 * The `authorization` block is present but is not a usable approval.
 *
 * Thrown only by the *enforcement* path ({@link checkAuthorityWindow}), which is
 * reached with attacker-supplied input from `X-TAP-Authorization` /
 * `_meta.tap.authorization` and must fail closed. The *labeling* path
 * ({@link authorityEffectLabel}) never throws — it is a verifier reading records
 * it did not choose, where one poisoned block must not end the report.
 */
export class AuthorityMalformed extends Error {
  constructor(message: string) {
    super(message);
    this.name = "AuthorityMalformed";
  }
}

/**
 * `authz_id` or `authority_state_version` names a revoked approval
 * [TAP-AUTHORITY-REVOKE], and this record is timestamped (by its own signed
 * `ts`) at or after the revocation boundary — the same effective-time-boundary
 * mechanism as key revocation [TAP-KEY-REVOCATION], applied to an approval
 * instead of a signing key.
 */
export class AuthorityRevoked extends Error {
  constructor(
    public readonly revokedId: string,
    public readonly revokedAt: number,
    public readonly signedTs: number,
  ) {
    super(`${revokedId} revoked at ${revokedAt}; record is timestamped ${signedTs}`);
    this.name = "AuthorityRevoked";
  }
}

/**
 * Enforce the revocation boundary [TAP-AUTHORITY-REVOKE].
 *
 * `revokedAt` is an ALREADY-RESOLVED boundary for whichever of `authzId` or
 * `authorityStateVersion` the caller looked up — this function performs no
 * lookup itself and holds no registry. Publication format and query interface
 * are a Service Profile concern (spec §9.2, §15); this is only the
 * comparison. Pass `null`/`undefined` when nothing is known to be revoked.
 *
 * Throws {@link AuthorityRevoked} when `signedTs >= revokedAt` — an
 * effective-time boundary, not blanket repudiation: a record signed before
 * the boundary stays valid, same as key revocation.
 */
export function checkAuthorityNotRevoked(
  authzId: string,
  authorityStateVersion: string,
  revokedAt: number | null | undefined,
  signedTs: number,
): void {
  if (revokedAt === null || revokedAt === undefined) return;
  if (signedTs >= revokedAt) {
    throw new AuthorityRevoked(authzId || authorityStateVersion, revokedAt, signedTs);
  }
}

/**
 * Label an Event's authority-binding outcome [TAP-AUTHORITY-EFFECT] by
 * comparing `result.effect_digest` against `authorization.target_state_digest`.
 *
 * Returns `null` when no `authorization` is present (the label does not
 * apply); otherwise one of `"authorized_match"` / `"authorized_mismatch"` /
 * `"unverified_authority"`. Reported ALONGSIDE two-sided assurance
 * [TAP-ASSURANCE], never in place of it — an Event can be independently
 * two-sided (execution attested by an independent key) and simultaneously
 * `authorized_mismatch` (the attested execution did something other than what
 * was approved). That combination is exactly the failure two-sided
 * attestation alone cannot see, because it only asks who signed, never what
 * was approved.
 */
export type AuthorityEffect =
  | "authorized_match"
  | "authorized_mismatch"
  | "unverified_authority"
  | "malformed_authority";

export function authorityEffectLabel(
  authorization: Authorization | AuthorizationRecord | null | undefined,
  result: { effect_digest?: string | null } | null | undefined,
): AuthorityEffect | null {
  if (authorization === null || authorization === undefined) return null;
  // `authorization` arrives from a signed body, and a valid signature says
  // nothing about a block's SHAPE — a hostile or buggy Signer can sign
  // `"authorization": {}` or `"authorization": "hello"` just as validly. A
  // verifier that throws on those is a verifier one poisoned event can take
  // down, which is why this returns a label rather than propagating.
  let target: unknown;
  if (authorization instanceof Authorization) {
    target = authorization.targetStateDigest;
  } else if (typeof authorization === "object" && !Array.isArray(authorization)) {
    target = (authorization as AuthorizationRecord).target_state_digest;
  } else {
    return "malformed_authority";
  }
  if (typeof target !== "string") return "malformed_authority";
  const effect = result?.effect_digest;
  if (effect === undefined || effect === null) return "unverified_authority";
  return effect === target ? "authorized_match" : "authorized_mismatch";
}
