# Changelog

All notable changes to the Traceable Agent Protocol — the specification, the reference implementation, the conformance vectors, and both SDKs.

## Versioning

Three version numbers appear in TAP and mean different things:

| Version | Changes when |
|---|---|
| **Wire version** (`v` field, `tap/0.1`) | The envelope changes such that a conforming Verifier cannot process it under the old version. Negotiated per `[TAP-NEGOTIATE]`. |
| **Document version** (this changelog) | Any correction to the specification or whitepaper. |
| **Package versions** (`traceable-agent-protocol`, `@traceableagent/sdk`) | Any SDK release. |

A document patch release does **not** normally change signed bytes. **v0.1.2 is a deliberate exception**, listed in full below. Any *future* signed-byte change requires a wire-version bump.

---

## [0.1.4] — 2026-08-29

Gives §9.2 authority binding (v0.1.3) a reference implementation for its **stateless** half. No existing signed bytes change — this only adds new code paths and one new, independent vector case.

### Added

- **`tap_ref.py`**: signs and verifies an Event carrying `authorization`; `check_authority_window` (`[TAP-AUTHORITY-VALIDITY]`) and `authority_effect_label` (`[TAP-AUTHORITY-EFFECT]`) as pure functions, the same shape as `checkpoint_root` — no state, no registry lookup.
- **`test-vectors.json` → `authorization`**: a new, independent top-level case (a server-attested `issue_refund` tool_call bound to a declared expected effect), plus fixture data for the validity-window boundaries and the match/mismatch/unverified effect labels, so other implementations have fixed numbers to test against without needing their own seed. **Verified byte-for-byte**: every pre-existing key in `test-vectors.json` (`event`, `decision`, `checkpoint`, `canonicalization`, `negative`, `jwks`, `passport`, `cid_construction`) is unchanged; `authorization` is a pure addition and `_spec_version` is the only pre-existing value that changed.
- **`schemas/event.schema.json`**: an `authorizationBlock` `$def` and `result.effect_digest`, both documented as provisional.
- **`registries/result-codes.json`**: `DENIED_AUTHORITY_EXPIRED` / `DENIED_AUTHORITY_REVOKED` / `DENIED_AUTHORITY_REUSED`, marked `"provisional": true`.
- **CI**: `scripts/check-spec-vectors.py` and `scripts/check-schemas.py` now cover the `authorization` case like every other one.

### Still not implemented anywhere

`[TAP-AUTHORITY-REVOKE]` and `[TAP-AUTHORITY-REUSE]` are stateful (a registry of revoked/consumed ids) and stay unbuilt — that is a Verifier/Service-Profile concern, not this file's. No production Signer, Verifier, or SDK implements any part of §9.2 yet; it remains **provisional** and out of §14's Conformance table.

---

## [0.1.3] — 2026-08-29

A specification-only release: it defines the wire shape and verification rules for **authority binding** (spec §9.2, whitepaper §9.2 — both marked provisional) but ships no reference implementation. `tap_ref.py`, both SDKs, and `test-vectors.json` are unchanged.

**No existing signed bytes change.** Everything added is OPTIONAL and omitted per `[TAP-EVT-OMIT]` when unused, so every v0.1.2 record and every existing conformance vector remains valid and unmodified.

### Why now

`policy_decision` (§9.1) proves a *class* of action was permitted under the rules in force. It does not prove a specific, authentically-signed instance stayed within what was actually approved for it — a valid Passport plus a compliant policy decision is not the same claim as "the approved effect is the effect that landed." Authority binding is that missing claim, layered onto the existing record rather than replacing it: `policy_decision` and `authorization` compose freely, and an Event can be simultaneously `two-sided` (§7 — an independent party attested the execution happened) and `authorized_mismatch` (§9.2 — what it did wasn't the thing anyone signed off on). That combination is precisely the gap two-sided attestation alone cannot see, since it only asks who signed, never what was approved.

### Added

- **The `authorization` block** (`[TAP-EVT-AUTHORIZATION]`) — an OPTIONAL Event field binding one action to a pre-declared expected outcome (`target_state_digest`), a versioned authority state (`authority_state_version`, the same digest construction as `policy_version`, §9.1), and a bounded validity window (`nbf`/`exp`, the same 60s skew discipline as Passport `[TAP-PASSPORT-VALIDATE]`).
- **`result.effect_digest`** — an OPTIONAL digest of the actual resulting state, computed the same way `target_state_digest` was declared, and comparable against it. `[TAP-AUTHORITY-EFFECT]` defines the resulting `authorized_match` / `authorized_mismatch` / `unverified_authority` labels.
- **Authority revocation** (`[TAP-AUTHORITY-REVOKE]`), reusing the same effective-time-boundary mechanism as `[TAP-KEY-REVOCATION]` rather than inventing a new trust model: a Verifier publishes `{ authz_id | authority_state_version, revoked_at }` entries, compared against the record's own signed `ts`.
- **Single-use enforcement** (`[TAP-AUTHORITY-REUSE]`) for `authz_id`, mirroring Passport `jti` uniqueness (§8.2) applied to a per-action approval instead of a per-record credential.
- **Three provisional result codes** (§10): `DENIED_AUTHORITY_EXPIRED`, `DENIED_AUTHORITY_REVOKED`, `DENIED_AUTHORITY_REUSED`. Not yet in §14's Conformance table — they move there once a reference implementation and conformance vectors exist.
- **Whitepaper §9.2** — explanatory rationale for the same extension, framed as "provenance proves an action is authentic; authority binding proves it was legitimate."

### Not in this release

Everything above is schema and verification rules only. `tap_ref.py` support, SDK ergonomics, a conformance vector exercising `authorization`, and a Service Profile for how a Verifier actually publishes/queries the revocation resource are tracked as the next implementation slice.

---

## [0.1.2] — 2026-07-30

A correctness release. v0.1.0 shipped a specification that disagreed with its own reference implementation in several places, several MUSTs that no implementation satisfied, and a conformance suite that did not exercise most of the contract it published. This release closes those gaps.

**The wire version stays `tap/0.1`**, because v0.1 has no production deployments to strand. Records signed under v0.1.0 still verify individually; they will differ structurally from v0.1.2 records for the reasons listed under *Changed signed bytes*.

### Changed signed bytes

Every change here regenerates `test-vectors.json`. Each corrects a place where the document and the reference implementation disagreed, or where the contract was under-specified.

- **`evidence.nego` carries `suite`, not `alg`.** §6.1's example showed a JOSE `alg` value; the reference implementation emitted a TAP suite id, and §4.1's prose said "suite". The suite id is correct — a `nego` block that named a JOSE algorithm could not express a future suite at all. The handshake fields are `suites`/`suite` to match; `algs`/`alg` are still accepted on input.
- **Absent optional fields are omitted, never `null`** — now normative as `[TAP-EVT-OMIT]`, with a per-field table distinguishing *omit-when-absent* from *explicitly nullable*. `null` and absent are different signed bytes, so two conforming Signers were producing structurally different Events for logically identical actions. Both verified. Their checkpoint roots could never have matched.
- **`checkpoint.from_seq` is REQUIRED.** The sealed interval is now self-describing — `(from_seq, through_seq]` — so a Verifier can reconcile a checkpoint without reconstructing the state of whichever checkpoint preceded it. Previously a verifier had to infer the lower bound, and got it wrong whenever an earlier checkpoint was lost or suppressed.
- **The checkpoint vector is internally coherent.** It claimed `through_seq: 8, count: 2` with no predecessor, implying an interval of eight events that contained two. It now declares `from_seq: 6`.
- **The reference issuer is `https://verifier.example.com`**, not a vendor hostname. A vendor-neutral conformance contract should not bake in one operator's domain.

### Added

- **A canonicalization conformance vector** exercising RFC 8785's hard half: non-BMP characters, surrogate pairs, C0 escaping, NFC/NFD (JCS does not normalize), and member ordering by UTF-16 code unit — where a non-BMP key orders by its *leading surrogate* and so sorts below `U+FB03` despite the larger code point. The vectors previously contained **zero non-ASCII content**, leaving the most divergence-prone part of the standard entirely untested. Both SDKs now agree on it byte-for-byte.
- **A `negative` section in the conformance vectors** — nine cases, each declaring its own expected outcome (`reject` / `accept` / `flag`). Reproduction alone proved only that an implementation can *sign* like the reference; a verifier that accepted everything passed every vector. Both SDKs run the same cases from the same file.
- **The `[TAP-NEGOTIATE]` handshake, implemented.** `tap_hello` / `tap_hello_ack` over both bindings (`X-TAP-Hello` headers and `_meta.tap.hello`), in both SDKs, in `TAPServer`, and in the Gateway. It previously existed only in the specification, while §14 listed it as a Server MUST and the `nego` binding attested to a negotiation that never happened on the wire.
- **`nego` in the TypeScript SDK**, closing a divergence on a spec MUST.
- **A TypeScript verifier** (`sdk/js/src/verify.ts`): assurance labelling with the full consistency predicate, `nego` violation detection, chain reconstruction, checkpoint reconciliation, and the audit report. Browser-safe, no Node built-ins — "any relying party can re-verify with only a public key" now means one that does not need a Python environment.
- **`emitCheckpoint` in the TypeScript SDK.** A Signer MUST seal every record; TypeScript previously had no way to emit a checkpoint at all, so a TS-signed record could never be sealed and every gap in it stayed permanently ambiguous.
- **Stable anchor tags** (`[TAP-EVT-ENVELOPE]`, `[TAP-KEY-REVOCATION]`, …) on every normative rule. Code cites the tag; section numbers move.
- **Machine-readable registries and schemas**: `registries/suites.json`, `registries/result-codes.json`, `schemas/{event,passport,annex}.schema.json`, and an example `.well-known/jwks.json` showing a revoked key still published.
- **Tests for the Gateway and the Inspector**, and both in CI. Neither had a single test.
- **CI guards** that the specification's quoted signatures match the vectors, that the schemas describe the vectors, that both packages install and import from a clean environment, and that the two SDKs **compose** identical bytes for the same logical action — not merely that each can re-sign a body the other composed.

### Fixed

- **Key revocation is enforced by the verification primitives.** `[TAP-KEY-REVOCATION]` is part of verification, but neither `tap_ref.verify_event` nor either SDK core checked it for Events — only a higher-level Python module did. Anyone using the documented primitive got no check at all. Now enforced in all three, against the Event's own signed `ts`, with a distinct `RevokedKey` error and explicit coverage that revocation is an effective-time boundary rather than blanket repudiation.
- **The TypeScript signer enforces the no-fractional-numbers rule.** `signEvent` had no canonicalization guard, so a TS signer silently emitted records the specification forbids.
- **Checkpoint reconciliation respects the interval's lower bound.** It gathered every event with `seq ≤ through_seq`, so with two or more checkpoints the second necessarily mismatched and the record was reported as containing provably-deleted events — a false accusation manufactured by the verifier's own bookkeeping.
- **A root mismatch is no longer reported as provable deletion.** They are distinct signals: a mismatch says the delivered set is wrong; provable deletion names a specific committed `event_id` that never arrived. Conflating them overstates the evidence.
- **The server leg emits a conforming envelope.** It put **raw intent plaintext** in the signed body — the exact thing the digest-only rule and the annex exist to prevent — and digested arguments with `json.dumps(sort_keys=True)` rather than JCS, so the two legs of one action digested identical arguments differently and could never have been correlated on them.
- **The replay cache is keyed on `jti` and `(aid, seq)`**, per `[TAP-REPLAY]`, with a TTL. It was keyed on `action_ref`, which a replayer simply regenerates, in an unbounded set that any caller able to mint identifiers could grow without limit.
- **Identifiers use a CSPRNG in TypeScript.** `newId` drew from `Math.random()`; these values become `event_id`s and `action_ref`s that checkpoint roots commit to.
- **The specification's §6.6 reference table was stale** — it published a `tool_call` signature that did not match the committed vectors, and nothing detected it. CI now compares them.
- **Scope matching is defined.** `[TAP-SCOPE-MATCH]`: exact string equality, no wildcards, no prefixes. Both SDKs already behaved this way; the specification never said so.
- **The clock-skew allowance is written as an inequality** (`iat − 60 ≤ now < exp + 60`) rather than prose admitting two readings.
- **Documentation coherence.** ~40 code citations pointed at section numbers that no longer meant what they said, 13 of them at Sworn's *private* build spec. Competitive-positioning prose was removed from the vendor-neutral SDK. Truncated comments left by the repo-extraction script, and its now-broken source tree, are gone.

### Notes for implementers

If you built against v0.1.0: re-run against the regenerated vectors. Your signatures will differ if you emitted explicit nulls, used `alg` in `nego`, or omitted `checkpoint.from_seq` — each of which is now testable rather than merely described.

The whitepaper is now explicitly **explanatory, not normative**. Where it and the specification disagree, the specification governs; where the specification and `test-vectors.json` disagree on signed bytes, the vectors govern.

---

## [0.1.0] — 2026-06-08

Initial draft: specification, whitepaper, reference implementation, conformance vectors, Python and TypeScript SDKs, Gateway, and Inspector.
