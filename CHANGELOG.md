# Changelog

All notable changes to the Traceable Agent Protocol — the specification, the reference implementation, the conformance vectors, and both SDKs.

## Versioning

Three version numbers appear in TAP and mean different things:

| Version | Changes when |
|---|---|
| **Wire version** (`v` field, `tap/0.1`) | The envelope changes such that a conforming Verifier cannot process it under the old version. Negotiated per `[TAP-NEGOTIATE]`. |
| **Document version** (this changelog) | Any correction to the specification or whitepaper. |
| **Package versions** (`traceable-agent-protocol`, `@traceableagent/sdk`) | Any SDK release. All three are 0.1.5; they had drifted apart. |

A document patch release does **not** normally change signed bytes. **v0.1.2 is a deliberate exception**, listed in full below. Any *future* signed-byte change requires a wire-version bump.

---

## [Unreleased]

Gives §9.2 authority binding TypeScript and Go parity with the Python SDK, makes it visible in the Inspector, closes the MCP scope question, gives TypeScript its own MCP client-side wrapper, lets `authorization` cross the Gateway's HTTP boundary, and adds resolver-based revocation detection plus batch-local and Gateway-side reuse detection. No signed bytes change — `test-vectors.json` is unmodified; every SDK tests against the *same* fixed numbers, and the new Gateway header/field are OPTIONAL and additive.

### Added

- **`sdk/js/src/authority.ts`**: TypeScript port of `authority.py` — `Authorization`, `authorityStateVersion`, `checkAuthorityWindow` (`[TAP-AUTHORITY-VALIDITY]`), `authorityEffectLabel` (`[TAP-AUTHORITY-EFFECT]`). Wired into `TAPClient.authorize()` and `TAPClient.traceTool()` (mirrors Python's `trace(authorize=, effect_of=)`: blocks *before acting* on an expired approval and emits a signed `denied`/`DENIED_AUTHORITY_EXPIRED` event, same as the Python SDK), and into `verify.ts`'s `evaluateEvent` (adds `authorization`/`authority_effect` to `EventEvaluation`, matching Python's `evaluate_event`).
- **`sdk/go/tap/authority.go`**: the same port for Go — `Authorization`, `GrantAuthorization`, `AuthorityStateVersion`, `CheckAuthorityWindow`, `AuthorityEffectLabel`. Purely functional, matching the rest of the Go SDK's primitives style (no client wrapper exists in Go yet, so there is no `authorize()`/`traceTool()` equivalent here).
- **`sdk/js/test/authority.test.ts`**, **`sdk/go/tap/authority_test.go`**, and a new case in **`sdk/python/tests/test_authority.py`**: all three now assert against `test-vectors.json -> authorization`'s own `validity_window` and `effect_check` fixed numbers (not just each SDK's own freely-chosen `nbf`/`exp`), which is what actually proves they agree on the boundary rather than each independently satisfying its own logic.
- **Inspector**: `build_record_from_local` now carries `authorization`/`authority_effect` through to the record it assembles, and `render_chain_ascii` displays the bound `authz_id` and effect label on any event that carries one. Display-only — no enforcement, matching the Inspector's existing scope.
- **`sdk/js/src/instrumentMcp.ts`**: TypeScript port of Python's `TAPClient.instrument_mcp` — wraps an MCP client's `callTool` to emit a signed `tool_call` Event, using the caller's own key. No `@modelcontextprotocol/sdk` dependency, no server, no key custody beyond the caller's own `TAPClient`. This is the *only* MCP-related addition in this release.
- **`docs/architecture.md`**: a new section explicitly stating that a hosted MCP server exposing TAP operations as callable tools (sign/verify/check-authority/revoke) is a Sworn product concern, not a protocol one — a hosted signer would require custodying every caller's key, which is the exact centralization TAP exists to avoid, and revocation is stateful for the same reason key revocation is. Closes the "should TAP have an MCP server" question raised during authority-binding follow-up work, in writing, so it isn't re-litigated per contributor.

**Gateway carriage for `authorization`** (§11.1/§11.2, spec updated): a new OPTIONAL `X-TAP-Authorization: <json>` header (and the JSON-RPC `_meta.tap.authorization` sibling), carried the same JSON-in-a-header way `X-TAP-Hello` already is — this block has no signature of its own, it's only ever evidence once embedded in a signed Event.
- **`negotiate.py`/`negotiate.ts`**: `authorization_headers`/`authorizationHeaders` + `authorization_from_headers`/`authorizationFromHeaders`, reusing the existing generic `to_header`/`from_header` JSON carriage — no new serialization code.
- **`Passport.http_headers()`/`.meta()`** (Python) and **`passportHttpHeaders()`/`passportMeta()`** (TS): accept an optional `authorization` alongside the existing `hello`.
- **`gateway/app.py`**: reads `X-TAP-Authorization`, validates its shape (a malformed/partial header degrades to absent — same discipline as a malformed hello — rather than crashing the request), strips it from the upstream-forwarded request, and passes it to `TAPServer.attest()`.
- **`TAPServer.attest()`/`_emit()`**: a new `authorization` parameter, echoed onto every Event the call emits (denials included) — so a Verifier gets two independently-signed records referencing the same `authz_id`, not just the agent's own say-so. Also applies `[TAP-AUTHORITY-VALIDITY]` at this accept boundary (`DENIED_AUTHORITY_EXPIRED`) — defense in depth on top of whatever the agent already checked before signing, since nothing here can compel a non-compliant Signer to have checked at all.

**Revocation and reuse detection** (§9.2, both still provisional — see the spec's updated status callout for exactly what remains open):
- **`authority.py`/`.ts`/`.go`**: `check_authority_not_revoked`/`checkAuthorityNotRevoked`/`CheckAuthorityNotRevoked` — a pure `(authz_id, authority_state_version, revoked_at, signed_ts) -> raise|throw|error` boundary check, same effective-time-boundary math as key revocation (`signed_ts >= revoked_at`), but taking an ALREADY-RESOLVED `revoked_at` rather than a registry. This repo ships no default revocation store — publication format and query interface stay a Service Profile concern, per the spec text (`TAP-spec-v0.1.md:582-586`); embedding `revoked_at` on the `Authorization` record itself (the way key revocation embeds it on a JWK) would let whoever controls the record self-declare non-revocation, so it needs an external lookup instead.
- **`verify.py`/`verify.ts`**: a new `AuthorityRevocationResolver` type mirroring `KeyResolver`'s shape (`(authz_id, authority_state_version) -> revoked_at | None`). An optional `resolve_authority_revocation` parameter on `evaluate_event`/`evaluateEvent` and `verify_transcript`/`verifyTranscript` surfaces a new `authority_revoked` signal — kept separate from `authority_effect` (a revoked-but-matching Event is a worse signal than a mismatch, not a non-signal) and never flips `sig_valid` (the signature stays authentic; only the claimed authority is void).
- **`verify_transcript`/`verifyTranscript`**: batch-local `[TAP-AUTHORITY-REUSE]` detection — a duplicate `authz_id` across two sig-valid events in one delivered report, the same shape and spot as the existing `seq_duplicate` check. Needs no registry; works offline (Inspector, an audit report) today. Surfaced as a new `authority_reuse` list.
- **`TAPServer`**: a second, separate `_authz_seen` tracking dict (deliberately not folded into the existing `_seen` replay cache — reuse must stay rejected for the approval's own validity window, not the shorter generic passport replay TTL) enforcing single-use at the Gateway's own accept boundary, denying a repeat `authz_id` with `DENIED_AUTHORITY_REUSED`.
- **Inspector**: `core.make_revocation_resolver` loads a local `{id: revoked_at}` JSON map (a debugging convenience, explicitly not a registry this repo operates) and wires it into `core.verify()`/`build_record_from_local()`; `render_chain_ascii` marks a flagged event `REVOKED`. New `inspector verify --revocations` / `inspector show-chain --revocations` CLI flags.

### Still not implemented anywhere

A full cross-session reuse registry over *agent-submitted* events (as opposed to the Gateway's own accept-point, which is now covered) needs a hosted ingest Verifier — a Service Profile's job, not this repo's. No default revocation registry ships, by design (see above). Nothing independently signs the `authorization` block on behalf of `issuer_kid` — see the spec's updated §9.2 status callout for why that limits what revocation/reuse enforcement actually proves. §9.2 remains **provisional** and out of §14's Conformance table. No MCP server exists or is planned in this repository.

---

## [0.1.5] — 2026-09-07

A review of the repository against its own specification. **No signed bytes change** — `test-vectors.json` is byte-for-byte identical except `_spec_version`, and every existing vector case is untouched. Everything here is either a defect fix, a rule the spec always assumed but never stated, or a check that makes one of those testable.

Every defect below passed the full 22-check `ci-local.sh` suite at the time it was found. That is the theme: the checks tested the wrong things.

### Fixed — security

- **A Signer could forge `two-sided` assurance with its own key.** `assurance_level`/`assuranceLevel` partitioned legs on the self-declared `attestor` string and never compared `kid`, so an agent emitting a second leg with `attestor: "server"`, signed by its own key, was labeled `two-sided` and `verified: true`. That is precisely the property §7 says a compromised Signer cannot forge. Both SDKs now apply a structural floor (a `server` leg may not share a correlated agent leg's `kid`) and accept an optional `is_server_key`/`isServerKey` predicate naming the keys a deployment recognizes as a Server's — the real check, since an operator holding two keys clears the floor. A `conflicting` action now also makes `verified` false; it did not before. Spec: new `[TAP-ASSURANCE-KEY]`.
- **Every non-signature check in the Python `verify_passport` was an `assert`.** Under `python -O` / `PYTHONOPTIMIZE=1` — an ordinary production flag — it accepted an expired Passport bearing the wrong `typ` and a mismatched `kid`. All are now raised as typed errors (`InvalidRecord`, `PassportExpired`). `check_passport` no longer decides "expired" by searching an exception message for a substring, in either SDK.
- **`alg: none` in the JOSE header was accepted.** Both SDKs validated the resolving key's suite but never the header's `alg` — the field every historical algorithm-confusion attack targets, and the one RFC 8725 requires be checked. The existing `unknown_suite_alg_none` vector only ever covered the JWK. Spec §3.1/§5.3 now say so explicitly.
- **An unsigned `_meta.tap.cid` could redirect a delegation chain.** `accept_a2a_delegation` preferred the unsigned `_meta` hint over the sender's signed Passport, so a caller could graft a record onto an unrelated chain (§8.1) with every signature still verifying. The signed value now wins, and a contradicting hint is rejected. Spec: new `[TAP-REPLAY-CID]`.
- **The A2A replay cache implemented the failure §8.2 names by hand.** It keyed on `(jti, action_ref)` — and §8.2 already said keying on `action_ref` "does not implement this rule", because a replayer keeps the stolen passport and picks a fresh ref. It was also an unbounded `set`, against the same section's explicit "entries **MUST** expire". Now keyed on `jti` alone, with TTL expiry.

### Fixed — availability

- **`TAPServer` (and therefore the Gateway) rejected every action after the first under one Passport.** A Passport is minted per record and attached to every action (§4.2, §5), but the replay cache treated `jti` as single-presentation, so call #2 of every record returned `403 VALIDATION_ERROR`. Any agent calling more than one tool through a Gateway was broken. The cache is now keyed for its edge: `(aid, seq)` at an action edge, `jti` at a delegation edge (`replay_scope="delegation"`). Because `(aid, seq)` needs to cross the wire to be checkable, §11 gains `X-TAP-Seq` / `_meta.tap.seq` and `Passport.reserve_seq()` allocates the slot before dispatch. A call arriving without `seq` is accepted and counted in `replay_unenforceable` rather than being silently treated as checked. Spec: new `[TAP-REPLAY-EDGE]`, `[TAP-REPLAY-SEQ]`.
- **`TAPClient.flush()` and `close()` spun forever against an unreachable Verifier.** `_send` re-queued the batch it failed to deliver and `flush` re-drained it immediately — a hot loop at shutdown, directly against §11.3's "a Signer **MUST NOT** block execution on reporting availability". `flush(timeout_s=...)` now makes one bounded pass and returns; undelivered events stay queued and `failed_sends` records that delivery failed. The signer's private `_Reporter` (a near-copy of `transport.EventReporter` that had drifted) is gone; there is one reporter now.
- **A malformed `authorization` block crashed the Verifier.** A valid signature says nothing about a block's shape, and a hostile Signer can validly sign `"authorization": {}` or `"authorization": "hello"`; `authority_effect_label` subscripted it and raised, ending the whole report. One poisoned Event could silence an audit. It now returns a new `malformed_authority` label. The *enforcement* path (`check_authority_window`, which reads the unsigned `X-TAP-Authorization` header) fails closed instead, with a new `AuthorityMalformed`. Spec §5.3 gains the general rule.

### Fixed — the SDKs disagreed with the spec, and with each other

Each of these produced events that failed `schemas/event.schema.json`. Nothing had ever validated SDK-composed events against it — `check-schemas.py` validates the *vectors*, which `tap_ref.py` generates.

- **`result.latency_ms: null`** on every Python decision, checkpoint and model-response event, where TypeScript omitted the key. Different signed bytes for logically identical events, which is exactly what `[TAP-EVT-OMIT]` exists to prevent, and what `TAPServer._emit`'s own comment says must never happen between two legs of one action.
- **`action.kind: "model_response"`** in both SDKs — neither one of §6.2's seven registered kinds nor an `x-` namespaced extension. Now `x-model-response`.
- **`record_output` used `tool: "agent.run"` in Python and `"agent.record"` in TypeScript.** Now `agent.record` in both.
- **`attestation: "requested"` was bound into `evidence.nego`.** §4.1 is explicit that `requested` is an offer, never a selection, and that a Signer "**MUST NOT** bind an *aspiration*". `negotiate.read_ack` already refused it on the observed-ack path, so the two paths disagreed about one rule. `test_nego.py` asserted the wrong behaviour and has been corrected.

### Added — specification

Rules v0.1.4 assumed but never stated, each one a place two implementers would have silently disagreed:

- `[TAP-ASSURANCE-KEY]` — key independence for `server` legs (above).
- `[TAP-ASSURANCE-SEQ]` — `seq` is monotonic per `(aid, attestor)`, not per `aid`. The agent and server legs of one action share an `aid` but come from different Signers with independent counters, so a Verifier pooling them reports a duplicate `(aid, seq)` on every correct two-sided record. `verify_transcript` did exactly that; `inspector/core.py` already worked around it, so the two disagreed.
- `[TAP-EVT-CHECKPOINT-LEAVES]` — a `checkpoint` Event consumes a `seq`, so a later checkpoint's interval contains earlier ones; they are **never** Merkle leaves, and `count` counts non-checkpoint Events. Both SDKs and `tap_ref.py` already behaved this way and nothing said so, so a third implementation reading §6.3 literally would compute a different root over the same record.
- `[TAP-REPLAY-EDGE]`, `[TAP-REPLAY-SEQ]`, `[TAP-REPLAY-CID]` (above), plus §11.1/§11.2 carriage for `seq`.
- §3.1/§5.3: the JOSE header's `alg` is validated; verification checks must not be compiled away by an optimization flag; a Verifier must not raise on a sig-valid record with malformed optional blocks.
- §6.3's aside misdescribed RFC 6962 as duplicating a lone odd node. It does not — it splits at the largest power of two; *Bitcoin* duplicates, which is what CVE-2012-2459 concerns. The warning stands, the citation was wrong.

### Added — checks

The recurring failure was CI testing something adjacent to the property it claimed.

- **`scripts/check-envelope-parity.py`** — runs both SDKs' own emit paths over four event kinds, diffs the normalized envelope shapes, and validates the composed events against `schemas/event.schema.json`. Verified to fail on all three original divergences. The pre-existing "the two SDKs compose identical envelopes" job asserted a rule about one SDK's output for one kind and compared nothing.
- **`sdk/python/tests/test_regressions.py`** (16 cases) and **`sdk/js/test/regressions.test.ts`** (8 cases) — one per defect above, each stating the guarantee it falsified.
- **A Go job in `ci.yml` and `ci-local.sh`.** The Go SDK shipped in the README's repository map and in "three SDKs cross-checked against one reference implementation" while running in no CI job and no line of `ci-local.sh`. The "change signed bytes and CI will fail" guarantee covered two of the three.
- **`ci.yml` now runs `test_authority.py`.** It ran only in `ci-local.sh`, so the newest feature's tests ran on no CI machine, despite that script's header saying "keep this in step with ci.yml".
- **The packaging job runs the README's literal commands.** It previously ran `npm run build` first, which is why it never caught that the README's TypeScript quickstart failed from a clean clone with `ERR_MODULE_NOT_FOUND`: `dist/` is gitignored and the build hook was `prepublishOnly`, which `npm install <folder>` does not run.

### Fixed — packaging and docs

- `package.json`'s build hook is now `prepare`, and the README/getting-started quickstart documents both steps a fresh clone needs.
- The Go module path was `github.com/traceable-agent/tap-sdk-go/v2` — a repository that does not exist, with a `/v2` suffix for a v0.1 protocol. Now `github.com/traceable-agent-protocol/tap/sdk/go`, matching where the code lives. The README's stale `go run test_negative_vectors.go` (no such file) is now `go test ./...`.
- **README publishes the §14 conformance matrix**, which §14 has required for four releases and which did not exist. It names real gaps: no SDK implements Passport renewal (`prev_jti` appears nowhere in this repository, and it is a Signer MUST); no Verifier implements `jti` uniqueness; the Verifier does not bind an Event to its Passport's `jti`/`aid`/`cid`.
- The README's repository-map table wrapped every markdown link in backticks, so all eleven rows rendered as literal text rather than links.
- Package versions realigned: `traceable-agent-protocol`, `@traceableagent/sdk`, and the specification are all 0.1.5. They had drifted to 0.1.3, 0.1.2 and 0.1.4.

### Known gaps, unchanged

Passport renewal, Verifier-side `jti` uniqueness, and Event-to-Passport binding are named in the README matrix and remain unimplemented. §9.2 stays provisional and outside §14's table. The `sigs` composite-signature array (§3.6) still has no implementation, schema entry, or vector.

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
