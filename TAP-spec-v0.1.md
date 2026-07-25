# Traceable Agent Protocol (TAP) — Specification v0.1

**Status:** Draft · **Version:** 0.1.0 · **Date:** 2026-06-08
**Steward:** Sworn (https://getsworn.ai) · **License (intended):** Apache-2.0 (spec + reference code)
**Reference implementation:** `tap_ref.py` · **Conformance vectors:** `test-vectors.json`

> **Note on conformance vectors.** `test-vectors.json` has been regenerated from `tap_ref.py` against the v0.1.0 envelope (digest-only signed body; annex; fractional number ban) and now carries live reference values for the Passport, Event, Decision, and Checkpoint cases (§6.6, §14). Any future change to the signed-body shape requires regenerating this file again before conformance testing.

---

## Abstract

TAP is an open standard for **cryptographically verifiable agent provenance**. It defines (1) the **Passport** — a signed, short-lived credential asserting an agent's identity and authorized scope — and (2) the **Event** — a signed, tamper-evident record of a single action, carrying intent, reasoning, and result as **digests only**, with human-readable plaintext in a separate crypto-shreddable **annex**. TAP signatures are produced at the source and verifiable by any third party against a published key, with no trust in the platform that stores them. TAP is transport-agnostic and binds cleanly to MCP (agent→tool) and A2A (agent→agent).

This document is the wire specification: data formats, cryptography, canonicalization, transport bindings, and verification rules. Policy languages, dashboards, and storage are out of scope (see §15, "Service Profiles").

---

## 1. Conventions & Terminology

The key words **MUST**, **MUST NOT**, **REQUIRED**, **SHOULD**, **SHOULD NOT**, and **MAY** are to be interpreted as in RFC 2119 / RFC 8174.

- **Agent** — an autonomous software process taking actions (tool calls, delegations).
- **Signer** — the component holding the private key that mints Passports and signs Events (in practice, the SDK / "Shim" embedded with the agent).
- **Verifier** — a service that validates signatures, checks integrity, and persists Events for audit.
- **TAP-aware Server** — a tool/resource or receiving agent that validates an inbound Passport and MAY emit its own server-attested Event.
- **TAP-aware Gateway** — a proxy that performs server-side attestation on behalf of upstream tools/agents that are not TAP-aware (§4.3).
- **Relying Party** — any consumer of TAP records (auditor, compliance tool, regulator) that re-verifies them.
- **Passport** — the signed identity + authority credential (§5).
- **Event** — a signed provenance record of one action (§6).
- **Annex** — the unsigned, crypto-shreddable plaintext that accompanies an Event but is not part of its signing input (§6.1).
- **cid** — *context id*, a digest binding all Events in one logical record/task (§3.3).
- **aid** — *agent instance id*, unique per record.
- **Digest string** — `"<alg>:<hex>"`, lowercase hex (§3.3).
- **Suite** — a named cryptographic algorithm set negotiated for a session (§3.6).

---

## 2. Architecture & Trust Model

```
            mints Passport, signs Events
   Agent ──────────────► Signer (SDK/Shim) ──────────────► TAP-aware Server / Gateway
                                 │  (verifies Passport, emits
                                 │   server-attested Event)
           async, signed Events  ▼
                             Verifier ───────► storage / audit
                                 ▲
             re-verifies (public key only)
                         Relying Party (auditor / regulator)
```

**Core trust property.** Verification requires **only the Signer's public key** (published as JWKS). Any Verifier, auditor, or regulator can validate any Passport or Event without trusting the Verifier's storage, the platform, or the operator. Tampering with a stored Event invalidates its signature.

**What TAP does not do.** TAP records and (optionally) enforces. It is not a content-safety filter, risk-management system, or confidentiality mechanism (§12). It does not judge the semantics of an action.

---

## 3. Cryptographic Foundations

### 3.1 Signatures

TAP uses **EdDSA over Curve25519 (Ed25519)**, per RFC 8032 and RFC 8037. The JOSE `alg` value is `EdDSA`. Implementations **MUST** use Ed25519. **MUST NOT** accept `alg: none`. **MUST NOT** accept any other algorithm for a v0.1 session. New algorithms are introduced via suite negotiation (§3.6, §4.1), never by widening an existing session.

### 3.2 Keys & Key Distribution

Public keys are published as a **JWKS** (RFC 7517) using the **OKP** key type (RFC 8037):

```json
{ "kty": "OKP", "crv": "Ed25519", "alg": "EdDSA", "use": "sig",
  "kid": "key_2026_ref01", "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" }
```

- `x` is the base64url (unpadded) raw 32-byte public key.
- `kid` uniquely identifies the key; every Passport and Event **MUST** carry the `kid` used to sign it, inside the signed body (so it cannot be swapped without breaking the signature).
- Verifiers resolve `kid → public key` via `https://<issuer>/.well-known/jwks.json`. Verifiers **SHOULD** cache JWKS and honor key rotation by `kid`.
- **Revocation.** A JWKS entry **MAY** carry a `revoked_at` epoch-seconds field. A Verifier **MUST** treat any record signed by that `kid` with `iat`/`ts` at or after `revoked_at` as invalid. This gives a compromised key an effective-time boundary rather than all-or-nothing repudiation.

### 3.3 Hashing, Digests, and Encoding

- Hash function: **SHA-256**. A **digest string** is `"sha256:" + lowercase_hex(SHA256(bytes))`.
- `cid` (context id) is a digest string over the canonical bytes of the parent task/prompt combined with a per-record **nonce**. The nonce is **REQUIRED** and **SHOULD** carry ≥ 128 bits of entropy, so that two records of an identical prompt do not collide on `cid` and `cid` cannot serve as a confirmation oracle for a low-entropy prompt.
- All Events and the Passport for one record share the same `cid`.
- Binary values (signatures, keys) use **base64url without padding** (RFC 7515 §2).

### 3.4 Canonicalization — the Interoperability Crux

Event signatures are computed over the **JCS canonicalization (RFC 8785)** of the Event body with `sig` removed. JCS fixes key ordering, whitespace, string escaping, and number formatting so two implementations produce identical bytes for the same logical object. Implementations **MUST** use RFC 8785. The Passport uses JOSE/JWS compact serialization (its own canonical signing input) and does **not** use JCS.

> **No fractional numbers in a signed body.** RFC 8785's number canonicalization is correct, but non-integer floating-point handling is the single most common source of cross-language signature divergence. TAP therefore **MUST NOT** include JSON numbers with a fractional part or exponent anywhere in a signed body. Quantities that are conceptually fractional (e.g. a decision `score`) **MUST** be encoded as **strings** (`"0.71"`) or as integers in fixed minor units. Integers **MUST** stay within the IEEE-754 safe range (±2^53−1). The conformance vectors include a fractional-valued field to force implementations to handle this case.

### 3.5 Key Hierarchy and Environment Attestation

Embedding a long-lived private key in each of thousands of ephemeral agents — and placing a KMS/HSM call on every signature — does not scale. TAP resolves this with a three-tier hierarchy that keeps the protected key off the signing hot path:

1. **Issuing key (root of trust).** A long-lived key held in a KMS/HSM. It never signs Events directly; it mints and attests signing keys. One issuing key serves an entire fleet.
2. **Signing key (ephemeral).** A short-lived Ed25519 keypair generated *locally* by the Shim — no HSM round-trip per signature. The issuing key signs a **key-attestation certificate** binding the ephemeral key to an agent id (`aid`) and short validity window (`nbf`/`exp`).
3. **The signatures themselves**, produced locally at full speed.

```jsonc
// key-attestation certificate — signed by the issuing key
{ "kid": "sk_eph_01J…",            // ephemeral signing key id
  "x": "…",                         // ephemeral public key (base64url)
  "aid": "agt_01J…",                // agent instance it is bound to
  "iss_kid": "key_issuer_2026",     // issuing key that attests it
  "nbf": 1767225600,
  "exp": 1767229200,
  "env": {                          // OPTIONAL environment attestation
    "tee": "sev-snp",
    "quote_digest": "sha256:…",
    "workload": "spiffe://…"
  },
  "sig": "…"                        // issuing key's signature over the above
}
```

A Verifier resolves an Event's `kid` → key-attestation certificate → `iss_kid` (the issuing key in JWKS), and accepts the signature only if the ephemeral key was validly attested, in-window, and bound to the same `aid`. `revoked_at` (§3.2) applies to both issuing and ephemeral keys. The OPTIONAL `env` block lets a deployment attest *where* signing happened, raising assurance that the key was minted in a trusted environment.

**Deployments that do not use the full key hierarchy MUST** at minimum hold signing keys in a KMS/HSM. The three-tier model is RECOMMENDED for fleet deployments; the bare-key model is acceptable only for development.

### 3.6 Cryptographic Agility and Post-Quantum Readiness

Ed25519 is the required suite for v0.1. Future and post-quantum suites are introduced through a **named suite registry** and **version/suite negotiation** (§4.1), never by widening an existing session.

**Suite registry:**

| Suite id | Algorithm | Status |
|---|---|---|
| `tap-ed25519` | Ed25519 (RFC 8032) | v0.1 — REQUIRED |
| `tap-ml-dsa-65` | ML-DSA (FIPS 204, lattice) | RESERVED — post-quantum |
| `tap-slh-dsa-128s` | SLH-DSA (FIPS 205, hash-based) | RESERVED — conservative archival |

**Algorithm-driven verification.** A Verifier **MUST** dispatch verification off the key's declared suite (`alg`/`crv` in JWKS), not off a hard-coded constant. This makes adding a future suite a registry addition, not a protocol change.

**Hybrid (composite) signatures.** A Signer MAY offer a composite suite (e.g. `tap-ed25519+ml-dsa-65`) and attach both signatures in a `sigs` array — each `{ kid, alg, sig }` — instead of the single `sig`. A Verifier **SHOULD** accept the record if any trusted suite in `sigs` verifies. A Verifier **MUST** reject a record whose only signatures are in unrecognized suites, rather than fall back to a default.

**Hash agility.** Digest strings are self-describing (`"<alg>:<hex>"`), so `cid`, `args_digest`, and Merkle roots can migrate to stronger hash functions by registry addition.

**Long-term validation.** Signers and Verifiers **SHOULD** submit each signed checkpoint's Merkle root (§6.3) to an RFC 3161 timestamp authority and/or an append-only transparency log, so records remain trustworthy after an algorithm is deprecated. Before a suite is deprecated, a Verifier SHOULD re-attest archived records under a new suite (RFC 4998 renewal pattern), preserving the original signatures.

> **Transport note.** PQ signatures are large (ML-DSA ≈ 2.4–4.6 KB vs Ed25519's 64 bytes). Where composite or PQ suites are active, signatures **MUST** ride in the request body or `_meta` (§11), not in an HTTP header.

---

## 4. Capability Negotiation

Like MCP, TAP is a negotiated protocol. A Signer and a TAP-aware Server (or Gateway) agree at session start on the protocol version, algorithm suite, and attestation capabilities each supports.

### 4.1 The Handshake

At the start of interacting with a TAP-aware Server, the Signer offers its capabilities; the Server responds with its selection. The exchange rides in the same channel as the first request's TAP metadata (§11):

```json
// Signer → Server
"tap_hello": {
  "versions": ["tap/0.1"],
  "algs": ["EdDSA"],
  "attestation": "requested",
  "kid": "key_2026_ref01"
}

// Server → Signer
"tap_hello_ack": {
  "version": "tap/0.1",
  "alg": "EdDSA",
  "attestation": "server",
  "checkpoints": "supported"
}
```

- `algs` carries TAP suite identifiers from §3.6. The selected `version` governs the session; parties choose the highest mutually supported version.
- `attestation: "server"` — the upstream will emit execution Events (two-sided assurance available). `attestation: "none"` — expect intent-only.
- If no mutually supported version exists, parties fall back to unattested operation; the Signer **MUST** label accordingly.

**Anti-downgrade.** Because the handshake is not itself signed, a network intermediary could strip it to force a silent downgrade. To make this detectable, the Signer **MUST** bind the negotiated outcome — selected `version`, suite, and `attestation` level — into the first Event it signs for the record, as a `nego` object under `evidence`. A Verifier compares the claimed negotiation against the assurance actually achieved: a Signer that recorded `attestation:"server"` but for which no server leg exists **MUST** be flagged identically to a `conflicting` attestation (§7).

### 4.2 Passport Lifecycle — Mint, Renew, Seal

Passports are short-lived (default TTL ≤ 3600 s). For long-running records:

- **Mint** — at the start of a record, the Signer mints a Passport for the record's `cid` and `scope`.
- **Renew** — before `exp`, the Signer mints a successor sharing the same `cid`, carrying `prev_jti` referencing the predecessor. `scope` **MUST** be a subset of the predecessor's (authority may narrow on renewal, never widen). A Verifier joins successors by `cid` + `prev_jti` into one continuous authority chain.
- **Seal** — at the end of a record, the Signer emits a final signed `checkpoint` Event (§6.3) closing the sequence. Any further Event under that `cid` after the seal is anomalous.

### 4.3 The Gateway

Where an upstream tool is not TAP-aware, a **TAP-aware Gateway** sits in front: it terminates the TAP handshake, verifies the inbound Passport, forwards the underlying request unchanged, observes the real result, and emits the server-attested Event. To the Signer the Gateway is indistinguishable from a TAP-aware Server.

---

## 5. The Passport

A Passport is a short-lived **compact JWS / JWT** (RFC 7519) asserting an agent instance's identity and authorized scope, minted once per record (or renewal segment, §4.2) and attached to every action.

### 5.1 JOSE Header

```json
{ "alg": "EdDSA", "typ": "tap-passport+jwt", "kid": "key_2026_ref01" }
```

The explicit `typ` of `tap-passport+jwt` is **REQUIRED** (RFC 8725 token-confusion defense). Verifiers **MUST** reject tokens with any other `typ`.

### 5.2 Claims

| Claim | Type | Req. | Meaning |
|---|---|---|---|
| `iss` | string (URL) | MUST | Issuer; the JWKS origin used to resolve `kid` |
| `iat` | int (epoch s) | MUST | Issued-at |
| `exp` | int (epoch s) | MUST | Expiry; default TTL **SHOULD** be ≤ 3600 s |
| `jti` | string | MUST | Unique passport id (sortable, e.g. ULID) |
| `aid` | string | MUST | Agent instance id (unique per record) |
| `cid` | digest string | MUST | Context id binding this record's Events |
| `scope` | array\<string\> | MUST | Authorized capabilities, e.g. `read:database`, `call:tool` |
| `prev_jti` | string | MAY | Predecessor passport id on renewal (§4.2) |
| `meta` | object | MAY | Non-authoritative context: `framework`, `model`, `agent_name` |

Scope tokens are `"<verb>:<resource>"`. `meta` is **never** trusted for a security decision.

### 5.3 Construction & Validation

Signing input: `base64url(header) + "." + base64url(claims)`; the Ed25519 signature over its ASCII bytes is the third segment.

A Verifier **MUST**, in order: (1) confirm `typ == tap-passport+jwt` and the session `alg`; (2) resolve `kid` via JWKS and confirm the key is not revoked as of `iat` (§3.2); (3) verify the signature; (4) check `iat ≤ now < exp` allowing **≤ 60 s** clock skew; (5) treat `aid`/`cid`/`scope` as authoritative only after steps 1–4 pass.

### 5.4 Reference Passport (from `test-vectors.json`)

Signed with the public test seed; reproducible byte-for-byte:

```
eyJhbGciOiJFZERTQSIsInR5cCI6InRhcC1wYXNzcG9ydCtqd3QiLCJraWQiOiJrZXlfMjAyNl9yZWYwMSJ9.
eyJpc3MiOiJodHRwczovL2dldHN3b3JuLmFpIiwiaWF0IjoxNzY3MjI1NjAwLCJleHAiOjE3NjcyMjkyMDAs...
.pLyyBvygk6lg9otedTpJ7wBryovkdrUVDvKorEq_PeGozhJoehGCQbOWypgnv3GcPoOs5oGzKJVdvn_WmRwTAA
```

(Full token in `test-vectors.json → passport.compact_jwt`.)

---

## 6. The Event

An Event is a JSON object recording one action, carrying a **detached Ed25519 signature** over the JCS canonicalization of the Event body with `sig` removed. The signed body contains **digests only** — never raw arguments, intent text, or reasoning (§6.1).

### 6.1 Envelope

```jsonc
{
  "v": "tap/0.1",                       // spec version (MUST)
  "event_id": "evt_01JABCDEF…",         // unique, sortable (MUST)
  "passport_jti": "psp_01JABCDEF…",     // links Event → Passport (MUST)
  "aid": "agt_01JABCDEF…",              // agent instance (MUST)
  "cid": "sha256:b6f6ed…",              // record context (MUST)
  "seq": 7,                             // monotonic per aid, from 1 (MUST)
  "ts": "2026-01-01T00:03:11.482Z",     // RFC 3339 UTC, ms (MUST)

  "action": {                           // (MUST)
    "kind": "tool_call",                // see §6.2
    "intent_digest": "sha256:…",        // SHA-256 of the intent string (MUST)
    "tool": "db_query",                 // tool name OR target agent id
    "scope_used": "read:database",      // checked ⊆ passport.scope (MUST when action exercises scope)
    "args_digest": "sha256:…"           // SHA-256 of canonical args (MUST when args exist)
  },

  "evidence": {                         // (SHOULD)
    "reasoning_digest": "sha256:…",     // SHA-256 of the reasoning text
    "model_output_digest": "sha256:…",  // SHA-256 of the full model output
    "nego": { "version": "tap/0.1", "alg": "EdDSA", "attestation": "server" }
    // nego MUST appear in the first Event of a record where a handshake occurred (§4.1)
  },

  "result": {                           // (MUST)
    "status": "success",                // success | failure | denied
    "code": "OK",                       // §10 registry
    "latency_ms": 142,
    "error": null
  },

  "attestor": "agent",                  // agent | server  (§7)
  "action_ref": "act_01JABCDEF…",       // correlates agent & server legs (§7)
  "parent_event_id": null,              // links received_delegation to agent_delegate (§8)
  "policy_decision": null,              // { decision, rule_id, policy_version }  (§9)

  "kid": "key_2026_ref01",              // signing key (MUST; inside signed body)
  "sig": "naUW4osbFd4ppCb7F2Qrre_Xx…"  // base64url(Ed25519 over JCS(body without sig)) (MUST)
}
```

**Digest-only rule.** The signed body **MUST NOT** contain raw intent text, argument values, reasoning, or any plaintext that may constitute personal data. Only SHA-256 digest strings of those fields appear in the signed body. This is what makes the signed chain survive data-erasure obligations intact (§12).

#### 6.1.1 The Annex

The human-readable plaintext corresponding to digests in the Event travels in a separate, **unsigned** annex keyed by `event_id`. The annex is delivered alongside the Event to the Verifier but is **not** part of the JCS signing input:

```jsonc
// annex — NOT signed; SHOULD be stored encrypted; crypto-shreddable
{
  "event_id": "evt_01JABCDEF…",
  "intent": "Call db_query to fetch users for the support ticket",
  "args": { "table": "users", "limit": 50 },
  "reasoning": "The ticket references an account lookup; fetch the user row first."
}
```

While the annex exists, each plaintext field **MUST** verify against its signed digest (re-hash and compare). When an erasure obligation requires it, the annex is deleted or its encryption key destroyed (crypto-shredding). The signed chain of digests remains intact, continuing to prove what was authorized and executed. A Verifier **MUST** treat a missing or unverifiable annex as an informational gap, not an integrity failure.

### 6.2 Action Taxonomy (`action.kind`)

| `kind` | Edge | `action.tool` holds |
|---|---|---|
| `tool_call` | MCP / local tool | tool name |
| `agent_delegate` | A2A (outbound) | target agent id |
| `received_delegation` | A2A (inbound) | sending agent id; `parent_event_id` set |
| `agent_message` | A2A (non-task) | peer agent id |
| `denied` | any | the attempted target; `result.status = "denied"` |
| `decision` | reasoning | the decision key/label (§6.4) |
| `checkpoint` | integrity | the run/segment being sealed (§6.3) |

Implementations **MAY** define namespaced extension kinds prefixed `x-`. Verifiers **MUST** preserve unknown kinds verbatim.

### 6.3 Sequence, Integrity, and Checkpoints

`seq` is a 1-based monotonic counter per `aid`. A Verifier **MUST** flag gaps and duplicates as integrity signals; a duplicate `(aid, seq)` with differing content is a tamper/replay indicator.

A bare sequence gap is ambiguous — tampering (an Event was deleted) or benign loss (reporting is fail-open). TAP resolves this with a signed **checkpoint** Event. The Signer **MUST** emit a `checkpoint` at the end of every record (the "seal", §4.2) and **SHOULD** emit one periodically during long-running records:

```jsonc
"action": { "kind": "checkpoint", "intent_digest": null, "tool": null, "scope_used": null },
"checkpoint": {
  "through_seq": 42,          // highest seq sealed by this checkpoint (MUST)
  "event_id_root": "sha256:…", // Merkle root over event_ids in (prev_checkpoint, through_seq] (MUST)
  "count": 42                  // number of Events the Signer claims to have emitted in interval (MUST)
}
```

A Verifier reconciles delivered Events against the checkpoint: an `event_id` present in the Merkle commitment but never delivered is **provable deletion**; a gap with no covering checkpoint is treated as in-flight/benign until the next checkpoint arrives. A root mismatch **MUST** be surfaced as an integrity failure, not silently ignored.

**Merkle construction (normative).** `event_id_root` commits to the `event_id`s in the half-open interval `(prev_checkpoint.through_seq, through_seq]`, ordered by `seq` ascending. Leaf: `SHA-256(0x00 ‖ utf8(event_id))`. Interior node: `SHA-256(0x01 ‖ left ‖ right)`. The `0x00`/`0x01` domain-separation prefixes prevent leaf/interior confusion and second-preimage attacks. An odd-count level promotes the final node unchanged. An empty interval yields `event_id_root = "sha256:" + hex(SHA-256(""))`.

### 6.4 Decision Events — The Counterfactual Ledger

A `decision` Event records *the option taken and the options considered and rejected, with reasons*. Because the entire option set is in the JCS signing input, an agent cannot later claim it weighed a different set.

All free-text fields (question, rationale, reasons) are digest strings in the signed body; plaintext lives in the annex per §6.1.1. `score` **MUST** be a string per §3.4.

```jsonc
"action": { "kind": "decision", "intent_digest": "sha256:…",
            "tool": "resolve_ticket", "scope_used": null },
"decision": {
  "question_digest": "sha256:…",               // SHA-256 of the decision question
  "chosen": "refund",
  "selection": "policy-weighted-argmax",        // OPTIONAL
  "options": [
    { "id": "refund",   "score": "0.71", "chosen": true,  "rationale_digest": "sha256:…" },
    { "id": "escalate", "score": "0.52", "chosen": false, "reason_digest": "sha256:…" },
    { "id": "deny",     "score": "0.10", "chosen": false, "reason_digest": "sha256:…" }
  ],
  "options_digest": "sha256:…"                  // SHA-256 over the canonical option set (MUST)
}
```

Rules:
- Exactly one option **MUST** have `chosen: true`, and `decision.chosen` **MUST** equal its `id`.
- Each non-chosen option **SHOULD** carry a `reason_digest`; the chosen option **SHOULD** carry a `rationale_digest`. Corresponding plaintext lives in the annex.
- `score` is OPTIONAL; when present it **MUST** be a string (§3.4).
- To raise assurance from commitment to cognition, the option set **SHOULD** be reflected in `evidence.model_output_digest` so the recorded counterfactual is bound to the actual model output.
- A `decision` MAY precede the `tool_call`/`agent_delegate` that enacts the chosen option, correlated by `cid` and OPTIONALLY `action_ref`.

### 6.5 Signing & Verification

**Sign:** remove `sig` if present → `JCS(body)` (RFC 8785, no fractional numbers per §3.4) → Ed25519 sign → set `sig = base64url(signature)`. `kid` is part of the signed body.

**Verify:** remove `sig` → `JCS(body)` → resolve `kid` (check revocation per §3.2) → Ed25519 verify. On failure the Event is **invalid** and **MUST** be marked as such — never silently dropped; an invalid signature is itself evidence.

### 6.6 Reference Event (from `test-vectors.json`)

The reference vectors exercise the digest-only envelope, the `decision` fractional-score case (§3.4, §6.4), and the `checkpoint` Merkle-reconciliation case (§6.3), all chained under one `cid` (`sha256:d7700ea2c5…`, `seq` 7–9) with a signed tamper-rejection case. Full objects, including annexes, live in `test-vectors.json`; the values below are the byte-for-byte signatures a conforming implementation **MUST** reproduce from the fixed seed.

| Case | `test-vectors.json` path | JCS signing-input SHA-256 | `sig` (base64url) |
|---|---|---|---|
| `tool_call` Event | `event.canonical_signing_input_sha256` / `event.signed_event.sig` | `d42f6a1b20a858187a7a6f1dd521a49c271dd4b532ab77d95f8e8eac92dd978d` | `A4UcQv-QAq8-8PdcYawyg-s9QR9GPVItchomfxibdeZUrpS_kiPOWNabnuCtqGE30qAdPNmlS52NAdcvaXBHDg` |
| `decision` Event (fractional-score case) | `decision.canonical_signing_input_sha256` / `decision.signed_event.sig` | `1482275e7afee1f381c9c51476b49dcd621cb4b04889c67884d165b4e25b4941` | `FZ_XpAJRB91vfAWUr4GicV29JsgCuS1JvmdPI5wMHOmntvlh9K9XbFa3ebvhh8cH2PIfy2sgi0O8LcueeA5dAA` |
| `checkpoint` Event | `checkpoint.canonical_signing_input_sha256` / `checkpoint.signed_event.sig` | `6769f701c45a65af3192cc1c29d209f045772d6e39261a975ac77a6ee9568360` | `ukeP_WdlxB1E9oKVhlF8dRV4GhwsERZ41lAbadcr-QOxW3LXi_5RE_nz-rbTbo2rF83YsS9TEcKGr5XrbISUCA` |

The checkpoint's `event_id_root` (`sha256:04424565134cf64d…`) commits to the `tool_call` and `decision` event ids above via `checkpoint.reconciliation.event_ids`; recomputing the Merkle root over those two ids per §6.3 **MUST** match. `tamper_check` records the invariant every implementation must enforce: `verify_event` **MUST** reject when any signed field changes.

> **Naming note.** Earlier drafts of this section referenced a `event.signing_input_sha256` field; the actual key emitted by `tap_ref.py` is `canonical_signing_input_sha256` (see table above). Implementations reading the vectors file programmatically should key off the field names actually present in `test-vectors.json`, not this prose.

---

## 7. Two-Sided Attestation

`attestor` distinguishes who signed an Event:
- `"agent"` — the Signer attests **intent** ("I am calling `db_query`").
- `"server"` — a TAP-aware Server or Gateway attests **execution** ("`db_query` ran and returned OK"), signed by an independent key.

The Signer stamps a per-call `action_ref`; a TAP-aware Server or Gateway echoes it in its server-attested Event. A Verifier correlates legs on `(aid, action_ref)` and assigns assurance:

| Assurance | Condition |
|---|---|
| `intent-only` | agent leg present; no server leg |
| `two-sided` | agent + server legs present and consistent |
| `conflicting` | legs disagree → integrity alert |

**Consistency predicate (normative).** Two legs sharing the same `(aid, action_ref)` are *consistent* — and the action is `two-sided` — only when they also agree on `cid`, `action.tool`, and `action.kind`, and their results do not contradict. A server `result.status` of `denied`/`failure` against an agent `success`, or differing `result.code`, is a contradiction and yields `conflicting`. A second agent leg or second server leg for the same `action_ref` is a duplicate and is itself an integrity signal.

A compromised Signer can attest false intent but cannot forge the server's independent signature over the actual execution. `conflicting` is a high-signal alert. Implementations **MUST** label assurance honestly and **MUST NOT** imply server attestation that did not occur.

---

## 8. Delegation, Chains & Replay

### 8.1 Chains

Multi-agent workflows form a tree. An orchestrator delegating over A2A emits an `agent_delegate` Event. The receiving agent operates under its **own** Passport (own identity and scope) sharing the same `cid`, and emits a `received_delegation` Event whose `parent_event_id` references the orchestrator's `agent_delegate`. A Verifier reconstructs the chain by joining on `cid` and `parent_event_id`. A broken or unverified handoff **MUST** break the chain visibly rather than being silently bridged.

### 8.2 Replay Defense

Replay protection rests on three elements a Verifier and a TAP-aware Server **MUST** enforce:

1. Passport `exp` (short TTL) bounds validity.
2. `jti` uniqueness — a repeated `jti` is rejected.
3. `(aid, seq)` monotonicity — duplicates/regressions are rejected and flagged.

A receiving A2A Server **SHOULD** keep a short-TTL cache of seen `(aid, seq)` and `jti` to reject duplicate inbound delegations at the edge. Cache TTL **SHOULD** be at least the maximum accepted Passport TTL plus the 60 s skew allowance (§5.3).

---

## 9. Policy Decisions (Record Format)

TAP standardizes the **record** of a policy decision, not the policy language (a Service Profile, §15). An enforcement point attaches:

```json
"policy_decision": { "decision": "deny", "rule_id": "no-prod-delete",
                     "policy_version": "sha256:…" }
```

- `decision` ∈ `allow | deny`.
- `policy_version` is a digest string over the canonical policy set in force, letting an auditor prove **which policy governed a historical action**.
- A denied action emits `action.kind = "denied"`, `result.status = "denied"`, `result.code` of `DENIED_POLICY` or `DENIED_SCOPE`.

**Drift** is the minimal built-in policy: `action.scope_used` **MUST** be ⊆ Passport `scope`; a violation is `DENIED_SCOPE`. Because drift is checked against the signed Passport scope, it is cryptographically grounded, not a heuristic.

---

## 10. Result Code Registry (v0.1)

| Code | Meaning |
|---|---|
| `OK` | action completed successfully |
| `DENIED_SCOPE` | `scope_used` ⊄ Passport `scope` — drift |
| `DENIED_POLICY` | denied by an explicit policy rule |
| `TOOL_ERROR` | the tool or target agent raised an error |
| `TIMEOUT` | action exceeded its deadline |
| `UPSTREAM_4XX` | upstream rejected the request |
| `UPSTREAM_5XX` | upstream failed to process the request |
| `VALIDATION_ERROR` | request or arguments were malformed |

Implementations **MAY** add namespaced codes (`x.<vendor>.<code>`). Verifiers **MUST** preserve unknown codes verbatim and **MUST NOT** coerce them to a known value.

---

## 11. Transport Bindings

The same signed bytes verify identically across all transport bindings.

### 11.1 HTTP (Remote MCP Servers, A2A HTTP Endpoints)

- Handshake: `X-TAP-Hello: <json>` / `X-TAP-Hello-Ack: <json>` on the first request.
- Passport: `X-Agent-Passport: <compact-jwt>`.
- Correlation: `X-TAP-Action-Ref: <action_ref>`.
- These ride **alongside** any `Authorization: Bearer` (OAuth) token — TAP adds provenance; it does not replace access control.

### 11.2 JSON-RPC `_meta` (stdio MCP, A2A Tasks/Messages)

Where no HTTP headers exist, TAP metadata rides in `_meta`:

```json
"_meta": { "tap": {
  "hello": { "versions": ["tap/0.1"], "algs": ["EdDSA"], "attestation": "requested", "kid": "…" },
  "passport": "<compact-jwt>",
  "action_ref": "act_…"
}}
```

A TAP-aware Server reads `_meta.tap`, verifies, and MAY emit a server-attested Event echoing `action_ref`. The `hello` field is included only on the first request of a session.

### 11.3 Event Reporting

Signed Events and their annexes are delivered to a Verifier out-of-band, asynchronously, batched:

```
POST /v1/events
{ "events": [ <event>, … ], "annexes": [ <annex>, … ] }
```

The Verifier returns per-`event_id` acks so a Signer can clear its buffer idempotently (dedupe on `event_id`). Annexes are keyed by `event_id` and matched to their Event by the Verifier. Reporting is **fail-open** for the agent: a Signer **MUST NOT** block execution on reporting availability (buffer + retry). Signed checkpoints (§6.3) make fail-open reporting safe for integrity.

---

## 12. Privacy & Data Minimization

The signed body contains **only digest strings** — never raw arguments, intent text, reasoning, or model output. Human-readable plaintext lives in the unsigned annex (§6.1.1), which **SHOULD** be stored encrypted so the data can be **crypto-shredded** (delete the encryption key) when an erasure obligation arises. Deleting or shredding the annex leaves the signed chain — computed over digests — valid and intact. A digest of deleted data is not personal data.

TAP records provenance; it does **not** provide confidentiality. Transport **SHOULD** use TLS. Signatures provide integrity and authenticity, not secrecy.

---

## 13. Security Considerations

- **Key custody and hierarchy.** Signer private keys are the root of trust. Production deployments **SHOULD** use the three-tier key hierarchy (§3.5). The bare-key model is acceptable only for development.
- **Algorithm pinning + agility.** A negotiated session pins one suite; `none` and RS/HS families **MUST** be rejected. New suites — including post-quantum and hybrid (§3.6) — arrive via negotiation, never by widening an existing session.
- **Revocation.** `revoked_at` in JWKS (§3.2) gives a compromised key an effective-time boundary.
- **Token confusion.** Explicit `typ` (§5.1) and the distinct Event signing scheme (§6.5) prevent cross-use.
- **Replay.** `exp` + `jti` + `(aid, seq)` + edge cache (§8.2); checkpoints (§6.3) bound undetected loss.
- **Downgrade / missing Passport.** An action without a valid Passport is *unattested*; Servers **MUST** treat it as such. Negotiated downgrade to `intent-only` **MUST** be labeled; the `nego` binding in §4.1 makes a forced downgrade detectable.
- **Canonicalization attacks.** Strict RFC 8785 + the no-fractional-numbers rule (§3.4) + algorithm pinning prevent signature-evasion via JSON ambiguity.
- **Post-quantum.** EdDSA offers no quantum resistance. TAP's answer is suite agility (§3.6), composite signatures, and timestamp anchoring of checkpoint roots to an RFC 3161 authority.
- **Scope of guarantees.** TAP proves *what an agent did and who signed for it*. It does not prove the *truthfulness* of stated reasoning, nor stop a fully compromised Signer from signing false intent — which is precisely why independent server attestation (§7) materially raises assurance.

---

## 14. Conformance

| Class | MUST implement |
|---|---|
| **Signer** | §3 crypto (incl. no fractional numbers, §3.4); §5 Passport minting + renewal; §6 Event signing over JCS with digest-only body; §6.3 checkpoints (seal MUST, periodic SHOULD); §11 carriage; fail-open reporting with annexes |
| **Verifier** | §3 verification + revocation (§3.2); §5.3 Passport validation; §6.5 Event verification; §6.3 checkpoint reconciliation + Merkle verification; §8 chain join + replay; §7 assurance labeling; §10 code preservation |
| **TAP-aware Server / Gateway** | §4.1 handshake; Passport verification; §7 server-attested Events echoing `action_ref`; §8.2 replay cache; OPTIONAL policy enforcement (§9) |

All classes **MUST** pass `test-vectors.json` (regenerated from `tap_ref.py` against the v0.1.0 envelope): reproduce the reference Passport and Event signatures from the fixed seed (`9d61b1…7f60`; JWK `x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`, `kid = key_2026_ref01`); reject the tampered variant; reproduce the fractional-field case (§3.4) and the checkpoint Merkle reconciliation case (§6.3). The reference seed **MUST NOT** be used in production.

A conforming Verifier **MUST** implement algorithm-driven verification (§3.6) so that future suites require no verifier rewrite. A conforming Verifier **MUST** reject any suite it does not recognize rather than fall back to a default.

---

## 15. Service Profiles (out of scope here, defined separately)

Policy language/DSL, the Verifier dashboard and query API, agent registration UX, retention tiers, KMS integration, and the trust-badge format are **Service Profiles** layered on this wire spec. Keeping them separate keeps TAP neutral and independently implementable.

---

## 16. References

RFC 2119 / 8174 (keywords) · RFC 8032 (Ed25519) · RFC 7515 / 7517 / 7518 / 7519 (JOSE / JWK / JWS / JWT) · RFC 8037 (EdDSA/OKP in JOSE) · RFC 8725 (JWT BCP) · RFC 8785 (JCS) · RFC 3339 (timestamps) · RFC 3161 (timestamp authority) · RFC 4998 (Evidence Record Syntax) · FIPS 204 (ML-DSA) · FIPS 205 (SLH-DSA) · JSON-RPC 2.0. Companion documents: *TAP Whitepaper v0.1*, `tap_ref.py`, `test-vectors.json`.

---

## Appendix A — Reference Material

- **`tap_ref.py`** — runnable reference Signer/Verifier (Python, `cryptography` + `jcs`). Generates the vectors in `test-vectors.json` and self-checks Passport, Event (digest-only envelope), annex verification, checkpoint Merkle, and tamper-rejection.
- **`test-vectors.json`** — fixed Ed25519 seed `9d61b1…7f60`, public JWK (`x = 11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo`, `kid = key_2026_ref01`), the reference Passport, the reference Event (digest-only envelope), signing-input hash, fractional-field case, and checkpoint-reconciliation case. **This file is the conformance contract** — every implementation must reproduce it byte-for-byte. Do not use the reference seed in production.
