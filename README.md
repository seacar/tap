# TAP — Traceable Agent Protocol

**Open evidence infrastructure for AI agents.**

TAP is a vendor-neutral protocol for producing signed, portable, independently verifiable records of agent activity. It defines how an agent presents authority, how actions are linked into an evidence chain, how a server independently attests what it observed, and how a verifier evaluates the result.

TAP is for developers, contributors, platform engineers, and security engineers. Managed-service features such as retention, reporting, tenant administration, and compliance workflows belong to [Sworn](https://getsworn.ai), not to this protocol.

## Start here


| Goal                            | Document                                             |
| ------------------------------- | ---------------------------------------------------- |
| Learn the architecture          | [Architecture and trust model](docs/architecture.md) |
| Add TAP to an agent             | [Getting started](docs/getting-started.md)           |
| Integrate a server or Gateway   | [Integration guide](docs/integration-guide.md)       |
| Implement the wire format       | [TAP specification v0.1](TAP-spec-v0.1.md)           |
| Understand the design rationale | [Whitepaper](TAP-whitepaper.md)                      |
| Test an implementation          | [Conformance guide](docs/conformance.md)             |
| Browse everything               | [Documentation index](docs/README.md)                |




## The protocol in one minute

```text
agent
  ├─ signed Passport: identity + presented authority
  └─ signed Event: intent + action + result digests
          │
          ▼
TAP-aware server or Gateway
  └─ signed observed Event: what crossed the server boundary
          │
          ▼
Verifier
  └─ signatures + sequence + replay + checkpoints + assurance
```

TAP separates three questions that ordinary logs blur together:

1. **Who made the claim?** Signatures bind records to keys.
2. **What authority was presented?** The Passport carries identity, scope, context, and validity.
3. **What was independently observed?** A TAP-aware server or Gateway can sign the execution result and link it to the agent’s intent.

Readable payloads live in a redactable annex. The signed record carries digests, allowing evidence integrity to survive deletion of sensitive plaintext.

## Quickstart

Packages are currently installed from this repository.

### Python

```bash
pip install ./sdk/python
```

```python
from tap_sdk import TAPClient

tap = TAPClient(
    agent_id="support-triage",
    private_key_hex=SEED,
    kid="key_2026_01",
    endpoint="https://verifier.example.com",
)

passport = tap.issue_passport(
    task_prompt="Resolve support ticket #8842",
    scope=["read:database"],
)

@tap.trace(tool="db_query", scope="read:database")
def db_query(table, limit):
    return run_query(table, limit)

db_query("users", limit=50)
tap.emit_checkpoint()
```



### TypeScript

```bash
npm --prefix sdk/js install   # installs deps and builds dist/ via `prepare`
npm install ./sdk/js
```

Both steps are needed from a fresh clone: `dist/` is a build artifact and is not
committed, and npm installs a local path as a *symlink* without building it.

```ts
import { TAPClient } from "@traceableagent/sdk/agent";

const tap = new TAPClient({
  agentId: "support-triage",
  privateKeyHex: seed,
  kid: "key_2026_01",
});

const passport = await tap.issuePassport({
  taskPrompt: "Resolve support ticket #8842",
  scope: ["read:database"],
});
```

See [Getting started](docs/getting-started.md) before using TAP in production.

## Repository map


| Path | Purpose |
| --- | --- |
| [docs/](docs/) | Learning, onboarding, integration, conformance, and governance guides |
| [TAP-spec-v0.1.md](TAP-spec-v0.1.md) | Normative protocol contract |
| [TAP-whitepaper.md](TAP-whitepaper.md) | Design rationale and threat model |
| [tap_ref.py](tap_ref.py) | Readable reference implementation and vector generator |
| [test-vectors.json](test-vectors.json) | Positive and negative interoperability contract |
| [sdk/python/](sdk/python/) | Python signer, verifier, and server primitives |
| [sdk/js/](sdk/js/) | TypeScript signer, verifier, and server primitives |
| [sdk/go/](sdk/go/) | Go signer and verification primitives |
| [gateway/](gateway/) | TAP-aware boundary for unchanged upstream services |
| [inspector/](inspector/) | Local record inspection and debugging tool |
| [schemas/](schemas/) | JSON Schemas |
| [registries/](registries/) | Cryptographic suite and result-code registries |
| [scripts/](scripts/) | Vector, schema, and cross-language parity checks run by CI |




## Conformance

TAP defines three implementation classes — **Signer**, **Verifier**, and **TAP-aware Server / Gateway**. Claims are made per class and protocol version. Passing the positive vectors alone is not enough; a verifier must also reject or flag every applicable negative case.

Specification §14 requires this matrix to be published here and kept honest. Coverage of the implementations in this repository, against TAP v0.1.5:

| | Python | TypeScript | Go | `tap_ref.py` |
| --- | --- | --- | --- | --- |
| **Signer** | partial | partial | partial | partial |
| **Verifier** | partial | partial | primitives only | partial |
| **Server / Gateway** | yes | yes | no | no |

Read "partial" precisely — the gaps are named, not rounded away:

- **No SDK implements Passport renewal** (`[TAP-PASSPORT-LIFECYCLE]`, §4.2). `prev_jti` appears nowhere in this repository, so a record outliving one Passport TTL cannot be continued as one authority chain. This is a Signer **MUST**, and no implementation here meets it.
- **No Verifier implements `jti` uniqueness** (`[TAP-REPLAY]`, §8.2). Uniqueness is enforced at the delegation edge by `TAPServer`/`TAPClient.accept_a2a_delegation`, which is a Server-class obligation; the Verifier class also lists it, and `verify_transcript` holds no registry. `(aid, seq)` monotonicity *is* checked.
- **The Verifier does not bind Events to their Passport.** `event.passport_jti`, `event.aid`, and `event.cid` are not checked against the Passport's own claims, so drift is evaluated against whichever Passport the caller supplied.
- **Go is Signer + verification primitives.** It signs and verifies Passports and Events, reproduces every vector including the canonicalization torture case, and implements the key hierarchy and §9.2's stateless half. It has no client wrapper, no checkpoint reconciliation, no assurance labeling, no chain join, and no server leg.
- **`[TAP-ASSURANCE-KEY]`'s trust anchor is optional in practice.** All Verifiers apply the structural floor (a `server` leg may not share the agent's `kid`). Supplying the set of recognized server keys is the caller's job; without it, "independently attested" is weaker than §7 describes.
- **§9.2 authority binding is provisional** and outside §14's table for every class — see Project status below.

Run the full local suite:

```bash
./scripts/ci-local.sh
```

Any change to signed bytes requires updated specification text, regenerated vectors, matching SDK changes, and a changelog entry.

## Security and limitations

TAP proves authorship and integrity of signed claims. It does not prove that an agent is truthful, that an authorized action is appropriate, or that a deployment is compliant.

Independent server attestation strengthens the record by separating agent intent from observed execution. It still proves only what crossed that attestation boundary.

Read [SECURITY.md](SECURITY.md) before deployment and use its private reporting path for vulnerabilities.

## Project status

Current protocol release: **v0.1.5**.

The specification, reference implementation, test vectors, Python, TypeScript, and Go SDKs, Gateway, and Inspector are available. Breaking changes remain possible before v1.0.0. See [CHANGELOG.md](CHANGELOG.md) for signed-byte changes and migration notes.

TAP currently has a single implementer and no external adopters — everything above is validated against itself (three SDKs cross-checked against one reference implementation and one author), not against an independent third party. Treat this as pre-adoption software: expect rough edges, and expect the protocol to firm up as real usage finds them.

v0.1.5 is what that looks like in practice. A review found defects that every one of the 22 checks in `ci-local.sh` passed over, because the checks tested the wrong things: a Signer could forge `two-sided` assurance with its own key (§7's central claim); the Gateway rejected every action after the first under one Passport, making it unusable for any agent that calls more than one tool; the Python Verifier's Passport checks were `assert` statements, which `python -O` strips; a signature-valid Event with a malformed `authorization` crashed the Verifier; and `flush()` spun forever against an unreachable Verifier. The specification and the SDKs also disagreed with each other in five places, including a `latency_ms` null-vs-omitted split that made the two SDKs compose different signed bytes for the same action — the exact failure `[TAP-EVT-OMIT]` exists to prevent, under a CI job named "the two SDKs compose identical envelopes" that never compared them. All are fixed, with regression tests and two new CI checks that reproduce each original defect. See [CHANGELOG.md](CHANGELOG.md).

**Authority binding (§9.2) is provisional**: the wire shape and its stateless checks (validity window, effect labeling) are implemented in all three SDKs (Python `tap_sdk.authority`/`TAPClient.authorize()`; TypeScript `authority.ts`/`traceTool({authorize, effectOf})`; Go `GrantAuthorization`/`CheckAuthorityWindow`/`AuthorityEffectLabel`, functions only — Go has no client wrapper yet). The Inspector displays a bound approval's `authz_id`, effect label, and revocation status, read-only.

`authorization` now crosses the Gateway boundary (`X-TAP-Authorization` / `_meta.tap.authorization`, §11.1/§11.2): the Gateway echoes it onto its own server-attested leg and enforces the validity window and single-use at that one accept point (`DENIED_AUTHORITY_EXPIRED`/`DENIED_AUTHORITY_REUSED`). Revocation is resolver-based — `check_authority_not_revoked`/`checkAuthorityNotRevoked` in all three SDKs, wired into `evaluate_event`/`evaluateEvent` and `verify_transcript`/`verifyTranscript` in Python/TypeScript — but this repo ships **no revocation registry**: a caller supplies the lookup (publication format stays a Service Profile concern, spec §15). Reuse detection beyond the Gateway's own accept point is only batch-local (a duplicate `authz_id` within one delivered report), not a live cross-session registry — that needs a hosted ingest Verifier, which remains a Service Profile's job. And nothing today independently signs the `authorization` block on behalf of `issuer_kid`: it is asserted inside the agent's own signed Event, so these checks make a *named* approval hard to reuse or resurrect, but do not by themselves prove its contents were legitimately granted.

Known gaps include the unimplemented production key hierarchy, post-quantum suites, composite signatures, timestamp anchoring, a third independently authored language implementation, and — as above — a hosted revocation registry, a live cross-session reuse registry, and independent signing of the `authorization` block itself.

## Contributing

Start with [Project governance](docs/governance.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

The hard rule is simple: if a change affects signing or verification, the conformance artifacts must change with it.

## License and stewardship

Apache-2.0. See [LICENSE](LICENSE).

TAP is stewarded by [Sworn](https://getsworn.ai). The protocol and verification logic remain open so a third party can validate a TAP record without trusting Sworn, the agent operator, or the system that stored the evidence.