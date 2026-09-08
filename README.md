# TAP — Traceable Agent Protocol

**Open evidence infrastructure for AI agents.**

TAP is a vendor-neutral protocol for producing signed, portable, independently verifiable records of agent activity. It defines how an agent presents authority, how actions are linked into an evidence chain, how a server independently attests what it observed, and how a verifier evaluates the result.

TAP is for developers, contributors, platform engineers, and security engineers. Managed-service features such as retention, reporting, tenant administration, and compliance workflows belong to [Sworn](https://getsworn.ai), not to this protocol.

## Start here

| Goal | Document |
|---|---|
| Learn the architecture | [Architecture and trust model](docs/architecture.md) |
| Add TAP to an agent | [Getting started](docs/getting-started.md) |
| Integrate a server or Gateway | [Integration guide](docs/integration-guide.md) |
| Implement the wire format | [TAP specification v0.1](TAP-spec-v0.1.md) |
| Understand the design rationale | [Whitepaper](TAP-whitepaper.md) |
| Test an implementation | [Conformance guide](docs/conformance.md) |
| See what changed | [Changelog](CHANGELOG.md) |
| Browse everything | [Documentation index](docs/README.md) |

## The protocol in one minute

```text
agent
  ├─ signed Passport: identity + presented scope
  └─ signed Event: intent + action + result digests
          │         (optional authorization: this instance was approved to land like this)
          ▼
TAP-aware server or Gateway
  └─ signed observed Event: what crossed the server boundary
          │
          ▼
Verifier
  └─ signatures + sequence + replay + checkpoints + assurance
     (+ optional effect label: authorized_match / mismatch / unverified)
```

TAP separates questions that ordinary logs blur together:

1. **Who made the claim?** Signatures bind records to keys.
2. **What authority was presented?** The Passport carries identity, scope, context, and validity.
3. **What was independently observed?** A TAP-aware server or Gateway can sign the execution result and link it to the agent’s intent.
4. **Did this instance land as approved?** Optional. An Event may carry a bound approval (`authorization`) compared against `result.effect_digest`. This is provisional (§9.2) and not required to use TAP.

Readable payloads live in a redactable annex. The signed record carries digests, so evidence integrity can survive deletion of sensitive plaintext.

## Current status

Protocol release: **v0.1.5**. Wire version: **`tap/0.1`**. Breaking changes remain possible before v1.0.0.

The specification, reference implementation, test vectors, Python / TypeScript / Go SDKs, Gateway, and Inspector are in this repository. Packages are installed from the repo; published package versions lag the protocol (Python `0.1.3`, TypeScript `0.1.2`).

TAP currently has a **single implementer and no external adopters**. The three SDKs are cross-checked against one reference implementation and one author, not against an independent third party. Treat this as pre-adoption software: expect rough edges, and expect the protocol to firm up as real usage finds them.

### What ships

| Piece | Status |
|---|---|
| Specification + whitepaper | v0.1.5; spec is normative, whitepaper is explanatory |
| Reference implementation | `tap_ref.py` generates and self-checks `test-vectors.json` |
| Conformance vectors | Positive cases (including `authorization`) + negative reject/flag cases |
| Python SDK | Full Signer / Verifier / Server client: Passports, `@trace`, decisions, checkpoints, handshake, policy, MCP wrap, authority binding |
| TypeScript SDK | Signer / Verifier / Server client: Passports, `traceTool`, decisions, checkpoints, handshake, MCP wrap. Authority primitives exist; the client does not yet mint or attach them |
| Go SDK | Wire-crypto primitives only (sign/verify Passport and Event, checkpoints, scope, authority functions). No `TAPClient` wrapper |
| Gateway | TAP-aware HTTP boundary: handshake, Passport check, unchanged upstream forward, independent server-attested Event |
| Inspector | Local mint / sign / verify / display for debugging. Wraps the Python SDK; does not re-implement verification |
| Schemas + registries | Event, Passport, annex schemas; suite and result-code registries |
| CI | Reference vectors, Python (3.10–3.13), TypeScript (Node 20/22), Gateway, Inspector, cross-language envelope parity, packaging, secret scan. Go is **not** in GitHub Actions yet; run `go test ./tap` under `sdk/go/` |

### Authority binding (§9.2) — provisional and optional

Core TAP (Passport + Events + optional server attestation) works **without** any `authorization` block. v0.1.2 records stay valid. The field is omitted when unused.

What exists today:

- **Wire shape** and `result.effect_digest`, with a fixed vector in `test-vectors.json → authorization`
- **Stateless checks** in `tap_ref.py` and all three SDKs: validity window (`nbf − 60 ≤ now < exp + 60`) and effect labels (`authorized_match` / `authorized_mismatch` / `unverified_authority`)
- **Python client**: `TAPClient.authorize()` + `@tap.trace(..., authorize=, effect_of=)` checks the window *before acting* and stamps the Event
- **Python verifier**: `evaluate_event` / `verify_transcript` report `authorization` and `authority_effect`
- **TypeScript / Go**: `authority.ts` / `authority.go` primitives (grant, window, effect label; Go/TS also have the revocation *comparison*). `evaluateEvent` reports `authorization` / `authority_effect`; not yet wired into `TAPClient.traceTool`, the Gateway, or the Inspector

What does **not** exist:

- A revocation registry (publication format is a Service Profile concern; the SDKs only compare an already-resolved `revoked_at`)
- Live cross-session reuse detection for agent-submitted events
- Gateway carriage (`X-TAP-Authorization`) or Inspector display
- An independent signature on the `authorization` block by `issuer_kid` — the agent asserts it inside its own Event, so checks make a *named* approval hard to reuse or resurrect but do not prove it was legitimately granted
- Any §9.2 MUST in the [conformance table](TAP-spec-v0.1.md) (§14)

### Known gaps

Unimplemented or incomplete relative to the longer-term design:

- Production key hierarchy, post-quantum suites, composite signatures, timestamp anchoring
- A third *independently authored* language implementation
- Hosted ingest Verifier, revocation registry, and live reuse registry (Service Profile / Sworn concerns)
- Independent issuer signing of bound approvals
- Go SDK client wrapper and CI job
- TypeScript client + verifier wiring for §9.2
- Gateway and Inspector support for `authorization`

See [CHANGELOG.md](CHANGELOG.md) for signed-byte changes and migration notes.

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

That is the whole core path: Passport, signed Events, checkpoint. No bound approval.

To also bind one action to a pre-declared effect (optional, provisional):

```python
authz = tap.authorize(
    target_state={"ticket": "8842", "status": "refunded", "refund_cents": 5000},
    authority_state={"policy": "refund-v3"},
    ttl_s=300,
)

@tap.trace(tool="issue_refund", scope="write:billing",
           authorize=authz, effect_of=lambda r: r)
def issue_refund(ticket, cents):
    return billing.refund(ticket, cents)
```

A verifier then labels `authorized_match` or `authorized_mismatch` from the two digests. Omit `authorize=` and TAP behaves exactly as in the first snippet.

### TypeScript

```bash
npm install ./sdk/js
```

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

await tap.traceTool(
  { tool: "db_query", scope: "read:database" },
  () => runQuery("users", 50),
);
await tap.emitCheckpoint();
```

Authority primitives live in `sdk/js/src/authority.ts` but are not yet on `TAPClient`.

### Go

```bash
cd sdk/go && go test ./tap
```

The Go SDK is primitives (`SignPassport`, `SignEvent`, `VerifyEvent`, `GrantAuthorization`, …), not a tracing client. See [sdk/go/README.md](sdk/go/README.md).

See [Getting started](docs/getting-started.md) before using TAP in production.

## Repository map

| Path | Purpose |
|---|---|
| [`docs/`](docs/) | Learning, onboarding, integration, conformance, and governance guides |
| [`TAP-spec-v0.1.md`](TAP-spec-v0.1.md) | Normative protocol contract |
| [`TAP-whitepaper.md`](TAP-whitepaper.md) | Design rationale and threat model |
| [`tap_ref.py`](tap_ref.py) | Readable reference implementation and vector generator |
| [`test-vectors.json`](test-vectors.json) | Positive and negative interoperability contract |
| [`sdk/python/`](sdk/python/) | Python signer, verifier, server, policy, and authority client |
| [`sdk/js/`](sdk/js/) | TypeScript signer, verifier, and server primitives |
| [`sdk/go/`](sdk/go/) | Go wire-crypto primitives |
| [`gateway/`](gateway/) | TAP-aware boundary for unchanged upstream services |
| [`inspector/`](inspector/) | Local record inspection and debugging tool |
| [`schemas/`](schemas/) | JSON Schemas |
| [`registries/`](registries/) | Cryptographic suite and result-code registries |

## Conformance

TAP defines three implementation classes:

- **Signer**
- **Verifier**
- **TAP-aware Server / Gateway**

Claims are made per class and protocol version. Passing the positive vectors alone is not enough; a verifier must also reject or flag every applicable negative case. Authority binding is **out of** the §14 table until the class is complete.

Run the full local suite (same checks as GitHub Actions, plus the Python authority tests):

```bash
./scripts/ci-local.sh
```

Any change to signed bytes requires updated specification text, regenerated vectors, matching SDK changes, and a changelog entry.

## Security and limitations

TAP proves authorship and integrity of signed claims. It does not prove that an agent is truthful, that an authorized action is appropriate, or that a deployment is compliant.

Independent server attestation strengthens the record by separating agent intent from observed execution. It still proves only what crossed that attestation boundary.

Authority binding, when used, adds a *named* expected effect. It does not, today, prove that `issuer_kid` actually granted that effect.

Read [SECURITY.md](SECURITY.md) before deployment and use its private reporting path for vulnerabilities.

## Contributing

Start with [Project governance](docs/governance.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

The hard rule is simple: if a change affects signing or verification, the conformance artifacts must change with it.

## License and stewardship

Apache-2.0. See [LICENSE](LICENSE).

TAP is stewarded by [Sworn](https://getsworn.ai). The protocol and verification logic remain open so a third party can validate a TAP record without trusting Sworn, the agent operator, or the system that stored the evidence.
