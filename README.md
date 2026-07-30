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
| Browse everything | [Documentation index](docs/README.md) |

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
```

See [Getting started](docs/getting-started.md) before using TAP in production.

## Repository map

| Path | Purpose |
|---|---|
| [`docs/`](docs/) | Learning, onboarding, integration, conformance, and governance guides |
| [`site/`](site/) | Dedicated TAP technical website |
| [`TAP-spec-v0.1.md`](TAP-spec-v0.1.md) | Normative protocol contract |
| [`TAP-whitepaper.md`](TAP-whitepaper.md) | Design rationale and threat model |
| [`tap_ref.py`](tap_ref.py) | Readable reference implementation and vector generator |
| [`test-vectors.json`](test-vectors.json) | Positive and negative interoperability contract |
| [`sdk/python/`](sdk/python/) | Python signer, verifier, and server primitives |
| [`sdk/js/`](sdk/js/) | TypeScript signer, verifier, and server primitives |
| [`gateway/`](gateway/) | TAP-aware boundary for unchanged upstream services |
| [`inspector/`](inspector/) | Local record inspection and debugging tool |
| [`schemas/`](schemas/) | JSON Schemas |
| [`registries/`](registries/) | Cryptographic suite and result-code registries |

## Conformance

TAP defines three implementation classes:

- **Signer**
- **Verifier**
- **TAP-aware Server / Gateway**

Claims are made per class and protocol version. Passing the positive vectors alone is not enough; a verifier must also reject or flag every applicable negative case.

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

Current protocol release: **v0.1.4**.

The specification, reference implementation, test vectors, Python and TypeScript SDKs, Gateway, and Inspector are available. Breaking changes remain possible before v1.0. See [CHANGELOG.md](CHANGELOG.md) for signed-byte changes and migration notes.

**Authority binding (§9.2) is provisional**: the wire shape, and a reference implementation of its stateless half (validity window, effect labeling), landed in v0.1.3/v0.1.4 and are implemented in the Python SDK (`tap_sdk.authority`, `TAPClient.authorize()`/`trace(authorize=...)`). It is not yet in the TypeScript SDK, not enforced by any Verifier (revocation and single-use are stateful and unbuilt), and not in the Gateway or Inspector.

Known gaps include the unimplemented production key hierarchy, post-quantum suites, composite signatures, timestamp anchoring, a third independently authored language implementation, and — as above — most of authority binding.

## Contributing

Start with [Project governance](docs/governance.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

The hard rule is simple: if a change affects signing or verification, the conformance artifacts must change with it.

## License and stewardship

Apache-2.0. See [LICENSE](LICENSE).

TAP is stewarded by [Sworn](https://getsworn.ai). The protocol and verification logic remain open so a third party can validate a TAP record without trusting Sworn, the agent operator, or the system that stored the evidence.
