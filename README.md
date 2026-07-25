# TAP — the Traceable Agent Protocol

**An open standard for cryptographically verifiable agent provenance.**

AI agents call tools, query databases, and delegate to one another — as black boxes. When an agent takes an unauthorized action or fails in a way that harms someone, there is no standard, tamper-evident way to establish *which* agent acted, *under what authority*, *with what reasoning*, and *with what result*. Application logs are mutable, unattributable to a decision, and unverifiable by anyone who wasn't already trusted.

TAP fixes the evidence layer. Where MCP governs how an agent *obtains* context and *calls* tools, TAP governs the agent's *evidentiary record*:

- a **Passport** — a signed credential asserting an agent's identity and authorized scope;
- **Events** — signed, tamper-evident records of each action, carrying intent, reasoning, and result.

Signatures are produced at the source and verifiable by any third party against a published public key. **No trust in the platform that stores them.** No blockchain.

```
[ your agent ] → [ TAP SDK ] → signed events → [ any Verifier ]
                      ↓                              ↓
              tools / other agents          auditor re-verifies
                                            with the public key alone
```

---

## Why this exists

Regulators moved the bar from *"do you have logs?"* to *"prove what the agent did."* The EU AI Act requires high-risk systems to keep traceable, attributable, retrievable logs under the deployer's control. NIST's AI Agent Standards Initiative names agent authorization and audit trails directly. Bank examiners now ask about agent governance as standard practice.

Conventional logs fail that bar on four counts auditors specifically probe: they're **mutable**, **not attributable to a decision**, often **not under the accountable party's control**, and **unverifiable by a third party**.

An audit trail that only its vendor can verify isn't evidence. It's a receipt.

---

## Quickstart

### Python

```bash
pip install traceable-agent-protocol
```

```python
from tap_sdk import TAPClient

tap = TAPClient(
    agent_id="support-triage",
    private_key_hex=SEED,
    kid="key_2026_01",
    endpoint="https://your-verifier.example.com",
)

passport = tap.issue_passport(
    task_prompt="Resolve support ticket #8842",
    scope=["read:database"],
)

@tap.trace(tool="db_query", scope="read:database")
def db_query(table, limit):
    return run_query(table, limit)      # your existing code, unchanged

db_query("users", limit=50)             # signed automatically
tap.emit_checkpoint()                   # seals the record
```

### TypeScript

```bash
npm install @traceableagent/sdk
```

```ts
import { TAPClient } from "@traceableagent/sdk/agent";

const tap = new TAPClient({ agentId: "support-triage", privateKeyHex: SEED, kid: "key_2026_01" });
const passport = await tap.issuePassport({ taskPrompt: "…", scope: ["read:database"] });
```

Both SDKs reproduce [`test-vectors.json`](test-vectors.json) byte-for-byte from the same fixed seed. That is the property the whole protocol rests on: **a Signer and a Verifier in different languages cannot drift apart.**

---

## What's in this repo

| Path | What it is |
|---|---|
| [`TAP-spec-v0.1.md`](TAP-spec-v0.1.md) | The normative wire contract — crypto, canonicalization, Passport/Event formats, transport bindings, conformance rules |
| [`TAP-whitepaper.md`](TAP-whitepaper.md) | The explanatory companion — design rationale, threat model, compliance context |
| [`tap_ref.py`](tap_ref.py) | Reference implementation. Normative-by-example; it generates and self-checks the vectors |
| [`test-vectors.json`](test-vectors.json) | **The conformance contract.** Every implementation must reproduce these signatures byte-for-byte |
| [`sdk/python/`](sdk/python) | `traceable-agent-protocol` — signer, verifier, server leg, policy records |
| [`sdk/js/`](sdk/js) | `@traceableagent/sdk` — the same, in TypeScript |
| [`gateway/`](gateway) | TAP-aware Gateway — adds server-side attestation in front of tools that have never heard of TAP |
| [`inspector/`](inspector) | Local dev tool — mint test Passports, sign/verify Events, visualize a record's chain |

---

## Three design decisions worth knowing

**Digests in the signed body; plaintext in a redactable annex.** The immutable record contains only SHA-256 digests of arguments, intent, and outputs. Human-readable text travels in a separate unsigned **annex** that can be stored encrypted and crypto-shredded. Delete the key and the personal data is gone while the signed chain still proves what was authorized and executed. This is how an immutable audit trail and a GDPR erasure obligation coexist.

**Two-sided attestation.** The agent signs *intent* ("I am calling `db_query`"). An independent server — or the Gateway, for upstreams that aren't TAP-aware — signs *execution* ("`db_query` ran and returned OK"). A compromised signer can lie about intent; it cannot forge the server's signature over what actually happened.

**Signed checkpoints make fail-open safe.** Reporting never blocks your agent. Periodic signed Merkle checkpoints let a verifier tell the difference between *provable deletion* and *benign loss* — turning "this gap is suspicious" into "this gap is provably malicious or provably benign."

And one deliberate constraint: **no fractional numbers in a signed body.** Float canonicalization is the single most common source of cross-language signature divergence. Scores and other fractional quantities are encoded as strings. The vectors include a fractional case to force the issue.

---

## Conformance

Three classes, defined in [spec §14](TAP-spec-v0.1.md):

| Class | Must implement |
|---|---|
| **Signer** | Passport minting + renewal, Event signing over JCS, checkpoints, carriage, fail-open reporting |
| **Verifier** | Signature verification + suite dispatch + revocation, checkpoint reconciliation, chain join, replay defense, honest assurance labeling |
| **TAP-aware Server / Gateway** | Handshake, Passport verification, server-attested Events echoing `action_ref`, replay cache |

All classes must pass `test-vectors.json`. A conforming verifier **must reject any suite it does not recognize** rather than fall back to a default — verification dispatches off the key's declared suite, so future (including post-quantum) suites need no verifier rewrite.

```bash
# reference implementation — regenerates and self-checks the vectors
python3 tap_ref.py

# Python SDK
cd sdk/python && PYTHONPATH=src python3 tests/test_conformance.py

# TypeScript SDK
cd sdk/js && npm install && npm test
```

---

## What TAP does *not* do

Credibility here depends on not overclaiming.

TAP proves **authorship and integrity, not honesty.** It cannot establish that an agent's stated reasoning is its *real* reasoning, or stop a fully compromised signer from signing fluent lies. The structural answers are independent server attestation, model-output-bound counterfactuals, and a record any skeptical third party can check — but the limitation is real and permanent.

TAP is also not a content filter, a risk-assessment framework, a bias evaluation tool, or a guardrail engine. It records provenance and provides evidence. It does not, by itself, make any deployer "compliant" — documentation should say TAP *supports* or *provides evidence for* an obligation, never that it certifies anything.

---

## Status

**v0.1 — early.** The spec, reference implementation, conformance vectors, both SDKs, the Gateway and the Inspector all ship and are tested.

Not yet built, and worth knowing before you depend on this: the Go SDK; the three-tier KMS/HSM key hierarchy of §3.5 (today every signer uses a single flat key, so treat signing keys as long-lived secrets); post-quantum suites, which are reserved in the registry but unimplemented; composite signatures; and RFC 3161 timestamp anchoring. The `nego` anti-downgrade binding (§4.1) ships in the Python SDK but not yet in TypeScript.

Open an issue if a gap blocks you — the roadmap is driven by what implementers actually hit.

Breaking changes are possible before v1.0. The wire format is versioned (`v: "tap/0.1"`) and negotiated, so upgrades are a gradient rather than a flag day.

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The one hard rule: **any change to signing or verification must be accompanied by regenerated test vectors and must pass both SDKs' conformance suites.** The vectors are the contract.

For security issues, see [SECURITY.md](SECURITY.md) — please don't open a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

*TAP is stewarded by [Sworn](https://getsworn.ai), which operates a hosted Verifier built on this standard. The protocol is deliberately vendor-neutral: the format, the reference implementation, the verification logic, and the conformance vectors are open so that anyone can verify a TAP record without trusting Sworn, the agent operator, or any other party.*
