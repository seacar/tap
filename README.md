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

> **Not yet on PyPI or npm.** The package names below are reserved but unpublished, so install from this repository for now — `pip install ./sdk/python`, or `npm install ./sdk/js`. The published commands are shown because they are what the names will be; they are not what works today.

### Python

```bash
pip install ./sdk/python        # published as `traceable-agent-protocol`
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

Against a TAP-aware server or Gateway, negotiate first — that is what lets the record claim *two-sided* assurance honestly:

```python
ack = requests.post(url, headers=passport.http_headers(hello=tap.hello())).headers
tap.negotiate(json.loads(ack["X-TAP-Hello-Ack"]))   # binds the OBSERVED outcome
```

If an intermediary strips the handshake, no ack comes back, nothing is bound, and the record degrades visibly to `intent-only` instead of claiming assurance nobody promised.

### TypeScript

```bash
npm install ./sdk/js            # published as `@traceableagent/sdk`
```

```ts
import { TAPClient } from "@traceableagent/sdk/agent";

const tap = new TAPClient({ agentId: "support-triage", privateKeyHex: SEED, kid: "key_2026_01" });
const passport = await tap.issuePassport({ taskPrompt: "…", scope: ["read:database"] });
```

Both SDKs reproduce [`test-vectors.json`](test-vectors.json) byte-for-byte from the same fixed seed — including a canonicalization case built from non-BMP characters, NFC/NFD pairs and control-character escapes, because that is where RFC 8785 implementations actually diverge. CI additionally checks that the two SDKs **compose** identical bytes for the same logical action, not merely that each can re-sign a body the other composed.

That is the property the whole protocol rests on: **a Signer and a Verifier in different languages cannot drift apart.**

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
| [`schemas/`](schemas) | JSON Schema for the Event, Passport claims, and annex |
| [`registries/`](registries) | Machine-readable crypto-suite and result-code registries |
| [`CHANGELOG.md`](CHANGELOG.md) | What changed, and which changes altered signed bytes |

---

## Three design decisions worth knowing

**Digests in the signed body; plaintext in a redactable annex.** The immutable record contains only SHA-256 digests of arguments, intent, and outputs. Human-readable text travels in a separate unsigned **annex** that can be stored encrypted and crypto-shredded. Delete the key and the personal data is gone while the signed chain still proves what was authorized and executed. This is how an immutable audit trail and a GDPR erasure obligation coexist.

**Two-sided attestation.** The agent signs *intent* ("I am calling `db_query`"). An independent server — or the Gateway, for upstreams that aren't TAP-aware — signs *execution* ("`db_query` ran and returned OK"). A compromised signer can lie about intent; it cannot forge the server's signature over what actually happened.

**Signed checkpoints make fail-open safe.** Reporting never blocks your agent. Periodic signed Merkle checkpoints let a verifier tell the difference between *provable deletion* and *benign loss* — turning "this gap is suspicious" into "this gap is provably malicious or provably benign." Each checkpoint carries its own interval bounds, so it reconciles on its own even when an earlier one never arrived.

And one deliberate constraint: **no fractional numbers in a signed body.** Float canonicalization is the single most common source of cross-language signature divergence. Scores and other fractional quantities are encoded as strings. The vectors include a fractional case to force the issue.

---

## Conformance

Three classes, defined in [spec §14](TAP-spec-v0.1.md):

| Class | Must implement |
|---|---|
| **Signer** | Passport minting + renewal, Event signing over JCS, checkpoints, the handshake binding, carriage, fail-open reporting |
| **Verifier** | Signature verification + suite dispatch + revocation, checkpoint reconciliation, chain join, replay defense, honest assurance labeling |
| **TAP-aware Server / Gateway** | Handshake, Passport verification, server-attested Events echoing `action_ref`, replay cache |

Passing `test-vectors.json` means passing **both halves**: reproducing every published signature byte-for-byte, *and* rejecting or flagging every case in its `negative` section. Reproduction alone establishes only that an implementation can sign like the reference — a verifier that accepted everything would pass it perfectly.

### What each implementation here actually covers

Conformance is claimed per class, and this repository's implementations do not all cover all three. Published so the gaps are visible rather than implied:

| | Reference (`tap_ref.py`) | Python SDK | TypeScript SDK | Gateway |
|---|---|---|---|---|
| Sign Passports + Events | ✅ | ✅ | ✅ | ✅ (server leg) |
| Digest-only body, omit-absent rule | ✅ | ✅ | ✅ | ✅ |
| No-fractional-numbers guard | ✅ | ✅ | ✅ | ✅ |
| Checkpoints (emit + seal) | ✅ | ✅ | ✅ | n/a |
| Handshake + `nego` binding | n/a | ✅ | ✅ | ✅ (answers) |
| Suite dispatch + revocation | ✅ | ✅ | ✅ | ✅ |
| Passport validation | ✅ | ✅ | ✅ | ✅ |
| Checkpoint reconciliation | ✅ | ✅ | ✅ | n/a |
| Assurance labelling + chain join | ❌ | ✅ | ✅ | n/a |
| Replay cache | n/a | n/a | n/a | ✅ |
| **Signer class** | partial | ✅ | ✅ | n/a |
| **Verifier class** | partial | ✅ | ✅ | n/a |
| **Server/Gateway class** | ❌ | ✅ (`TAPServer`) | ✅ (`TAPServer`) | ✅ |

`tap_ref.py` is deliberately partial: it is a readable definition of the wire crypto, not a product. Its job is to generate the vectors and to be short enough that you can check it by eye.

### Running it

```bash
# everything CI runs, locally
./scripts/ci-local.sh

# or piecemeal:
python3 tap_ref.py                    # regenerate + self-check the vectors
python3 scripts/check-spec-vectors.py # the spec's quoted values match the vectors
python3 scripts/check-schemas.py      # the schemas describe the vectors
cd sdk/python && PYTHONPATH=src python3 tests/test_conformance.py
cd sdk/js && npm install && npm test
```

---

## What TAP does *not* do

Credibility here depends on not overclaiming.

TAP proves **authorship and integrity, not honesty.** It cannot establish that an agent's stated reasoning is its *real* reasoning, or stop a fully compromised signer from signing fluent lies. The structural answers are independent server attestation, model-output-bound counterfactuals, and a record any skeptical third party can check — but the limitation is real and permanent.

TAP is also not a content filter, a risk-assessment framework, a bias evaluation tool, or a guardrail engine. It records provenance and provides evidence. It does not, by itself, make any deployer "compliant" — documentation should say TAP *supports* or *provides evidence for* an obligation, never that it certifies anything.

---

## Status

**v0.1.2 — early.** The spec, reference implementation, conformance vectors, both SDKs, the Gateway and the Inspector all ship and are tested, and the two SDKs now compose byte-identical envelopes for the same logical action.

v0.1.2 changed signed bytes on purpose, to fix places where the specification disagreed with its own reference implementation. If you built against v0.1.0, see [CHANGELOG.md](CHANGELOG.md) — the changed fields are listed individually.

Not yet built, and worth knowing before you depend on this:

- **No key hierarchy.** Every signer uses a single flat key. The three-tier KMS/HSM design in §3.5 is specified but unimplemented, so treat signing keys as long-lived secrets and protect them accordingly.
- **No post-quantum suites.** `tap-ml-dsa-65` and `tap-slh-dsa-128s` are reserved in the registry with no implementation.
- **No composite signatures** and **no RFC 3161 timestamp anchoring**.
- **No third-language SDK.** A Go, Rust, or Java signer that reproduces the vectors is the single strongest validation the spec can get, and the surest way to find remaining ambiguities — two implementations by the same authors agree partly because they share assumptions.

Open an issue if a gap blocks you — the roadmap is driven by what implementers actually hit.

Breaking changes are possible before v1.0. The wire format is versioned (`v: "tap/0.1"`) and negotiated, so upgrades are a gradient rather than a flag day.

---

## Contributing

Issues and PRs welcome — see [CONTRIBUTING.md](CONTRIBUTING.md). The one hard rule: **any change to signing or verification must be accompanied by regenerated test vectors and must pass both SDKs' conformance suites.** The vectors are the contract.

Two conventions worth knowing before you read the code: comments cite the spec's stable `[TAP-…]` anchor tags rather than section numbers, which move and leave citations quietly wrong; and a change that adds a rule should add a *negative* vector for it, because a rule the vectors cannot fail is a rule nobody has to follow.

For security issues, see [SECURITY.md](SECURITY.md) — please don't open a public issue.

## License

Apache-2.0. See [LICENSE](LICENSE).

---

*TAP is stewarded by [Sworn](https://getsworn.ai), which operates a hosted Verifier built on this standard. The protocol is deliberately vendor-neutral: the format, the reference implementation, the verification logic, and the conformance vectors are open so that anyone can verify a TAP record without trusting Sworn, the agent operator, or any other party.*
