# Architecture and trust model

**Audience:** developers, platform engineers, and security reviewers  
**Status:** explanatory; the specification remains normative

TAP creates portable evidence about agent activity. It does not decide whether an action is safe, correct, or compliant. It records who acted, the authority presented, what action was attempted, what result was observed, and how those facts are linked.

## The evidence path

```text
Agent runtime
  ├─ issues a signed Passport
  ├─ signs intent and action Events
  └─ reports Events without blocking the workload
          │
          ▼
TAP-aware server or Gateway
  ├─ validates the Passport
  ├─ negotiates supported capabilities
  └─ signs the observed execution result
          │
          ▼
Verifier
  ├─ validates signatures and key status
  ├─ checks sequence, replay, and checkpoint integrity
  ├─ joins client and server evidence
  └─ labels the resulting assurance honestly
```

## The two core records

### Passport

A Passport is a signed credential for an agent run. It binds an agent identity to an issuer, an authorized scope, a validity window, a context, and protocol metadata.

A Passport is evidence of presented authority. It is not proof that the issuer should have granted that authority.

### Event

An Event is a signed record of one step in an agent run. Events carry a sequence number, action classification, digests of relevant content, links to prior evidence, and a result.

Sensitive plaintext belongs in the redactable annex. The signed body contains digests so the integrity proof can survive removal of the plaintext.

## Two-sided attestation

The agent can sign what it intended to do. A TAP-aware server or Gateway can independently sign what it observed.

These statements are intentionally separate:

- **intent-only:** the agent signed its own claim;
- **observed:** an independent server leg signed the execution result;
- **joined:** the verifier matched the intent and observed records through `action_ref` and negotiation evidence.

If the server leg is absent, a verifier must not label the record as independently observed.

## Failure model

TAP reporting is fail-open for the workload. A reporting outage should not take down an agent. Signed checkpoints make this operational choice visible: the verifier can distinguish a reconciled interval from an unexplained gap.

This does not guarantee delivery. It makes missing evidence detectable.

## Trust boundaries

TAP assumes:

- signing keys are protected by their owners;
- verifiers obtain authentic public keys and revocation state;
- cryptographic algorithms and canonicalization are implemented correctly;
- independent attestors are meaningfully separate from the signer when stronger assurance is claimed.

TAP does not prove:

- that an agent’s stated reasoning is truthful;
- that an authorized action was appropriate;
- that a model was unbiased or safe;
- that a deployment complies with a law or control framework.

## Privacy model

The immutable evidence layer and the readable evidence layer are separated:

- the signed body carries stable digests and minimal metadata;
- the annex carries readable prompts, arguments, outputs, and explanations;
- annex data can be encrypted, access-controlled, retained for a defined period, or crypto-shredded.

This design preserves integrity checks after sensitive plaintext has been deleted.

## Where TAP sits

MCP and A2A move requests, context, and work between systems. TAP records signed evidence about those interactions.

TAP is complementary to:

- identity and access management;
- policy engines and guardrails;
- observability and tracing;
- governance and risk platforms;
- security incident and case-management systems.

Those systems can consume TAP evidence, but TAP does not replace them.

### TAP does not ship an MCP server

TAP's MCP support is a thin, client-side seam: `instrument_mcp`/`instrumentMcp` wrap an existing MCP client's `call_tool` to sign a `tool_call` Event around it, using the caller's own key. There is no `@modelcontextprotocol/sdk` dependency anywhere in this repository, and no plan to add one.

A hosted MCP server exposing TAP operations as callable tools — mint a credential, check authority, revoke an approval — is a **managed-service concern, not a protocol one**, for the same reason retention, reporting, and tenant administration are (see [the README](../README.md#start-here)). Concretely: a server that signs on a caller's behalf must custody that caller's key, which is exactly the centralization TAP exists to avoid — "a third party can validate a TAP record without trusting Sworn, the agent operator, or the system that stored the evidence" only holds if signing keys never leave the signer. Revocation and authority-state currency (`[TAP-AUTHORITY-REVOKE]`, `[TAP-AUTHORITY-REUSE]`) are stateful for the same reason `[TAP-KEY-REVOCATION]` is — they need a registry someone runs, which is a Verifier/Service-Profile deployment, not a protocol primitive.

If a hosted MCP surface gets built, it belongs to Sworn (or any self-hoster), built on the open `verify`/`authority` primitives this repository already ships — not maintained here.
