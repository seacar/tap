# traceable-agent-protocol — Traceable Agent Protocol for Python

Sign every action your agent takes, so anyone can verify what it did without trusting you.

Part of the [TAP monorepo](../../). See the [specification](../../TAP-spec-v0.1.md) for the wire contract.

```bash
pip install traceable-agent-protocol
```

## Sign an agent

```python
from tap_sdk import TAPClient

tap = TAPClient(
    agent_id="support-triage",
    private_key_hex=SEED,
    kid="key_2026_01",
    endpoint="https://your-verifier.example.com",
    api_key="...",
)

passport = tap.issue_passport(
    task_prompt="Resolve support ticket #8842",
    scope=["read:database", "call:tool"],
)

@tap.trace(tool="db_query", scope="read:database")
def db_query(table, limit):
    return run_query(table, limit)      # unchanged

db_query("users", limit=50)
tap.emit_checkpoint()                   # seals the record
```

Reporting is **asynchronous and fail-open** — your agent never blocks on the Verifier being reachable. Signed checkpoints make that safe: a verifier can tell a dropped batch from a deleted event.

## Record a decision, including what you didn't choose

```python
tap.decision(
    question="How should I resolve refund ticket #8842?",
    options=[
        {"id": "refund",   "score": "0.71", "rationale": "Within policy; SLA breached"},
        {"id": "escalate", "score": "0.52", "reason": "Higher cost; not required"},
        {"id": "deny",     "score": "0.10", "reason": "Would violate refund policy v3"},
    ],
    chosen="refund",
)
```

The whole option set is inside the signature, so the agent can't later claim it weighed a different one. **Scores must be strings** — fractional numbers are forbidden in a signed body (spec §3.4) because float canonicalization is the most common source of cross-language signature divergence.

## Verify — with only a public key

```python
from tap_sdk.verify import verify_transcript

report = verify_transcript(passport_compact, events, resolve_key=lambda kid: JWKS[kid])
```

No database, no vendor, no network. This is the point of the whole protocol: verification is stateless and needs nothing but the published JWKS. (Audit and drift detection are deliberately stateful; *verification* is not.)

## Attest the server side

Two-sided provenance: the agent attests *intent*, the tool operator attests *execution* with its own key. A compromised agent can lie about intent; it can't forge the server's signature over what actually ran.

```python
from tap_sdk.server import TAPServer

server = TAPServer(private_key_hex=SERVER_SEED, kid="key_tool_01",
                   endpoint="https://your-verifier.example.com",
                   resolve_key=lambda kid: JWKS.get(kid))

result = server.attest(passport_jwt, action_ref=ref, tool="db_query",
                       scope_used="read:database", handler=run_query)
```

For upstreams that don't support TAP, put the [Gateway](../../gateway) in front instead — it terminates the handshake and emits the server leg on their behalf.

## Enforce policy before acting

```python
POLICY = {"default": "allow",
          "rules": [{"id": "no-shell", "effect": "deny", "when": {"tool": "run_shell"}}]}

tap = TAPClient(..., policy=POLICY, enforce=True)
```

A denied action raises `PolicyDenied` *and* still records a signed `denied` event — the action stops, the evidence stays. Every action carries the `policy_version` digest of the policy set in force, so an auditor can prove which policy governed a historical decision.

## Modules

| Module | What's in it |
|---|---|
| `tap_sdk.core` | Crypto primitives — signing, verification, canonicalization guard, checkpoint Merkle, suite dispatch, revocation |
| `tap_sdk.signer` | `TAPClient` — passports, `@trace`, decisions, checkpoints, A2A delegation |
| `tap_sdk.verify` | Transcript verification, assurance labeling, chain reconstruction |
| `tap_sdk.server` | `TAPServer` — the server-attested execution leg |
| `tap_sdk.policy` | Policy evaluation and the `policy_decision` record |
| `tap_sdk.tracer` | `TAPTracer` — high-level entry point; registers identities from an API key |
| `tap_sdk.verifier_api` | Typed REST client for a Verifier (requires the `http` extra) |
| `tap_sdk.transport` | Buffered, fail-open event reporter |

`tap_sdk.core` and `tap_sdk.verify` import with no network dependencies — install `traceable-agent-protocol[http]` only if you need the REST client or automatic identity registration.

## Conformance

```bash
PYTHONPATH=src python3 tests/test_conformance.py      # reproduces the reference vectors
PYTHONPATH=src python3 tests/test_verifier_musts.py   # suite dispatch + revocation MUSTs
```

This SDK reproduces [`test-vectors.json`](../../test-vectors.json) byte-for-byte, as does the [TypeScript SDK](../js). That cross-language agreement is the contract.

Apache-2.0.
