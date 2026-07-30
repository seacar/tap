# Getting started

**Audience:** agent developers and platform engineers  
**Status:** implementation guide for TAP v0.1.2

This guide takes an existing agent from no evidence to a signed TAP record.

## 1. Choose an SDK

Packages are currently installed from this repository.

```bash
# Python
pip install ./sdk/python

# TypeScript
npm install ./sdk/js
```

Use the [Python SDK guide](../sdk/python/README.md) or [TypeScript SDK guide](../sdk/js/README.md) for the complete API surface.

## 2. Protect a signing key

For development, generate an Ed25519 seed locally. For production, load signing material through your secrets or key-management boundary. Do not commit seeds, private keys, or production Passports.

Every signature identifies its key with `kid`. Publish the corresponding public key through an authenticated JWKS endpoint and define how verifiers obtain revocation state.

## 3. Create a client

```python
from tap_sdk import TAPClient

tap = TAPClient(
    agent_id="support-triage",
    private_key_hex=SEED,
    kid="key_2026_01",
    endpoint="https://verifier.example.com",
)
```

The endpoint can be your own verifier. Sworn is not required.

## 4. Issue a Passport

```python
passport = tap.issue_passport(
    task_prompt="Resolve support ticket #8842",
    scope=["read:database"],
)
```

Keep the requested scope narrow. A verifier can detect activity outside the Passport scope, but it cannot repair an overly broad authorization decision.

## 5. Sign actions

```python
@tap.trace(tool="db_query", scope="read:database")
def db_query(table, limit):
    return run_query(table, limit)

db_query("users", limit=50)
```

The SDK hashes content before it enters the signed body. Configure annex handling separately if readable payloads must be retained.

## 6. Negotiate with the server leg

Two-sided evidence requires an acknowledgement from a TAP-aware server or Gateway.

```python
ack = requests.post(
    url,
    headers=passport.http_headers(hello=tap.hello()),
).headers

tap.negotiate(json.loads(ack["X-TAP-Hello-Ack"]))
```

When the acknowledgement is missing, the record remains useful but must be labeled `intent-only`.

## 7. Seal and report

```python
tap.emit_checkpoint()
```

Checkpoints allow a verifier to reconcile event intervals and surface unexplained gaps. Reporting is designed not to block the agent workload; operate a retry queue appropriate for your reliability requirements.

## 8. Verify independently

Verification needs the record, the signer’s public key, and the TAP rules. It does not require access to the system that stored the record.

During development:

```bash
python3 tap_ref.py
python3 inspector/cli.py --help
./scripts/ci-local.sh
```

## Production checklist

- Keep signing keys outside application source and logs.
- Publish authenticated key-discovery and revocation information.
- Set Passport scopes and lifetimes deliberately.
- Use a TAP-aware server or Gateway when observed assurance is required.
- Define annex encryption, retention, access, and deletion rules.
- Monitor reporting lag and unreconciled checkpoints.
- Run the positive and negative conformance vectors in CI.
- Preserve the protocol version and suite identifiers with exported evidence.
