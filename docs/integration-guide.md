# Integration guide

**Audience:** platform engineers and service owners  
**Status:** explanatory guide for TAP v0.1.2

TAP can be added at three boundaries: inside an agent runtime, at a server that understands TAP, or at a Gateway in front of an unchanged upstream.

## Agent integration

Instrument the narrowest reusable client boundary that sees the action before it leaves the process. That is usually:

- an MCP client wrapper;
- an A2A delegation client;
- a shared tool dispatcher;
- a framework middleware hook;
- a decorator around local tools.

The integration should:

1. issue or renew a Passport for the run;
2. record the action before dispatch;
3. attach TAP transport metadata;
4. capture the result without putting plaintext in the signed body;
5. report the Event asynchronously;
6. emit periodic checkpoints.

Avoid instrumenting only individual business functions when a common tool boundary exists. Coverage gaps are harder to reason about than a single interception point.

## TAP-aware server

A TAP-aware server validates the Passport and participates in capability negotiation. It independently records the observed action and result.

Server responsibilities include:

- suite and protocol-version negotiation;
- Passport validation and scope checks;
- replay protection;
- server-side signing;
- returning the acknowledgement and correlation material;
- preserving honest assurance labels when negotiation is incomplete.

The Python and TypeScript SDKs both provide server-leg primitives. See their README files for language-specific APIs.

## Gateway

The Gateway adds a TAP-aware boundary in front of a service that does not implement TAP.

```text
agent ── TAP headers ──> Gateway ── ordinary request ──> upstream
                            │
                            └── signed observed Event
```

Use the Gateway when:

- the upstream is third-party or difficult to modify;
- one platform team needs consistent Passport enforcement;
- replay checks and server-side signing should be centralized;
- a migration must begin without changing every tool server.

The Gateway proves what passed through its boundary. It does not prove what an opaque upstream did internally.

Run the reference Gateway:

```bash
python3 -m gateway.serve
```

Review `gateway/config.py` before production use. Treat signing keys, replay storage, public-key discovery, and upstream TLS as production security boundaries.

## Inspector

The Inspector is a local development tool for examining TAP records. Use it to:

- mint development Passports;
- sign and verify Events;
- inspect sequence and chain links;
- understand assurance labels;
- debug canonicalization and signature failures.

```bash
python3 -m inspector --help
```

The Inspector is not a production evidence store.

## Transport bindings

TAP v0.1 defines bindings for:

- HTTP headers for remote calls;
- JSON-RPC `_meta` for stdio MCP and A2A messages;
- asynchronous Event reporting to a verifier.

The [specification](../TAP-spec-v0.1.md) is authoritative for exact field names, required validation, and failure behavior.

## Integration anti-patterns

- Calling a mutable application log a TAP record.
- Signing only after the action and treating it as proof of prior intent.
- Storing private keys beside exported evidence.
- Claiming observed assurance without a server acknowledgement.
- Copying annex plaintext into the signed body.
- Accepting positive test vectors while ignoring negative vectors.
- Depending on Sworn-specific behavior in a protocol implementation.
