# TAP documentation

**Audience:** developers, contributors, platform engineers, and security engineers  
**Status:** public documentation index

TAP is the Traceable Agent Protocol: an open protocol for producing signed, independently verifiable evidence of AI-agent actions.

## Start here

| If you want to… | Read |
|---|---|
| Understand the protocol in ten minutes | [Architecture and trust model](architecture.md) |
| Add TAP to an agent | [Getting started](getting-started.md) |
| Put a TAP-aware boundary in front of tools | [Integration guide](integration-guide.md) |
| Implement or audit the wire format | [TAP specification](../TAP-spec-v0.1.md) |
| Understand the design rationale | [TAP whitepaper](../TAP-whitepaper.md) |
| Test an implementation | [Conformance](conformance.md) |
| Contribute a change | [Project governance](governance.md) and [CONTRIBUTING.md](../CONTRIBUTING.md) |

## Documentation map

### Learn

- [Architecture and trust model](architecture.md)
- [Getting started](getting-started.md)
- [Integration guide](integration-guide.md)

### Implement

- [Python SDK](../sdk/python/README.md)
- [TypeScript SDK](../sdk/js/README.md)
- [Gateway](integration-guide.md#gateway)
- [Inspector](integration-guide.md#inspector)
- [Schemas](../schemas/)
- [Registries](../registries/)

### Verify

- [Conformance](conformance.md)
- [Test vectors](../test-vectors.json)
- [Security policy](../SECURITY.md)
- [Changelog](../CHANGELOG.md)

### Specify

- [Normative specification](../TAP-spec-v0.1.md)
- [Whitepaper](../TAP-whitepaper.md)
- [Reference implementation](../tap_ref.py)

## TAP and Sworn

TAP is vendor-neutral. Its signed records can be produced, stored, and verified without using Sworn.

[Sworn](https://getsworn.ai) is a managed service built on TAP. It operates verification, retention, reporting, and evidence workflows for organizations that do not want to run those services themselves. Commercial service documentation belongs to Sworn; protocol documentation belongs here.
