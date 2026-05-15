# Project governance

**Audience:** contributors and implementers  
**Status:** public project policy

TAP is stewarded by Sworn as an open, vendor-neutral protocol. The specification, reference implementation, verification logic, schemas, registries, and conformance vectors remain publicly reviewable and Apache-2.0 licensed.

## Decision principles

Protocol changes are evaluated in this order:

1. interoperability across independent implementations;
2. verifiability without dependence on a single vendor;
3. accurate security and assurance claims;
4. privacy and data minimization;
5. operational adoption;
6. implementation convenience.

## Change categories

### Editorial

Clarifies wording without changing behavior or signed bytes. Requires review and must not introduce new normative requirements.

### Compatible

Adds optional behavior, a registry entry, or an extension that older implementations can safely ignore. Requires tests and an interoperability explanation.

### Breaking

Changes signed bytes, validation, required behavior, or interpretation. Requires a versioning decision, regenerated vectors, migration notes, and a changelog entry.

## Extension policy

Extensions must:

- use a collision-resistant namespace;
- define how unknown fields are handled;
- preserve base-protocol verification;
- avoid changing assurance labels without negotiation;
- include test cases;
- remain implementable without Sworn.

## Contribution path

Read [CONTRIBUTING.md](../CONTRIBUTING.md), open an issue for material protocol changes, and include tests with the pull request.

Security vulnerabilities follow [SECURITY.md](../SECURITY.md) and should not be reported in public issues.
