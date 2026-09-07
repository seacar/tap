# Conformance

**Audience:** SDK authors, verifier authors, and security reviewers  
**Status:** public implementation guide; requirements are defined by the specification

TAP conformance is claimed by implementation class.

## Classes

| Class | Responsibility |
|---|---|
| Signer | Issue Passports, sign Events, maintain sequence and checkpoints, negotiate capabilities, and report without blocking the workload |
| Verifier | Validate signatures, suites, keys, revocation, sequence, replay, chains, checkpoints, and assurance labels |
| TAP-aware Server / Gateway | Validate Passports, negotiate capabilities, prevent replay, and sign observed execution Events |

An implementation should state exactly which class and protocol version it supports.

## What the vectors prove

[`test-vectors.json`](../test-vectors.json) contains:

- deterministic positive cases that must reproduce the same canonical bytes and signatures;
- negative cases that a verifier must reject or flag;
- cross-language edge cases for Unicode, omission, escapes, and fractional values.

Matching only the positive signatures is insufficient. A verifier that accepts invalid input is not conformant.

## Local conformance run

```bash
./scripts/ci-local.sh
```

The script exercises:

- reference-vector generation and self-checks;
- quoted spec values against the vector file;
- schemas against the vectors;
- Python, TypeScript, and Go SDK tests;
- regression tests for defects that shipped once;
- cross-language envelope parity — both SDKs' *composed* events diffed against
  each other and validated against the published schema;
- Gateway and Inspector tests.

The parity check is separate from the vectors on purpose. A vector proves an
implementation can re-sign a body someone else composed; it says nothing about
the body that implementation composes on its own, which is where the two SDKs
actually diverged.

Per-implementation coverage, including the classes these SDKs do **not** fully
cover, is published in the [README's conformance matrix](../README.md#conformance)
as §14 requires.

## Changes to signed bytes

Any change that affects canonical signed bytes must include:

1. an explicit specification change;
2. regenerated vectors;
3. a negative vector when a new rejection rule is introduced;
4. matching implementation changes;
5. a changelog entry that names the affected fields;
6. a compatibility note.

Do not silently “fix” one SDK. Cross-language byte equality is the interoperability contract.

## Publishing a conformance claim

A useful claim includes:

- implementation name and version;
- TAP protocol version;
- conformance class;
- cryptographic suites;
- vector version or repository commit;
- known deviations;
- date and environment of the test run.

Avoid a single undifferentiated “TAP compliant” badge. It hides which obligations were actually tested.
