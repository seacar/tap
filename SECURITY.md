# Security Policy

## Reporting a vulnerability

**Please do not open a public issue.**

Report privately via GitHub's [Report a vulnerability](../../security/advisories/new) form, or email **security@getsworn.ai**.

Please include: what you found, how to reproduce it, which component and version, and what an attacker gains. A proof-of-concept against `test-vectors.json` is ideal.

We aim to acknowledge within 3 business days and to ship a fix or a clear timeline within 90 days. We'll credit you in the advisory unless you'd rather stay anonymous.

## What's in scope

Anything that lets an attacker forge, alter, or suppress evidence without detection:

- signature forgery or verification bypass in `tap_ref.py` or either SDK
- canonicalization divergence — two implementations producing different signed bytes for the same logical object, or the same signature for different objects
- token confusion between Passports and Events
- replay that survives the `exp` / `jti` / `(aid, seq)` defenses
- checkpoint Merkle construction flaws that let an event be dropped without detection
- downgrade attacks that evade the `nego` binding
- suite-dispatch bypass — getting a verifier to accept a key whose declared suite it should reject
- revocation bypass — getting a verifier to accept records signed by a revoked key
- private key or annex plaintext leaking into a signed body, a log, or an error message

## What's out of scope

These are known, documented limitations rather than vulnerabilities:

- **TAP proves authorship and integrity, not honesty.** A fully compromised Signer can sign truthful-looking but false intent. The structural mitigation is independent server attestation (spec §7). Reports that amount to "a compromised agent can lie" will be closed with a pointer here.
- **TAP provides no confidentiality.** It is a provenance layer; use TLS. Digests in the signed body are deliberately not secret.
- **`cid` is opaque to verifiers** and is never recomputed by them.
- **The reference seed** in `test-vectors.json` (`9d61b1…7f60`) is public and intentionally so. It MUST NOT be used in production; that's stated in the spec. Reporting that the test key is compromised is not a finding.
- Denial of service against a specific deployment's Verifier — report that to the operator.
- Missing hardening in example or demo code clearly marked as such.

## Known limitations in v0.1

Worth stating plainly:

- **No key hierarchy yet.** Every Signer currently signs with a single flat key. The three-tier design (KMS/HSM issuing key → attested ephemeral signing key) is specified in §3.5 but not implemented. Treat signing keys as long-lived secrets and protect them accordingly.
- **No post-quantum suites.** `tap-ml-dsa-65` and `tap-slh-dsa-128s` are reserved in the registry with no implementation.
- **No timestamp anchoring.** Checkpoint Merkle roots are not yet submitted to an RFC 3161 authority, so long-term "this record predates the break" evidence isn't available yet.

## Supported versions

v0.1 is pre-1.0 and only the latest commit on `main` receives fixes. Once v1.0 ships, this section will describe a real support window.
