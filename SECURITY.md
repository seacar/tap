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
- downgrade attacks that evade the `nego` binding, including any way to make a Signer bind an assurance level it did not actually obtain
- suite-dispatch bypass — getting a verifier to accept a key whose declared suite it should reject
- revocation bypass — getting a verifier to accept records signed by a revoked key
- private key or annex plaintext leaking into a signed body, a log, or an error message

## What's out of scope

These are known, documented limitations rather than vulnerabilities:

- **TAP proves authorship and integrity, not honesty.** A fully compromised Signer can sign truthful-looking but false intent. The structural mitigation is independent server attestation (spec §7). Reports that amount to "a compromised agent can lie" will be closed with a pointer here.
- **TAP provides no confidentiality.** It is a provenance layer; use TLS. Digests in the signed body are deliberately not secret.
- **`cid` is opaque to verifiers** and is never recomputed by them.
- **Non-conforming-but-validly-signed records.** A record that carries explicit nulls where the spec says omit is a conformance defect, not a vulnerability: it verifies against its own signature and misleads nobody about authorship. It is caught by the `negative` vectors, not by this policy.
- **The reference seed** in `test-vectors.json` (`9d61b1…7f60`) is public and intentionally so. It MUST NOT be used in production; that's stated in the spec. Reporting that the test key is compromised is not a finding.
- Denial of service against a specific deployment's Verifier — report that to the operator.
- Missing hardening in example or demo code clearly marked as such.

## Known limitations in v0.1

Worth stating plainly:

- **No key hierarchy yet.** Every Signer currently signs with a single flat key. The three-tier design (KMS/HSM issuing key → attested ephemeral signing key) is specified in §3.5 but not implemented. Treat signing keys as long-lived secrets and protect them accordingly.
- **No post-quantum suites.** `tap-ml-dsa-65` and `tap-slh-dsa-128s` are reserved in the registry with no implementation.
- **No timestamp anchoring.** Checkpoint Merkle roots are not yet submitted to an RFC 3161 authority, so long-term "this record predates the break" evidence isn't available yet.
- **The replay cache is per-process.** `TAPServer` holds seen `jti` and `(aid, seq)` values in memory with a TTL. A horizontally scaled deployment therefore enforces `[TAP-REPLAY]` per instance, not per fleet; a replay routed to a different instance inside the TTL window is not caught at the edge. A Verifier still detects the duplicate `(aid, seq)` downstream — the evidence is intact, but the edge rejection is not. Shared-cache deployment is a Service Profile concern.
- **Only two implementations, by the same authors.** Python and TypeScript agree byte-for-byte, including on the canonicalization vector, which is meaningful. It is less meaningful than an independent third implementation would be: two codebases written by the same people can share a wrong assumption and agree perfectly.

## Fixed in v0.1.2

These were real weaknesses in v0.1.0, listed because "we quietly fixed it" is not how a security-relevant project should behave. None had a known exploit; all were reachable by ordinary use.

- **Key revocation was not enforced for Events** by the documented verification primitive in the reference implementation or in either SDK — only by a higher-level Python module. A caller using `verify_event` accepted records signed by a key its owner had already reported compromised.
- **The TypeScript signer did not enforce the no-fractional-numbers rule**, so it could emit records the specification forbids, whose divergence would surface only later as a checkpoint that would not reconcile.
- **The server leg placed raw intent plaintext in the signed body**, defeating the digest-only rule that makes crypto-shredding possible: that text could not be erased without invalidating the signature over it.
- **The replay cache was keyed on `action_ref`**, which the caller chooses freely, so an attacker replayed simply by picking a new one. It was also unbounded — a memory-exhaustion surface reachable by any caller able to mint identifiers.
- **Identifiers in the TypeScript SDK came from `Math.random()`**. `event_id` and `action_ref` values are committed to by checkpoint Merkle roots and correlate the two legs of an attested action; predictable ones let an attacker anticipate a slot before it is filled.
- **The specification published a reference signature that did not match the committed vectors**, which would have sent an implementer hunting a mismatch that was the document's fault. CI now compares them.

## Supported versions

v0.1 is pre-1.0 and only the latest commit on `main` receives fixes. Once v1.0 ships, this section will describe a real support window.
