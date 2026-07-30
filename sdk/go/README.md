# TAP Go SDK

Go implementation of the Traceable Agent Protocol (TAP) v0.1.

This SDK is a conforming implementation of the TAP v0.1 wire crypto:
- Ed25519 over JCS-canonicalized event bodies
- Compact-JWS Passports (`tap-passport+jwt`)
- Checkpoint Merkle roots per §6.3
- Canonicalization guard (no fractional numbers in signed bodies)
- Negative test vector compliance (rejects invalid signatures, unknown suites, etc.)

## Conformance

This SDK reproduces all test vectors from `test-vectors.json` byte-for-byte,
including the canonicalization torture test with non-BMP characters, UTF-16
member ordering, and NFC/NFD distinction.

Run the conformance tests:

```bash
go test -v ./tap -run TestConformanceVectors
go run test_negative_vectors.go  # from repo root tap/sdk/go/
```

## Installation

```bash
go get github.com/traceable-agent/tap-sdk-go/v2/tap
```

## Quick Start

```go
import "github.com/traceable-agent/tap-sdk-go/v2/tap"

// Generate a new signing key
sk, seedHex, err := tap.GenerateSigner()
if err != nil {
    log.Fatal(err)
}

// Create a JWK for distribution
jwk := tap.PublicJWK(sk, "key_2026_01")

// Sign a Passport
claims := map[string]any{
    "iss": "https://verifier.example.com",
    "iat": time.Now().Unix(),
    "exp": time.Now().Add(time.Hour).Unix(),
    "jti": "psp_01JABCDEF0000000000000000",
    "aid": "agt_01JABCDEF1111111111111111",
    "cid": tap.TextDigest("prompt" + string(nonce)),
    "scope": []string{"read:database", "call:tool"},
}
passport, err := tap.SignPassport(sk, "key_2026_01", claims)

// Sign an Event
eventBody := map[string]any{
    "v":           "tap/0.1",
    "event_id":    tap.NewID("evt"),
    "passport_jti": "psp_01JABCDEF0000000000000000",
    "aid":         "agt_01JABCDEF1111111111111111",
    "cid":         cid,
    "seq":         1,
    "ts":          tap.NowTS(),
    "action": map[string]any{
        "kind":           "tool_call",
        "intent_digest":  tap.TextDigest("Call db_query to fetch users"),
        "tool":           "db_query",
        "scope_used":     "read:database",
        "args_digest":    tap.JSONDigest(map[string]any{"table": "users", "limit": 50}),
    },
    "evidence": map[string]any{
        "reasoning_digest":     tap.TextDigest("Fetch user rows first"),
        "model_output_digest":  tap.Digest([]byte("<full trace>")),
        "nego":                 map[string]any{"version": "tap/0.1", "suite": "tap-ed25519", "attestation": "server"},
    },
    "result":     map[string]any{"status": "success", "code": "OK", "latency_ms": 142, "error": nil},
    "attestor":   "agent",
    "action_ref": tap.NewID("act"),
    "kid":        "key_2026_01",
}
signedEvent, err := tap.SignEvent(sk, eventBody)

// Verify an Event
err = tap.VerifyEvent(jwk, signedEvent)

// Verify a Passport
claims, err := tap.VerifyPassport(jwk, passport, time.Now().Unix())

// Checkpoint Merkle root
root := tap.CheckpointRoot([]string{"evt_1", "evt_2"})
```

## Key Types

- `tap.SuiteID` — crypto-suite identifier (currently only `tap-ed25519`)
- `tap.CanonicalizationError` — raised when a signed body contains forbidden numbers
- `tap.ErrUnknownSuite` — key declares an unsupported crypto suite
- `tap.ErrRevokedKey` — record timestamp falls at or after key's `revoked_at`

## Functions

### Passport (compact JWS/JWT)
- `SignPassport(sk, kid, claims) (string, error)`
- `VerifyPassport(jwk, token, now) (map[string]any, error)`

### Event (detached signature over JCS body)
- `SignEvent(sk, body) (map[string]any, error)`
- `VerifyEvent(jwk, event) error`
- `SigningInput(eventBody) ([]byte, error)` — bytes that get signed

### Canonicalization & Digests
- `Canonicalize(v) ([]byte, error)` — RFC 8785 JCS
- `Digest(data) string` — `sha256:<hex>`
- `TextDigest(text) string` — digest of UTF-8 string
- `JSONDigest(v) (string, error)` — digest of JCS-canonical JSON

### Canonicalization Guard
- `CanonicalGuard(v, path) error` — rejects floats and out-of-range ints in signed bodies

### Checkpoint Merkle (§6.3)
- `CheckpointRoot(eventIDs []string) string` — Merkle root over event_ids

### IDs & Time
- `NewID(prefix) string` — sortable ID with timestamp + random
- `NowTS() string` — RFC 3339 with millisecond precision
- `NewNonce() []byte` — 128-bit random nonce
- `CIDFromPrompt(prompt string, nonce []byte) (string, error)` — `cid = digest(prompt ‖ nonce)`

### Crypto Suite & Revocation
- `SuiteForJWK(jwk) (SuiteID, error)` — dispatch off declared (alg, crv)
- `KeyRevokedAt(jwk) (int64, bool)` — optional revocation boundary
- `CheckNotRevoked(jwk, signedAt) error` — enforce revocation against record's own timestamp
- `ParseTS(ts) (int64, error)` — RFC 3339 → epoch seconds

### Scope Check
- `ScopeSatisfied(scopeUsed string, passportScope []string) bool` — exact match per [TAP-SCOPE-MATCH]

## Negative Vectors

The SDK correctly rejects:
- Unknown crypto suites (`unknown_suite_rs256`, `unknown_suite_alg_none`)
- Wrong passport `typ` (`passport_wrong_typ`)
- Events signed after key revocation (`event_signed_after_revocation`)
- Tampered events (`tampered_event`)
- Explicit nulls where optionals must be omitted (`explicit_nulls_non_conforming`)
- Duplicate (aid, seq) with different content (`duplicate_aid_seq`)
- Checkpoints omitting delivered events (`checkpoint_omits_delivered_event`)

## Specification

See `TAP-spec-v0.1.md` for the full protocol specification with stable `[TAP-...]` anchor tags.

## License

MIT