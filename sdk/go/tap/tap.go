// Package tap provides the Traceable Agent Protocol (TAP) Go SDK.
// This is a conforming implementation of TAP v0.1 wire crypto: Ed25519 over
// JCS-canonicalized event bodies and compact-JWS passports.
// It reproduces the test vectors from test-vectors.json byte-for-byte.
package tap

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// SpecVersion is the TAP specification version implemented by this SDK.
const SpecVersion = "tap/0.1"

const (
	// PassportTyp is the required JOSE typ for TAP Passports.
	PassportTyp = "tap-passport+jwt"
	// DefaultIssuer is a neutral example issuer for test vectors.
	DefaultIssuer = "https://verifier.example.com"
	// DefaultTTL is the default passport TTL in seconds (1 hour).
	DefaultTTL = 3600
)

// Result codes as defined in the TAP spec.
const (
	ResultOK              = "OK"
	ResultDeniedScope     = "DENIED_SCOPE"
	ResultDeniedPolicy    = "DENIED_POLICY"
	ResultToolError       = "TOOL_ERROR"
	ResultTimeout         = "TIMEOUT"
	ResultUpstream4xx     = "UPSTREAM_4XX"
	ResultUpstream5xx     = "UPSTREAM_5XX"
	ResultValidationError = "VALIDATION_ERROR"
)

// ActionKinds are the registered action kinds per [TAP-EVT-KIND].
// Implementations MAY define namespaced extension kinds prefixed "x-";
// verifiers MUST preserve unknown kinds verbatim.
var ActionKinds = map[string]bool{
	"tool_call":            true,
	"agent_delegate":       true,
	"received_delegation":  true,
	"agent_message":        true,
	"denied":               true,
	"decision":             true,
	"checkpoint":           true,
}

// ---------- Errors ----------

// ErrCanonicalization indicates a value that JCS cannot canonicalize identically
// across implementations — a fractional/exponent number, or an out-of-range integer.
var ErrCanonicalization = errors.New("canonicalization error")

// ErrUnknownSuite indicates the key declares a crypto suite this implementation
// does not recognize. A conforming verifier MUST reject it rather than fall back.
var ErrUnknownSuite = errors.New("unknown crypto suite")

// ErrRevokedKey indicates the signing key's revocation boundary excludes this record.
var ErrRevokedKey = errors.New("key revoked")

// ---------- Base64url encoding ----------

// b64u encodes bytes as base64url without padding (RFC 7515 §2).
func b64u(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// b64uDec decodes base64url without padding.
func b64uDec(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// ---------- Digests ----------

// Digest returns a TAP digest string: "sha256:<hex>".
func Digest(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// TextDigest returns the digest of a UTF-8 string (the value signed when
// plaintext lives in the annex per §6.1).
func TextDigest(text string) string {
	return Digest([]byte(text))
}

// JSONDigest returns the digest over the JCS-canonical bytes of a JSON value
// — cross-language stable per §6.1.
func JSONDigest(v any) (string, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	return Digest(canon), nil
}

// ---------- Canonicalization Guard ([TAP-CANON-NUMBERS]) ----------

const maxSafeInt = 1<<53 - 1

// CanonicalizationError is raised when a signed body contains a value JCS
// cannot canonicalize identically across implementations.
type CanonicalizationError string

func (e CanonicalizationError) Error() string {
	return "canonicalization error: " + string(e)
}

// CanonicalGuard rejects any float or unsafe integer anywhere in a signed body.
// Fractional quantities (e.g., decision score) MUST be encoded as strings.
func CanonicalGuard(v any, path string) error {
	switch val := v.(type) {
	case bool:
		return nil
	case float64:
		// Check if it's actually an integer value (no fractional part)
		if val == float64(int64(val)) {
			// It's an integer - check safe range
			i := int64(val)
			if i < -maxSafeInt || i > maxSafeInt {
				return CanonicalizationError(fmt.Sprintf("integer %d exceeds ±(2^53−1) safe range", i))
			}
			return nil
		}
		// Has fractional part - reject
		return CanonicalizationError("fractional/float numbers are forbidden in a signed body; encode as a string")
	case int, int8, int16, int32, int64:
		i, _ := v.(int64)
		if i < -maxSafeInt || i > maxSafeInt {
			return CanonicalizationError(fmt.Sprintf("integer %d exceeds ±(2^53−1) safe range", i))
		}
		return nil
	case uint, uint8, uint16, uint32, uint64:
		u, _ := v.(uint64)
		if u > uint64(maxSafeInt) {
			return CanonicalizationError(fmt.Sprintf("integer %d exceeds ±(2^53−1) safe range", u))
		}
		return nil
	case string:
		return nil
	case []any:
		for i, elem := range val {
			if err := CanonicalGuard(elem, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		for k, elem := range val {
			if err := CanonicalGuard(elem, fmt.Sprintf("%s.%s", path, k)); err != nil {
				return err
			}
		}
		return nil
	case nil:
		return nil
	default:
		// Try JSON marshaling to catch other numeric types
		b, err := json.Marshal(v)
		if err != nil {
			return nil
		}
		var f float64
		if json.Unmarshal(b, &f) == nil {
			// Check if it's actually an integer
			if f == float64(int64(f)) {
				i := int64(f)
				if i < -maxSafeInt || i > maxSafeInt {
					return CanonicalizationError(fmt.Sprintf("integer %d exceeds ±(2^53−1) safe range", i))
				}
				return nil
			}
			return CanonicalizationError("fractional/float numbers are forbidden in a signed body; encode as a string")
		}
		var i int64
		if json.Unmarshal(b, &i) == nil {
			if i < -maxSafeInt || i > maxSafeInt {
				return CanonicalizationError(fmt.Sprintf("integer %d exceeds ±(2^53−1) safe range", i))
			}
		}
		return nil
	}
}

// ---------- JCS Canonicalization (RFC 8785) ----------

// Canonicalize returns the JCS-canonical bytes of a JSON value.
// This implementation follows RFC 8785 exactly.
func Canonicalize(v any) ([]byte, error) {
	// First marshal to JSON
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	// Parse into a generic structure for canonicalization
	var parsed any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return nil, err
	}

	// Apply JCS canonicalization
	return jcsCanonicalize(parsed)
}

// jcsCanonicalize implements RFC 8785 JSON Canonicalization Scheme.
func jcsCanonicalize(v any) ([]byte, error) {
	switch val := v.(type) {
	case nil:
		return []byte("null"), nil
	case bool:
		if val {
			return []byte("true"), nil
		}
		return []byte("false"), nil
	case string:
		return json.Marshal(val)
	case float64:
		// RFC 8785: Numbers must be serialized without fractional part if integer
		// and using the shortest possible decimal representation
		return []byte(rfc8785FormatNumber(val)), nil
	case int:
		return []byte(strconv.FormatInt(int64(val), 10)), nil
	case int64:
		return []byte(strconv.FormatInt(val, 10)), nil
	case uint64:
		return []byte(strconv.FormatUint(val, 10)), nil
	case []any:
		// Array
		var parts []string
		for _, elem := range val {
			elemBytes, err := jcsCanonicalize(elem)
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(elemBytes))
		}
		return []byte("[" + strings.Join(parts, ",") + "]"), nil
	case map[string]any:
		// Object - JCS sorts keys by UTF-16 code unit order
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		// Sort by UTF-16 code unit order per RFC 8785
		sort.Slice(keys, func(i, j int) bool {
			return utf16Less(keys[i], keys[j])
		})

		var parts []string
		for _, k := range keys {
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			valBytes, err := jcsCanonicalize(val[k])
			if err != nil {
				return nil, err
			}
			parts = append(parts, string(keyBytes)+":"+string(valBytes))
		}
		return []byte("{" + strings.Join(parts, ",") + "}"), nil
	default:
		// Fallback to standard JSON marshaling for other types
		return json.Marshal(val)
	}
}

// Utf16Less compares two strings by UTF-16 code unit order (RFC 8785).
// This is the correct comparison for JCS member ordering.
func Utf16Less(a, b string) bool {
	// Convert to UTF-16 for comparison
	u16a := UTF16Encode(a)
	u16b := UTF16Encode(b)

	// Compare code unit by code unit
	for i := 0; i < len(u16a) && i < len(u16b); i++ {
		if u16a[i] != u16b[i] {
			return u16a[i] < u16b[i]
		}
	}
	// If all compared units are equal, shorter string comes first
	return len(u16a) < len(u16b)
}

// UTF16Encode converts a string to its UTF-16 code unit representation.
// Returns a slice of uint16 representing the UTF-16 encoding.
func UTF16Encode(s string) []uint16 {
	// Pre-allocate with estimate (at most 2 code units per rune)
	result := make([]uint16, 0, len(s)*2)
	for _, r := range s {
		if r <= 0xFFFF {
			// BMP character - single code unit
			result = append(result, uint16(r))
		} else {
			// Non-BMP character - surrogate pair
			r -= 0x10000
			result = append(result, 0xD800+uint16(r>>10))
			result = append(result, 0xDC00+uint16(r&0x3FF))
		}
	}
	return result
}

// utf16Less compares two strings by UTF-16 code unit order (RFC 8785).
func utf16Less(a, b string) bool {
	return Utf16Less(a, b)
}

// utf16Encode converts a string to its UTF-16 code unit representation.
func utf16Encode(s string) []uint16 {
	return UTF16Encode(s)
}

// rfc8785FormatNumber formats a float64 per RFC 8785 (JCS).
func rfc8785FormatNumber(f float64) string {
	// Handle special cases
	if f == 0 {
		return "0"
	}

	// Check if it's an integer value
	if f == float64(int64(f)) && f >= -9007199254740991 && f <= 9007199254740991 {
		return strconv.FormatInt(int64(f), 10)
	}

	// Use the shortest decimal representation that round-trips
	return strconv.FormatFloat(f, 'f', -1, 64)
}

// ---------- Keys & Crypto-Suite Dispatch ([TAP-SUITE-DISPATCH]) ----------

// SuiteID is the TAP crypto-suite identifier.
type SuiteID string

const (
	SuiteEd25519 SuiteID = "tap-ed25519"
)

// SuiteForJWK resolves a JWK's declared (alg, crv) to a TAP suite ID.
func SuiteForJWK(jwk map[string]any) (SuiteID, error) {
	alg, _ := jwk["alg"].(string)
	crv, _ := jwk["crv"].(string)

	if alg == "EdDSA" && crv == "Ed25519" {
		return SuiteEd25519, nil
	}

	return "", fmt.Errorf("%w: unrecognized crypto suite for key %v: (%s, %s)",
		ErrUnknownSuite, jwk["kid"], alg, crv)
}

// ---------- Three-Tier Key Hierarchy ([TAP-KEY-HIERARCHY]) ----------

// KeyAttestationCertificate is the key-attestation certificate per [TAP-KEY-HIERARCHY, §3.5].
// Signed by the issuing key, binding an ephemeral signing key to an agent.
type KeyAttestationCertificate struct {
	KID       string                 `json:"kid"`        // ephemeral signing key id
	X         string                 `json:"x"`          // ephemeral public key (base64url)
	AID       string                 `json:"aid"`        // agent instance it is bound to
	IssKID    string                 `json:"iss_kid"`    // issuing key that attests it
	NBF       int64                  `json:"nbf"`        // not-before (epoch seconds)
	Exp       int64                  `json:"exp"`        // expiry (epoch seconds)
	Env       *EnvironmentAttestation `json:"env,omitempty"` // optional environment attestation
	Sig       string                 `json:"sig"`        // issuing key's signature over the above
}

// EnvironmentAttestation carries optional environment attestation (TEE quote, SPIFFE identity).
type EnvironmentAttestation struct {
	TEE           string `json:"tee,omitempty"`            // e.g., "sev-snp"
	QuoteDigest   string `json:"quote_digest,omitempty"`   // digest of TEE quote
	Workload      string `json:"workload,omitempty"`       // SPIFFE identity
}

// SignKeyAttestation signs a key-attestation certificate with an issuing key.
func SignKeyAttestation(issuingKey ed25519.PrivateKey, issKID string, cert *KeyAttestationCertificate) error {
	// Canonicalize the certificate without the signature for signing
	certForSigning := map[string]any{
		"kid":    cert.KID,
		"x":      cert.X,
		"aid":    cert.AID,
		"iss_kid": cert.IssKID,
		"nbf":    cert.NBF,
		"exp":    cert.Exp,
	}
	if cert.Env != nil {
		certForSigning["env"] = cert.Env
	}

	canon, err := Canonicalize(certForSigning)
	if err != nil {
		return err
	}

	sig := ed25519.Sign(issuingKey, canon)
	cert.Sig = b64u(sig)
	return nil
}

// VerifyKeyAttestation verifies a key-attestation certificate against an issuing key JWK.
func VerifyKeyAttestation(issuingJWK map[string]any, cert *KeyAttestationCertificate) error {
	// Suite dispatch
	if _, err := SuiteForJWK(issuingJWK); err != nil {
		return err
	}

	// Check revocation
	if err := CheckNotRevoked(issuingJWK, cert.NBF); err != nil {
		return err
	}

	// Verify the issuing key matches
	if issuingJWK["kid"] != cert.IssKID {
		return errors.New("iss_kid mismatch")
	}

	// Reconstruct the signed payload
	certForVerify := map[string]any{
		"kid":     cert.KID,
		"x":       cert.X,
		"aid":     cert.AID,
		"iss_kid": cert.IssKID,
		"nbf":     cert.NBF,
		"exp":     cert.Exp,
	}
	if cert.Env != nil {
		certForVerify["env"] = cert.Env
	}

	canon, err := Canonicalize(certForVerify)
	if err != nil {
		return err
	}

	sig, err := b64uDec(cert.Sig)
	if err != nil {
		return err
	}

	pubKey, err := b64uDec(issuingJWK["x"].(string))
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, canon, sig) {
		return errors.New("key attestation signature verification failed")
	}

	// Verify time window
	now := time.Now().Unix()
	if now < cert.NBF || now >= cert.Exp {
		return errors.New("key attestation expired or not yet valid")
	}

	return nil
}

// ResolveEphemeralKey resolves an ephemeral signing key through its attestation chain.
// Returns the ephemeral key's JWK if valid.
func ResolveEphemeralKey(ephemeralKID string, attestation *KeyAttestationCertificate, issuingJWK map[string]any) (map[string]any, error) {
	// Verify the attestation
	if err := VerifyKeyAttestation(issuingJWK, attestation); err != nil {
		return nil, err
	}

	// Verify the ephemeral KID matches
	if attestation.KID != ephemeralKID {
		return nil, errors.New("ephemeral KID mismatch")
	}

	// Return the ephemeral key as a JWK
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "EdDSA",
		"use": "sig",
		"kid": attestation.KID,
		"x":   attestation.X,
	}, nil
}

// PublicJWKFromSeed returns the public JWK for a seed hex string.
func PublicJWKFromSeed(seedHex string, kid string) (map[string]any, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, errors.New("seed must be 32 bytes (64 hex chars)")
	}
	sk := ed25519.NewKeyFromSeed(seed)
	pub := sk.Public().(ed25519.PublicKey)
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "EdDSA",
		"use": "sig",
		"kid": kid,
		"x":   b64u(pub),
	}, nil
}

// VerifyEventWithAttestation verifies an Event using a key-attestation certificate chain.
// It validates: Event sig → ephemeral key → attestation cert → issuing key (in JWKS).
func VerifyEventWithAttestation(jwks map[string]any, event map[string]any, attestCert *KeyAttestationCertificate) error {
	// 1. Verify the event signature against the ephemeral key in the attestation cert
	ephemeralJWK := map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "EdDSA",
		"use": "sig",
		"kid": attestCert.KID,
		"x":   attestCert.X,
	}
	if err := VerifyEvent(ephemeralJWK, event); err != nil {
		return fmt.Errorf("event verification failed: %w", err)
	}

	// 2. Verify the attestation cert's binding to the event's aid
	if event["aid"] != attestCert.AID {
		return errors.New("attestation cert aid mismatch with event")
	}

	// 3. Verify the attestation cert against the issuing key in JWKS
	keys := jwks["keys"].([]any)
	var issuingJWK map[string]any
	for _, k := range keys {
		key := k.(map[string]any)
		if key["kid"] == attestCert.IssKID {
			issuingJWK = key
			break
		}
	}
	if issuingJWK == nil {
		return fmt.Errorf("issuing key %s not found in JWKS", attestCert.IssKID)
	}

	if err := VerifyKeyAttestation(issuingJWK, attestCert); err != nil {
		return fmt.Errorf("key attestation verification failed: %w", err)
	}

	// 4. Check the issuing key's revocation boundary against the event's ts
	if err := CheckNotRevoked(issuingJWK, event["ts"]); err != nil {
		return err
	}

	return nil
}

// KeyRevokedAt returns the optional epoch-seconds revocation boundary for a key.
func KeyRevokedAt(jwk map[string]any) (int64, bool) {
	if rev, ok := jwk["revoked_at"]; ok {
		switch v := rev.(type) {
		case float64:
			return int64(v), true
		case int64:
			return v, true
		case int:
			return int64(v), true
		case string:
			if i, err := strconv.ParseInt(v, 10, 64); err == nil {
				return i, true
			}
		}
	}
	return 0, false
}

// ParseTS parses an RFC 3339 UTC timestamp to epoch seconds.
func ParseTS(ts string) (int64, error) {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		// Try with Z suffix replacement
		t, err = time.Parse("2006-01-02T15:04:05.000Z", ts)
		if err != nil {
			return 0, err
		}
	}
	return t.Unix(), nil
}

// CheckNotRevoked enforces a key's revocation boundary against the record's timestamp.
func CheckNotRevoked(jwk map[string]any, signedAt any) error {
	revoked, ok := KeyRevokedAt(jwk)
	if !ok {
		return nil
	}

	var at int64
	if signedAt == nil {
		return fmt.Errorf("%w: key is revoked and the record carries no timestamp to place it", ErrRevokedKey)
	}

	switch v := signedAt.(type) {
	case string:
		var err error
		at, err = ParseTS(v)
		if err != nil {
			return fmt.Errorf("%w: key is revoked and the record timestamp is unparseable: %v", ErrRevokedKey, err)
		}
	case int64:
		at = v
	case int:
		at = int64(v)
	default:
		return fmt.Errorf("%w: key is revoked and the record timestamp has unexpected type", ErrRevokedKey)
	}

	if at >= revoked {
		return fmt.Errorf("%w: key revoked at %d; record is timestamped %d", ErrRevokedKey, revoked, at)
	}
	return nil
}

// LoadSigner loads an Ed25519 private key from a 32-byte seed hex string.
func LoadSigner(seedHex string) (ed25519.PrivateKey, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		return nil, err
	}
	if len(seed) != 32 {
		return nil, errors.New("seed must be 32 bytes (64 hex chars)")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// GenerateSigner generates a new Ed25519 signer and returns the private key and seed hex.
func GenerateSigner() (ed25519.PrivateKey, string, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", err
	}
	seed := priv.Seed()
	return priv, hex.EncodeToString(seed), nil
}

// PublicJWK returns the public JWK for a signer.
func PublicJWK(sk ed25519.PrivateKey, kid string) map[string]any {
	pub := sk.Public().(ed25519.PublicKey)
	return map[string]any{
		"kty": "OKP",
		"crv": "Ed25519",
		"alg": "EdDSA",
		"use": "sig",
		"kid": kid,
		"x":   b64u(pub),
	}
}

// ---------- Passport (Compact JWS/JWT) ----------

// SignPassport creates a compact JWS/JWT Passport.
// Key order must match the reference implementation exactly for interoperability.
func SignPassport(sk ed25519.PrivateKey, kid string, claims map[string]any) (string, error) {
	// Header must have exact key order: alg, typ, kid (matching reference)
	header := `{"alg":"EdDSA","typ":"tap-passport+jwt","kid":"` + kid + `"}`

	// Claims must match reference key order
	// We need to manually construct to match the reference's key ordering
	claimsJSON, err := marshalClaimsDeterministic(claims)
	if err != nil {
		return "", err
	}

	seg := b64u([]byte(header)) + "." + b64u(claimsJSON)
	sig := ed25519.Sign(sk, []byte(seg))

	return seg + "." + b64u(sig), nil
}

// marshalClaimsDeterministic marshals claims with the exact key order expected by TAP reference.
func marshalClaimsDeterministic(claims map[string]any) ([]byte, error) {
	// The reference uses this specific key order for claims
	// We need to marshal in a specific order
	orderedKeys := []string{
		"iss", "iat", "exp", "jti", "aid", "cid", "scope", "meta",
	}

	// Build the JSON manually with correct order
	result := "{"
	first := true
	for _, key := range orderedKeys {
		if val, ok := claims[key]; ok {
			if !first {
				result += ","
			}
			first = false

			keyJSON, _ := json.Marshal(key)
			valJSON, err := marshalValueDeterministic(val, key)
			if err != nil {
				return nil, err
			}
			result += string(keyJSON) + ":" + string(valJSON)
		}
	}

	// Add any extra keys not in orderedKeys (in sorted order for determinism)
	extraKeys := make([]string, 0)
	for k := range claims {
		found := false
		for _, ok := range orderedKeys {
			if k == ok {
				found = true
				break
			}
		}
		if !found {
			extraKeys = append(extraKeys, k)
		}
	}
	// Sort extra keys for determinism
	for i := 0; i < len(extraKeys); i++ {
		for j := i + 1; j < len(extraKeys); j++ {
			if extraKeys[i] > extraKeys[j] {
				extraKeys[i], extraKeys[j] = extraKeys[j], extraKeys[i]
			}
		}
	}

	for _, key := range extraKeys {
		if !first {
			result += ","
		}
		first = false
		val := claims[key]
		keyJSON, _ := json.Marshal(key)
		valJSON, err := marshalValueDeterministic(val, key)
		if err != nil {
			return nil, err
		}
		result += string(keyJSON) + ":" + string(valJSON)
	}

	result += "}"
	return []byte(result), nil
}

// marshalValueDeterministic marshals a value with deterministic ordering for nested objects.
func marshalValueDeterministic(v any, parentKey string) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		// Special handling for meta object - use specific key order
		var orderedKeys []string
		if parentKey == "meta" {
			orderedKeys = []string{"framework", "model", "agent_name"}
		} else {
			// For other objects, use sorted keys
			orderedKeys = make([]string, 0, len(val))
			for k := range val {
				orderedKeys = append(orderedKeys, k)
			}
			for i := 0; i < len(orderedKeys); i++ {
				for j := i + 1; j < len(orderedKeys); j++ {
					if orderedKeys[i] > orderedKeys[j] {
						orderedKeys[i], orderedKeys[j] = orderedKeys[j], orderedKeys[i]
					}
				}
			}
		}

		result := "{"
		first := true
		for _, key := range orderedKeys {
			if v, ok := val[key]; ok {
				if !first {
					result += ","
				}
				first = false
				keyJSON, _ := json.Marshal(key)
				valJSON, err := marshalValueDeterministic(v, key)
				if err != nil {
					return nil, err
				}
				result += string(keyJSON) + ":" + string(valJSON)
			}
		}
		result += "}"
		return []byte(result), nil

	case []any:
		// Array - marshal each element
		result := "["
		for i, elem := range val {
			if i > 0 {
				result += ","
			}
			elemJSON, err := marshalValueDeterministic(elem, "")
			if err != nil {
				return nil, err
			}
			result += string(elemJSON)
		}
		result += "]"
		return []byte(result), nil

	default:
		// Primitive types - use standard JSON marshaling
		return json.Marshal(val)
	}
}

// VerifyPassport validates a Passport per [TAP-PASSPORT-VALIDATE].
func VerifyPassport(jwk map[string]any, token string, now int64) (map[string]any, error) {
	// Suite dispatch
	if _, err := SuiteForJWK(jwk); err != nil {
		return nil, err
	}

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	hB64, pB64, sB64 := parts[0], parts[1], parts[2]

	pubKey, err := b64uDec(jwk["x"].(string))
	if err != nil {
		return nil, err
	}

	sig, err := b64uDec(sB64)
	if err != nil {
		return nil, err
	}

	signingInput := hB64 + "." + pB64
	if !ed25519.Verify(pubKey, []byte(signingInput), sig) {
		return nil, errors.New("invalid signature")
	}

	headerBytes, err := b64uDec(hB64)
	if err != nil {
		return nil, err
	}

	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, err
	}

	if header["alg"] != "EdDSA" {
		return nil, fmt.Errorf("unsupported alg in JOSE header: %v", header["alg"])
	}
	if header["typ"] != PassportTyp {
		return nil, errors.New("wrong token type")
	}
	if header["kid"] != jwk["kid"] {
		return nil, errors.New("kid mismatch")
	}

	claimsBytes, err := b64uDec(pB64)
	if err != nil {
		return nil, err
	}

	var claims map[string]any
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, err
	}

	// Check revocation against iat
	iat, _ := claims["iat"].(float64)
	if err := CheckNotRevoked(jwk, int64(iat)); err != nil {
		return nil, err
	}

	// Freshness with ±60s skew allowance per [TAP-PASSPORT-VALIDATE]
	exp, _ := claims["exp"].(float64)
	if int64(iat)-60 > now || now >= int64(exp)+60 {
		return nil, errors.New("passport expired / not yet valid")
	}

	return claims, nil
}

// ---------- Event (Detached Sig over JCS Canonical Body) ----------

// SigningInput returns the canonical bytes that get signed: JCS(event without sig).
func SigningInput(eventBody map[string]any) ([]byte, error) {
	body := make(map[string]any)
	for k, v := range eventBody {
		if k != "sig" {
			body[k] = v
		}
	}
	return Canonicalize(body)
}

// SignEvent signs an event body and returns the signed event.
func SignEvent(sk ed25519.PrivateKey, eventBody map[string]any) (map[string]any, error) {
	// Canonicalization guard
	bodyForGuard := make(map[string]any)
	for k, v := range eventBody {
		if k != "sig" {
			bodyForGuard[k] = v
		}
	}
	if err := CanonicalGuard(bodyForGuard, ""); err != nil {
		return nil, err
	}

	input, err := SigningInput(eventBody)
	if err != nil {
		return nil, err
	}

	sig := ed25519.Sign(sk, input)

	signed := make(map[string]any)
	for k, v := range eventBody {
		signed[k] = v
	}
	signed["sig"] = b64u(sig)

	return signed, nil
}

// VerifyEvent verifies one Event per [TAP-EVT-VERIFY].
func VerifyEvent(jwk map[string]any, event map[string]any) error {
	// Suite dispatch and revocation boundary are part of verification
	if _, err := SuiteForJWK(jwk); err != nil {
		return err
	}

	if err := CheckNotRevoked(jwk, event["ts"]); err != nil {
		return err
	}

	pubKey, err := b64uDec(jwk["x"].(string))
	if err != nil {
		return err
	}

	sigB64, ok := event["sig"].(string)
	if !ok {
		return errors.New("missing or invalid sig")
	}
	sig, err := b64uDec(sigB64)
	if err != nil {
		return err
	}

	input, err := SigningInput(event)
	if err != nil {
		return err
	}

	if !ed25519.Verify(pubKey, input, sig) {
		return errors.New("signature verification failed")
	}

	if event["kid"] != jwk["kid"] {
		return errors.New("kid mismatch")
	}

	return nil
}

// ---------- IDs & Timestamps ----------

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

func b32(value uint64, length int) string {
	out := make([]byte, length)
	for i := length - 1; i >= 0; i-- {
		out[i] = crockford[value&31]
		value >>= 5
	}
	return string(out)
}

// NewID generates a new TAP ID with the given prefix.
func NewID(prefix string) string {
	tsMs := uint64(time.Now().UnixMilli())
	randBytes := make([]byte, 10)
	rand.Read(randBytes)
	randVal := uint64(0)
	for _, b := range randBytes {
		randVal = (randVal << 8) | uint64(b)
	}
	return fmt.Sprintf("%s_%s%s", prefix, b32(tsMs, 10), b32(randVal, 16))
}

// NowTS returns the current time as RFC 3339 with millisecond precision.
func NowTS() string {
	now := time.Now().UTC()
	return now.Format("2006-01-02T15:04:05.000Z")
}

// NewNonce generates a 128-bit nonce for cid construction.
func NewNonce() []byte {
	nonce := make([]byte, 16)
	rand.Read(nonce)
	return nonce
}

// CIDFromPrompt computes cid = digest(utf8(prompt) ‖ nonce) per §3.3.
func CIDFromPrompt(prompt string, nonce []byte) (string, error) {
	if len(nonce) < 16 {
		return "", errors.New("cid nonce MUST be at least 16 bytes (128 bits)")
	}
	return Digest([]byte(prompt + string(nonce))), nil
}

// ---------- Checkpoint Merkle ([TAP-EVT-CHECKPOINT]) ----------

const (
	ckptLeafPrefix = 0x00
	ckptNodePrefix = 0x01
)

func ckptLeafHash(eventID string) []byte {
	h := sha256.New()
	h.Write([]byte{ckptLeafPrefix})
	h.Write([]byte(eventID))
	return h.Sum(nil)
}

func ckptNodeHash(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{ckptNodePrefix})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// CheckpointRoot computes the Merkle root over event_ids per §6.3.
func CheckpointRoot(eventIDs []string) string {
	if len(eventIDs) == 0 {
		return Digest([]byte{})
	}

	level := make([][]byte, len(eventIDs))
	for i, eid := range eventIDs {
		level[i] = ckptLeafHash(eid)
	}

	for len(level) > 1 {
		var next [][]byte
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				next = append(next, ckptNodeHash(level[i], level[i+1]))
			} else {
				next = append(next, level[i]) // promote odd node unchanged
			}
		}
		level = next
	}

	return "sha256:" + hex.EncodeToString(level[0])
}

// ---------- Scope Check ([TAP-SCOPE-MATCH]) ----------

// ScopeSatisfied performs exact-match scope check per [TAP-SCOPE-MATCH].
// v0.1 matches scope tokens by exact string equality: no wildcards, no prefix rule.
func ScopeSatisfied(scopeUsed string, passportScope []string) bool {
	if scopeUsed == "" {
		return true
	}
	for _, s := range passportScope {
		if s == scopeUsed {
			return true
		}
	}
	return false
}