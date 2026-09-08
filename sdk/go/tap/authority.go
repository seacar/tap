package tap

import "fmt"

// Authority binding — bind one Event to a pre-declared expected effect
// [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL].
//
// policy_decision proves a *class* of action was permitted under the rules in
// force. It does not prove a specific, authentically-signed instance stayed
// within what was actually approved *for that instance* — a Signer holding a
// validly-scoped Passport and a compliant policy decision can still take an
// authentic action nobody approved for that particular case. Authority
// binding is that missing claim: it binds one Event to one pre-declared
// expected outcome, under a specific version of the authority that granted
// it, valid only for a bounded window. policy_decision and authorization
// compose freely — an Event MAY carry either, both, or neither.
//
// PROVISIONAL. The wire shape and the two STATELESS checks here
// (CheckAuthorityWindow, AuthorityEffectLabel) mirror the reference
// implementation in tap_ref.py and sdk/python/src/tap_sdk/authority.py as of
// protocol v0.1.4, reproducing the same test-vectors.json -> authorization
// vector. [TAP-AUTHORITY-REVOKE] and [TAP-AUTHORITY-REUSE] are STATEFUL (a
// registry of revoked/consumed authz_ids) and are therefore a
// Verifier/Service-Profile concern, not this SDK's — no production Verifier
// enforces them yet. Track status in tap/CHANGELOG.md.

// Authorization is the exact shape stamped onto an Event's "authorization"
// field. The signed body never carries the raw expected state — only its
// digest, matching the digest-only discipline of the rest of the envelope
// [TAP-EVT-ENVELOPE]. Plaintext, where retained, belongs in the annex.
type Authorization struct {
	AuthzID               string `json:"authz_id"`
	AuthorityStateVersion string `json:"authority_state_version"`
	TargetStateDigest     string `json:"target_state_digest"`
	Nbf                   int64  `json:"nbf"`
	Exp                   int64  `json:"exp"`
	IssuerKID             string `json:"issuer_kid"`
}

// GrantAuthorization mints a new approval binding targetState under
// authorityState. Both are digested here, once, so every other layer only
// ever sees the digest — a caller cannot accidentally leak the raw state into
// a signed body. Pass authzID = "" to mint a fresh one.
func GrantAuthorization(targetState, authorityState any, nbf, exp int64, issuerKID, authzID string) (*Authorization, error) {
	asv, err := AuthorityStateVersion(authorityState)
	if err != nil {
		return nil, err
	}
	tsd, err := JSONDigest(targetState)
	if err != nil {
		return nil, err
	}
	if authzID == "" {
		authzID = NewID("auz")
	}
	return &Authorization{
		AuthzID:               authzID,
		AuthorityStateVersion: asv,
		TargetStateDigest:     tsd,
		Nbf:                   nbf,
		Exp:                   exp,
		IssuerKID:             issuerKID,
	}, nil
}

// ToRecord returns the exact map[string]any JSON stamped onto an Event's
// "authorization" field.
func (a *Authorization) ToRecord() map[string]any {
	return map[string]any{
		"authz_id":                a.AuthzID,
		"authority_state_version": a.AuthorityStateVersion,
		"target_state_digest":     a.TargetStateDigest,
		"nbf":                     a.Nbf,
		"exp":                     a.Exp,
		"issuer_kid":              a.IssuerKID,
	}
}

// AuthorizationFromRecord decodes an Authorization from a decoded wire Event's
// "authorization" field (map[string]any, as produced by encoding/json).
func AuthorizationFromRecord(record map[string]any) (*Authorization, error) {
	authzID, _ := record["authz_id"].(string)
	asv, _ := record["authority_state_version"].(string)
	tsd, _ := record["target_state_digest"].(string)
	issuerKID, _ := record["issuer_kid"].(string)
	nbf, err := asInt64(record["nbf"])
	if err != nil {
		return nil, fmt.Errorf("authorization.nbf: %w", err)
	}
	exp, err := asInt64(record["exp"])
	if err != nil {
		return nil, fmt.Errorf("authorization.exp: %w", err)
	}
	return &Authorization{
		AuthzID: authzID, AuthorityStateVersion: asv, TargetStateDigest: tsd,
		Nbf: nbf, Exp: exp, IssuerKID: issuerKID,
	}, nil
}

func asInt64(v any) (int64, error) {
	switch n := v.(type) {
	case int64:
		return n, nil
	case int:
		return int64(n), nil
	case float64:
		return int64(n), nil
	default:
		return 0, fmt.Errorf("expected a number, got %T", v)
	}
}

// AuthorityStateVersion content-hashes an authority/policy state to its
// version digest. The SAME construction as policy_version — sha256(JCS(state))
// — scoped to one approval rather than the whole active policy set, so an
// auditor can prove *which* authority state governed a specific approval.
func AuthorityStateVersion(state any) (string, error) {
	return JSONDigest(state)
}

// AuthorityExpired reports that the current time falls outside an
// authorization's validity window [TAP-AUTHORITY-VALIDITY], with the same
// +/-60s skew allowance as Passport freshness [TAP-PASSPORT-VALIDATE].
type AuthorityExpired struct {
	AuthzID string
	Nbf     int64
	Exp     int64
	Now     int64
}

func (e *AuthorityExpired) Error() string {
	return fmt.Sprintf("authorization %q outside validity window: nbf=%d exp=%d now=%d",
		e.AuthzID, e.Nbf, e.Exp, e.Now)
}

// CheckAuthorityWindow enforces the validity window [TAP-AUTHORITY-VALIDITY]:
//
//	nbf - 60 <= now < exp + 60
//
// the same inequality and skew allowance as Passport freshness
// [TAP-PASSPORT-VALIDATE]. Returns an *AuthorityExpired outside it.
func CheckAuthorityWindow(a *Authorization, now int64) error {
	if !(a.Nbf-60 <= now && now < a.Exp+60) {
		return &AuthorityExpired{AuthzID: a.AuthzID, Nbf: a.Nbf, Exp: a.Exp, Now: now}
	}
	return nil
}

// AuthorityRevoked reports that authz_id or authority_state_version names a
// revoked approval [TAP-AUTHORITY-REVOKE], and this record is timestamped (by
// its own signed ts) at or after the revocation boundary — the same
// effective-time-boundary mechanism as key revocation [TAP-KEY-REVOCATION],
// applied to an approval instead of a signing key.
type AuthorityRevoked struct {
	RevokedID string
	RevokedAt int64
	SignedTS  int64
}

func (e *AuthorityRevoked) Error() string {
	return fmt.Sprintf("%q revoked at %d; record is timestamped %d", e.RevokedID, e.RevokedAt, e.SignedTS)
}

// CheckAuthorityNotRevoked enforces the revocation boundary
// [TAP-AUTHORITY-REVOKE].
//
// revokedAt is an ALREADY-RESOLVED boundary for whichever of authzID or
// authorityStateVersion the caller looked up — this function performs no
// lookup itself and holds no registry. Publication format and query
// interface are a Service Profile concern (spec §9.2, §15); this is only the
// comparison. Pass a nil revokedAt when nothing is known to be revoked.
//
// Returns an *AuthorityRevoked when signedTS >= *revokedAt — an
// effective-time boundary, not blanket repudiation: a record signed before
// the boundary stays valid, same as key revocation.
func CheckAuthorityNotRevoked(authzID, authorityStateVersion string, revokedAt *int64, signedTS int64) error {
	if revokedAt == nil {
		return nil
	}
	if signedTS >= *revokedAt {
		revokedID := authzID
		if revokedID == "" {
			revokedID = authorityStateVersion
		}
		return &AuthorityRevoked{RevokedID: revokedID, RevokedAt: *revokedAt, SignedTS: signedTS}
	}
	return nil
}

// Authority-binding outcome labels [TAP-AUTHORITY-EFFECT].
const (
	AuthorizedMatch     = "authorized_match"
	AuthorizedMismatch  = "authorized_mismatch"
	UnverifiedAuthority = "unverified_authority"
)

// AuthorityEffectLabel labels an Event's authority-binding outcome
// [TAP-AUTHORITY-EFFECT] by comparing result["effect_digest"] against
// authorization.TargetStateDigest.
//
// Returns "" when authorization is nil (the label does not apply); otherwise
// one of AuthorizedMatch / AuthorizedMismatch / UnverifiedAuthority. Reported
// ALONGSIDE two-sided assurance [TAP-ASSURANCE], never in place of it — an
// Event can be independently two-sided (execution attested by an independent
// key) and simultaneously AuthorizedMismatch (the attested execution did
// something other than what was approved). That combination is exactly the
// failure two-sided attestation alone cannot see, because it only asks who
// signed, never what was approved.
func AuthorityEffectLabel(authorization *Authorization, result map[string]any) string {
	if authorization == nil {
		return ""
	}
	effect, ok := result["effect_digest"].(string)
	if !ok || effect == "" {
		return UnverifiedAuthority
	}
	if effect == authorization.TargetStateDigest {
		return AuthorizedMatch
	}
	return AuthorizedMismatch
}
