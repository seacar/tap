package tap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Authority binding in Go [TAP-EVT-AUTHORIZATION, §9.2, PROVISIONAL], mirroring
// sdk/python/tests/test_authority.py and sdk/js/test/authority.test.ts.
//
// Before this, authorization/authority_state_version/target_state_digest
// appeared nowhere in the Go tree — only tap_ref.py, the Python SDK, and the
// TypeScript SDK implemented the stateless half of §9.2.

var authorityStateFixture = map[string]any{
	"policy": "refund-v3",
	"rules":  []any{"max_refund_cents:10000"},
}

var targetStateFixture = map[string]any{
	"ticket": "8842", "status": "refunded", "refund_cents": float64(5000),
}

func TestAuthorityStateVersionMatchesJSONDigest(t *testing.T) {
	got, err := AuthorityStateVersion(authorityStateFixture)
	if err != nil {
		t.Fatalf("AuthorityStateVersion: %v", err)
	}
	want, err := JSONDigest(authorityStateFixture)
	if err != nil {
		t.Fatalf("JSONDigest: %v", err)
	}
	if got != want {
		t.Errorf("AuthorityStateVersion = %q, want %q", got, want)
	}
}

func TestGrantAndRecordRoundTrip(t *testing.T) {
	auth, err := GrantAuthorization(targetStateFixture, authorityStateFixture, 1000, 2000, "key_admin", "")
	if err != nil {
		t.Fatalf("GrantAuthorization: %v", err)
	}
	if auth.Nbf != 1000 || auth.Exp != 2000 || auth.IssuerKID != "key_admin" {
		t.Errorf("unexpected fields: %+v", auth)
	}
	wantASV, _ := AuthorityStateVersion(authorityStateFixture)
	if auth.AuthorityStateVersion != wantASV {
		t.Errorf("authority_state_version = %q, want %q", auth.AuthorityStateVersion, wantASV)
	}
	wantTSD, _ := JSONDigest(targetStateFixture)
	if auth.TargetStateDigest != wantTSD {
		t.Errorf("target_state_digest = %q, want %q", auth.TargetStateDigest, wantTSD)
	}

	back, err := AuthorizationFromRecord(auth.ToRecord())
	if err != nil {
		t.Fatalf("AuthorizationFromRecord: %v", err)
	}
	if *back != *auth {
		t.Errorf("round trip mismatch: %+v != %+v", *back, *auth)
	}
}

func TestCheckAuthorityWindowSkewBoundary(t *testing.T) {
	auth, err := GrantAuthorization(targetStateFixture, authorityStateFixture, 1000, 2000, "key_admin", "")
	if err != nil {
		t.Fatalf("GrantAuthorization: %v", err)
	}
	if err := CheckAuthorityWindow(auth, 1500); err != nil {
		t.Errorf("mid-window must not error: %v", err)
	}
	if err := CheckAuthorityWindow(auth, 1000-60); err != nil {
		t.Errorf("inclusive lower skew edge must not error: %v", err)
	}
	for _, badNow := range []int64{1000 - 61, 2000 + 61} {
		err := CheckAuthorityWindow(auth, badNow)
		if err == nil {
			t.Errorf("expected AuthorityExpired at now=%d", badNow)
			continue
		}
		if _, ok := err.(*AuthorityExpired); !ok {
			t.Errorf("expected *AuthorityExpired, got %T", err)
		}
	}
}

func TestAuthorityEffectLabel(t *testing.T) {
	auth, err := GrantAuthorization(targetStateFixture, authorityStateFixture, 1000, 2000, "key_admin", "")
	if err != nil {
		t.Fatalf("GrantAuthorization: %v", err)
	}
	if got := AuthorityEffectLabel(nil, map[string]any{"effect_digest": "x"}); got != "" {
		t.Errorf("nil authorization -> want \"\", got %q", got)
	}
	if got := AuthorityEffectLabel(auth, map[string]any{}); got != UnverifiedAuthority {
		t.Errorf("no effect_digest -> want %q, got %q", UnverifiedAuthority, got)
	}
	matchDigest, _ := JSONDigest(targetStateFixture)
	if got := AuthorityEffectLabel(auth, map[string]any{"effect_digest": matchDigest}); got != AuthorizedMatch {
		t.Errorf("matching effect_digest -> want %q, got %q", AuthorizedMatch, got)
	}
	other := map[string]any{"ticket": "8842", "status": "refunded", "refund_cents": float64(7500)}
	mismatchDigest, _ := JSONDigest(other)
	if got := AuthorityEffectLabel(auth, map[string]any{"effect_digest": mismatchDigest}); got != AuthorizedMismatch {
		t.Errorf("differing effect_digest -> want %q, got %q", AuthorizedMismatch, got)
	}
}

// TestAuthorityReproducesFixedVector cross-checks against
// test-vectors.json -> authorization's own validity_window and effect_check
// fixed numbers — the same numbers the Python and TypeScript suites check —
// so all three SDKs are proven to agree on [TAP-AUTHORITY-VALIDITY] and
// [TAP-AUTHORITY-EFFECT], not merely that each independently satisfies its
// own logic.
func TestCheckAuthorityNotRevokedBoundary(t *testing.T) {
	if err := CheckAuthorityNotRevoked("auz_x", "sha256:v", nil, 1500); err != nil {
		t.Errorf("nothing revoked must not error: %v", err)
	}
	boundary := int64(2000)
	if err := CheckAuthorityNotRevoked("auz_x", "sha256:v", &boundary, 1999); err != nil {
		t.Errorf("before boundary must not error: %v", err)
	}
	for _, badTS := range []int64{2000, 2001} {
		err := CheckAuthorityNotRevoked("auz_x", "sha256:v", &boundary, badTS)
		if err == nil {
			t.Errorf("expected AuthorityRevoked at signedTS=%d", badTS)
			continue
		}
		revoked, ok := err.(*AuthorityRevoked)
		if !ok {
			t.Errorf("expected *AuthorityRevoked, got %T", err)
			continue
		}
		if revoked.RevokedID != "auz_x" || revoked.RevokedAt != 2000 || revoked.SignedTS != badTS {
			t.Errorf("unexpected fields: %+v", revoked)
		}
	}
}

func TestAuthorityReproducesFixedVector(t *testing.T) {
	repoRoot := findRepoRoot(t)
	data, err := os.ReadFile(filepath.Join(repoRoot, "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var vectors map[string]any
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("parse test-vectors.json: %v", err)
	}

	av := vectors["authorization"].(map[string]any)
	signedEvent := av["signed_event"].(map[string]any)
	authRecord := signedEvent["authorization"].(map[string]any)
	auth, err := AuthorizationFromRecord(authRecord)
	if err != nil {
		t.Fatalf("AuthorizationFromRecord: %v", err)
	}

	vw := av["validity_window"].(map[string]any)
	acceptedNow, _ := asInt64(vw["accepted_now"])
	if err := CheckAuthorityWindow(auth, acceptedNow); err != nil {
		t.Errorf("vector's accepted_now must not error: %v", err)
	}
	for _, key := range []string{"rejected_now_not_yet_valid", "rejected_now_expired"} {
		badNow, _ := asInt64(vw[key])
		if err := CheckAuthorityWindow(auth, badNow); err == nil {
			t.Errorf("vector's %s=%d must raise AuthorityExpired", key, badNow)
		}
	}

	ec := av["effect_check"].(map[string]any)
	matchDigest := ec["authorized_match_effect_digest"].(string)
	mismatchDigest := ec["authorized_mismatch_effect_digest"].(string)
	if got := AuthorityEffectLabel(auth, map[string]any{"effect_digest": matchDigest}); got != AuthorizedMatch {
		t.Errorf("vector's authorized_match_effect_digest -> want %q, got %q", AuthorizedMatch, got)
	}
	if got := AuthorityEffectLabel(auth, map[string]any{"effect_digest": mismatchDigest}); got != AuthorizedMismatch {
		t.Errorf("vector's authorized_mismatch_effect_digest -> want %q, got %q", AuthorizedMismatch, got)
	}
	if got := AuthorityEffectLabel(auth, map[string]any{}); got != UnverifiedAuthority {
		t.Errorf("absent effect_digest -> want %q, got %q", UnverifiedAuthority, got)
	}
}
