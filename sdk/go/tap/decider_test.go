package tap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Typed decisions in Go [TAP-EVT-DECIDER, TAP-EVT-GATE, §6.4.1, PROVISIONAL],
// mirroring sdk/python/tests/test_typed_decisions.py and
// sdk/js/test/typedDecisions.test.ts.

func loadTypedVectors(t *testing.T) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(findRepoRoot(t), "test-vectors.json"))
	if err != nil {
		t.Fatalf("read test-vectors.json: %v", err)
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("parse test-vectors.json: %v", err)
	}
	return v
}

func TestTypedDecisionVectorsReproduce(t *testing.T) {
	v := loadTypedVectors(t)
	sk, err := LoadSigner(v["ed25519_private_seed_hex"].(string))
	if err != nil {
		t.Fatal(err)
	}
	jwk := v["jwks"].(map[string]any)["keys"].([]any)[0].(map[string]any)
	for _, c := range []string{"typed_decision", "typed_decision_fallback", "typed_decision_resolution"} {
		ev := v[c].(map[string]any)["signed_event"].(map[string]any)
		if err := VerifyEvent(jwk, ev); err != nil {
			t.Errorf("%s: verify: %v", c, err)
		}
		body := map[string]any{}
		for k, val := range ev {
			if k != "sig" {
				body[k] = val
			}
		}
		signed, err := SignEvent(sk, body)
		if err != nil {
			t.Fatalf("%s: sign: %v", c, err)
		}
		if signed["sig"] != ev["sig"] {
			t.Errorf("%s: Go must reproduce the reference sig", c)
		}
	}
}

func TestDecisionGateLabelsMatchVectors(t *testing.T) {
	v := loadTypedVectors(t)
	dec := func(c string) map[string]any {
		return v[c].(map[string]any)["signed_event"].(map[string]any)["decision"].(map[string]any)
	}
	cases := map[string]string{
		"typed_decision":            GateConsistent,
		"typed_decision_fallback":   GateConsistent,
		"typed_decision_resolution": "",
		"decision":                  "",
	}
	for c, want := range cases {
		if got := DecisionGateLabel(dec(c)); got != want {
			t.Errorf("%s: label = %q, want %q", c, got, want)
		}
	}
	neg := v["negative"].(map[string]any)["gate_outcome_inconsistent"].(map[string]any)
	d := neg["event"].(map[string]any)["decision"].(map[string]any)
	if got := DecisionGateLabel(d); got != neg["expected_label"] {
		t.Errorf("negative: label = %q, want %q", got, neg["expected_label"])
	}
}

func TestGateFixtureTable(t *testing.T) {
	v := loadTypedVectors(t)
	fx := v["decision_gate"].(map[string]any)
	for _, r := range fx["outcomes"].([]any) {
		row := r.(map[string]any)
		got, err := GateOutcome(row["score"].(string), row["threshold"].(string))
		if err != nil || got != row["outcome"] {
			t.Errorf("row %v: got %q (%v)", row, got, err)
		}
	}
	for _, bad := range append(fx["malformed"].([]any), 0.9, nil) {
		if _, err := GateDecimalMicros(bad); err == nil {
			t.Errorf("%v must be rejected", bad)
		}
	}
}

func TestUnresolvedFallbacks(t *testing.T) {
	v := loadTypedVectors(t)
	ev := func(c string) map[string]any { return v[c].(map[string]any)["signed_event"].(map[string]any) }
	fb := ev("typed_decision_fallback")
	if got := UnresolvedFallbacks([]map[string]any{ev("typed_decision"), fb}); len(got) != 1 || got[0] != fb["event_id"] {
		t.Errorf("open fallback: got %v", got)
	}
	if got := UnresolvedFallbacks([]map[string]any{ev("typed_decision"), fb, ev("typed_decision_resolution")}); len(got) != 0 {
		t.Errorf("resolved chain: got %v", got)
	}
}
