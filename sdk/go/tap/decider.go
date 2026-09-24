package tap

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Typed decisions — decider provenance and confidence gates
// [TAP-EVT-DECIDER, TAP-EVT-GATE, §6.4.1, PROVISIONAL].
//
// A §6.4 decision records what was chosen and what else was considered.
// decision.decider records WHO chose — a model, a rule, or a human — and under
// which typed output contract; decision.gate records the confidence threshold
// the decision was held to and whether it cleared it ("accept") or fell back
// ("fallback"). Both are OPTIONAL and omitted when absent.
//
// Purely functional, matching the rest of the Go SDK's primitives style, and
// mirroring tap_ref.py, sdk/python/src/tap_sdk/decider.py and
// sdk/js/src/decider.ts. Gate arithmetic is exact decimal arithmetic on
// integer millionths [TAP-EVT-GATE-DECIMAL] — never float64 — so every
// implementation agrees about a score sitting exactly on the threshold.

// Gate labels [TAP-EVT-GATE].
const (
	GateConsistent   = "gate_consistent"
	GateInconsistent = "gate_inconsistent"
	GateUnscorable   = "gate_unscorable"
)

var gateDecimalRE = regexp.MustCompile(`^(?:0(?:\.[0-9]{1,6})?|1(?:\.0{1,6})?)$`)

// GateDecimalMicros parses a gate decimal to integer millionths, exactly.
// Accepts only strings matching 0, 1, 0.d{1,6} or 1.0{1,6}.
func GateDecimalMicros(v any) (int64, error) {
	s, ok := v.(string)
	if !ok || !gateDecimalRE.MatchString(s) {
		return 0, fmt.Errorf("not a gate decimal in [0, 1] with <= 6 places: %v", v)
	}
	whole, frac, _ := strings.Cut(s, ".")
	w, _ := strconv.ParseInt(whole, 10, 64)
	f, _ := strconv.ParseInt((frac + "000000")[:6], 10, 64)
	return w*1_000_000 + f, nil
}

// GateOutcome returns "accept" iff score >= threshold as exact decimals, else "fallback".
func GateOutcome(score, threshold string) (string, error) {
	s, err := GateDecimalMicros(score)
	if err != nil {
		return "", err
	}
	t, err := GateDecimalMicros(threshold)
	if err != nil {
		return "", err
	}
	if s >= t {
		return "accept", nil
	}
	return "fallback", nil
}

// DecisionGateLabel labels a decision block's confidence gate. It returns ""
// when the decision carries no gate (the label does not apply).
func DecisionGateLabel(decision map[string]any) string {
	if decision == nil {
		return ""
	}
	rawGate, has := decision["gate"]
	if !has {
		return ""
	}
	gate, ok := rawGate.(map[string]any)
	if !ok {
		return GateUnscorable
	}
	decider, _ := decision["decider"].(map[string]any)
	sem, _ := decider["score_semantics"].(string)
	if sem != "calibrated_probability" && sem != "probability" {
		return GateUnscorable
	}
	opts, _ := decision["options"].([]any)
	var chosen []map[string]any
	for _, o := range opts {
		if m, ok := o.(map[string]any); ok {
			if c, ok := m["chosen"].(bool); ok && c {
				chosen = append(chosen, m)
			}
		}
	}
	if len(chosen) != 1 || chosen[0]["id"] != decision["chosen"] {
		return GateUnscorable
	}
	score, _ := chosen[0]["score"].(string)
	threshold, _ := gate["threshold"].(string)
	expected, err := GateOutcome(score, threshold)
	if err != nil {
		return GateUnscorable
	}
	outcome, _ := gate["outcome"].(string)
	if outcome != "accept" && outcome != "fallback" {
		return GateUnscorable
	}
	if outcome == expected {
		return GateConsistent
	}
	return GateInconsistent
}

// UnresolvedFallbacks returns the event_ids of fallback-gated decisions that
// no delivered decision names as its parent_event_id. Informational: the
// superseding decision may simply not have arrived yet.
func UnresolvedFallbacks(events []map[string]any) []string {
	parents := map[any]bool{}
	for _, e := range events {
		if a, _ := e["action"].(map[string]any); a["kind"] == "decision" {
			if p, ok := e["parent_event_id"]; ok {
				parents[p] = true
			}
		}
	}
	var out []string
	for _, e := range events {
		a, _ := e["action"].(map[string]any)
		d, _ := e["decision"].(map[string]any)
		g, _ := d["gate"].(map[string]any)
		if a["kind"] == "decision" && g["outcome"] == "fallback" && !parents[e["event_id"]] {
			id, _ := e["event_id"].(string)
			out = append(out, id)
		}
	}
	return out
}
