package tap

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestConformanceVectors(t *testing.T) {
	// Locate test-vectors.json at the repo root
	repoRoot := findRepoRoot(t)
	vectorsPath := filepath.Join(repoRoot, "test-vectors.json")

	data, err := os.ReadFile(vectorsPath)
	if err != nil {
		t.Fatalf("Failed to read test vectors: %v", err)
	}

	var vectors map[string]any
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatalf("Failed to parse test vectors: %v", err)
	}

	seed := vectors["ed25519_private_seed_hex"].(string)
	jwk := vectors["jwks"].(map[string]any)["keys"].([]any)[0].(map[string]any)
	kid := jwk["kid"].(string)

	sk, err := LoadSigner(seed)
	if err != nil {
		t.Fatalf("Failed to load signer: %v", err)
	}

	// Test 1: Passport reproduces byte-for-byte
	t.Run("passport_reproduces", func(t *testing.T) {
		passportClaims := vectors["passport"].(map[string]any)["claims"].(map[string]any)
		expectedPassport := vectors["passport"].(map[string]any)["compact_jwt"].(string)

		gotPassport, err := SignPassport(sk, kid, passportClaims)
		if err != nil {
			t.Fatalf("sign error: %v", err)
		}

		if gotPassport != expectedPassport {
			t.Errorf("passport mismatch\nexpected: %s\ngot:      %s", expectedPassport, gotPassport)
		}
	})

	// Test 2: Verify passport
	t.Run("passport_verifies", func(t *testing.T) {
		passportClaims := vectors["passport"].(map[string]any)["claims"].(map[string]any)
		expectedPassport := vectors["passport"].(map[string]any)["compact_jwt"].(string)
		iat := int64(passportClaims["iat"].(float64))

		_, err := VerifyPassport(jwk, expectedPassport, iat+1)
		if err != nil {
			t.Errorf("passport verification failed: %v", err)
		}
	})

	// Test 3: All signed cases reproduce signature and JCS input
	t.Run("signed_cases_reproduce", func(t *testing.T) {
		signedCases := []string{"event", "decision", "checkpoint", "canonicalization"}

		for _, caseName := range signedCases {
			caseData := vectors[caseName].(map[string]any)
			signed := caseData["signed_event"].(map[string]any)

			// Reproduce signature
			body := make(map[string]any)
			for k, v := range signed {
				if k != "sig" {
					body[k] = v
				}
			}

			signedEvent, err := SignEvent(sk, body)
			if err != nil {
				t.Errorf("%s: sign error: %v", caseName, err)
				continue
			}

			if signedEvent["sig"] != signed["sig"] {
				t.Errorf("%s: sig mismatch\nexpected: %s\ngot:      %s", caseName, signed["sig"], signedEvent["sig"])
			}

			// Verify JCS signing input matches
			input, err := SigningInput(signed)
			if err != nil {
				t.Errorf("%s: signing input error: %v", caseName, err)
				continue
			}

expectedHash := caseData["canonical_signing_input_sha256"].(string)
		sum := sha256.Sum256(input)
		actualHash := hex.EncodeToString(sum[:])
		if actualHash != expectedHash {
				t.Errorf("%s: JCS input mismatch\nexpected: %s\ngot:      %s", caseName, expectedHash, actualHash)
			}

			// Verify the event
			if err := VerifyEvent(jwk, signed); err != nil {
				t.Errorf("%s: verification failed: %v", caseName, err)
			}
		}
	})

	// Test 4: Tamper detection
	t.Run("tamper_rejected", func(t *testing.T) {
		toolEvent := vectors["event"].(map[string]any)["signed_event"].(map[string]any)
		tampered := make(map[string]any)
		for k, v := range toolEvent {
			tampered[k] = v
		}
		action := toolEvent["action"].(map[string]any)
		tampered["action"] = map[string]any{
			"kind":           "tool_call",
			"intent_digest":  action["intent_digest"],
			"tool":           "drop_table", // Changed from db_query
			"scope_used":     action["scope_used"],
			"args_digest":    action["args_digest"],
		}

		err := VerifyEvent(jwk, tampered)
		if err == nil {
			t.Error("tamper not detected")
		}
	})

	// Test 5: Decision - string scores, no fractional numbers
	t.Run("decision_string_scores", func(t *testing.T) {
		dec := vectors["decision"].(map[string]any)["signed_event"].(map[string]any)["decision"].(map[string]any)
		options := dec["options"].([]any)

		for _, opt := range options {
			optMap := opt.(map[string]any)
			score := optMap["score"]
			if _, ok := score.(string); !ok {
				t.Errorf("score must be a string, got %T", score)
			}
		}

		// Check no floats in signed body
		if err := checkNoFloats(vectors["decision"].(map[string]any)["signed_event"]); err != nil {
			t.Errorf("%v", err)
		}

		chosen := []any{}
		for _, opt := range options {
			optMap := opt.(map[string]any)
			if chosenFlag, ok := optMap["chosen"].(bool); ok && chosenFlag {
				chosen = append(chosen, opt)
			}
		}

		if len(chosen) != 1 || chosen[0].(map[string]any)["id"] != dec["chosen"] {
			t.Error("exactly one option chosen and decision.chosen names it")
		}
	})

	// Test 6: Checkpoint Merkle reconciliation
	t.Run("checkpoint_merkle", func(t *testing.T) {
		rec := vectors["checkpoint"].(map[string]any)["reconciliation"].(map[string]any)
		cp := vectors["checkpoint"].(map[string]any)["signed_event"].(map[string]any)["checkpoint"].(map[string]any)

		eventIDs := make([]string, len(rec["event_ids"].([]any)))
		for i, v := range rec["event_ids"].([]any) {
			eventIDs[i] = v.(string)
		}

		computedRoot := CheckpointRoot(eventIDs)
		if computedRoot != rec["event_id_root"] || computedRoot != cp["event_id_root"] {
			t.Errorf("Merkle root mismatch\ncomputed: %s\nexpected: %s", computedRoot, rec["event_id_root"])
		}

		emptyRoot := CheckpointRoot([]string{})
	emptySum := sha256.Sum256([]byte{})
	expectedEmptyRoot := "sha256:" + hex.EncodeToString(emptySum[:])
	if emptyRoot != rec["empty_interval_root"] || emptyRoot != expectedEmptyRoot {
			t.Errorf("empty interval root mismatch\ngot: %s\nexpected: %s", emptyRoot, rec["empty_interval_root"])
		}

		if cp["from_seq"] != rec["from_seq"] || cp["through_seq"] != rec["through_seq"] {
			t.Error("checkpoint interval bounds mismatch")
		}

		if cp["count"].(float64) != float64(len(eventIDs)) {
			t.Error("checkpoint count mismatch")
		}

		// Leaf order matters
		reversed := make([]string, len(eventIDs))
		copy(reversed, eventIDs)
		for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
			reversed[i], reversed[j] = reversed[j], reversed[i]
		}
		if CheckpointRoot(reversed) == rec["event_id_root"] {
			t.Error("leaf order must affect root")
		}
	})

	// Test 7: Canonicalization torture test
	t.Run("canonicalization_torture", func(t *testing.T) {
		canon := vectors["canonicalization"].(map[string]any)
		order := canon["member_ordering"].(map[string]any)["jcs_member_order"].([]any)
		args := canon["member_ordering"].(map[string]any)["args"].(map[string]any)

		argsDigest, err := JSONDigest(args)
		if err != nil {
			t.Fatalf("JSONDigest error: %v", err)
		}

		expectedArgsDigest := canon["member_ordering"].(map[string]any)["args_digest"].(string)
		if argsDigest != expectedArgsDigest {
			t.Errorf("JCS digest mismatch\nexpected: %s\ngot:      %s", expectedArgsDigest, argsDigest)
		}

// Verify member ordering matches reference
	canonBytes, err := Canonicalize(args)
	if err != nil {
		t.Fatalf("canonicalization error: %v", err)
	}

	// Extract keys from canonical JSON in order
	canonStr := string(canonBytes)
	actualOrder := extractKeysFromJSON(canonStr)
	if actualOrder == nil {
		t.Fatalf("failed to extract keys from canonical JSON")
	}

	expectedOrder := make([]string, len(order))
	for i, v := range order {
		expectedOrder[i] = v.(string)
	}

	if !equalStringSlices(actualOrder, expectedOrder) {
		t.Errorf("JCS member ordering mismatch\nexpected: %v\ngot:      %v", expectedOrder, actualOrder)
	}

		if expectedOrder[0] != "" {
			t.Error("empty key must sort first")
		}

		// Non-BMP key (U+1F511) must order by leading surrogate (U+D83D) BELOW U+FB03
		key1 := "\U0001f511" // U+1F511
		key2 := "\ufb03"      // U+FB03
		idx1 := indexOf(expectedOrder, key1)
		idx2 := indexOf(expectedOrder, key2)
		if idx1 >= idx2 {
			t.Error("non-BMP key must order by leading surrogate, below U+FB03")
		}

		// NFD and NFC must be distinct keys
		if _, ok := args["e\u0301"]; !ok {
			t.Error("NFD key missing")
		}
		if _, ok := args["\u00e9"]; !ok {
			t.Error("NFC key missing")
		}
		if args["e\u0301"] == args["\u00e9"] {
			t.Error("NFD and NFC must be different entries")
		}

		// Annex plaintext verifies against signed digests
		annex := canon["annex"].(map[string]any)
		reasoningDigest := TextDigest(annex["reasoning"].(string))
		signedReasoningDigest := canon["signed_event"].(map[string]any)["evidence"].(map[string]any)["reasoning_digest"].(string)
		if reasoningDigest != signedReasoningDigest {
			t.Error("UTF-8 digest of mixed-script plaintext mismatch")
		}
	})

	// Test 8: Annex digests verify; no plaintext in signed bodies
	t.Run("annex_digests_verify", func(t *testing.T) {
		signedCases := []string{"event", "decision", "checkpoint", "canonicalization"}

		for _, caseName := range signedCases {
			body := vectors[caseName].(map[string]any)["signed_event"].(map[string]any)
			action := body["action"].(map[string]any)
			
			// evidence is optional - only present for some event types
			var evidence map[string]any
			if ev, ok := body["evidence"].(map[string]any); ok {
				evidence = ev
			}

			forbidden := []string{"intent", "args", "args_preview", "reasoning"}
			for _, f := range forbidden {
				if _, ok := action[f]; ok {
					t.Errorf("%s: %s in signed action", caseName, f)
				}
				if evidence != nil {
					if _, ok := evidence[f]; ok {
						t.Errorf("%s: %s in signed evidence", caseName, f)
					}
				}
			}

			// Absent optionals must be omitted, never null
			for _, absent := range []string{"parent_event_id", "policy_decision"} {
				if _, ok := body[absent]; ok {
					t.Errorf("%s: %s present (must be omitted when absent)", caseName, absent)
				}
			}
		}

		// Verify annex digests for tool_call event
		ev := vectors["event"].(map[string]any)
		intentDigest := TextDigest(ev["annex"].(map[string]any)["intent"].(string))
		expectedIntentDigest := ev["signed_event"].(map[string]any)["action"].(map[string]any)["intent_digest"].(string)
		if intentDigest != expectedIntentDigest {
			t.Error("annex intent digest mismatch")
		}

		argsPreview := ev["annex"].(map[string]any)["args_preview"]
		argsPreviewDigest, err := JSONDigest(argsPreview)
		if err != nil {
			t.Fatalf("args_preview digest error: %v", err)
		}
		expectedArgsDigest := ev["signed_event"].(map[string]any)["action"].(map[string]any)["args_digest"].(string)
		if argsPreviewDigest != expectedArgsDigest {
			t.Error("annex args_preview digest mismatch")
		}
	})
}

func checkNoFloats(v any) error {
	switch val := v.(type) {
	case float64:
		return nil // JSON numbers are always float64 in Go, but we only care about fractional
	case map[string]any:
		for k, v := range val {
			if err := checkNoFloats(v); err != nil {
				return err
			}
			_ = k
		}
	case []any:
		for i, v := range val {
			if err := checkNoFloats(v); err != nil {
				return err
			}
			_ = i
		}
	}
	return nil
}

func equalStringSlices(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func indexOf(slice []string, val string) int {
	for i, v := range slice {
		if v == val {
			return i
		}
	}
	return -1
}

// extractKeysFromJSON extracts object keys from a JSON string in the order they appear.
// This preserves the JCS canonical ordering.
func extractKeysFromJSON(jsonStr string) []string {
	var keys []string
	i := 0
	// Skip to first {
	for i < len(jsonStr) && jsonStr[i] != '{' {
		i++
	}
	i++ // skip {

	for i < len(jsonStr) {
		// Skip whitespace
		for i < len(jsonStr) && (jsonStr[i] == ' ' || jsonStr[i] == '\t' || jsonStr[i] == '\n' || jsonStr[i] == '\r') {
			i++
		}
		if i >= len(jsonStr) || jsonStr[i] == '}' {
			break
		}

		// Parse key (should be a quoted string)
		if jsonStr[i] == '"' {
			i++ // skip opening quote
			var keyBuilder strings.Builder
			for i < len(jsonStr) && jsonStr[i] != '"' {
				if jsonStr[i] == '\\' && i+1 < len(jsonStr) {
					// Handle escape sequences
					i++
					switch jsonStr[i] {
					case '"', '\\', '/':
						keyBuilder.WriteByte(jsonStr[i])
					case 'b':
						keyBuilder.WriteByte('\b')
					case 'f':
						keyBuilder.WriteByte('\f')
					case 'n':
						keyBuilder.WriteByte('\n')
					case 'r':
						keyBuilder.WriteByte('\r')
					case 't':
						keyBuilder.WriteByte('\t')
					case 'u':
						// Unicode escape \uXXXX
						if i+4 < len(jsonStr) {
							hex := jsonStr[i+1 : i+5]
							r, err := strconv.ParseUint(hex, 16, 16)
							if err == nil {
								keyBuilder.WriteRune(rune(r))
							} else {
								keyBuilder.WriteString("\\u" + hex)
							}
							i += 4
						}
					default:
						keyBuilder.WriteByte(jsonStr[i])
					}
				} else {
					keyBuilder.WriteByte(jsonStr[i])
				}
				i++
			}
			if i < len(jsonStr) {
				keys = append(keys, keyBuilder.String())
				i++ // skip closing quote
			}
		}

		// Skip to next comma or }
		for i < len(jsonStr) && jsonStr[i] != ',' && jsonStr[i] != '}' {
			i++
		}
		if i < len(jsonStr) && jsonStr[i] == ',' {
			i++
		}
	}
	return keys
}

func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, _ := os.Getwd()
	for {
		if _, err := os.Stat(filepath.Join(dir, "test-vectors.json")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("Could not find repo root with test-vectors.json")
	return ""
}