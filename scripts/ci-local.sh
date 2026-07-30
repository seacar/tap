#!/usr/bin/env bash
#
# Run the same checks as .github/workflows/ci.yml, locally.
#
# Useful when GitHub Actions is unavailable, and as a pre-push gate generally —
# the conformance vectors are the protocol's contract, so it's worth knowing
# they still reproduce before anyone else pulls.
#
# Keep this in step with ci.yml. If you add a job there, add it here.
#
#   ./scripts/ci-local.sh
#
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
failed_names=()

run() {
  local name="$1"; shift
  printf '  %-46s ' "$name"
  if output=$("$@" 2>&1); then
    echo "PASS"
    pass=$((pass + 1))
  else
    echo "FAIL"
    fail=$((fail + 1))
    failed_names+=("$name")
    printf '%s\n' "$output" | tail -12 | sed 's/^/        /'
  fi
}

echo
echo "reference implementation reproduces the vectors"
# tap_ref.py regenerates test-vectors.json and self-checks. If the committed
# vectors differ from what the reference produces, the contract is broken.
cp test-vectors.json /tmp/tap-committed-vectors.json
run "tap_ref.py self-check" python3 tap_ref.py
run "vectors reproduce byte-for-byte" \
  diff -q /tmp/tap-committed-vectors.json test-vectors.json
rm -f /tmp/tap-committed-vectors.json
# The spec quotes live signatures and hashes; they were stale for a whole release
# because nothing compared them to the vectors.
run "spec agrees with the vectors"     python3 scripts/check-spec-vectors.py
run "schemas + registries describe it" python3 scripts/check-schemas.py

echo
echo "python SDK"
pushd sdk/python >/dev/null
export PYTHONPATH=src
run "conformance (every vector)"  python3 tests/test_conformance.py
run "negative vectors"            python3 tests/test_negative_vectors.py
run "verifier MUST-behaviours"    python3 tests/test_verifier_musts.py
run "handshake + nego binding"    python3 tests/test_handshake.py
run "anti-downgrade (nego)"       python3 tests/test_nego.py
run "policy engine"               python3 tests/test_policy.py
run "instance suffix"             python3 tests/test_instance_suffix.py
run "core imports w/o network deps" \
  python3 -c "import tap_sdk.core, tap_sdk.verify"
unset PYTHONPATH
popd >/dev/null

echo
echo "typescript SDK"
pushd sdk/js >/dev/null
if [ ! -d node_modules ]; then
  printf '  %-46s ' "npm install"
  if npm install --silent --no-audit --no-fund >/dev/null 2>&1; then
    echo "done"
  else
    echo "FAILED — remaining TS checks will fail"
  fi
fi
run "conformance + MUSTs + unit tests" npm test
run "type check / build"               npm run build
popd >/dev/null

echo
echo "gateway + inspector"
# The Gateway carries the two-sided story for every upstream that is not
# TAP-aware; the Inspector is what an implementer debugs with. Neither had a
# single test before v0.1.2.
run "gateway"    python3 gateway/test_gateway.py
run "inspector"  python3 inspector/test_inspector.py

echo
echo "cross-language agreement"
# Both SDKs verify against the same committed vectors; if either drifts, the
# Signer/Verifier interoperability guarantee is gone.
run "python against the vectors" \
  env PYTHONPATH=sdk/python/src python3 sdk/python/tests/test_conformance.py
run "typescript against the same vectors" \
  bash -c 'cd sdk/js && npx tsx test/conformance.ts'
run "both reject the same negatives" \
  bash -c 'cd sdk/js && npx tsx test/negativeVectors.test.ts'
# The strongest check: reproducing a vector proves an SDK can re-sign a body
# someone else composed. This proves the two COMPOSE identical bytes.
run "the two SDKs compose identical envelopes" \
  bash -c 'cd sdk/js && npx tsx test/envelopeParity.test.ts && cd ../python && PYTHONPATH=src python3 tests/test_envelope_parity.py'
run "a JS-signed record verifies in python" \
  bash -c 'cd sdk/js && npx tsx test/interop.ts > /tmp/js_event.json && cd ../python && PYTHONPATH=src python3 -c "
import json
from tap_sdk.core import verify_event, verify_passport
d = json.load(open(\"/tmp/js_event.json\"))
assert verify_passport(d[\"jwk\"], d[\"passport\"])
assert verify_event(d[\"jwk\"], d[\"event\"])
"'

echo
echo "secret scan"
if command -v gitleaks >/dev/null 2>&1; then
  run "gitleaks" gitleaks detect --no-banner --redact
else
  printf '  %-46s %s\n' "gitleaks" "SKIP (not installed — CI runs it)"
fi

echo
echo "──────────────────────────────────────────────"
if [ "$fail" -eq 0 ]; then
  echo "  ${pass} passed, 0 failed"
  exit 0
fi
echo "  ${pass} passed, ${fail} FAILED:"
for n in "${failed_names[@]}"; do echo "    - $n"; done
exit 1
