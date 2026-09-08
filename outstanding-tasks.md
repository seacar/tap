# Outstanding tasks

Generated 2026-09-08 from a full-repo review: every check in `scripts/ci-local.sh`
plus three new, not-yet-wired-in test suites (`sdk/*/test/regressions.test.ts`,
`sdk/python/tests/test_regressions.py`, `scripts/check-envelope-parity.py`).
The straightforward, low-risk findings from that pass were already fixed and
are listed in [CHANGELOG.md](CHANGELOG.md) under `[0.1.5]`. Everything below
is either too large/security-sensitive to land in that same pass, or is
process/wiring debt the review surfaced along the way.

## Security-relevant (fix first)

- [ ] **Two-sided assurance never checks signing-key independence.**
  `assuranceLevel` (`sdk/js/src/verify.ts`) and `assurance_level`
  (`sdk/python/src/tap_sdk/verify.py`) label a `server` leg `"two-sided"`
  purely on content agreement (`cid`, `action.tool`, `action.kind`, result
  consistency). Neither checks that the `agent` and `server` legs were signed
  by *different* keys, so a Signer can mint a self-consistent fake server leg
  under its own key and have it reported as independently-attested
  [TAP-ASSURANCE-KEY] — the exact guarantee "two-sided" is supposed to make.
  `sdk/python/tests/test_regressions.py` (`a trust anchor rejects a server
  leg from an unrecognized key`) already sketches the fix shape: thread an
  `is_server_key(kid) -> bool` trust-anchor callback through
  `verify_transcript` (both languages) so a deployment can say which keys may
  legitimately attest as a server. Needs a deliberate API review, not a
  same-session patch — this is the single biggest finding of the review.

- [ ] **Delegation: an unsigned `_meta.tap.cid` can redirect the chain.**
  `sdk/python/tests/test_regressions.py`
  (`an unsigned _meta.tap.cid cannot redirect the chain`) fails today:
  `TAPClient.accept_a2a_delegation` does not reject a `_meta` block whose
  `cid` contradicts the sender's *signed* passport. `_meta` is unsigned
  (§8.1), so trusting it over the signed passport lets a caller splice a
  record into an unrelated chain while every individual signature still
  verifies.

- [ ] **Delegation: replay survives a rotated `action_ref`.**
  `sdk/python/tests/test_regressions.py`
  (`a replayed delegation is rejected even with a rotated action_ref`) fails
  today: a second `accept_a2a_delegation` call with the same sender passport
  but a fresh `action_ref` is accepted rather than rejected. §8.2 names this
  failure explicitly — keying the replay cache on `action_ref` doesn't
  implement the rule, because a replayer picks a fresh one on purpose.

- [ ] **`attestation:"requested"` gets bound into `evidence.nego`.**
  `sdk/python/tests/test_regressions.py`
  (`attestation:'requested' is never bound into evidence.nego`) fails today:
  `"requested"` is an *offer* under [TAP-NEGO-BINDING] (§4.1), never a
  selection, but the current code binds it as if the Signer's own wish were a
  negotiated outcome — which is exactly what the anti-downgrade check is
  supposed to be unable to say.

## Correctness / API completion

- [ ] **Passport-scoped replay cache is keyed wrong (or the test API doesn't
  exist yet — needs triage).** `sdk/python/tests/test_regressions.py`
  (`a server accepts every action under one passport, not just the first`,
  `a replayed (aid, seq) slot is rejected even with a fresh action_ref`,
  `a call with no seq is accepted but counted as un-enforceable`) all fail
  with `AttributeError: 'Passport' object has no attribute 'reserve_seq'` /
  `'TAPServer' object has no attribute 'replay_unenforceable'`. Unclear yet
  whether this is a missing method the tests assume was already added, or a
  genuinely unbuilt feature (a Passport is minted per record and attached to
  every action, so keying the replay cache on `jti` alone at the action edge
  would reject call #2 of every record). Needs a read of
  `TAPServer.attest`'s current replay-cache key before deciding the fix.

- [ ] **`TAPServer` has no `replay_scope` parameter.**
  `sdk/python/tests/test_regressions.py`
  (`a delegation edge still enforces jti uniqueness`) fails with
  `TypeError: TAPServer.__init__() got an unexpected keyword argument
  'replay_scope'`. Related to the item above — the delegation edge and the
  action edge may need distinct replay-cache semantics.

- [ ] **`flush()` may not return promptly against an unreachable Verifier.**
  `sdk/python/tests/test_regressions.py`
  (`flush() returns promptly when the Verifier is unreachable`) fails: the
  test's own comment names the likely cause — "the obvious retry loop
  (drain, send, re-queue on failure, repeat until empty) never terminates
  against a down Verifier: every drain hands back what the last send just
  re-queued." §11.3 requires a Signer MUST NOT block execution on reporting
  availability. Confirm whether `TAPClient._reporter` actually has this spin,
  or whether the test's 5s budget is just too tight in this environment.

## Wiring / process debt

- [ ] **The new regression and parity suites aren't in CI anywhere.**
  `sdk/js/test/regressions.test.ts`, `sdk/js/test/emitShapes.ts`,
  `sdk/python/tests/test_regressions.py`, `sdk/python/tests/emit_shapes.py`,
  and `scripts/check-envelope-parity.py` are uncommitted and referenced by
  neither `scripts/ci-local.sh` nor `.github/workflows/ci.yml`. They're what
  caught every bug in this review — add them to both once the failures above
  are resolved (or decide per-file whether it should block CI red today).

- [ ] **TypeScript: authority binding isn't wired into `TAPClient`.**
  `sdk/js/src/authority.ts` has the primitives (mirrors
  `sdk/python/src/tap_sdk/authority.py`); `traceTool` has no `authorize=` /
  `effect_of=` equivalent to the Python client's. Already tracked in
  [README.md](README.md#authority-binding-§92--provisional-and-optional);
  listed here so it isn't lost.

- [ ] **Go SDK has no `TAPClient` wrapper and isn't in GitHub Actions.**
  `sdk/go/tap` is wire-crypto primitives only (sign/verify Passport and
  Event, checkpoints, scope, authority functions) — no tracing client, and
  `go test ./tap` has to be run by hand (`README.md` already says so).

- [ ] **`sdk/python/pyproject.toml`'s `dev` extra is incomplete.**
  It lists `httpx` and `pytest` but not `fastapi`/`uvicorn`, which
  `gateway/test_gateway.py` needs — `.github/workflows/ci.yml` installs them
  as a separate manual `pip install` step rather than through the extra, and
  a local `pip install -e ".[dev]"` won't be enough to run
  `./scripts/ci-local.sh` end to end. Either add them to `dev`, or add a
  `gateway` extra and point CI + `ci-local.sh`'s header comment at it.

## Very minor

- [ ] `gitleaks` isn't installed in this dev environment, so the secret-scan
  step in `ci-local.sh` silently skips locally (CI still runs it). No action
  needed unless local secret-scanning coverage matters to you — noting it so
  it isn't mistaken for a passing check.
