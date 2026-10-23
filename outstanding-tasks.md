# Outstanding tasks

Originally generated 2026-09-08 from a full-repo review; re-audited
2026-10-23 against v0.1.7. Every item that review found has since been closed
except the ones under **Open** below — see [CHANGELOG.md](CHANGELOG.md) for
the detail behind each closed item.

## Open

- [ ] **Go SDK has no `TAPClient` wrapper.** `sdk/go/tap` is wire-crypto
  primitives only (sign/verify Passport and Event, checkpoints, scope,
  authority and decider functions) — no tracing client, so Go cannot take part
  in `scripts/check-envelope-parity.py`, which compares *client-composed*
  envelopes. (`go test ./...` does run in CI, as the `go-sdk` job.)

- [ ] `gitleaks` isn't installed in this dev environment, so the secret-scan
  step in `ci-local.sh` silently skips locally (CI still runs it). No action
  needed unless local secret-scanning coverage matters — noting it so it
  isn't mistaken for a passing check.

## Closed

| Item | Closed in |
|---|---|
| Two-sided assurance never checked signing-key independence (`[TAP-ASSURANCE-KEY]`, `is_server_key` / `isServerKey`) | 0.1.5 |
| An unsigned `_meta.tap.cid` could redirect a delegation chain (`[TAP-REPLAY-CID]`) | 0.1.5 |
| Delegation replay survived a rotated `action_ref` | 0.1.5 |
| `attestation:"requested"` was bound into `evidence.nego` | 0.1.5 |
| Passport-scoped replay cache keyed wrong; `Passport.reserve_seq()`, `replay_unenforceable` (`[TAP-REPLAY-EDGE]`, `[TAP-REPLAY-SEQ]`) | 0.1.5 |
| `TAPServer` had no `replay_scope` parameter | 0.1.5 |
| `flush()` spun forever against an unreachable Verifier | 0.1.5 |
| Regression and envelope-parity suites not in CI | 0.1.5 (both `ci.yml` and `ci-local.sh`) |
| TypeScript authority binding not wired into `TAPClient` (`traceTool({authorize, effectOf})`) | 0.1.6 |
| `dev` extra missing the Gateway's test dependencies (`gateway` extra added in 0.1.6; `uvicorn` added to `dev`) | 0.1.6 / unreleased |
| Inspector did not display typed-decision `decider` / `gate` information | unreleased |

All 16 checks in `sdk/python/tests/test_regressions.py` pass as of v0.1.7.
