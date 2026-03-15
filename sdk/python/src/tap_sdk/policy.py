"""Policy engine — policy-as-code, shared by the Shim, the server leg, and the
Verifier (build spec §9.4; TAP-spec §8 defines only the *record* format).

One policy set, three enforcement points (defense in depth):
  * the Shim    — deny **before acting**     (prevention; the Tenet-uncopyable edge)
  * the server  — deny **before executing**  (server leg, §9.1)
  * the Verifier — evaluate + flag/report    (post-hoc; the source of truth for audit)

Because all three import *this* module, a decision made at the edge is reproducible
byte-for-byte at audit time — which is the compliance crux: an auditor can prove
exactly which rule, in which policy version, governed any historical action.

Design choices (build spec §9.4):
  * **Constrained JSON rule schema**, not a hand-rolled DSL — predictable, diffable.
  * Hidden behind an **``Evaluator`` interface** so an OPA/Rego or CEL backend can
    slot in later without touching any call site.
  * Every policy set is **content-hashed** to a ``policy_version`` (a TAP digest
    string over its JCS canonicalization), so "we had a policy" becomes "here is
    the signed proof of the policy that ran."

The wire spec keeps the policy *language* out of scope (TAP-spec §14, Service
Profiles); this is that Service Profile. What crosses the wire is only the
``policy_decision`` record (TAP-spec §8): ``{decision, rule_id, policy_version}``.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import jcs  # RFC 8785 — same canonicalizer the signatures use

from .core import digest

__all__ = [
    "PolicyError",
    "PolicyRequest",
    "PolicyDecision",
    "Evaluator",
    "JSONRuleEvaluator",
    "policy_version",
    "EMPTY_POLICY",
]

# An empty default-allow policy: a real, hashable policy that denies nothing.
# Useful as a neutral baseline (drift, TAP-spec §8, remains a separate built-in).
EMPTY_POLICY: dict = {"default": "allow", "rules": []}


class PolicyError(ValueError):
    """A malformed policy document (caught at load/author time, not eval time)."""


def policy_version(policy: dict) -> str:
    """Content-hash a policy set to its ``policy_version`` digest string.

    Uses the same JCS (RFC 8785) canonicalization as event signing, so the
    version is stable across key reordering / whitespace and reproducible by any
    third party. This is the value stamped into every ``policy_decision`` so an
    auditor can prove *which* policy governed a historical action (build spec §9.4).
    """
    return digest(jcs.canonicalize(policy))


# --- the request a decision is made about ------------------------------------

@dataclass(frozen=True)
class PolicyRequest:
    """The facts a rule matches against — assembled identically at every
    enforcement point so the same action yields the same decision everywhere."""

    tool: str | None = None              # action.tool (tool name or target agent id)
    scope_used: str | None = None        # action.scope_used
    kind: str = "tool_call"              # action.kind (TAP-spec §5.2)
    agent_name: str | None = None        # passport.meta.agent_name
    agent_id: str | None = None          # logical agent id
    args: dict[str, Any] | None = None   # args_preview (when captured) for predicates
    env: str | None = None               # deployment environment, e.g. "production"
    delegation_depth: int = 0            # how deep in a delegation chain (§9.3)

    @classmethod
    def from_event(cls, event: dict, *, passport_claims: dict | None = None,
                   env: str | None = None, delegation_depth: int = 0) -> "PolicyRequest":
        """Build a request from a signed event + its passport — the path the
        Verifier uses to re-evaluate a historical transcript (policy backtest)."""
        action = event.get("action") or {}
        meta = (passport_claims or {}).get("meta") or {}
        return cls(
            tool=action.get("tool"),
            scope_used=action.get("scope_used"),
            kind=action.get("kind", "tool_call"),
            agent_name=meta.get("agent_name"),
            args=action.get("args_preview"),
            env=env,
            delegation_depth=delegation_depth,
        )


@dataclass(frozen=True)
class PolicyDecision:
    """The TAP-spec §8 ``policy_decision`` record, plus the matched rule for UX."""

    decision: str               # "allow" | "deny"
    rule_id: str | None         # the rule that fired (None ⇒ default decision)
    policy_version: str         # digest string over the policy set in force

    @property
    def denied(self) -> bool:
        return self.decision == "deny"

    def to_record(self) -> dict:
        """The exact JSON stamped onto an event's ``policy_decision`` field."""
        return {
            "decision": self.decision,
            "rule_id": self.rule_id,
            "policy_version": self.policy_version,
        }


# --- the evaluator interface (OPA/Rego/CEL can replace the default) -----------

class Evaluator(Protocol):
    def evaluate(self, policy: dict, request: PolicyRequest) -> PolicyDecision: ...


class JSONRuleEvaluator:
    """The default evaluator over the constrained JSON rule schema.

    Schema::

        {
          "default": "allow" | "deny",        # decision when no rule matches
          "rules": [
            { "id": "no-prod-delete",
              "effect": "deny",               # "allow" | "deny"
              "when": {                        # all keys AND together
                "tool":        "drop_table" | ["delete", "drop_table"],
                "scope_used":  "write:database",
                "kind":        "tool_call",
                "agent_name":  "support-bot",
                "env":         "production",
                "max_delegation_depth": 2,     # match iff depth <= this
                "args":        { "table": "users" }   # equality over args_preview
              }
            }
          ]
        }

    Rules are evaluated **in order; first match wins**. A scalar matcher means
    equality; a list matcher means membership. Omitted keys don't constrain.
    """

    def evaluate(self, policy: dict, request: PolicyRequest) -> PolicyDecision:
        version = policy_version(policy)
        default = policy.get("default", "allow")
        if default not in ("allow", "deny"):
            raise PolicyError(f"policy.default must be allow|deny, got {default!r}")

        for rule in policy.get("rules", []):
            if self._matches(rule.get("when") or {}, request):
                effect = rule.get("effect")
                if effect not in ("allow", "deny"):
                    raise PolicyError(
                        f"rule {rule.get('id')!r} effect must be allow|deny, got {effect!r}"
                    )
                return PolicyDecision(effect, rule.get("id"), version)

        return PolicyDecision(default, None, version)

    # --- matching ------------------------------------------------------------

    def _matches(self, when: dict, req: PolicyRequest) -> bool:
        for key, want in when.items():
            if key == "args":
                if not self._args_match(want, req.args):
                    return False
            elif key == "max_delegation_depth":
                if req.delegation_depth > want:
                    return False
            elif key in ("tool", "scope_used", "kind", "agent_name", "agent_id", "env"):
                if not self._scalar_match(want, getattr(req, key)):
                    return False
            else:
                raise PolicyError(f"unknown match key {key!r} in rule.when")
        return True

    @staticmethod
    def _scalar_match(want: Any, have: Any) -> bool:
        if isinstance(want, list):
            return have in want
        return have == want

    @staticmethod
    def _args_match(want: dict, have: dict | None) -> bool:
        if not isinstance(want, dict):
            raise PolicyError("rule.when.args must be an object of equality predicates")
        if have is None:
            return False  # rule needs args we don't have ⇒ cannot match
        for k, v in want.items():
            if JSONRuleEvaluator._scalar_match(v, have.get(k)) is False:
                return False
        return True


# A module-level default instance for the common case.
_DEFAULT = JSONRuleEvaluator()


def evaluate(policy: dict, request: PolicyRequest) -> PolicyDecision:
    """Evaluate with the default JSON-rule evaluator (convenience)."""
    return _DEFAULT.evaluate(policy, request)
