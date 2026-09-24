# Typed decisions

**Status:** provisional (v0.1.7) · **Normative text:** [TAP specification §6.4.1](../TAP-spec-v0.1.md) (`[TAP-EVT-DECIDER]`, `[TAP-EVT-GATE]`, `[TAP-EVT-GATE-DECIMAL]`)

Agents no longer make every decision with their main LLM. Narrow decisions (classify this ticket, route this invoice, approve or review, which GL code) increasingly go to separate components picked for speed and cost:

- **typed decision models**: "System One" models that take unstructured input and return one label from a fixed set with a calibrated probability, in tens to hundreds of milliseconds, with no free text to parse;
- **compiled rules**: deterministic paths an agent-workflow compiler produced from repeated runs;
- **human reviewers**, when confidence is too low to act.

A v0.1.6 `decision` Event records *what* was chosen and *what else* was considered. It cannot say *which component* decided, what contract that component was held to, or whether a low-confidence answer was acted on anyway. v0.1.7 adds two optional blocks inside `decision` that can.

## What gets signed

```jsonc
"decision": {
  "question_digest": "sha256:…",
  "chosen": "auto_approve",
  "selection": "argmax",
  "options": [
    { "id": "auto_approve",  "score": "0.72", "chosen": true },
    { "id": "manual_review", "score": "0.28", "chosen": false }
  ],
  "options_digest": "sha256:…",
  "decider": {
    "kind": "model",                              // model | rule | human
    "id": "example.com/typed-decider",
    "version": "2026-09-15",
    "output_schema_digest": "sha256:…",           // the typed contract; plaintext in the annex
    "score_semantics": "calibrated_probability"
  },
  "gate": { "threshold": "0.90", "outcome": "fallback", "fallback_to": "llm" }
}
```

- The decider's **input** is committed by `action.args_digest`, like any tool call. The plaintext goes to the annex, so it can be shredded.
- The **output schema** is committed by digest. The plaintext schema goes to the annex as `decision.output_schema`, and a Verifier holding it can check that every option is a label the schema allows.
- The **gate outcome is derived, not asserted.** The SDKs compute it from the chosen score and the threshold using exact decimal arithmetic. A caller cannot record `accept` for a score below its own threshold. If a hand-built record does, every Verifier labels it `gate_inconsistent`.

## The fallback chain

When a gate falls back, the gated Event's `chosen` is what the decider **proposed**, not what happened. The decision that actually counts is a new `decision` Event with `parent_event_id` pointing at the gated one:

```
seq 13  decision  decider=typed-decider  auto_approve @0.72  gate 0.90 → fallback (llm)
seq 14  decision  decider=frontier-llm   manual_review       parent_event_id = seq 13
seq 15  tool_call route_to_queue(manual_review)
```

`verify_transcript` / `verifyTranscript` reports a fallback nothing has superseded yet as `gate_unresolved`. That label is informational, like a sequence gap with no checkpoint yet.

## Python

```python
from tap_sdk import Decider, TAPClient

ROUTE_SCHEMA = {"type": "object",
                "properties": {"label": {"enum": ["auto_approve", "manual_review"]}}}
jev = Decider(kind="model", id="typesafe.ai/jev", version="2026-09-15",
              output_schema=ROUTE_SCHEMA, score_semantics="calibrated_probability")

result = typesafe_client.decide(invoice_text)          # your model call
ev = tap.typed_decision(
    question="Route this invoice: auto-approve or manual review?",
    labels=["auto_approve", "manual_review"],
    chosen=result.label, score=result.probability,     # probability as a string, e.g. "0.72"
    decider=jev, threshold="0.90", fallback_to="llm",
    input={"invoice_text": invoice_text},
    decision_key="invoice_route",
)

if ev["decision"]["gate"]["outcome"] == "accept":
    route(result.label)
else:
    llm_choice = ask_frontier_model(invoice_text)      # constrained to the same schema
    tap.decision(
        question="Route this invoice: auto-approve or manual review?",
        options=[{"id": "auto_approve", "reason": "..."},
                 {"id": "manual_review", "rationale": "..."}],
        chosen=llm_choice,
        decider=Decider(kind="model", id="example.com/frontier-llm", version="2026-06-01",
                        output_schema=ROUTE_SCHEMA),
        parent_event_id=ev["event_id"], action_ref=ev["action_ref"],
        decision_key="invoice_route",
    )
```

## TypeScript

```ts
const ev = await tap.typedDecision({
  question: "Route this invoice: auto-approve or manual review?",
  labels: ["auto_approve", "manual_review"],
  chosen: result.label, score: result.probability,
  decider: { kind: "model", id: "typesafe.ai/jev", version: "2026-09-15",
             outputSchema: ROUTE_SCHEMA, scoreSemantics: "calibrated_probability" },
  threshold: "0.90", fallbackTo: "llm",
  input: { invoice_text: invoiceText },
});
if ((ev.decision as any).gate.outcome === "fallback") { /* escalate, then record with parentEventId */ }
```

## Scores are strings, and gates compare them exactly

Scores were already strings (`[TAP-CANON-NUMBERS]`). Gated scores and thresholds must also match `^(0(\.[0-9]{1,6})?|1(\.0{1,6})?)$` and are compared as exact decimals: `"0.9"` equals `"0.90"`, and a score exactly on the threshold is `accept`. If your model returns a float, format it yourself to at most six places before you record it. The SDKs refuse to guess.

## What this does and does not prove

- **Proves:** which component the Signer says decided, under which output contract, with what score, against what threshold. It also proves the record's gate outcome agrees with its own numbers, and that none of this was revised after signing.
- **Does not prove:** that the decider was right, that its probabilities really are calibrated (`calibrated_probability` is the Signer's claim), or that the named model is the one that actually answered. For that last point, a server-attested leg from the model provider (§7) is the path to independent evidence.

## Status

Provisional, and outside the §14 conformance table until a production Signer emits it. `tap_ref.py`, all three SDKs (signing and verification), and the vectors (`typed_decision`, `typed_decision_fallback`, `typed_decision_resolution`, `decision_gate`, `negative.gate_outcome_inconsistent`) implement it now. A `gate_inconsistent` label is reported but does not yet turn `verified` false.
