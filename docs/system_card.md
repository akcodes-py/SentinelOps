# System card — AI Ops Copilot

**Purpose.** Answer operational questions over synthetic customer, invoice, pickup and
document data for a recycling and waste-logistics operation. The domain is context only;
the contribution is the security design.

**Tools and risk tiers.** `query_db` (medium), `search_docs` (medium),
`generate_report` (low), `send_email` (high), `dispatch_vehicle` (high). High-risk
tools always enter the approval queue and never run on model output alone.

**Guardrails.** Five checkpoints (input, context, prompt hardening, tool, output), a
versioned `policy.yaml`, 20+ reason codes, calibrated injection thresholds, session
risk scoring, egress control and self-protection limits with fail-closed behaviour.

**Measured behaviour.** ASR per category before and after, held-out and adaptive
results, per-layer catch rate and latency, false-positive rate and ECE are written to
`results/*.json` by `python scripts/run_evaluation.py`. Figures are reported as measured.

**Limitations.** The offline model adapter is deterministic and rule-driven; it
demonstrates the security boundaries but is not a general conversational model. The
guardrails reduce risk without removing it — surviving attacks are listed in
[`residual_risk.md`](residual_risk.md).
