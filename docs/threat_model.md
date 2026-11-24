# Threat model (PDR §7)

| Asset | Threat | Reference | Primary controls |
|---|---|---|---|
| Agent behaviour | Direct/indirect prompt injection | LLM01 | Input and document scanning, policy engine |
| Customer data | Sensitive information disclosure | LLM02 | PII masking, tenant scoping, output filters, canary tokens |
| System prompt | Prompt leakage | LLM07 | No secrets in prompts, leakage detection |
| Tool actions | Excessive agency | LLM06 | Allowlists, risk tiers, human approval |
| Vector store | Poisoned retrieved content | LLM04, LLM08 | Source trust levels, ingestion checks |
| Availability/cost | Unbounded consumption | LLM10, API4 | Rate limiting, quotas, token limits |
| Business APIs | BOLA, broken auth, injection | API1, API2, API3 | Object-level checks, JWT validation, parameterised queries |
| Output channel | Exfiltration via links/images | LLM02, LLM05 | Egress allowlist, output sanitising, CSP |
| Session context | Instructions split across turns | LLM01 | Session risk score, windowed scan |
| Guardrail layer | Resource exhaustion, policy tampering | LLM10 | Size/time budgets, fail closed, versioned policy reviewed in CI |
