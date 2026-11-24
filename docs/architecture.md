# Architecture (PDR §5)

Four layers, with all traffic passing through the gateway before reaching the application.

1. **Clients** — API clients and a simple web UI.
2. **Security gateway (control plane)** — JWT authentication, RBAC, tenant scoping,
   token-bucket rate limiting, five guardrail checkpoints, PII masking, tool policy
   and structured audit logging. Implemented as FastAPI middleware and dependencies.
3. **Application layer** — AI Ops Copilot (LangChain-compatible tool interface, RAG)
   and business REST APIs for customers, invoices and pickups.
4. **Data layer** — PostgreSQL (SQLite offline), a vector store (TF-IDF/ChromaDB) and
   environment-based secrets.

Observability and testing (log pipeline, red-team engine, CI checks) sit alongside.

## Request flow

1. Request is authenticated and rate-limited.
2. Input gate normalises bounded encodings, applies rule patterns, scores the injection
   classifier and checks the session risk score.
3. Retrieved chunks are scanned by the context gate before prompt assembly; the prompt
   hardener applies instruction hierarchy, delimiters and a canary token.
4. Any tool call is checked by the tool gate against allowlists, parameter rules, tenant
   scope, risk tier and the approval queue.
5. Output is checked for canary leakage, system-prompt similarity, PII and egress.
6. Every decision is logged with a reason code and the policy version.

Fail-closed: tool calls and the output gate deny on error or timeout; low-risk read-only
answers continue with the failure logged. User-facing refusals never reveal the rule.
