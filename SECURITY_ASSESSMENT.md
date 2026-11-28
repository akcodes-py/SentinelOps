# SentinelOps — Security Assessment (VAPT)

**Assessment date:** 2026-11-28 · **Scope:** SentinelOps v1.0.0 FastAPI gateway, 5-checkpoint guardrail pipeline, agent tools, business APIs and audit trail. **Target:** `SENTINEL_MODE=defended` unless a row explicitly says `baseline`. All data is synthetic; no real personal data, third-party service or production system was used.

This is a reference-implementation assessment, not a certification. OWASP risk IDs follow the **2026** editions of the [OWASP Top 10 for LLM Applications](https://genai.owasp.org/) (published August 2026) and the [OWASP Top 10 for Agentic Applications](https://genai.owasp.org/top-10-for-agentic-applications-2026/) (published December 2025, referred to as 2026). Where older 2025 IDs appear in the code/tests (for example `LLM06` used for excessive agency), the 2026 equivalent is given below.

---

## 1. Executive summary

| Control area | Result |
|---|---|
| Guardrail pipeline | 5 checkpoints intact; 114/114 pytest cases pass (101 original + 13 new crypto/TLS/OWASP-2026 cases) |
| Red-team ASR, defended | **0.0%** on `dev`, `held-out` and `adaptive` (fresh `run_evaluation.py --repeats 1`, 2026-11-28) |
| False positives | **0.0%** over 76 benign English/Hinglish/Hindi queries per split |
| Transport headers | 5/5 present on normal and early-denial responses (`Strict-Transport-Security`, `X-Content-Type-Options`, `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`) |
| Secrets at rest | Sensitive audit payloads AES-256-GCM encrypted; no plaintext prompt at rest; tamper detection tested |
| Static analysis | `bandit -r src/ -ll`: **no Medium/High issues** (4 deliberate, justified suppressions; 2 B615 Hugging Face revision findings fixed via immutable-commit pinning) |
| Dependency audit | `pip-audit -r requirements.txt`: **No known vulnerabilities found** |
| ZAP baseline | CI gate configured via `.zap/rules.tsv`; zero `FAIL` rules; two header `WARN` rules now addressed (see §7) |

> **Metrics provenance.** The task brief supplied 68.0% → 6.0% ASR, 14.3% held-out ASR and 3.3% false-positive rate. Those figures could not be reproduced by this repository's harness. The committed artifacts and a fresh run give the measured numbers in §6. Only the measured numbers are presented as results here; the brief figures are recorded as supplied-but-unverified in `decision.md` (D5).

---

## 2. Five-checkpoint threat model

Every `/copilot` request crosses an edge layer and five checkpoints. Any exception or timeout fails closed (`GUARD_TIMEOUT`). End users receive only a generic safe refusal; reason codes stay in structured logs, `/reports/timeline` and reviewer views.

| Stage | Trust boundary | Threats addressed | Primary controls | Evidence |
|---|---|---|---|---|
| **Edge (0)** | Network → gateway | Unauthenticated access, cross-tenant access, resource exhaustion, HTTP downgrade | JWT + role claims, tenant scope, token-bucket limiter, optional `SENTINEL_REQUIRE_HTTPS`, 5 security headers | `auth.py`, `rate_limit.py`, `middleware/security_headers.py`; tests `test_api.py`, `test_security_controls.py` |
| **1 · Input gate** | User prompt → agent | Direct/encoded/multi-turn prompt injection, hidden-context elicitation | Bounded normalisation, 15 policy rules, calibrated classifier, session scoring, safe mode | `guardrails/gates.py:InputGate`, `normalise.py`, `classifier.py`; `test_security_controls.py`, `test_gateway_crypto_and_owasp2026.py` |
| **2 · Context gate** | Retrieval → prompt | Poisoned RAG chunks, low-trust content, instruction-in-document | Per-chunk scan, trust label, quarantine (`CTX_POISON`) | `guardrails/gates.py:ContextGate`; ASI06 tests |
| **3 · Prompt hardening** | Prompt assembly → model | Instruction hierarchy bypass, canary leak | System-instruction precedence, untrusted-data delimiters, canary token | `agent/prompts.py`, `guardrails/gates.py:PromptHardening` |
| **4 · Tool gate** | Model output → side effects | Tool misuse, SQLi, table escalation, cross-tenant queries, unsafe email/dispatch | Tool allowlist + param schema, single-SELECT gate, table allowlist, tenant backstop, read-only DB, dispatch caps, HITL approval queue | `guardrails/gates.py:ToolGate`, `approval.py`, `db.py`; `test_tool_gate.py` |
| **5 · Output gate** | Model output → client | PII disclosure, canary/system-prompt/policy leak, external tracking/egress | Canary + similarity + hidden-context detection, regex/Presidio masking, egress allowlist, HTML escaping | `guardrails/gates.py:OutputGate`, `pii.py`; LLM08 tests |
| **Audit (cross-cutting)** | Decisions → storage | Log tampering, secret exposure at rest | JSONL logs with `request_id`/`policy_version`, registered reason codes, AES-256-GCM encrypted audit payloads in `encrypted_audit_events` | `logging_utils.py`, `db.py`, `security/encryption.py` |

---

## 3. OWASP LLM Top 10 (2026) mapping

| ID | 2026 risk | SentinelOps control | Verification |
|---|---|---|---|
| **LLM01** | Prompt Injection | Input Gate normalisation + 15 rules (incl. encoded and multi-turn), classifier, Context Gate quarantine, instruction hierarchy, canary | `test_security_controls.py` (all INJ rules), `test_redteam.py`, Postman request 03 |
| **LLM02** | Sensitive Information Disclosure | Tenant-scoped retrieval and DB, PII masking (regex/Presidio), egress allowlist, encrypted audit payloads at rest | `test_pii.py` cases in `test_security_controls.py`, `test_gateway_crypto_and_owasp2026.py` |
| **LLM03** | Excessive Agency *(LLM06:2025)* | Tool allowlist, risk tiers, parameter schemas, dispatch caps, HITL `/approvals` queue for `send_email`/`dispatch_vehicle` | `test_tool_gate.py`, `test_api.py` |
| **LLM06** | Unbounded Consumption *(LLM10:2025)* | Token-bucket rate limiter (429), bounded input length/expansion, checkpoint time budgets, fail-closed timeout | `test_security_controls.py` (429), `test_self_protection.py`, Postman request 08 |
| **LLM08** | Hidden Context Exposure *(formerly System Prompt Leakage)* | System prompt never contains real secrets (synthetic `SECRET_VALUE` only), `CANARY_LEAK`/`SYSPROMPT_LEAK` output blocks, `INJ_RULE_15` for `policy.yaml`/hidden-rule extraction | `test_llm08_*` in `test_gateway_crypto_and_owasp2026.py`, Postman request 04 |
| **LLM09** | Vector and Embedding Weaknesses | Tenant-scoped TF-IDF retrieval, per-chunk trust scan, quarantine of instruction-bearing or low-trust chunks | `test_security_controls.py` VectorStore cases, ASI06 tests |
| **LLM10** | Improper Output Handling | Output Gate HTML escaping, allowed schemes/domains, URL/image stripping, block on canary or hidden-context leak | `test_egress_sanitisation_variants`, LLM08 output-gate test |

Not claimed as fully mitigated by this reference slice: LLM04 (Supply Chain) and LLM05 (Data and Model Poisoning of training data) — no fine-tuning pipeline is in scope; LLM07 (Misinformation) is out of scope for the deterministic mock backend.

---

## 4. OWASP Agentic Top 10 (2026) mapping

| ID | Risk | SentinelOps control | Verification |
|---|---|---|---|
| **ASI01** | Agent Goal Hijack | Input Gate rule/classifier/session scoring blocks goal-overriding prompts; Context Gate strips instruction-bearing retrieved text | Red-team `direct`/`indirect` families; `test_llm08_system_prompt_extraction_blocked_and_logged` |
| **ASI02** | Tool Misuse & Exploitation | Tool allowlist, single-`SELECT` gate, table allowlist, recipient-domain checks, caps, HITL approval; read-only DB backstop (`PRAGMA query_only=ON`) | `test_tool_gate.py`, `test_query_for_agent_*`, Postman requests 05–06 |
| **ASI03** | Identity & Privilege Abuse | JWT tenant/role claims enforced at gateway and business APIs; BOLA/IDOR returns 404; RBAC on `/approvals` | `test_defended_tenant_scoping`, `test_rbac_*`, Postman request 07 |
| **ASI06** | Memory & Context Poisoning | Session window is rescanned on every turn (`SESSION_RISK`); retrieved chunks quarantined (`CTX_POISON`); poisoned instructions never become trusted context | `test_asi06_*` in `test_gateway_crypto_and_owasp2026.py`, multi-turn `ABU-MT1` red-team case |
| **ASI09** | Human-Agent Trust Exploitation | High-risk actions never execute on model output alone: HITL queue, generic refusals, reviewer-visible reason codes in timeline/alerts | `test_approval_queue_requires_approval`, `/reports/timeline` |

Out of scope (single-agent, single-process reference implementation): ASI04, ASI05, ASI07, ASI08, ASI10.

---

## 5. Encryption and TLS implementation

### 5.1 AES-256-GCM at rest

- `src/security/encryption.py` uses `cryptography.hazmat.primitives.ciphers.aead.AESGCM` with a 32-byte key read from `ENCRYPTION_KEY` (base64) and a fresh `os.urandom(12)` nonce per encryption.
- Stored token: `base64(nonce || ciphertext || 16-byte GCM tag)`. Associated data `sentinelops:audit:v1` binds tokens to the audit context.
- `InvalidTag` (and malformed/short tokens) raise `DecryptionTamperError`; never a partial plaintext.
- Used **only** for sensitive stored audit payloads in `encrypted_audit_events` (prompt, tenant, session, decisions), written from `/copilot` in defended mode. With no valid key the write is skipped and the gateway behaves as before.
- Key generation and rotation: `python -c "import base64,os;print(base64.b64encode(os.urandom(32)).decode())"`. Store the key in the deployment secret manager, not in `.env` committed to source control. Rotating the key requires re-encrypting existing rows; this reference slice does not implement automatic re-keying.
- No real secret is hardcoded. `SECRET_VALUE` in `agent/agent.py` is a synthetic canary-like string used only to demonstrate baseline leakage; it is not a credential.

### 5.2 HTTPS/TLS headers

`src/middleware/security_headers.py` sets, on every HTTP response (including 401/403/413/429 early denials):

| Header | Value |
|---|---|
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` |
| `X-Content-Type-Options` | `nosniff` |
| `X-Frame-Options` | `DENY` |
| `Content-Security-Policy` | `default-src 'self'` |
| `Referrer-Policy` | `no-referrer` |

Local TLS: generate a certificate and start uvicorn with `--ssl-keyfile`/`--ssl-certfile` (exact commands in `.env.example` and `README.md`). Behind a TLS-terminating proxy set `SENTINEL_REQUIRE_HTTPS=true` and list the proxy in `SENTINEL_TRUSTED_PROXIES` so `X-Forwarded-Proto: https` is honoured; plain HTTP is rejected with 403 in defended mode.

---

## 6. Red-team metrics (fresh run, 2026-11-28)

Harness: `python scripts/run_evaluation.py --repeats 1`; 49 adversarial cases + 76 benign queries; raw JSON in `results/`.

| Split | Cases | Baseline ASR | Defended ASR | Defended FPR | Mean latency |
|---|---:|---:|---:|---:|---:|
| `dev` | 24 | 0.7083 | **0.000** | **0.000** | 23.83 ms |
| `held-out` | 12 | 0.4167 | **0.000** | **0.000** | 33.57 ms |
| `adaptive` | 13 | 0.6154 | **0.000** | **0.000** | 29.57 ms |

Classifier calibration: ECE 0.0158 (isotonic 5-fold CV, `scripts/train_classifier.py`). Reason-code coverage: 100% of the registry. High-risk tool approval: 100% queued. Residual risk rows: 0.

### 6.1 Local LLM backend check (separate from the verified scorecard)

The hosted `opencode/hy4-flash-free` model returned HTTP 429 (free quota exhausted) and other hosted models require paid credits; `Qwen2.5-0.5B-Instruct` was too slow on this CPU. The check therefore used a pinned local `google/flan-t5-small` model (revision `0fc9ddf78a1e988dac52e2dac162b0ede4fd74ab`) with batched prewarm and cache, via `scripts/run_opencode_llm_check.py` with `write=False`.

| Metric | Result |
|---|---:|
| ASR (49 attacks, `all`, defended) | **0.0000** |
| FPR (76 benign queries) | **0.0000** |
| Mean / P95 latency | 21.745 ms / 31.872 ms |
| Model calls / errors | 84 / 0 |

Raw artifacts: `results/local_llm_check.json` and `results/local_llm_check_summary.md`. This is a local model check, not an independent pentest; tool calls are parsed from a JSON envelope and unparseable replies degrade to text only, so tool-gate coverage is limited. It does not replace the owner-verified mock-backend results in §6.

---

## 7. Tooling evidence and limitations

| Tool | Command | Outcome |
|---|---|---|
| Pytest | `python -m pytest -v` | 114 passed (101 baseline + 13 new) |
| Bandit | `python -m bandit -r src/ -ll` | No Medium/High issues (exit 0). 4 justified `# nosec`: 3 baseline-mode SQL strings (needed for the BOLA/SQLi demonstration) and 1 local classifier-pickle load with rebuild-on-failure fallback. **2 B615 findings fixed:** `HFLocalAgent._load()` now requires an immutable `SENTINEL_HF_REVISION` commit SHA and passes `revision=` to both `from_pretrained()` calls; branches/tags are rejected and a missing SHA fails closed |
| pip-audit | `python -m pip_audit -r requirements.txt --progress-spinner off` | No known vulnerabilities in declared project dependencies. A whole-environment audit surfaces unrelated packages installed by other projects on the host; those are outside this project's dependency set |
| OWASP ZAP | CI `zaproxy/action-baseline@v0.15.0` with `.zap/rules.tsv` | Local baseline rerun (2026-11-28): **0 FAIL / 0 WARN**, 65 PASS, 3 justified IGNORE (`10024`, `10049`, `10112`). The earlier CI failure was caused by 4 WARN alerts and an outdated action/artifact-name bug; `Cross-Origin-Resource-Policy: same-origin`, no-store cache headers and rule entries resolved it. A full ZAP HTML report should still be saved in `docs/security_evidence/` by the operator |
| Burp Suite | `docs/BURP_SUITE_CHECKLIST.md` | Four Repeater captures defined; screenshots are intentionally not fabricated. Add captures to `docs/security_evidence/` when performing the assessment |

**Known limitations / residual risk:** strict CSP blocks the inline `<style>`/`<script>` in the built-in `/ui` demo page (use the same-origin React frontend in `frontend/` for production); key rotation requires re-encryption; baseline mode remains deliberately vulnerable by design and must never be deployed; the classifier artifact is a local pickle loaded with a rebuild fallback.

**Artifacts:** Postman collection `docs/sentinelops.postman_collection.json` · Burp checklist `docs/BURP_SUITE_CHECKLIST.md` · evidence folder `docs/security_evidence/` · decisions `decision.md` · progress `tracker.md`.
