# SentinelOps — Implementation Decision Log

Task: Gateway Secret Encryption, HTTPS/TLS & OWASP 2026 Alignment · 2026-11-28

## D1 — Module location follows the existing package layout

The brief names `src/security/encryption.py` and `src/middleware/security_headers.py`.
Those paths are created verbatim, each with an `__init__.py`, so setuptools'
`packages.find(where=["src"])` includes them and `tests/conftest.py` (which puts
`src/` on `sys.path`) resolves them. They are imported as `security.encryption`
and `security_headers` from `sentinelops.app.main`. No new top-level package name
collides with an installed package on this machine (verified with
`importlib.util.find_spec`).

## D2 — Encryption is narrow and opt-in

AES-256-GCM is used only for sensitive stored gateway artifacts: a new
`encrypted_audit_events` table holding JSON audit payloads (request id, tenant,
session, prompt and guard decisions) written from `/copilot`. The helper reads a
32-byte base64 `ENCRYPTION_KEY` from the environment at call time; no key is
committed. If no valid key is configured the write is skipped and the gateway
behaves exactly as before — the 5-checkpoint pipeline, red-team harness and all
98 existing tests are untouched in the default configuration. Decrypting a
modified/malformed token raises `DecryptionTamperError` (from `InvalidTag`).

AAD is bound to `b"sentinelops:audit:v1"` so a token cannot be replayed in a
different context. Nonces are 12 bytes from `os.urandom(12)` and are prepended
to the ciphertext in the stored base64 token.

## D3 — Header middleware owns HSTS

`SecurityHeadersMiddleware` is a pure-ASGI middleware added *after* the existing
`@app.middleware("http")` handler, so it wraps early denials (413/403/429) as
well as normal responses. The duplicate HSTS assignment in `gateway_middleware`
is removed so there is one source of truth. Headers are applied in both modes:
they are transport-level controls, not guardrail decisions, and baseline mode
must remain exploitable for the red-team comparison.

CSP is exactly `default-src 'self'` as requested. The built-in `/ui` page uses
inline `<style>`/`<script>`, so browsers will block those under strict CSP; the
documented production path is the React frontend in `frontend/` (served from
the same origin). This is called out in the assessment rather than weakening
the header with `unsafe-inline`.

## D4 — OWASP 2026 detection reuses existing reason codes

Hidden-context extraction (LLM08) and context poisoning (ASI06) are handled by
existing checkpoints and reason codes:

- System-prompt extraction → Input Gate `INJ_RULE_03` / Output Gate
  `SYSPROMPT_LEAK` / `CANARY_LEAK`.
- `policy.yaml` / internal-config extraction → new Output Gate pattern using
  the registered `SYSPROMPT_LEAK` code (no unregistered codes, so the 100%
  reason-code coverage test stays valid).
- Poisoned retrieved chunk → Context Gate `CTX_POISON` quarantine.

No policy thresholds or tool allowlists were loosened; CI's policy-diff gate
remains satisfied.

## D5 — Metrics provenance

The brief supplies 68.0% → 6.0% ASR, 14.3% held-out ASR and 3.3% false-positive
rate. The committed artifacts in `results/` and a fresh `run_evaluation.py`
run instead show 70.8% → 0.0% (dev), 41.7% → 0.0% (held-out), 61.5% → 0.0%
(adaptive), FPR 0.0%. The security assessment reports only the measured values
and adds an explicit note that the brief figures could not be reproduced by
this harness. Claiming them as verified would violate the project's
"zero unverified claims" rule.

## D6 — Bandit findings

The 3 `B608` findings are the *intentionally vulnerable* baseline endpoints
required by the red-team suite (BOLA/SQLi demonstration); removing them would
break baseline tests and the evaluation. They are annotated with
`# nosec B608` plus an inline justification. The `B301` pickle load reads a
locally generated classifier artifact; it is annotated `# nosec B301` with a
justification that the artifact is local, repo-controlled and falls back to
rebuilding the model on any load failure. These are documented in the
assessment; no High-severity findings remain.

## D7 — ZAP evidence

`.zap/rules.tsv` is the committed baseline-scan rule configuration, not a full
scan report. CI runs `zaproxy/action-baseline` against the live gateway. The
assessment describes this honestly and notes the new `X-Content-Type-Options`
and CSP headers directly address the two WARN rules in that file. Burp
screenshots are left as an operator checklist (`docs/security_evidence/README.md`)
because synthetic screenshots would be false evidence.

## D8 — Immutable Hugging Face revision pinning (B615 fix)

Bandit 1.9 flagged two `B615` findings in `HFLocalAgent._load()`: `from_pretrained()`
without a pinned, immutable revision allows a branch/tag to be repointed to a
malicious model (OWASP LLM04:2026, ASI04:2026). Decided to require
`SENTINEL_HF_REVISION` — a hexadecimal commit SHA of at least 7 characters —
and pass it explicitly to both tokenizer and model loads. Branches/tags are
rejected at construction and a missing SHA raises at load time (fail closed).
The default backend remains `mock`, so offline tests/evaluation are unaffected.
Result: 114 tests pass and `bandit -r src/ -ll` exits 0 with no Medium/High issues.
