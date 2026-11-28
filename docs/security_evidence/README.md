# Security Evidence Folder

Place operator-captured evidence here alongside `SECURITY_ASSESSMENT.md`:

| File | Source |
|---|---|
| `01_auth_idor.png` | Burp Repeater — cross-tenant `404` + unauthenticated `401` |
| `02_llm01_injection.png` | Burp Repeater — prompt injection blocked |
| `03_llm08_hidden_context.png` | Burp Repeater — hidden-context extraction blocked |
| `04_asi02_sqli_gate.png` | Burp Repeater — SQLi / tool-gate bypass blocked |
| `zap-baseline-report.html` | OWASP ZAP baseline scan (`zaproxy/action-baseline` in CI) |
| `bandit.txt`, `pip-audit.txt` | Optional saved scanner output from Phase 4 verification |

See `docs/BURP_SUITE_CHECKLIST.md` for exact Repeater steps. Screenshots are not
pre-populated: synthetic or edited evidence would be a false claim. Record the
tool version and capture date here when files are added.
