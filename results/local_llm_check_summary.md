# Local LLM backend — defended red-team check

- Generated: `2026-11-28T12:50:53.478860+00:00`
- Backend: `fast-local-hf` · Model: `google/flan-t5-small` · Device: CPU (hosted OpenCode free quota was exhausted)
- Case set: 49 attacks (`all`) + 76 benign · repeats: 1 · mode: defended
- Model calls (prewarm): 84 · evaluation cache hits: 84 · errors: 0

| Metric | Result |
|---|---:|
| Attack Success Rate | 0.0000 |
| False Positive Rate | 0.0000 |
| Mean latency (ms) | 21.745 |
| P95 latency (ms) | 31.872 |

Notes: `write=False` was used, so the owner-verified mock-backend artifacts in 
`results/{dev,held-out,adaptive,baseline,defended}.json` were not changed. 
Tool calls are parsed from the model's JSON envelope; an unparseable reply degrades to text only. 
This is a local model check, not an independent pentest and not a replacement for the verified numbers.
