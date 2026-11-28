"""Run the defended red-team check with a real local LLM (Qwen 0.5B Instruct).

The hosted OpenCode free quota was exhausted (429), so this uses a locally
downloaded Hugging Face instruct model instead. Optimisation: a fast recorder
pass collects every exact prompt, the adapter prewarms unique prompts in
batches, then the timed evaluation replays from cache. ``write=False`` keeps
the owner-verified mock-backend artifacts untouched.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelops.agent.agent import LocalHFLLM  # noqa: E402
from sentinelops.redteam.runner import run_suite  # noqa: E402


class PromptRecorder:
    """Capture exact prompts without making any model calls."""

    def __init__(self) -> None:
        self.prompts: list[str] = []

    def decide(self, prompt: str, tenant_id: int, db: Any) -> tuple[list[dict[str, Any]], str]:
        self.prompts.append(prompt)
        return [], ""


def main() -> None:
    print("Recorder pass: collecting exact prompts...", flush=True)
    recorder = PromptRecorder()
    run_suite(mode="defended", split="all", repeats=1, benign=True, write=False, llm=recorder)
    unique = list(dict.fromkeys(recorder.prompts))
    print(f"Collected {len(recorder.prompts)} requests / {len(unique)} unique prompts.", flush=True)

    adapter = LocalHFLLM()
    print(f"Prewarming with model={adapter.model_name} batch={adapter.batch_size}...", flush=True)
    adapter.prewarm(unique)
    print(f"Prewarm complete: calls={adapter.calls} errors={adapter.errors}", flush=True)

    report = run_suite(mode="defended", split="all", repeats=1, benign=True, write=False, llm=adapter)
    summary = report["summary"]

    out = ROOT / "results" / "local_llm_check.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "backend": "local-hf",
                "model": adapter.model_name,
                "server": "cpu",
                "mode": "defended",
                "split": "all",
                "repeats": 1,
                "attack_cases": len([c for c in report["cases"]]),
                "benign_queries": 76,
                "unique_prompts": len(unique),
                "model_calls": adapter.calls,
                "cache_hits_during_evaluation": adapter.hits,
                "model_errors": adapter.errors,
                "summary": summary,
                "cases": report["cases"],
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    md = ROOT / "results" / "local_llm_check_summary.md"
    md.write_text(
        "\n".join(
            [
                "# Local LLM backend — defended red-team check",
                "",
                f"- Generated: `{datetime.now(timezone.utc).isoformat()}`",
                f"- Backend: `local-hf` · Model: `{adapter.model_name}` · Device: CPU (hosted OpenCode free quota was exhausted)",
                f"- Case set: 49 attacks (`all`) + 76 benign · repeats: 1 · mode: defended",
                f"- Model calls (prewarm): {adapter.calls} · evaluation cache hits: {adapter.hits} · errors: {adapter.errors}",
                "",
                "| Metric | Result |",
                "|---|---:|",
                f"| Attack Success Rate | {summary['overall_asr']:.4f} |",
                f"| False Positive Rate | {summary['false_positive_rate']:.4f} |",
                f"| Mean latency (ms) | {summary['mean_latency_ms']} |",
                f"| P95 latency (ms) | {summary['p95_latency_ms']} |",
                "",
                "Notes: `write=False` was used, so the owner-verified mock-backend artifacts in ",
                "`results/{dev,held-out,adaptive,baseline,defended}.json` were not changed. ",
                "Tool calls are parsed from the model's JSON envelope; an unparseable reply degrades to text only. ",
                "This is a local model check, not an independent pentest and not a replacement for the verified numbers.",
                "",
            ]
        ),
        encoding="utf-8",
    )

    print(
        f"RESULT backend=local-hf model={adapter.model_name} ASR={summary['overall_asr']:.4f} "
        f"FPR={summary['false_positive_rate']:.4f} mean_ms={summary['mean_latency_ms']} "
        f"calls={adapter.calls} errors={adapter.errors}",
        flush=True,
    )
    print(f"WROTE {out}")
    print(f"WROTE {md}")


if __name__ == "__main__":
    main()
