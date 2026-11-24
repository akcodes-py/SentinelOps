"""Run the full before/after evaluation and build the residual risk table.

Usage: python scripts/run_evaluation.py [--splits dev held-out adaptive] [--repeats 2]
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelops.redteam.runner import run_suite
from sentinelops.reports import build_residual_risk


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--splits", nargs="+", default=["dev", "held-out", "adaptive"])
    parser.add_argument("--repeats", type=int, default=1)
    args = parser.parse_args()

    for mode in ("baseline", "defended"):
        for split in args.splits:
            report = run_suite(mode=mode, split=split, repeats=args.repeats)
            summary = report["summary"]
            print(f"{mode:8s} {split:9s} ASR={summary['overall_asr']:.3f} FPR={summary['false_positive_rate']}")

    residual = build_residual_risk(ROOT / "results")
    out = ROOT / "results" / "residual_risk.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(residual, indent=2), encoding="utf-8")
    print(f"residual risk rows: {len(residual['rows'])} -> {out}")


if __name__ == "__main__":
    main()
