"""CI check: reject policy.yaml changes that loosen security (PDR 6.3.4)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def load(text: str) -> dict:
    return yaml.safe_load(text)


def main() -> int:
    path = ROOT / "policy.yaml"
    if not (ROOT / ".git").exists():
        print("no git repository; skipping diff check")
        return 0
    try:
        old_text = subprocess.check_output(
            ["git", "show", "main:policy.yaml"], cwd=ROOT, stderr=subprocess.DEVNULL, text=True
        )
    except subprocess.CalledProcessError:
        print("no main branch policy.yaml to compare; skipping")
        return 0
    old, new = load(old_text), load(path.read_text(encoding="utf-8"))
    problems = []
    for key in ("injection_low", "injection_high", "session_safe", "session_lock", "max_input_chars", "max_input_tokens"):
        if float(new["thresholds"][key]) > float(old["thresholds"][key]):
            problems.append(f"threshold {key} was loosened")
    if set(new["tools"]) - set(old["tools"]):
        problems.append("a tool was added")
    for tool, cfg in new["tools"].items():
        prev = old["tools"].get(tool, {})
        for key in ("allowed_domains", "allowed_tables", "report_types"):
            if set(cfg.get(key, [])) - set(prev.get(key, [])):
                problems.append(f"tool {tool} widened {key}")
    if set(new["egress"]["allowed_domains"]) - set(old["egress"]["allowed_domains"]):
        problems.append("egress allowlist widened")
    for problem in problems:
        print(f"POLICY DIFF: {problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
