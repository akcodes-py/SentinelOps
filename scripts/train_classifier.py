"""Train and calibrate the injection classifier, then report ECE (PDR 6.6)."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sentinelops.guardrails.classifier import INJECTION_EXAMPLES, BENIGN_EXAMPLES, expected_calibration_error, reliability_diagram, save_artifact, score

if __name__ == "__main__":
    texts = INJECTION_EXAMPLES + BENIGN_EXAMPLES
    labels = [1] * len(INJECTION_EXAMPLES) + [0] * len(BENIGN_EXAMPLES)
    artifact = save_artifact(ROOT / "artifacts" / "classifier.pkl")
    ece = expected_calibration_error(texts, labels)
    print(f"saved: {artifact}")
    print(f"ECE: {ece:.4f}")
    print("reliability diagram:")
    for row in reliability_diagram(texts, labels):
        print(row)
    print(f"example attack score: {score(texts[0]):.3f}")
    print(f"example benign score: {score(texts[-1]):.3f}")
