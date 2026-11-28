# Model card — injection classifier

**Intended use.** Score user input and retrieved text for prompt injection in
SentinelOps. Two thresholds from the calibrated score drive block / safe-mode decisions.

**Training data.** A built-in labelled development set of generic injection and benign
operational strings (`src/sentinelops/guardrails/classifier.py`). The held-out and
adaptive red-team splits are never used for training or tuning.

**Model.** TF-IDF (1–2 grams) + logistic regression with isotonic calibration.

**Metrics.** Precision, recall, false positives and expected calibration error (ECE)
are produced by `python scripts/train_classifier.py`, which also writes a reliability
diagram. The threshold is chosen against the <5% false-positive target.

**Known failure cases.** Heavy paraphrase, novel encodings, instructions split across
turns and low-trust document payloads. These are handled by the rule patterns, bounded
normalisation, context gate and session scoring rather than by the classifier alone.

**Out of scope.** Detecting malicious intent in ordinary natural language without an
instruction-like payload; classifying non-English attacks beyond the benign bias check.
