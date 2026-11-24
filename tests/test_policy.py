"""Phase 4/7: policy validation and versioned configuration."""
from pathlib import Path

import pytest

from sentinelops.guardrails.policy import PolicyError, load_policy

ROOT = Path(__file__).resolve().parents[1]


def test_policy_loads_and_validates(policy):
    assert policy.version == "2.2"
    assert policy.thresholds["injection_low"] < policy.thresholds["injection_high"]
    assert len(policy.rules) >= 10
    assert set(policy.tools) == {"query_db", "search_docs", "generate_report", "send_email", "dispatch_vehicle"}


def test_policy_rejects_inconsistent_thresholds(tmp_path):
    raw = (ROOT / "policy.yaml").read_text(encoding="utf-8")
    raw = raw.replace("injection_low: 0.35", "injection_low: 0.85")
    p = tmp_path / "policy.yaml"
    p.write_text(raw, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p, ROOT / "policy.schema.json")


def test_policy_rejects_invalid_schema(tmp_path):
    p = tmp_path / "policy.yaml"
    p.write_text("version: 1\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p, ROOT / "policy.schema.json")


def test_policy_rejects_unregistered_reason_code(tmp_path):
    raw = (ROOT / "policy.yaml").read_text(encoding="utf-8")
    raw = raw.replace("reason_code: INJ_RULE_01", "reason_code: MADE_UP_CODE", 1)
    p = tmp_path / "policy.yaml"
    p.write_text(raw, encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(p, ROOT / "policy.schema.json")
