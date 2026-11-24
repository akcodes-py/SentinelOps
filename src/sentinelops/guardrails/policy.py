"""Load and validate the single versioned policy file (PDR 6.3.4).

The gateway validates against policy.schema.json at startup and refuses to
start if invalid. Every decision logs the policy version.
"""
from __future__ import annotations

import json
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import jsonschema
import yaml

from ..logging_utils import policy_version_var


class PolicyError(ValueError):
    """Raised when the policy file is missing, invalid or internally inconsistent."""


@dataclass
class Rule:
    id: str
    reason_code: str
    severity: str
    pattern: str
    description: str = ""
    compiled: re.Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        try:
            self.compiled = re.compile(self.pattern, re.IGNORECASE)
        except re.error as exc:  # pragma: no cover - exercised via tests
            raise PolicyError(f"Rule {self.id} has an invalid regex: {exc}") from exc


class Policy:
    def __init__(self, raw: dict[str, Any], source: str = "<policy>") -> None:
        self.raw = raw
        self.source = source
        self.version: str = str(raw["version"])
        self.thresholds: dict[str, Any] = raw["thresholds"]
        self.budgets: dict[str, Any] = raw["budgets"]
        self.tools: dict[str, Any] = raw["tools"]
        self.egress: dict[str, Any] = raw["egress"]
        self.pii: dict[str, Any] = raw["pii"]
        self.logging: dict[str, Any] = raw["logging"]
        self.rules: list[Rule] = [Rule(**r) for r in raw["rules"]]
        self._validate_internal_consistency()

    def _validate_internal_consistency(self) -> None:
        if self.thresholds["injection_low"] >= self.thresholds["injection_high"]:
            raise PolicyError("injection_low must be below injection_high")
        if self.thresholds["session_safe"] >= self.thresholds["session_lock"]:
            raise PolicyError("session_safe must be below session_lock")
        if self.budgets["total_gateway_timeout_ms"] < self.budgets["checkpoint_timeout_ms"]:
            raise PolicyError("total gateway budget cannot be smaller than a checkpoint budget")
        codes = [r.reason_code for r in self.rules]
        if len(codes) != len(set(codes)):
            raise PolicyError("reason codes must be unique across rules")
        from .registry import is_registered

        for code in codes:
            if not is_registered(code):
                raise PolicyError(f"rule reason code {code} is not in the registry")
        for name, tool in self.tools.items():
            if "risk_tier" not in tool:
                raise PolicyError(f"tool {name} has no risk tier")
            for code in tool.get("reason_codes", []):
                if not is_registered(code):
                    raise PolicyError(f"tool {name} references unknown reason code {code}")

    def t(self, key: str, default: Any = None) -> Any:
        return self.thresholds.get(key, default)

    def b(self, key: str, default: Any = None) -> Any:
        return self.budgets.get(key, default)

    def tool(self, name: str) -> dict[str, Any] | None:
        return self.tools.get(name)

    def activate(self) -> None:
        policy_version_var.set(self.version)


_current: Policy | None = None
_lock = threading.Lock()


def load_policy(path: str | Path | None = None, schema_path: str | Path | None = None) -> Policy:
    """Validate and return a Policy. Raises PolicyError on any problem."""
    from ..config import get_settings

    settings = get_settings()
    policy_file = Path(path or settings.policy_path)
    schema_file = Path(schema_path or settings.policy_schema_path)
    if not policy_file.exists():
        raise PolicyError(f"policy file not found: {policy_file}")
    raw = yaml.safe_load(policy_file.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise PolicyError("policy file must contain a YAML mapping")
    if schema_file.exists():
        schema = json.loads(schema_file.read_text(encoding="utf-8"))
        try:
            jsonschema.validate(raw, schema)
        except jsonschema.ValidationError as exc:
            raise PolicyError(f"policy schema validation failed: {exc.message}") from exc
    return Policy(raw, source=str(policy_file))


def get_policy() -> Policy:
    global _current
    if _current is None:
        with _lock:
            if _current is None:
                _current = load_policy()
                _current.activate()
    return _current


def set_policy(policy: Policy | None) -> None:
    global _current
    with _lock:
        _current = policy
    if policy is not None:
        policy.activate()
