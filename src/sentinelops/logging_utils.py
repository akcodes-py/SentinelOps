"""Structured JSON logging, reason codes and request correlation (PDR 6.4).

Every line carries the request id and the policy version so a decision can be
traced back to the exact rules that made it.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
policy_version_var: ContextVar[str] = ContextVar("policy_version", default="-")
tenant_var: ContextVar[str] = ContextVar("tenant", default="-")

_lock = threading.Lock()


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def emit(event: str, **fields: Any) -> dict[str, Any]:
    """Write one structured log line and return it (useful for tests)."""
    record: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "request_id": request_id_var.get(),
        "policy_version": policy_version_var.get(),
        "tenant": tenant_var.get(),
    }
    record.update(fields)
    line = json.dumps(record, default=str, sort_keys=True)
    print(line, flush=True)
    path = Path(_log_path())
    if path.parent.exists():
        try:
            with _lock:
                with path.open("a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
        except OSError:
            pass
    return record


_LOG_PATH = ""


def _log_path() -> str:
    return _LOG_PATH


def configure_logging(path: str) -> None:
    global _LOG_PATH
    _LOG_PATH = path
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)


def decision(
    checkpoint: str,
    action: str,
    reason_code: str,
    detail: str = "",
    **extra: Any,
) -> dict[str, Any]:
    """Log a guardrail decision. Reason code is only ever internal."""
    return emit(
        "guardrail_decision",
        checkpoint=checkpoint,
        action=action,
        reason_code=reason_code,
        detail=detail,
        **extra,
    )


def log_tool_call(name: str, params: dict[str, Any], outcome: str, reason_code: str = "") -> None:
    emit("tool_call", tool=name, params=params, outcome=outcome, reason_code=reason_code)


def log_rate_limit(key: str, allowed: bool) -> None:
    emit("rate_limit", key=key, allowed=allowed)


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)
