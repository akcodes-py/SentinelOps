"""Structured JSON logging, reason codes and request correlation (PDR 6.4).

Every line carries the request id and the policy version so a decision can be
traced back to the exact rules that made it.
"""
from __future__ import annotations

import json
import threading
import time
import uuid
from collections import deque
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
policy_version_var: ContextVar[str] = ContextVar("policy_version", default="-")
tenant_var: ContextVar[str] = ContextVar("tenant", default="-")

_lock = threading.Lock()
_ALERTS: deque[dict[str, Any]] = deque(maxlen=200)
_ALERT_WEBHOOK = ""


def configure_alerting(webhook_url: str) -> None:
    global _ALERT_WEBHOOK
    _ALERT_WEBHOOK = webhook_url.strip()


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
    record = emit(
        "guardrail_decision",
        checkpoint=checkpoint,
        action=action,
        reason_code=reason_code,
        detail=detail,
        **extra,
    )
    if action in {"block", "review", "quarantine"}:
        alert("high" if action == "block" else "medium", reason_code, detail, checkpoint=checkpoint, action=action)
    return record


def alert(severity: str, reason_code: str, detail: str = "", **extra: Any) -> dict[str, Any]:
    """Record a security alert for blocked or flagged requests."""
    entry = emit(
        "security_alert",
        severity=severity,
        reason_code=reason_code,
        detail=detail,
        **extra,
    )
    with _lock:
        _ALERTS.append(entry)
    if _ALERT_WEBHOOK:
        try:
            import httpx

            httpx.post(_ALERT_WEBHOOK, json=entry, timeout=1.0)
        except Exception:
            pass
    return entry


def get_alerts(limit: int = 50) -> list[dict[str, Any]]:
    with _lock:
        return list(_ALERTS)[-limit:]


def log_tool_call(name: str, params: dict[str, Any], outcome: str, reason_code: str = "") -> None:
    emit("tool_call", tool=name, params=params, outcome=outcome, reason_code=reason_code)


def log_rate_limit(key: str, allowed: bool) -> None:
    emit("rate_limit", key=key, allowed=allowed)


def elapsed_ms(start: float) -> float:
    return round((time.perf_counter() - start) * 1000, 3)
