"""Incident timeline, vulnerability report and residual risk table (PDR 6.5, 6.3.10)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .guardrails.policy import Policy


def build_timeline(db, session_id: str | None = None) -> list[dict[str, Any]]:
    if session_id:
        rows = db.rows("SELECT * FROM guard_decisions WHERE session_id = ? ORDER BY id", (session_id,))
    else:
        rows = db.rows("SELECT * FROM guard_decisions ORDER BY id LIMIT 500")
    return [
        {
            "ts": r["ts"],
            "request_id": r["request_id"],
            "session_id": r["session_id"],
            "checkpoint": r["checkpoint"],
            "action": r["action"],
            "reason_code": r["reason_code"],
            "detail": r["detail"],
            "policy_version": r["policy_version"],
        }
        for r in rows
    ]


def build_vulnerability_report(db, policy: Policy) -> dict[str, Any]:
    findings = db.rows("SELECT * FROM findings ORDER BY id")
    items = [
        {
            "finding": f["attack_id"],
            "severity": f["severity"],
            "evidence": f["evidence"],
            "affected_component": f["category"],
            "owasp_mapping": f["owasp"],
            "remediation": "See guardrail design section 6.3 in the PDR",
            "before_status": "exploitable on baseline",
            "after_status": f["status"],
        }
        for f in findings
    ]
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "policy_version": policy.version,
        "finding_count": len(items),
        "findings": items,
    }


def build_residual_risk(results_dir: str | Path) -> dict[str, Any]:
    """Build the table from held-out and adaptive runs, not the development set."""
    directory = Path(results_dir)
    rows: list[dict[str, Any]] = []
    for name in ("held-out.json", "adaptive.json"):
        path = directory / name
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        for case in data.get("cases", []):
            rate = float(case.get("success_rate", 0))
            if rate > 0:
                rows.append(
                    {
                        "attack_case": case.get("id"),
                        "split": case.get("split", name.removesuffix(".json")),
                        "owasp_ref": case.get("owasp", ""),
                        "success_rate": rate,
                        "layer_that_should_have_caught": case.get("expected_layer", "output gate"),
                        "why_missed": case.get("why_missed", "see evaluation notes"),
                        "decision": case.get("decision", "scheduled for fix"),
                    }
                )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "complete": True,
        "rows": rows,
        "note": "Only held-out and adaptive cases with success rate above zero are listed.",
    }
