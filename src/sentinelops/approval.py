"""Human-in-the-loop approval queue (PDR 6.3.1, 6.6).

High-risk calls wait here. No response means deny: a pending call is never
executed by the agent, so silence is safe by construction.
"""
from __future__ import annotations

import json
import threading
from datetime import datetime, timezone


class ApprovalStore:
    def __init__(self, db) -> None:
        self.db = db
        self._lock = threading.Lock()

    def enqueue(self, tenant_id: int, session_id: str, tool: str, params: dict, reason_codes: list[str]) -> int:
        with self._lock:
            cur = self.db.conn.execute(
                "INSERT INTO approvals (tenant_id, session_id, tool, params_json, status, reason, created_at) VALUES (?,?,?,?,?,?,?)",
                (tenant_id, session_id, tool, json.dumps(params), "pending", ",".join(reason_codes), datetime.now(timezone.utc).isoformat()),
            )
            self.db.conn.commit()
            return int(cur.lastrowid)

    def list(self, tenant_id: int | None = None, status: str = "pending") -> list[dict]:
        if tenant_id is None:
            rows = self.db.rows("SELECT * FROM approvals WHERE status = ? ORDER BY id", (status,))
        else:
            rows = self.db.rows("SELECT * FROM approvals WHERE status = ? AND tenant_id = ? ORDER BY id", (status, tenant_id))
        for row in rows:
            row["params"] = json.loads(row["params_json"])
        return rows

    def get(self, approval_id: int) -> dict | None:
        row = self.db.one("SELECT * FROM approvals WHERE id = ?", (approval_id,))
        if row:
            row["params"] = json.loads(row["params_json"])
        return row

    def decide(self, approval_id: int, decision: str, reviewer: str, reason: str = "") -> dict | None:
        if decision not in {"approved", "rejected"}:
            raise ValueError("decision must be approved or rejected")
        with self._lock:
            self.db.execute(
                "UPDATE approvals SET status = ?, reason = ? WHERE id = ? AND status = 'pending'",
                (decision, f"{reviewer}: {reason}".strip(), approval_id),
            )
        return self.get(approval_id)

    def is_approved(self, approval_id: int, tenant_id: int) -> bool:
        row = self.db.one("SELECT status FROM approvals WHERE id = ? AND tenant_id = ?", (approval_id, tenant_id))
        return bool(row and row["status"] == "approved")
