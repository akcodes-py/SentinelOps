"""SQLite data layer with a Postgres-compatible schema (PDR 4, 5, 9).

The core slice uses SQLite so the whole project runs offline. Swapping to
PostgreSQL is a connection-string change; the SQL uses only common syntax.
"""
from __future__ import annotations

import random
import re
import sqlite3
import threading
from pathlib import Path
from typing import Any

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenants (
    id INTEGER PRIMARY KEY, name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, username TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL, api_key TEXT UNIQUE NOT NULL
);
CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, name TEXT NOT NULL,
    email TEXT NOT NULL, phone TEXT NOT NULL, address TEXT NOT NULL,
    bank_like TEXT NOT NULL, ssn_like TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, customer_id INTEGER NOT NULL,
    amount REAL NOT NULL, status TEXT NOT NULL, doc_ref TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS pickups (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, customer_id INTEGER NOT NULL,
    material TEXT NOT NULL, scheduled TEXT NOT NULL, status TEXT NOT NULL, vehicle_id TEXT
);
CREATE TABLE IF NOT EXISTS materials (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, name TEXT NOT NULL, category TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS documents (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, title TEXT NOT NULL,
    content TEXT NOT NULL, trust TEXT NOT NULL, source TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals (
    id INTEGER PRIMARY KEY, tenant_id INTEGER NOT NULL, session_id TEXT NOT NULL,
    tool TEXT NOT NULL, params_json TEXT NOT NULL, status TEXT NOT NULL,
    reason TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY, mode TEXT NOT NULL, attack_id TEXT NOT NULL,
    category TEXT NOT NULL, owasp TEXT NOT NULL, severity TEXT NOT NULL,
    evidence TEXT NOT NULL, status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS guard_decisions (
    id INTEGER PRIMARY KEY, request_id TEXT, session_id TEXT, checkpoint TEXT,
    action TEXT, reason_code TEXT, detail TEXT, policy_version TEXT, ts TEXT
);
"""

TENANT_TABLES = {"customers", "invoices", "pickups", "materials", "documents"}
_FIRST = ["Aarav", "Priya", "Rohan", "Meera", "Vikram", "Ananya", "Kabir", "Diya"]
_LAST = ["Sharma", "Verma", "Gupta", "Mehta", "Iyer", "Nair", "Reddy", "Khan"]
_MATERIALS = ["plastic", "paper", "glass", "metal", "organic", "electronic"]
_STATUS = ["open", "scheduled", "completed", "delayed"]


class Database:
    def __init__(self, url: str = "sqlite:///:memory:") -> None:
        self.url = url
        path = url.replace("sqlite:///", "", 1)
        if path in ("", ":memory:"):
            path = ":memory:"
        else:
            p = Path(path)
            p.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self.conn.executescript(SCHEMA)
            self.conn.commit()
        self.seeded = False

    def close(self) -> None:
        with self._lock:
            self.conn.close()

    # -- synthetic data ---------------------------------------------------
    def seed(self, seed: int = 42, tenants: int = 2, per_tenant: int = 4) -> None:
        """Load deterministic synthetic data. No real personal data is used."""
        rng = random.Random(seed)
        with self._lock:
            if self.seeded:
                return
            if self.conn.execute("SELECT COUNT(*) FROM customers").fetchone()[0] > 0:
                self.seeded = True
                return
            self.seeded = True
            for t in range(1, tenants + 1):
                self.conn.execute("INSERT OR IGNORE INTO tenants VALUES (?, ?)", (t, f"tenant-{t}"))
                for role, api_key in [
                    ("admin", f"key-admin-{t}"),
                    ("analyst", f"key-analyst-{t}"),
                    ("viewer", f"key-viewer-{t}"),
                ]:
                    self.conn.execute(
                        "INSERT OR IGNORE INTO users (tenant_id, username, role, api_key) VALUES (?,?,?,?)",
                        (t, f"{role}{t}", role, api_key),
                    )
                for m_idx, name in enumerate(_MATERIALS, 1):
                    self.conn.execute(
                        "INSERT INTO materials (tenant_id, name, category) VALUES (?,?,?)",
                        (t, name, "recyclable" if m_idx % 2 else "general"),
                    )
                for c in range(1, per_tenant + 1):
                    cid = (t - 1) * 100 + c
                    first, last = rng.choice(_FIRST), rng.choice(_LAST)
                    name = f"{first} {last}"
                    email = f"{first.lower()}.{last.lower()}@acme-recycling.example"
                    phone = f"+91 98{c:02d} {rng.randint(100,999)} {rng.randint(1000,9999)}"
                    bank = f"GB{rng.randint(10,99)}NWBK{rng.randint(100000,999999)}"
                    ssn = f"{rng.randint(100,999)}-{rng.randint(10,99)}-{rng.randint(1000,9999)}"
                    self.conn.execute(
                        "INSERT INTO customers VALUES (?,?,?,?,?,?,?,?)",
                        (cid, t, name, email, phone, f"{rng.randint(1,99)} {last} Street", bank, ssn),
                    )
                    for i in range(1, 3):
                        inv = cid * 10 + i
                        self.conn.execute(
                            "INSERT INTO invoices VALUES (?,?,?,?,?,?)",
                            (inv, t, cid, round(rng.uniform(50, 5000), 2), rng.choice(_STATUS), f"INV-{inv:04d}"),
                        )
                    for p in range(1, 3):
                        pk = cid * 10 + p
                        self.conn.execute(
                            "INSERT INTO pickups VALUES (?,?,?,?,?,?,?)",
                            (pk, t, cid, rng.choice(_MATERIALS), f"2026-11-{20+p:02d}", rng.choice(_STATUS), f"V-{rng.randint(1,3)}"),
                        )
                    self.conn.execute(
                        "INSERT INTO documents VALUES (?,?,?,?,?,?)",
                        (cid, t, f"Client email {name}", f"Routine pickup and invoice correspondence for {name}.", "high", "client_email"),
                    )
            # Benign SOP documents.
            for t in range(1, tenants + 1):
                self.conn.execute(
                    "INSERT INTO documents VALUES (?,?,?,?,?,?)",
                    (900 + t, t, "Pickup SOP", "Standard procedure: verify the pickup ID, confirm the material and assign a vehicle. Do not share customer data externally.", "high", "sop"),
                )
                self.conn.execute(
                    "INSERT INTO documents VALUES (?,?,?,?,?,?)",
                    (910 + t, t, "Compliance guide", "Invoices must be retained for 30 days. Customer records are tenant scoped.", "high", "compliance"),
                )
            self.conn.commit()

    # -- query helpers ----------------------------------------------------
    def rows(self, sql: str, params: tuple | list = ()) -> list[dict[str, Any]]:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            return [dict(r) for r in cur.fetchall()]

    def one(self, sql: str, params: tuple | list = ()) -> dict[str, Any] | None:
        rows = self.rows(sql, params)
        return rows[0] if rows else None

    def execute(self, sql: str, params: tuple | list = ()) -> None:
        with self._lock:
            self.conn.execute(sql, tuple(params))
            self.conn.commit()

    def scalar(self, sql: str, params: tuple | list = ()) -> Any:
        with self._lock:
            cur = self.conn.execute(sql, tuple(params))
            row = cur.fetchone()
            return row[0] if row else None

    # -- the two modes of agent database access ---------------------------
    def query_for_agent(self, sql: str, tenant_id: int, defended: bool, max_rows: int = 50) -> list[dict[str, Any]]:
        """Baseline executes arbitrary SQL; defended adds a tenant backstop."""
        if not defended:
            return self.rows(sql)
        statement = sql.strip().rstrip(";")
        table = _first_table(statement)
        if table in TENANT_TABLES and not re.search(r"\btenant_id\b", statement, re.I):
            clause = "WHERE" if not re.search(r"\bWHERE\b", statement, re.I) else "AND"
            statement = f"{statement} {clause} tenant_id = ?"
        if not re.search(r"\bLIMIT\b", statement, re.I):
            statement = f"{statement} LIMIT {int(max_rows)}"
        return self.rows(statement, (tenant_id,) if "tenant_id = ?" in statement else ())


def _first_table(sql: str) -> str:
    m = re.search(r"\b(?:FROM|JOIN|UPDATE|INTO)\s+([A-Za-z_][A-Za-z0-9_]*)", sql, re.I)
    return m.group(1).lower() if m else ""
