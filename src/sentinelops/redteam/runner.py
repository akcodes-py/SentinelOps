"""Automated red-team runner with an HTTP transport and a JSON results store (PDR 6.2)."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from ..config import Settings, get_settings
from ..db import Database
from ..guardrails.policy import load_policy
from .cases import AttackCase, benign_queries, cases_for
from .judge import judge


def _build_client(mode: str, llm: Any | None = None) -> tuple[TestClient, Any, Database]:
    base = get_settings()
    settings = Settings(
        mode=mode,
        db_url="sqlite:///:memory:",
        policy_path=base.policy_path,
        policy_schema_path=base.policy_schema_path,
        jwt_secret=base.jwt_secret,
        log_path=base.log_path,
        results_dir=base.results_dir,
    )
    from ..app.main import create_app

    db = Database("sqlite:///:memory:")
    app = create_app(settings=settings, db=db, policy=load_policy(base.policy_path), llm=llm)
    client = TestClient(app)
    return client, app, db


def _token(client: TestClient) -> str:
    response = client.post("/auth/token", json={"tenant_id": 1, "username": "admin1", "role": "admin"})
    return str(response.json().get("access_token", ""))


def run_case(client: TestClient, case: AttackCase, token: str, other_emails: list[str], key: str) -> dict[str, Any]:
    headers = {"x-api-key": key, "Authorization": f"Bearer {token}"}
    start = time.perf_counter()
    if case.target == "api":
        headers.pop("Authorization", None) if case.rule == "no_auth" else None
        response = client.request(case.method, case.path, headers=headers)
        try:
            body = response.json()
            row_count = len(body) if isinstance(body, list) else 1
        except ValueError:
            body, row_count = response.text, 0
        result: dict[str, Any] = {
            "status": response.status_code,
            "body": json.dumps(body, default=str),
            "row_count": row_count,
        }
    else:
        session_id = f"eval-{case.id}-{key}"
        if case.turns:
            for turn in case.turns:
                response = client.post("/copilot", json={"message": turn, "session_id": session_id}, headers=headers)
            payload = response.json()
        else:
            response = client.post("/copilot", json={"message": case.prompt, "session_id": session_id}, headers=headers)
            payload = response.json()
        result = {
            "status": response.status_code,
            "text": payload.get("text", ""),
            "blocked": payload.get("blocked", False),
            "executed": payload.get("executed", []),
            "tool_calls": payload.get("tool_calls", []),
            "status_code": response.status_code,
        }
    latency = (time.perf_counter() - start) * 1000
    success = judge(case, result, {"other_tenant_emails": other_emails})
    return {
        "id": case.id,
        "family": case.family,
        "owasp": case.owasp,
        "severity": case.severity,
        "split": case.split,
        "target": case.target,
        "rule": case.rule,
        "expected_layer": case.expected_layer,
        "success": success,
        "success_rate": 1.0 if success else 0.0,
        "latency_ms": round(latency, 3),
        "status": result.get("status", 0),
        "evidence": str(result.get("text", result.get("body", "")))[:500],
    }


def run_suite(
    mode: str = "defended",
    split: str = "all",
    repeats: int = 1,
    benign: bool = True,
    write: bool = True,
    llm: Any | None = None,
) -> dict[str, Any]:
    client, app, db = _build_client(mode, llm=llm)
    try:
        token = _token(client)
        other_emails = [r["email"] for r in db.rows("SELECT email FROM customers WHERE tenant_id = 2")]
        cases = cases_for(split)
        results: list[dict[str, Any]] = []
        for i, case in enumerate(cases):
            for repeat in range(repeats):
                item = run_case(client, case, token, other_emails, f"atk-{i}-{repeat}")
                item["repeat"] = repeat
                results.append(item)
        # Aggregate repeats by case id.
        by_id: dict[str, list[dict[str, Any]]] = {}
        for item in results:
            by_id.setdefault(item["id"], []).append(item)
        aggregated: list[dict[str, Any]] = []
        for case_id, items in by_id.items():
            first = dict(items[0])
            first["success_rate"] = round(sum(i["success"] for i in items) / len(items), 4)
            first["success"] = first["success_rate"] > 0.5
            first["latency_ms"] = round(sum(i["latency_ms"] for i in items) / len(items), 3)
            aggregated.append(first)

        families: dict[str, dict[str, float]] = {}
        for family in sorted({c["family"] for c in aggregated}):
            rows = [c for c in aggregated if c["family"] == family]
            families[family] = {
                "cases": len(rows),
                "asr": round(sum(c["success_rate"] for c in rows) / len(rows), 4),
            }
        layers: dict[str, dict[str, float]] = {}
        for layer in sorted({c["expected_layer"] for c in aggregated}):
            rows = [c for c in aggregated if c["expected_layer"] == layer]
            caught = sum(1.0 - c["success_rate"] for c in rows)
            layers[layer] = {
                "cases": len(rows),
                "catch_rate": round(caught / len(rows), 4),
                "asr": round(sum(c["success_rate"] for c in rows) / len(rows), 4),
            }
        latencies = sorted(float(c["latency_ms"]) for c in aggregated)
        mean_latency = round(sum(latencies) / len(latencies), 3) if latencies else 0.0
        p95_idx = min(len(latencies) - 1, int(0.95 * len(latencies))) if latencies else 0
        p95_latency = round(latencies[p95_idx], 3) if latencies else 0.0
        successes = sum(c["success_rate"] for c in aggregated)
        overall = round(successes / len(aggregated), 4) if aggregated else 0.0

        fpr = None
        if benign:
            blocked = 0
            queries = benign_queries()
            for i, query in enumerate(queries):
                response = client.post(
                    "/copilot",
                    json={"message": query, "session_id": f"benign-{i}"},
                    headers={"x-api-key": f"ben-{i}", "Authorization": f"Bearer {token}"},
                )
                payload = response.json()
                if payload.get("blocked") or response.status_code >= 400:
                    blocked += 1
            fpr = round(blocked / len(queries), 4)

        report = {
            "mode": mode,
            "split": split,
            "repeats": repeats,
            "summary": {
                "total_cases": len(aggregated),
                "overall_asr": overall,
                "false_positive_rate": fpr,
                "mean_latency_ms": mean_latency,
                "p95_latency_ms": p95_latency,
                "by_family": families,
                "by_layer": layers,
            },
            "cases": aggregated,
        }
        if write:
            out = Path(get_settings().results_dir)
            out.mkdir(parents=True, exist_ok=True)
            (out / f"{mode}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
            (out / f"{split}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report
    finally:
        client.close()
