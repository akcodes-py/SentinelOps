"""SentinelOps FastAPI application — the security gateway and business APIs."""
from __future__ import annotations

from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from ..agent.agent import Agent
from ..approval import ApprovalStore
from ..auth import AuthError, Principal, authenticate, create_token
from ..config import Settings, get_settings
from ..db import Database
from ..guardrails.policy import Policy, get_policy, set_policy
from ..guardrails.registry import checkpoint_for
from ..guardrails.session import SessionStore
from ..logging_utils import (
    configure_alerting,
    configure_logging,
    decision,
    elapsed_ms,
    emit,
    new_request_id,
    policy_version_var,
    request_id_var,
    tenant_var,
)
from ..rate_limit import TokenBucketLimiter
from ..vectorstore import VectorStore

APP_STATE: dict[str, Any] = {}


class CopilotRequest(BaseModel):
    message: str
    session_id: str = "anonymous"


class TokenRequest(BaseModel):
    tenant_id: int = 1
    username: str = "admin1"
    role: str = "admin"


class ApprovalDecision(BaseModel):
    reviewer: str = "reviewer"
    reason: str = ""


def create_app(settings: Settings | None = None, db: Database | None = None, policy: Policy | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_path)
    configure_alerting(settings.alert_webhook)
    active_policy = policy or get_policy()
    set_policy(active_policy)
    database = db or Database(settings.db_url)
    database.seed()
    state = {
        "settings": settings,
        "db": database,
        "policy": active_policy,
        "vector": VectorStore(),
        "approvals": ApprovalStore(database),
        "sessions": SessionStore(
            safe=int(active_policy.t("session_safe", 6)),
            lock_at=int(active_policy.t("session_lock", 12)),
            decay=float(active_policy.t("session_decay_per_minute", 1.0)),
            window=int(active_policy.t("window_turns", 4)),
        ),
        "limiter": TokenBucketLimiter(),
        "agent": None,
    }
    state["agent"] = Agent(
        db=database,
        vector=state["vector"],
        policy=active_policy,
        approvals=state["approvals"],
        sessions=state["sessions"],
        defended=settings.is_defended,
        pii_backend=settings.pii_backend,
    )
    APP_STATE.update(state)

    app = FastAPI(title="SentinelOps", version="1.0.0", description="Secure AI control plane reference implementation")
    app.state.sentinel = state

    @app.exception_handler(AuthError)
    async def auth_error_handler(request: Request, exc: AuthError) -> JSONResponse:
        return JSONResponse(status_code=401, content={"detail": str(exc)})

    @app.middleware("http")
    async def gateway_middleware(request: Request, call_next):
        start = __import__("time").perf_counter()
        rid = new_request_id()
        token = request_id_var.set(rid)
        policy_token = policy_version_var.set(active_policy.version)
        try:
            body_size = int(request.headers.get("content-length", "0") or 0)
            max_chars = int(active_policy.t("max_input_chars", 8000))
            if settings.is_defended and body_size > max_chars * 8:
                decision("gateway", "block", "INPUT_TRUNCATED", "request body too large")
                return JSONResponse(status_code=413, content={"detail": "request too large"})

            if settings.is_defended:
                if settings.require_https:
                    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip().lower()
                    if proto != "https":
                        decision("gateway", "block", "TENANT_MISMATCH", "https required for token and api traffic")
                        return JSONResponse(status_code=403, content={"detail": "HTTPS required"})
                client_ip = _client_ip(request, settings.trusted_proxy_set)
                api_key = request.headers.get("x-api-key", client_ip)
                if not state["limiter"].allow(f"{api_key}|{client_ip}"):
                    from ..logging_utils import log_rate_limit

                    log_rate_limit(api_key, False)
                    return JSONResponse(status_code=429, content={"detail": "rate limit exceeded"})
            response = await call_next(request)
            response.headers["X-Request-ID"] = rid
            response.headers["X-Policy-Version"] = active_policy.version
            if settings.is_defended:
                response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
            emit("http_request", method=request.method, path=request.url.path, status=response.status_code, latency_ms=elapsed_ms(start))
            return response
        finally:
            request_id_var.reset(token)
            policy_version_var.reset(policy_token)

    def principal(request: Request, authorization: str | None = Header(default=None)) -> Principal:
        return authenticate(authorization, settings.jwt_secret, settings.is_defended, database)

    @app.get("/ui", response_class=HTMLResponse, include_in_schema=False)
    def web_ui() -> str:
        from .ui import UI_HTML

        return UI_HTML

    @app.get("/health")
    def health() -> dict[str, str]:
        return {"status": "ok", "mode": settings.mode, "policy": active_policy.version}

    @app.post("/auth/token")
    def token(req: TokenRequest) -> dict[str, str]:
        return {
            "access_token": create_token(req.tenant_id, req.username, req.role, settings.jwt_secret, settings.jwt_expiry_minutes),
            "token_type": "bearer",
        }

    @app.post("/copilot")
    def copilot(req: CopilotRequest, p: Principal = Depends(principal)) -> dict[str, Any]:
        tenant_token = tenant_var.set(str(p.tenant_id))
        try:
            result = state["agent"].run(req.message, p.tenant_id, p.role, req.session_id)
        finally:
            tenant_var.reset(tenant_token)
        for d in result.decisions:
            database.execute(
                "INSERT INTO guard_decisions (request_id, session_id, checkpoint, action, reason_code, detail, policy_version, ts) VALUES (?,?,?,?,?,?,?,?)",
                (
                    request_id_var.get(),
                    req.session_id,
                    checkpoint_for(d.reason_code),
                    d.action,
                    d.reason_code,
                    d.detail,
                    active_policy.version,
                    __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
                ),
            )
        return {
            "text": result.text,
            "blocked": result.blocked,
            "safe_mode": result.safe_mode,
            "tool_calls": result.tool_calls,
            "executed": result.executed,
            "approval_ids": result.approval_ids,
        }

    # -- business APIs ----------------------------------------------------
    @app.get("/customers/{customer_id}")
    def get_customer(customer_id: str, p: Principal = Depends(principal)) -> Any:
        if settings.is_defended:
            if not customer_id.isdigit():
                raise HTTPException(404, "not found")
            row = database.one("SELECT * FROM customers WHERE id = ? AND tenant_id = ?", (int(customer_id), p.tenant_id))
        else:
            # Intentional BOLA/SQLi flaw: no tenant check, string-built SQL.
            rows = database.rows(f"SELECT * FROM customers WHERE id = {customer_id}")
            row = rows if len(rows) > 1 else (rows[0] if rows else None)
        if not row:
            raise HTTPException(404, "not found")
        return row

    @app.get("/invoices/{invoice_id}")
    def get_invoice(invoice_id: str, p: Principal = Depends(principal)) -> Any:
        if settings.is_defended:
            if not invoice_id.isdigit():
                raise HTTPException(404, "not found")
            row = database.one("SELECT * FROM invoices WHERE id = ? AND tenant_id = ?", (int(invoice_id), p.tenant_id))
        else:
            rows = database.rows(f"SELECT * FROM invoices WHERE id = {invoice_id}")
            row = rows if len(rows) > 1 else (rows[0] if rows else None)
        if not row:
            raise HTTPException(404, "not found")
        return row

    @app.get("/pickups/{pickup_id}")
    def get_pickup(pickup_id: str, p: Principal = Depends(principal)) -> Any:
        if settings.is_defended:
            if not pickup_id.isdigit():
                raise HTTPException(404, "not found")
            row = database.one("SELECT * FROM pickups WHERE id = ? AND tenant_id = ?", (int(pickup_id), p.tenant_id))
        else:
            rows = database.rows(f"SELECT * FROM pickups WHERE id = {pickup_id}")
            row = rows if len(rows) > 1 else (rows[0] if rows else None)
        if not row:
            raise HTTPException(404, "not found")
        return row

    # -- approval queue ---------------------------------------------------
    @app.get("/approvals")
    def list_approvals(p: Principal = Depends(principal)) -> list[dict[str, Any]]:
        if settings.is_defended and not p.has_role("analyst"):
            raise HTTPException(403, "reviewer role required")
        return state["approvals"].list(p.tenant_id if settings.is_defended else None)

    @app.post("/approvals/{approval_id}/approve")
    def approve(approval_id: int, body: ApprovalDecision, p: Principal = Depends(principal)) -> dict[str, Any]:
        row = state["approvals"].decide(approval_id, "approved", body.reviewer or p.username, body.reason)
        if not row:
            raise HTTPException(404, "not found")
        return row

    @app.post("/approvals/{approval_id}/reject")
    def reject(approval_id: int, body: ApprovalDecision, p: Principal = Depends(principal)) -> dict[str, Any]:
        row = state["approvals"].decide(approval_id, "rejected", body.reviewer or p.username, body.reason)
        if not row:
            raise HTTPException(404, "not found")
        return row

    # -- internal reporting endpoints ------------------------------------
    @app.get("/reports/vulnerability")
    def vulnerability_report(p: Principal = Depends(principal)) -> dict[str, Any]:
        from ..reports import build_vulnerability_report

        return build_vulnerability_report(database, active_policy)

    @app.get("/reports/timeline")
    def timeline(session_id: str | None = None, p: Principal = Depends(principal)) -> list[dict[str, Any]]:
        from ..reports import build_timeline

        return build_timeline(database, session_id)

    @app.get("/reports/residual")
    def residual(p: Principal = Depends(principal)) -> dict[str, Any]:
        from ..reports import build_residual_risk

        return build_residual_risk(state["settings"].results_dir)

    @app.get("/reports/alerts")
    def security_alerts(limit: int = 50, p: Principal = Depends(principal)) -> list[dict[str, Any]]:
        from ..logging_utils import get_alerts

        return get_alerts(limit=limit)

    return app


def _client_ip(request: Request, trusted: set[str]) -> str:
    host = request.client.host if request.client else "unknown"
    forwarded = request.headers.get("x-forwarded-for", "").split(",")[0].strip()
    if forwarded and host in trusted:
        return forwarded
    return host


app = create_app()
