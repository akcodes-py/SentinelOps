"""The five guardrail checkpoints (PDR 6.3.1)."""
from __future__ import annotations

import difflib
import html
import re
from dataclasses import dataclass, field
from typing import Any, Callable
from urllib.parse import urlparse

from ..agent.prompts import CANARY_TOKEN, SYSTEM_PROMPT, build_prompt
from ..approval import ApprovalStore
from ..db import Database
from ..logging_utils import decision
from ..pii import mask as mask_pii
from . import classifier as injection_classifier
from .normalise import normalise
from .policy import Policy
from .session import SessionStore

_INSTRUCTION_IN_DOC = re.compile(
    r"(?i)(ignore (all )?(previous|prior|above)|you must|do not tell|print the system prompt|"
    r"send .* to @|render this image|bypass the guardrail|pretend you are)"
)
_SQL_COMMENT = re.compile(r"--[^\n]*|/\*.*?\*/", re.S)
# LLM08:2026 — hidden context (system prompt, policy.yaml, internal config).
_HIDDEN_CONTEXT = re.compile(
    r"(?i)(policy\.yaml|policy\.schema\.json|injection_low\s*[:=]|injection_high\s*[:=]|"
    r"allowed_tables\s*[:=]|reason_codes\s*[:=]|session_lock\s*[:=]|version\s*['\"]?\s*:\s*['\"]?2\.2)"
)


@dataclass
class Decision:
    action: str  # allow | block | mask | review | drop | quarantine
    reason_code: str
    detail: str = ""
    meta: dict[str, Any] = field(default_factory=dict)


def run_budgeted(fn: Callable[[], Any], timeout_ms: int) -> tuple[bool, Any]:
    """Run a checkpoint and enforce its wall-clock budget.

    The work is synchronous (no executor start-up cost charged to the request);
    exceeding the budget fails closed and discards the value.
    """
    import time

    start = time.perf_counter()
    value = fn()
    elapsed = (time.perf_counter() - start) * 1000
    if elapsed > timeout_ms:
        return False, None
    return True, value


class InputGate:
    """Checkpoint 1: length, normalisation, rules, classifier, session score."""

    def __init__(self, policy: Policy, sessions: SessionStore, model: Any = None) -> None:
        self.policy = policy
        self.sessions = sessions
        self.model = model or injection_classifier
        # Warm up outside the request budget: first-call model training must
        # never be charged to a request's checkpoint timeout.
        self.model.score("warmup")

    def check(self, text: str, session_id: str = "anonymous") -> Decision:
        timeout = int(self.policy.b("checkpoint_timeout_ms", 30))
        completed, result = run_budgeted(lambda: self._check(text, session_id), timeout)
        if not completed:
            decision("input_gate", "block", "GUARD_TIMEOUT", "input checkpoint exceeded its budget")
            return Decision("block", "GUARD_TIMEOUT", "input checkpoint timed out")
        return result

    def _check(self, text: str, session_id: str) -> Decision:
        max_chars = int(self.policy.t("max_input_chars", 8000))
        norm = normalise(
            text,
            max_depth=int(self.policy.b("max_normalise_depth", 3)),
            max_expansion=int(self.policy.b("max_normalise_expansion", 4)),
            max_chars=int(self.policy.b("classifier_max_chars", 4000)),
        )
        if len(text) > max_chars * 2:
            decision("input_gate", "block", "INPUT_TRUNCATED", f"input of {len(text)} chars rejected")
            return Decision("block", "INPUT_TRUNCATED", "input exceeds twice the length limit")
        if norm.truncated:
            decision("input_gate", "allow", "INPUT_TRUNCATED", "input truncated for scanning")

        window = self.sessions.window_text(session_id)
        combined = f"{window}\n{norm.text}".strip()

        matched = None
        for rule in self.policy.rules:
            if rule.compiled.search(combined):
                matched = rule
                break

        limit = int(self.policy.b("classifier_max_chars", 4000))
        score = float(self.model.score(combined[:limit]))

        points = 0.0
        if score >= float(self.policy.t("injection_low", 0.35)):
            points += 1.0
        if matched is not None:
            points += 3.0
        if "system prompt" in norm.text.lower():
            points += 1.0
        state = self.sessions.add_turn(session_id, norm.text, points)
        level = self.sessions.level(session_id)

        meta = {"score": score, "normalised": norm.text, "level": level, "session_score": state.score}

        if matched is not None:
            decision("input_gate", "block", matched.reason_code, matched.description, score=score)
            return Decision("block", matched.reason_code, matched.description, meta)
        if score >= float(self.policy.t("injection_high", 0.75)):
            decision("input_gate", "block", "INJ_CLS_HIGH", f"classifier score {score:.3f}", score=score)
            return Decision("block", "INJ_CLS_HIGH", "classifier score above high threshold", meta)
        if score >= float(self.policy.t("injection_low", 0.35)):
            decision("input_gate", "review", "INJ_CLS_MID", f"classifier score {score:.3f}", score=score)
            return Decision("review", "INJ_CLS_MID", "score between thresholds; safe mode", meta)
        if level != "normal":
            decision("input_gate", "block" if level == "locked" else "review", "SESSION_RISK", f"session level {level}", session_score=state.score)
            return Decision("block" if level == "locked" else "review", "SESSION_RISK", f"session level {level}", meta)
        decision("input_gate", "allow", "INJ_ALLOW", "clean input", score=score)
        return Decision("allow", "INJ_ALLOW", "clean input", meta)


class ContextGate:
    """Checkpoint 2: scan every retrieved chunk before prompt assembly."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def scan(self, chunks: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[Decision]]:
        kept: list[dict[str, Any]] = []
        decisions: list[Decision] = []
        for chunk in chunks[: int(self.policy.t("max_context_chunks", 5))]:
            text = chunk.get("content", "")
            trust = chunk.get("trust", "unknown")
            poisoned = bool(chunk.get("poisoned")) or trust == "low" or bool(_INSTRUCTION_IN_DOC.search(text))
            if poisoned:
                decisions.append(Decision("quarantine", "CTX_POISON", f"chunk {chunk.get('id')} contained instructions or low-trust content", {"chunk": chunk}))
                decision("context_gate", "quarantine", "CTX_POISON", f"chunk {chunk.get('id')} dropped")
            else:
                kept.append(chunk)
                decision("context_gate", "allow", "CTX_ALLOW", f"chunk {chunk.get('id')} accepted")
        return kept, decisions


class PromptHardening:
    """Checkpoint 3: preventive only — no decision is emitted."""

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def build(self, user_text: str, chunks: list[dict[str, Any]], safe_mode: bool = False) -> str:
        return build_prompt(user_text, chunks, safe_mode=safe_mode, defended=True)


class ToolGate:
    """Checkpoint 4: allowlist, schema, parameter rules, tenant scope, approval."""

    REQUIRED = {
        "query_db": {"query"},
        "search_docs": {"query"},
        "generate_report": {"report_type"},
        "send_email": {"recipient", "subject", "body"},
        "dispatch_vehicle": {"vehicle_id", "pickup_id"},
    }

    def __init__(self, policy: Policy, db: Database, approvals: ApprovalStore) -> None:
        self.policy = policy
        self.db = db
        self.approvals = approvals

    def _fail(self, code: str, detail: str, tool: str) -> Decision:
        decision("tool_gate", "block", code, detail, tool=tool)
        return Decision("block", code, detail, {"tool": tool})

    def check(self, tool: str, params: dict[str, Any], tenant_id: int, session_id: str, safe_mode: bool = False) -> Decision:
        cfg = self.policy.tool(tool)
        if cfg is None or not cfg.get("allowed", False) or safe_mode:
            return self._fail("TOOL_NOT_ALLOWED", f"tool {tool} not allowed (safe_mode={safe_mode})", tool)
        missing = self.REQUIRED.get(tool, set()) - set(params)
        if missing:
            return self._fail("TOOL_PARAM_INVALID", f"missing parameters: {sorted(missing)}", tool)
        if tool == "query_db":
            result = self._check_query(params["query"], tenant_id, tool)
        elif tool == "search_docs":
            target = int(params.get("tenant_id", tenant_id))
            result = None if target == tenant_id else self._fail("TENANT_MISMATCH", "cross-tenant retrieval", tool)
            if result is None:
                decision("tool_gate", "allow", "TOOL_ALLOW", "retrieval scoped to tenant")
                result = Decision("allow", "TOOL_ALLOW")
        elif tool == "generate_report":
            allowed = set(cfg.get("report_types", []))
            result = None if params["report_type"] in allowed else self._fail("TOOL_PARAM_INVALID", "report type outside allowlist", tool)
            if result is None:
                result = Decision("allow", "TOOL_ALLOW")
        elif tool == "send_email":
            result = self._check_email(params, tenant_id, cfg, tool)
        elif tool == "dispatch_vehicle":
            result = self._check_dispatch(params, tenant_id, session_id, cfg, tool)
        else:  # pragma: no cover - all tools covered above
            result = self._fail("TOOL_NOT_ALLOWED", "unknown tool", tool)
        if result.action != "allow":
            return result
        if cfg.get("approval_required", False):
            approval_id = self.approvals.enqueue(tenant_id, session_id, tool, params, cfg.get("reason_codes", []))
            decision("tool_gate", "review", "APPROVAL_PENDING", f"approval {approval_id} queued", tool=tool, approval_id=approval_id)
            return Decision("review", "APPROVAL_PENDING", "high-risk call queued for approval", {"approval_id": approval_id, "tool": tool})
        decision("tool_gate", "allow", "TOOL_ALLOW", f"tool {tool} allowed")
        return Decision("allow", "TOOL_ALLOW", "tool allowed", {"tool": tool})

    def _check_query(self, sql: str, tenant_id: int, tool: str) -> Decision:
        cleaned = _SQL_COMMENT.sub(" ", sql).strip().rstrip(";")
        statements = [s for s in cleaned.split(";") if s.strip()]
        if len(statements) != 1:
            return self._fail("SQL_NOT_SELECT", "expected exactly one statement", tool)
        statement = statements[0].strip()
        first = re.match(r"[A-Za-z]+", statement)
        if not first or first.group(0).upper() != "SELECT":
            return self._fail("SQL_NOT_SELECT", "only SELECT statements are permitted", tool)
        tables = re.findall(r"(?i)\b(?:FROM|JOIN)\s+([A-Za-z_][A-Za-z0-9_]*)", statement)
        allowed = set((self.policy.tool("query_db") or {}).get("allowed_tables", []))
        for table in tables:
            if table.lower() not in allowed:
                return self._fail("TABLE_NOT_ALLOWED", f"table {table} not on allowlist", tool)
        forced = re.findall(r"(?i)\btenant_id\s*=\s*(\d+)", statement)
        if any(int(v) != tenant_id for v in forced):
            return self._fail("TENANT_MISMATCH", "query requests another tenant", tool)
        return Decision("allow", "TOOL_ALLOW")

    def _check_email(self, params: dict, tenant_id: int, cfg: dict, tool: str) -> Decision:
        recipients = [r.strip() for r in str(params["recipient"]).split(",") if r.strip()]
        if len(recipients) > int(cfg.get("max_recipients", 5)):
            return self._fail("TOOL_PARAM_INVALID", "too many recipients", tool)
        domains = set(cfg.get("allowed_domains", []))
        valid = set()
        for recipient in recipients:
            domain = recipient.split("@")[-1].lower() if "@" in recipient else ""
            exists = self.db.one("SELECT id FROM customers WHERE tenant_id = ? AND email = ?", (tenant_id, recipient))
            if domain not in domains or exists is None:
                return self._fail("RECIPIENT_DOMAIN", f"recipient {recipient} outside allowlist or tenant records", tool)
            valid.add(recipient)
        return Decision("allow", "TOOL_ALLOW", meta={"recipients": sorted(valid)})

    def _check_dispatch(self, params: dict, tenant_id: int, session_id: str, cfg: dict, tool: str) -> Decision:
        vehicle = self.db.one("SELECT id FROM pickups WHERE tenant_id = ? AND vehicle_id = ?", (tenant_id, params.get("vehicle_id")))
        pickup = self.db.one("SELECT id FROM pickups WHERE tenant_id = ? AND id = ?", (tenant_id, params.get("pickup_id")))
        if vehicle is None or pickup is None:
            return self._fail("TOOL_PARAM_INVALID", "vehicle or pickup not found in tenant", tool)
        session_count = self.db.scalar("SELECT COUNT(*) FROM guard_decisions WHERE session_id = ? AND reason_code = 'DISPATCH_CAP'", (session_id,)) or 0
        hour_count = self.db.scalar("SELECT COUNT(*) FROM approvals WHERE tenant_id = ? AND tool = 'dispatch_vehicle'", (tenant_id,)) or 0
        if session_count >= int(cfg.get("cap_session", 2)) or hour_count >= int(cfg.get("cap_hour", 5)):
            decision("tool_gate", "block", "DISPATCH_CAP", "dispatch cap reached", tool=tool)
            return Decision("block", "DISPATCH_CAP", "dispatch cap reached", {"tool": tool})
        return Decision("allow", "TOOL_ALLOW")


def _url_allowed(url: str, policy: Policy) -> bool:
    parsed = urlparse(url)
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    if scheme not in set(policy.egress.get("allowed_schemes", [])):
        return False
    allowed = set(policy.egress.get("allowed_domains", []))
    return host in allowed or any(host.endswith("." + d) for d in allowed)


def sanitise_egress(text: str, policy: Policy) -> tuple[str, bool]:
    """Remove outbound links/images outside the allowlist. Returns (text, changed)."""
    original = text
    max_len = int(policy.egress.get("max_url_length", 200))

    def repl_link(m: re.Match[str]) -> str:
        label, url = m.group(1), m.group(2)
        return label if _url_allowed(url, policy) and len(url) <= max_len else label

    def repl_image(m: re.Match[str]) -> str:
        alt, url = m.group(1), m.group(2)
        return m.group(0) if _url_allowed(url, policy) and len(url) <= max_len else f"[image removed: {alt}]"

    text = re.sub(r"!\[([^\]]*)\]\(([^)]+)\)", repl_image, text)
    text = re.sub(r"(?<!!)\[([^\]]+)\]\(([^)]+)\)", repl_link, text)
    for url in re.findall(r"https?://[^\s<>)]+", text):
        if not _url_allowed(url, policy) or len(url) > max_len:
            text = text.replace(url, "[link removed]")
    text = html.escape(text, quote=False)
    return text, text != original


class OutputGate:
    """Checkpoint 5: canary, system-prompt similarity, PII and egress."""

    def __init__(self, policy: Policy, pii_backend: str = "regex") -> None:
        self.policy = policy
        self.pii_backend = pii_backend

    def check(self, text: str) -> tuple[str, list[Decision]]:
        decisions: list[Decision] = []
        if CANARY_TOKEN in text:
            decision("output_gate", "block", "CANARY_LEAK", "canary token found in output")
            return "[blocked]", [Decision("block", "CANARY_LEAK", "canary token found", {"text": "[blocked]"})]
        similarity = difflib.SequenceMatcher(None, text, SYSTEM_PROMPT).ratio()
        if similarity >= 0.62:
            decision("output_gate", "block", "SYSPROMPT_LEAK", f"similarity {similarity:.2f}")
            return "[blocked]", [Decision("block", "SYSPROMPT_LEAK", "output too similar to system prompt", {"text": "[blocked]"})]
        if _HIDDEN_CONTEXT.search(text):
            decision("output_gate", "block", "SYSPROMPT_LEAK", "hidden context or policy file content in output")
            return "[blocked]", [Decision("block", "SYSPROMPT_LEAK", "hidden context exposure blocked", {"text": "[blocked]"})]
        masked, found = mask_pii(
            text,
            backend=self.pii_backend,
            mask_char=self.policy.pii.get("mask_char", "*"),
            types=self.policy.pii.get("field_types"),
        )
        if found:
            decision("output_gate", "mask", "PII_MASKED", "masked: " + ",".join(sorted(set(found))))
            decisions.append(Decision("mask", "PII_MASKED", "sensitive value masked", {"text": masked}))
        cleaned, changed = sanitise_egress(masked, self.policy)
        if changed:
            decision("output_gate", "mask", "EGRESS_BLOCKED", "external URL or image removed")
            decisions.append(Decision("mask", "EGRESS_BLOCKED", "egress sanitised", {"text": cleaned}))
        if not decisions:
            decision("output_gate", "allow", "OUT_ALLOW", "clean output")
            return text, []
        return cleaned, decisions
