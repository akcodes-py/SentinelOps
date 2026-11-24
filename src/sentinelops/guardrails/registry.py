"""Single reason-code registry used by code, tests and reports (PDR 6.3.9)."""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Reason:
    code: str
    checkpoint: str
    meaning: str


REASON_CODES: dict[str, Reason] = {
    r.code: r
    for r in [
        Reason("INJ_RULE_nn", "Input gate", "A named rule pattern matched"),
        Reason("INJ_CLS_HIGH", "Input gate", "Classifier score above the high threshold; blocked"),
        Reason("INJ_CLS_MID", "Input gate", "Score between the thresholds; safe mode and review"),
        Reason("INPUT_TRUNCATED", "Input gate", "Input exceeded the length limit and was truncated or rejected"),
        Reason("SESSION_RISK", "Input gate", "Cumulative session score above a limit"),
        Reason("CTX_POISON", "Context gate", "Instruction found in a retrieved chunk; chunk dropped or quarantined"),
        Reason("TOOL_NOT_ALLOWED", "Tool gate", "Tool is not on the allowlist"),
        Reason("TOOL_PARAM_INVALID", "Tool gate", "Parameters failed schema validation"),
        Reason("SQL_NOT_SELECT", "Tool gate", "Query is not a single SELECT statement"),
        Reason("TABLE_NOT_ALLOWED", "Tool gate", "Query touches a table outside the allowlist"),
        Reason("TENANT_MISMATCH", "Tool gate, gateway", "Request reaches for another tenant's data"),
        Reason("RECIPIENT_DOMAIN", "Tool gate", "Email recipient outside the allowed domains or records"),
        Reason("DISPATCH_CAP", "Tool gate", "Dispatch limit for the session or hour reached"),
        Reason("APPROVAL_PENDING", "Tool gate", "High-risk call waiting in the approval queue"),
        Reason("PII_MASKED", "Output gate", "Sensitive value detected and masked"),
        Reason("CANARY_LEAK", "Output gate", "Canary token found in output; blocked"),
        Reason("SYSPROMPT_LEAK", "Output gate", "Output too similar to the system prompt; blocked"),
        Reason("EGRESS_BLOCKED", "Output gate", "URL or image outside the egress allowlist"),
        Reason("GUARD_TIMEOUT", "Any checkpoint", "Guardrail errored or exceeded its time budget; failed closed"),
        Reason("INJ_ALLOW", "Input gate", "Input passed all checks; allowed"),
        Reason("CTX_ALLOW", "Context gate", "Retrieved chunk passed scanning; allowed"),
        Reason("TOOL_ALLOW", "Tool gate", "Tool call passed all checks; allowed"),
        Reason("OUT_ALLOW", "Output gate", "Output passed all checks; allowed"),
    ]
}


def is_registered(code: str) -> bool:
    """Concrete INJ_RULE_07 maps to the INJ_RULE_nn family entry."""
    if code in REASON_CODES:
        return True
    return code.startswith("INJ_RULE_") and code[len("INJ_RULE_") :].isdigit()


def describe(code: str) -> str:
    if code in REASON_CODES:
        return REASON_CODES[code].meaning
    if is_registered(code):
        return REASON_CODES["INJ_RULE_nn"].meaning
    return "Unknown reason code"


def all_codes() -> set[str]:
    return set(REASON_CODES)


def checkpoint_for(code: str) -> str:
    if code in REASON_CODES:
        return REASON_CODES[code].checkpoint
    if code.startswith("INJ_RULE_") or code in {"INJ_CLS_HIGH", "INJ_CLS_MID", "INPUT_TRUNCATED", "SESSION_RISK"}:
        return "Input gate"
    return "Unknown"
