"""Phase 7: reason-code registry and coverage."""
from sentinelops.guardrails.gates import (
    ContextGate,
    Decision,
    InputGate,
    OutputGate,
    ToolGate,
)
from sentinelops.guardrails.registry import all_codes, checkpoint_for, describe, is_registered

# One block test and one allow test per emitted decision code (PDR 6.3.9).
BLOCK_TESTS = {
    "INJ_RULE_01", "INJ_RULE_03", "INPUT_TRUNCATED", "SESSION_RISK", "CTX_POISON",
    "TOOL_NOT_ALLOWED", "TOOL_PARAM_INVALID", "SQL_NOT_SELECT", "TABLE_NOT_ALLOWED",
    "TENANT_MISMATCH", "RECIPIENT_DOMAIN", "DISPATCH_CAP", "APPROVAL_PENDING",
    "PII_MASKED", "CANARY_LEAK", "EGRESS_BLOCKED", "GUARD_TIMEOUT",
}
ALLOW_TESTS = {
    "INJ_ALLOW", "CTX_ALLOW", "TOOL_ALLOW", "OUT_ALLOW", "INJ_CLS_MID",
}


def test_registry_covers_all_emitted_codes():
    emitted = BLOCK_TESTS | ALLOW_TESTS
    for code in emitted:
        assert is_registered(code), code
        assert describe(code)
    assert all_codes() <= emitted | {"INJ_RULE_nn", "INJ_CLS_HIGH", "SYSPROMPT_LEAK"}


def test_family_codes_are_registered():
    assert is_registered("INJ_RULE_07")
    assert checkpoint_for("INJ_RULE_07") == "Input gate"
    assert checkpoint_for("PII_MASKED") == "Output gate"


def test_every_registry_code_has_a_block_or_allow_test():
    covered = BLOCK_TESTS | ALLOW_TESTS | {"INJ_CLS_HIGH", "SYSPROMPT_LEAK"}
    # INJ_RULE_nn is a family placeholder covered by concrete rules.
    assert all_codes() - {"INJ_RULE_nn"} <= covered
