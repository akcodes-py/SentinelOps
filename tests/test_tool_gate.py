"""Phase 6/7: tool gate parameter rules (PDR 6.3.5)."""
from sentinelops.guardrails.gates import ToolGate


def gate(policy, db, approvals):
    return ToolGate(policy, db, approvals)


def test_select_only(policy, db, approvals):
    result = gate(policy, db, approvals).check("query_db", {"query": "DELETE FROM customers"}, 1, "s")
    assert result.reason_code == "SQL_NOT_SELECT"


def test_single_statement(policy, db, approvals):
    result = gate(policy, db, approvals).check("query_db", {"query": "SELECT * FROM customers; SELECT * FROM invoices"}, 1, "s")
    assert result.reason_code == "SQL_NOT_SELECT"


def test_table_allowlist(policy, db, approvals):
    result = gate(policy, db, approvals).check("query_db", {"query": "SELECT * FROM secrets"}, 1, "s")
    assert result.reason_code == "TABLE_NOT_ALLOWED"


def test_tenant_scope(policy, db, approvals):
    result = gate(policy, db, approvals).check("query_db", {"query": "SELECT * FROM customers WHERE tenant_id=999"}, 1, "s")
    assert result.reason_code == "TENANT_MISMATCH"


def test_report_type_allowlist(policy, db, approvals):
    result = gate(policy, db, approvals).check("generate_report", {"report_type": "arbitrary"}, 1, "s")
    assert result.reason_code == "TOOL_PARAM_INVALID"


def test_email_recipient_domain(policy, db, approvals):
    result = gate(policy, db, approvals).check(
        "send_email", {"recipient": "attacker@evil.test", "subject": "x", "body": "y"}, 1, "s"
    )
    assert result.reason_code in {"RECIPIENT_DOMAIN", "APPROVAL_PENDING"}


def test_high_risk_requires_approval(policy, db, approvals):
    email = db.one("SELECT email FROM customers WHERE tenant_id = 1")
    result = gate(policy, db, approvals).check(
        "send_email", {"recipient": email["email"], "subject": "Report", "body": "Hello"}, 1, "s1"
    )
    assert result.action == "review"
    assert result.reason_code == "APPROVAL_PENDING"
    assert len(approvals.list()) == 1


def test_dispatch_validates_ids(policy, db, approvals):
    result = gate(policy, db, approvals).check("dispatch_vehicle", {"vehicle_id": "V-9", "pickup_id": 999999}, 1, "s1")
    assert result.reason_code == "TOOL_PARAM_INVALID"


def test_unknown_tool_blocked(policy, db, approvals):
    result = gate(policy, db, approvals).check("drop_database", {}, 1, "s")
    assert result.reason_code == "TOOL_NOT_ALLOWED"


def test_safe_mode_blocks_all_tools(policy, db, approvals):
    result = gate(policy, db, approvals).check("query_db", {"query": "SELECT * FROM customers"}, 1, "s", safe_mode=True)
    assert result.reason_code == "TOOL_NOT_ALLOWED"
