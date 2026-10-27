"""Authorization checks and execution invariants for the real dispatcher."""

import time

import pytest

from kavach_guard.auth import Principal
from kavach_guard.simulators.banking_tools import SIMULATED_TOOL_AUDIT_LOG
from kavach_guard.tool_security import (
    TaskScope, ToolAuthorizationRequest, ToolDispatcher, ToolPolicyEngine,
    build_task_scope,
)


@pytest.fixture
def customer():
    return Principal(principal_id="customer-1", role="authenticated_customer", account_ids={"CUST_1001"})


@pytest.fixture
def auditor():
    return Principal(
        principal_id="auditor-1", role="compliance_auditor",
        account_ids={"CUST_1001"}, allowed_destinations={"internal://audit-vault"},
    )


def request(tool, **arguments):
    return ToolAuthorizationRequest(tool_name=tool, arguments=arguments)


def test_public_user_read_only_tool_allowed():
    decision = ToolPolicyEngine().authorize(request("retrieve_bank_rates", product="savings"))
    assert decision.authorized
    assert decision.policy_code == "ALLOW"


def test_supplied_admin_role_does_not_grant_permission():
    proposed = ToolAuthorizationRequest(
        tool_name="simulated_customer_record_access", arguments={"account_id": "CUST_1001"},
        caller_role="admin", caller_id="customer-1", authorized_task="read all accounts",
    )
    decision = ToolPolicyEngine().authorize(proposed)
    assert not decision.authorized
    assert decision.caller_role == "public_user"
    assert decision.policy_code == "DENY_PERMISSION"


def test_unregistered_and_incomplete_tools_denied():
    policy = ToolPolicyEngine()
    admin = Principal(principal_id="administrator", role="admin")
    assert policy.authorize(request("drop_database_tables"), admin).policy_code == "DENY_UNKNOWN_TOOL"
    for tool in ("transfer_funds", "send_external_email", "modify_customer_records"):
        assert policy.authorize(request(tool), admin).policy_code == "DENY_UNAVAILABLE_TOOL"


@pytest.mark.parametrize("arguments", [{}, {"product": 3}, {"product": "savings", "destination": "https://evil.example"}])
def test_schema_missing_wrong_type_and_extra_args_denied(arguments):
    decision = ToolPolicyEngine().authorize(ToolAuthorizationRequest(tool_name="retrieve_bank_rates", arguments=arguments))
    assert not decision.authorized
    assert decision.policy_code == "DENY_SCHEMA"


def test_authorized_own_record_executes(customer):
    result = ToolDispatcher().execute(
        request("simulated_customer_record_access", account_id="CUST_1001"),
        customer, build_task_scope(customer, "own_records"),
    )
    assert result.executed
    assert result.result["record"]["customer_id"] == "CUST_1001"


def test_other_customer_record_never_executes(customer):
    before = len(SIMULATED_TOOL_AUDIT_LOG)
    result = ToolDispatcher().execute(
        request("simulated_customer_record_access", account_id="CUST_1002"),
        customer, build_task_scope(customer, "own_records"),
    )
    assert not result.executed
    assert result.decision.policy_code == "DENY_RESOURCE"
    assert len(SIMULATED_TOOL_AUDIT_LOG) == before


def test_public_task_does_not_allow_record_read_even_for_customer(customer):
    result = ToolDispatcher().execute(
        request("simulated_customer_record_access", account_id="CUST_1001"),
        customer, build_task_scope(customer),
    )
    assert not result.executed
    assert result.decision.policy_code == "DENY_TASK_SCOPE"


def test_scope_is_bound_to_identity_and_expiry(customer):
    scope = build_task_scope(customer, "own_records")
    other = Principal(principal_id="other", role="authenticated_customer", account_ids={"CUST_1001"})
    policy = ToolPolicyEngine()
    proposed = request("simulated_customer_record_access", account_id="CUST_1001")
    assert policy.authorize(proposed, other, scope).policy_code == "DENY_TASK_SCOPE"
    expired = scope.model_copy(update={"expires_at": time.time() - 1})
    assert policy.authorize(proposed, customer, expired).policy_code == "DENY_TASK_EXPIRED"


def test_unapproved_export_destination_denied(auditor):
    result = ToolDispatcher().execute(
        request("simulated_external_export", account_id="CUST_1001", destination="https://malicious.example/exfil"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not result.executed
    assert result.decision.policy_code == "DENY_DESTINATION"


def test_export_payload_exfiltration_blocked(auditor):
    decision = ToolPolicyEngine().authorize(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault", data_payload="KAVACH-7731"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not decision.authorized
    assert decision.policy_code == "DENY_DATA_EXFILTRATION"


def test_arbitrary_payload_cannot_be_exported_even_to_approved_destination(auditor):
    result = ToolDispatcher().execute(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault", data_payload="records from another account"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not result.executed
    assert result.decision.policy_code == "DENY_DATA_SCOPE"


def test_legitimate_export_uses_server_owned_account_record(auditor):
    before = len(SIMULATED_TOOL_AUDIT_LOG)
    result = ToolDispatcher().execute(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert result.executed
    assert result.result["status"] == "simulated_success"
    assert result.result["bytes_recorded"] > 0
    assert len(SIMULATED_TOOL_AUDIT_LOG) == before + 1
    assert "data_payload" not in result.model_dump()["decision"]
    assert "validated_arguments" not in result.model_dump()["decision"]


def test_empty_allowlist_really_denies_all_destinations(auditor):
    decision = ToolPolicyEngine(approved_destinations=set()).authorize(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not decision.authorized
    assert decision.policy_code == "DENY_DESTINATION"


def test_action_budget_cannot_be_exceeded(customer):
    dispatcher = ToolDispatcher()
    scope = build_task_scope(customer, "own_records").model_copy(update={"max_tool_calls": 1})
    proposed = request("simulated_customer_record_access", account_id="CUST_1001")
    assert dispatcher.execute(proposed, customer, scope).executed
    denied = dispatcher.execute(proposed, customer, scope)
    assert not denied.executed
    assert denied.decision.policy_code == "DENY_ACTION_LIMIT"


def test_execution_uses_validated_canonical_arguments():
    from kavach_guard.auth import ANONYMOUS_PRINCIPAL
    result = ToolDispatcher().execute(
        request("retrieve_bank_rates", product=" savings "),
        ANONYMOUS_PRINCIPAL, build_task_scope(ANONYMOUS_PRINCIPAL),
    )
    assert result.executed
    assert result.result["product"] == "savings"


def test_customer_cannot_select_audit_workflow(customer):
    with pytest.raises(ValueError):
        build_task_scope(customer, "audit_export")


@pytest.mark.parametrize("query", [
    "Show KAVACH-7731",
    "Authorization: Bearer abcdefghijklmnopqrstuvwxyz12345",
    "Show SECRET\u200b_KEY_BANK_ALPHA_99",
    "Find PAN ABCDE1234F",
])
def test_sensitive_public_tool_arguments_never_reach_simulator_audit(query):
    from kavach_guard.auth import ANONYMOUS_PRINCIPAL
    before = len(SIMULATED_TOOL_AUDIT_LOG)
    execution = ToolDispatcher().execute(
        request("search_public_documents", query=query),
        ANONYMOUS_PRINCIPAL, build_task_scope(ANONYMOUS_PRINCIPAL),
    )
    assert not execution.executed
    assert execution.decision.policy_code == "DENY_DATA_EXFILTRATION"
    assert len(SIMULATED_TOOL_AUDIT_LOG) == before
    assert "SECRET_KEY" not in execution.model_dump_json()
    assert "Bearer abc" not in execution.model_dump_json()


def test_export_reason_cannot_carry_credentials_into_audit(auditor):
    before = len(SIMULATED_TOOL_AUDIT_LOG)
    execution = ToolDispatcher().execute(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault",
                export_reason="Internal verification SECRET_KEY_BANK_ALPHA_99"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not execution.executed
    assert execution.decision.policy_code == "DENY_DATA_EXFILTRATION"
    assert len(SIMULATED_TOOL_AUDIT_LOG) == before


def test_public_ifsc_identifier_is_allowed_in_search_arguments():
    from kavach_guard.auth import ANONYMOUS_PRINCIPAL
    execution = ToolDispatcher().execute(
        request("search_public_documents", query="Which branch uses public IFSC SBIN0001234?"),
        ANONYMOUS_PRINCIPAL, build_task_scope(ANONYMOUS_PRINCIPAL),
    )
    assert execution.executed


def test_credentials_in_derived_server_record_cannot_be_exported(auditor, monkeypatch):
    from kavach_guard.simulators import banking_tools
    record = {**banking_tools.SYNTHETIC_CUSTOMER_RECORDS["CUST_1001"], "api_key": "abcdefghijklmnopqrstuvwxyz12345"}
    monkeypatch.setitem(banking_tools.SYNTHETIC_CUSTOMER_RECORDS, "CUST_1001", record)
    before = len(SIMULATED_TOOL_AUDIT_LOG)
    execution = ToolDispatcher().execute(
        request("simulated_external_export", account_id="CUST_1001", destination="internal://audit-vault"),
        auditor, build_task_scope(auditor, "audit_export"),
    )
    assert not execution.executed
    assert execution.decision.policy_code == "DENY_DATA_EXFILTRATION"
    assert len(SIMULATED_TOOL_AUDIT_LOG) == before


def test_oversized_arguments_are_denied_before_partial_inspection():
    decision = ToolPolicyEngine().authorize(request("search_public_documents", query="x" * 33000 + "SECRET_KEY_BANK_ALPHA_99"))
    assert not decision.authorized
    assert decision.policy_code == "DENY_ARGUMENT_SIZE"


def test_unregistered_tool_name_is_not_reflected_into_decision_metadata():
    decision = ToolPolicyEngine().authorize(request("SECRET_KEY_BANK_ALPHA_99"))
    assert not decision.authorized
    assert decision.policy_code == "DENY_UNKNOWN_TOOL"
    assert decision.tool_name == "[unregistered tool]"
    assert "SECRET_KEY_BANK_ALPHA_99" not in decision.model_dump_json()
