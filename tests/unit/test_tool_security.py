"""
Unit tests for KAVACH v2 Layer 5: Tool Policy Engine and RBAC Enforcement.
"""

import pytest
from kavach_guard.tool_security import (
    ToolPolicyEngine,
    ToolAuthorizationRequest,
    ToolAuthorizationDecision
)

@pytest.fixture
def policy_engine():
    return ToolPolicyEngine()

def test_public_user_read_only_tool_allowed(policy_engine):
    req = ToolAuthorizationRequest(
        tool_name="retrieve_bank_rates",
        arguments={"product": "savings"},
        caller_role="public_user"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is True
    assert decision.policy_code == "ALLOW"

def test_public_user_restricted_tool_denied(policy_engine):
    req = ToolAuthorizationRequest(
        tool_name="simulated_customer_record_access",
        arguments={"account_id": "CUST_1001"},
        caller_role="public_user"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is False
    assert decision.policy_code == "DENY_PERMISSION"
    assert "RBAC violation" in decision.violations[0]

def test_unregistered_tool_denied(policy_engine):
    req = ToolAuthorizationRequest(
        tool_name="drop_database_tables",
        arguments={"table": "customers"},
        caller_role="admin"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is False
    assert decision.policy_code == "DENY_UNKNOWN_TOOL"

def test_schema_argument_validation_failure(policy_engine):
    # Missing required argument 'product' for retrieve_bank_rates
    req = ToolAuthorizationRequest(
        tool_name="retrieve_bank_rates",
        arguments={},
        caller_role="public_user"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is False
    assert decision.policy_code == "DENY_SCHEMA"

def test_unapproved_export_destination_denied(policy_engine):
    req = ToolAuthorizationRequest(
        tool_name="simulated_external_export",
        arguments={
            "destination": "https://malicious-attacker-c2.com/exfil",
            "data_payload": "mock data"
        },
        caller_role="compliance_auditor"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is False
    assert decision.policy_code == "DENY_DESTINATION"
    assert "not in the approved export destination allowlist" in decision.decision_reason

def test_export_payload_exfiltration_blocked(policy_engine):
    # Attempting to export canary or system secret to approved destination
    req = ToolAuthorizationRequest(
        tool_name="simulated_external_export",
        arguments={
            "destination": "internal://audit-vault",
            "data_payload": "Customer leaked canary: KAVACH-7731"
        },
        caller_role="compliance_auditor"
    )
    decision = policy_engine.authorize(req)
    assert decision.authorized is False
    assert decision.policy_code == "DENY_DATA_EXFILTRATION"
