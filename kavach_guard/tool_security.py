"""
KAVACH v2 - Layer 5: Deterministic Tool Security & Runtime Authorization Engine
Executes strict, fail-closed runtime policy enforcement independent of LLM decisions.
Validates:
- Tool allowlists & role-based permissions (READ_ONLY vs RESTRICTED)
- Pydantic argument schemas and type constraints
- Destination allowlists (blocking unapproved external endpoints)
- Sensitive payload / exfiltration detection within arguments
- Explicit deny rules taking precedence over allow rules
"""

from typing import Dict, Any, List, Optional, Set
from pydantic import BaseModel, Field, ValidationError

# --- Tool Categorization ---
READ_ONLY_TOOLS: Set[str] = {
    "search_public_documents",
    "retrieve_bank_rates",
    "summarize_public_policy"
}

RESTRICTED_TOOLS: Set[str] = {
    "simulated_customer_record_access",
    "simulated_external_export",
    "send_external_email",
    "transfer_funds",
    "modify_customer_records"
}

# Approved destinations for export / network operations
APPROVED_DESTINATIONS: Set[str] = {
    "https://api.internal-bank.local/reports",
    "internal://audit-vault"
}

# Role permissions
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "public_user": {"search_public_documents", "retrieve_bank_rates", "summarize_public_policy"},
    "authenticated_customer": {
        "search_public_documents", "retrieve_bank_rates", "summarize_public_policy",
        "simulated_customer_record_access"
    },
    "compliance_auditor": {
        "search_public_documents", "retrieve_bank_rates", "summarize_public_policy",
        "simulated_customer_record_access", "simulated_external_export"
    },
    "admin": READ_ONLY_TOOLS | RESTRICTED_TOOLS
}


class ToolAuthorizationRequest(BaseModel):
    tool_name: str
    arguments: Dict[str, Any] = Field(default_factory=dict)
    caller_role: str = "public_user"
    caller_id: str = "anon"
    authorized_task: Optional[str] = None
    source_provenance: str = "assistant_proposal"


class ToolAuthorizationDecision(BaseModel):
    authorized: bool
    tool_name: str
    decision_reason: str
    policy_code: str  # "DENY_UNKNOWN_TOOL", "DENY_PERMISSION", "DENY_DESTINATION", "DENY_SCHEMA", "ALLOW"
    caller_role: str
    risk_level: str = "low"  # "low", "medium", "high", "critical"
    violations: List[str] = Field(default_factory=list)


# --- Tool Argument Schemas for Strict Runtime Validation ---
class SearchPublicDocumentsArgs(BaseModel):
    query: str = Field(min_length=1, max_length=200)

class RetrieveBankRatesArgs(BaseModel):
    product: str = Field(min_length=2, max_length=50)

class SummarizePublicPolicyArgs(BaseModel):
    policy_name: str = Field(min_length=2, max_length=100)

class CustomerRecordAccessArgs(BaseModel):
    account_id: str = Field(min_length=5, max_length=30)
    auth_token: Optional[str] = None

class ExternalExportArgs(BaseModel):
    destination: str
    data_payload: str
    export_reason: Optional[str] = None

TOOL_ARG_SCHEMAS = {
    "search_public_documents": SearchPublicDocumentsArgs,
    "retrieve_bank_rates": RetrieveBankRatesArgs,
    "summarize_public_policy": SummarizePublicPolicyArgs,
    "simulated_customer_record_access": CustomerRecordAccessArgs,
    "simulated_external_export": ExternalExportArgs,
}


class ToolPolicyEngine:
    def __init__(self, approved_destinations: Optional[Set[str]] = None):
        self.approved_destinations = approved_destinations or APPROVED_DESTINATIONS

    def authorize(self, request: ToolAuthorizationRequest) -> ToolAuthorizationDecision:
        """
        Validates proposed tool execution against deterministic authorization policies.
        Operates completely independently of LLM outputs or prompt-injection detectors.
        """
        tool = request.tool_name
        role = request.caller_role
        args = request.arguments
        violations = []

        # 1. Unknown Tool Check (Fail-closed)
        all_registered = READ_ONLY_TOOLS | RESTRICTED_TOOLS
        if tool not in all_registered:
            return ToolAuthorizationDecision(
                authorized=False,
                tool_name=tool,
                decision_reason=f"Tool '{tool}' is not registered in security policy allowlist.",
                policy_code="DENY_UNKNOWN_TOOL",
                caller_role=role,
                risk_level="high",
                violations=[f"Unregistered tool: {tool}"]
            )

        # 2. Role-Based Access Control (RBAC) Enforcement
        allowed_tools_for_role = ROLE_PERMISSIONS.get(role, set())
        if tool not in allowed_tools_for_role:
            return ToolAuthorizationDecision(
                authorized=False,
                tool_name=tool,
                decision_reason=f"Role '{role}' is not authorized to invoke '{tool}'.",
                policy_code="DENY_PERMISSION",
                caller_role=role,
                risk_level="critical" if tool in RESTRICTED_TOOLS else "medium",
                violations=[f"RBAC violation: {role} attempted {tool}"]
            )

        # 3. Argument Schema Validation
        schema_cls = TOOL_ARG_SCHEMAS.get(tool)
        if schema_cls:
            try:
                schema_cls(**args)
            except ValidationError as ve:
                err_msg = "; ".join(f"{e['loc']}: {e['msg']}" for e in ve.errors())
                return ToolAuthorizationDecision(
                    authorized=False,
                    tool_name=tool,
                    decision_reason=f"Argument schema validation failed: {err_msg}",
                    policy_code="DENY_SCHEMA",
                    caller_role=role,
                    risk_level="medium",
                    violations=[err_msg]
                )

        # 4. Destination Allowlist for External Export Operations
        if tool == "simulated_external_export":
            dest = str(args.get("destination", "")).strip()
            if dest not in self.approved_destinations:
                return ToolAuthorizationDecision(
                    authorized=False,
                    tool_name=tool,
                    decision_reason=f"Destination '{dest}' is not in the approved export destination allowlist.",
                    policy_code="DENY_DESTINATION",
                    caller_role=role,
                    risk_level="critical",
                    violations=[f"Unapproved destination: {dest}"]
                )

            # Check if payload contains canary token or system keys
            payload = str(args.get("data_payload", ""))
            if "KAVACH-" in payload or "SECRET_KEY_" in payload:
                return ToolAuthorizationDecision(
                    authorized=False,
                    tool_name=tool,
                    decision_reason="Data payload contains planted canary or secret tokens. Exfiltration blocked.",
                    policy_code="DENY_DATA_EXFILTRATION",
                    caller_role=role,
                    risk_level="critical",
                    violations=["Exfiltration of canary/secret detected in payload"]
                )

        # 5. Authorization Granted
        return ToolAuthorizationDecision(
            authorized=True,
            tool_name=tool,
            decision_reason=f"Tool '{tool}' authorized for role '{role}' under policy v2.",
            policy_code="ALLOW",
            caller_role=role,
            risk_level="low",
            violations=[]
        )
