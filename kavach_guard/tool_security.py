"""Deterministic, task-scoped authorization and synthetic-tool dispatch.

The dispatcher is the execution boundary. Request bodies and model proposals can
name tools and arguments, but cannot choose their identity or expand task scope.
"""

from dataclasses import dataclass
import json
import threading
import time
import uuid
from typing import Any, Callable, Dict, FrozenSet, List, Literal, Optional, Set

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from kavach_guard.auth import ANONYMOUS_PRINCIPAL, Principal
from kavach_guard.detectors.normalizer import normalize_input
from kavach_guard.detectors.pii_secrets import PIISecretDetector
from kavach_guard.simulators import banking_tools

READ_ONLY_TOOLS: Set[str] = {
    "search_public_documents", "retrieve_bank_rates", "summarize_public_policy"
}
RESTRICTED_TOOLS: Set[str] = {
    "simulated_customer_record_access", "simulated_external_export",
    "send_external_email", "transfer_funds", "modify_customer_records"
}
APPROVED_DESTINATIONS: Set[str] = {
    "https://api.internal-bank.local/reports", "internal://audit-vault"
}
ROLE_PERMISSIONS: Dict[str, Set[str]] = {
    "public_user": set(READ_ONLY_TOOLS),
    "authenticated_customer": READ_ONLY_TOOLS | {"simulated_customer_record_access"},
    "compliance_auditor": READ_ONLY_TOOLS | {
        "simulated_customer_record_access", "simulated_external_export"
    },
    "admin": READ_ONLY_TOOLS | RESTRICTED_TOOLS,
}
Workflow = Literal["public_banking", "own_records", "audit_export"]
MAX_ARGUMENT_BYTES = 32768
CREDENTIAL_CATEGORIES = {"planted_secret", "benchmark_canary", "api_key"}


class TaskScope(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    task_id: str = Field(default_factory=lambda: f"TASK_{uuid.uuid4().hex}")
    principal_id: str
    workflow: Workflow = "public_banking"
    allowed_tools: FrozenSet[str] = Field(default_factory=frozenset)
    account_ids: FrozenSet[str] = Field(default_factory=frozenset)
    allowed_destinations: FrozenSet[str] = Field(default_factory=frozenset)
    expires_at: float = Field(default_factory=lambda: time.time() + 300)
    max_tool_calls: int = Field(default=6, ge=1, le=20)


def build_task_scope(principal: Principal, workflow: Workflow = "public_banking") -> TaskScope:
    """Select an application-defined workflow; model text never grants scope."""
    tools = set(READ_ONLY_TOOLS)
    accounts = frozenset()
    destinations = frozenset()
    if workflow == "own_records":
        if principal.role == "public_user" or not principal.account_ids:
            raise ValueError("Record access requires an authenticated identity with explicit accounts")
        tools.add("simulated_customer_record_access")
        accounts = principal.account_ids
    elif workflow == "audit_export":
        if principal.role not in {"compliance_auditor", "admin"} or not principal.account_ids or not principal.allowed_destinations:
            raise ValueError("Audit export requires an auditor with explicit accounts and destinations")
        tools |= {"simulated_customer_record_access", "simulated_external_export"}
        accounts = principal.account_ids
        destinations = principal.allowed_destinations & frozenset(APPROVED_DESTINATIONS)
        if not destinations:
            raise ValueError("No approved audit export destination is available")
    elif workflow != "public_banking":
        raise ValueError("Unknown application workflow")
    return TaskScope(
        principal_id=principal.principal_id,
        workflow=workflow,
        allowed_tools=frozenset(tools & ROLE_PERMISSIONS.get(principal.role, set())),
        account_ids=accounts,
        allowed_destinations=destinations,
    )


class ToolAuthorizationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str = Field(min_length=1, max_length=100)
    arguments: Dict[str, Any] = Field(default_factory=dict)
    # Legacy compatibility fields are descriptive and never used as authority.
    caller_role: str = "public_user"
    caller_id: str = "anon"
    authorized_task: Optional[str] = None
    source_provenance: str = "assistant_proposal"


class ToolAuthorizationDecision(BaseModel):
    authorized: bool
    tool_name: str
    decision_reason: str
    policy_code: str
    caller_role: str
    risk_level: str = "low"
    violations: List[str] = Field(default_factory=list)
    task_id: Optional[str] = None
    validated_arguments: Dict[str, Any] = Field(default_factory=dict, exclude=True)


class StrictToolArgs(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True, str_strip_whitespace=True)


class SearchPublicDocumentsArgs(StrictToolArgs):
    query: str = Field(min_length=1, max_length=200)


class RetrieveBankRatesArgs(StrictToolArgs):
    product: str = Field(min_length=2, max_length=50)


class SummarizePublicPolicyArgs(StrictToolArgs):
    policy_name: str = Field(min_length=2, max_length=100)


class CustomerRecordAccessArgs(StrictToolArgs):
    account_id: str = Field(min_length=5, max_length=30)


class ExternalExportArgs(StrictToolArgs):
    account_id: str = Field(min_length=5, max_length=30)
    destination: str = Field(min_length=1, max_length=300)
    # Empty means: export the authorized server-side record. Arbitrary model
    # payloads are never executed, even when the destination is approved.
    data_payload: str = Field(
        default="", max_length=10000,
        description="Leave empty: the server selects the authorized account's synthetic report. Never supply arbitrary report text or credentials.",
    )
    export_reason: Optional[str] = Field(default=None, max_length=200)


@dataclass(frozen=True)
class ToolDefinition:
    schema: Optional[type[BaseModel]]
    handler: Optional[Callable[..., Dict[str, Any]]]


TOOL_REGISTRY = {
    "search_public_documents": ToolDefinition(SearchPublicDocumentsArgs, banking_tools.search_public_documents),
    "retrieve_bank_rates": ToolDefinition(RetrieveBankRatesArgs, banking_tools.retrieve_bank_rates),
    "summarize_public_policy": ToolDefinition(SummarizePublicPolicyArgs, banking_tools.summarize_public_policy),
    "simulated_customer_record_access": ToolDefinition(CustomerRecordAccessArgs, banking_tools.simulated_customer_record_access),
    "simulated_external_export": ToolDefinition(ExternalExportArgs, banking_tools.simulated_external_export),
    # These names are reserved, but cannot execute until fully implemented.
    "send_external_email": ToolDefinition(None, None),
    "transfer_funds": ToolDefinition(None, None),
    "modify_customer_records": ToolDefinition(None, None),
}
TOOL_ARG_SCHEMAS = {name: definition.schema for name, definition in TOOL_REGISTRY.items() if definition.schema}


def _canonical_record_payload(account_id: str) -> str:
    return json.dumps(banking_tools.SYNTHETIC_CUSTOMER_RECORDS[account_id], sort_keys=True, ensure_ascii=False)


def _argument_texts(value, key=""):
    """Keep actual string values and field context, rather than JSON escapes."""
    if isinstance(value, dict):
        for name, item in value.items():
            yield from _argument_texts(item, str(name))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _argument_texts(item, key)
    elif value is not None:
        yield f"{key}: {value}"


class ToolPolicyEngine:
    def __init__(self, approved_destinations: Optional[Set[str]] = None):
        self.approved_destinations = frozenset(APPROVED_DESTINATIONS if approved_destinations is None else approved_destinations)
        self.pii_detector = PIISecretDetector(redact_public_identifiers=False)

    def authorize(
        self,
        request: ToolAuthorizationRequest,
        principal: Optional[Principal] = None,
        scope: Optional[TaskScope] = None,
    ) -> ToolAuthorizationDecision:
        principal = principal or ANONYMOUS_PRINCIPAL
        scope = scope or build_task_scope(principal)
        tool = request.tool_name
        safe_tool_name = tool if tool in TOOL_REGISTRY else "[unregistered tool]"

        def deny(code: str, reason: str, risk: str = "high") -> ToolAuthorizationDecision:
            return ToolAuthorizationDecision(
                authorized=False, tool_name=safe_tool_name, decision_reason=reason,
                policy_code=code, caller_role=principal.role, risk_level=risk,
                violations=[reason], task_id=scope.task_id,
            )

        definition = TOOL_REGISTRY.get(tool)
        if definition is None:
            return deny("DENY_UNKNOWN_TOOL", "Tool is not registered")
        if definition.schema is None or definition.handler is None:
            return deny("DENY_UNAVAILABLE_TOOL", "Tool lacks a complete schema and execution handler")
        if scope.principal_id != principal.principal_id:
            return deny("DENY_TASK_SCOPE", "Task scope belongs to another identity", "critical")
        if scope.expires_at <= time.time():
            return deny("DENY_TASK_EXPIRED", "Task scope has expired")
        if tool not in ROLE_PERMISSIONS.get(principal.role, set()):
            return deny("DENY_PERMISSION", "RBAC violation: identity cannot invoke this tool", "critical")
        if tool not in scope.allowed_tools:
            return deny("DENY_TASK_SCOPE", "Tool is outside the authorized task")
        try:
            serialized = json.dumps(request.arguments, ensure_ascii=False, allow_nan=False)
            serialized_size = len(serialized.encode("utf-8"))
        except (TypeError, ValueError, RecursionError, UnicodeError):
            return deny("DENY_SCHEMA", "Tool arguments must be bounded JSON values", "medium")
        if serialized_size > MAX_ARGUMENT_BYTES:
            return deny("DENY_ARGUMENT_SIZE", "Tool arguments exceed the inspection budget")
        try:
            validated = definition.schema.model_validate(request.arguments).model_dump()
        except ValidationError as exc:
            # Field names and input values may themselves carry private data.
            errors = ", ".join(sorted({error["type"] for error in exc.errors()}))
            return deny("DENY_SCHEMA", f"Argument schema validation failed: {errors}", "medium")
        normalized = normalize_input("\n".join(_argument_texts(validated)))
        if normalized.truncated:
            return deny("DENY_ARGUMENT_SIZE", "Tool arguments could not be completely inspected")
        if self.pii_detector.scan(normalized.canonical_text).matches:
            return deny("DENY_DATA_EXFILTRATION", "Model-proposed arguments contain sensitive identifiers or credentials", "critical")

        if tool in {"simulated_customer_record_access", "simulated_external_export"}:
            account = validated["account_id"]
            if account not in principal.account_ids or account not in scope.account_ids:
                return deny("DENY_RESOURCE", "Account is outside the identity or task resource scope", "critical")
            if account not in banking_tools.SYNTHETIC_CUSTOMER_RECORDS:
                return deny("DENY_RESOURCE", "Requested synthetic account is unavailable")

        if tool == "simulated_external_export":
            destination = validated["destination"]
            if destination not in self.approved_destinations or destination not in principal.allowed_destinations or destination not in scope.allowed_destinations:
                return deny("DENY_DESTINATION", "Destination is not in the approved export destination allowlist", "critical")
            payload = validated["data_payload"]
            try:
                trusted_payload = _canonical_record_payload(validated["account_id"])
            except (TypeError, ValueError, RecursionError):
                return deny("DENY_DATA_SCOPE", "The selected server-side report is unavailable")
            if len(trusted_payload.encode("utf-8")) > MAX_ARGUMENT_BYTES:
                return deny("DENY_ARGUMENT_SIZE", "Server-side report exceeds the inspection budget")
            report_text = "\n".join(_argument_texts(banking_tools.SYNTHETIC_CUSTOMER_RECORDS[validated["account_id"]]))
            report_normalized = normalize_input(report_text)
            if report_normalized.truncated:
                return deny("DENY_ARGUMENT_SIZE", "The selected report could not be completely inspected")
            report_findings = self.pii_detector.scan(report_normalized.canonical_text)
            if CREDENTIAL_CATEGORIES.intersection(report_findings.categories_found):
                return deny("DENY_DATA_EXFILTRATION", "Server-side report contains credentials or protected tokens", "critical")
            if payload and payload != trusted_payload:
                return deny("DENY_DATA_SCOPE", "Export payload must be the selected authorized server-side record", "critical")
            validated["data_payload"] = trusted_payload

        return ToolAuthorizationDecision(
            authorized=True, tool_name=tool, decision_reason="Authorized for the authenticated identity and application task",
            policy_code="ALLOW", caller_role=principal.role, risk_level="low",
            task_id=scope.task_id, validated_arguments=validated,
        )


class ToolExecutionResult(BaseModel):
    decision: ToolAuthorizationDecision
    executed: bool = False
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ToolDispatcher:
    """Only dispatches validated arguments after an independent authorization."""

    def __init__(self, policy: Optional[ToolPolicyEngine] = None):
        self.policy = policy or ToolPolicyEngine()
        self._calls: Dict[str, int] = {}
        self._expiries: Dict[str, float] = {}
        self._lock = threading.Lock()

    def execute(self, request: ToolAuthorizationRequest, principal: Principal, scope: TaskScope) -> ToolExecutionResult:
        decision = self.policy.authorize(request, principal=principal, scope=scope)
        if not decision.authorized:
            return ToolExecutionResult(decision=decision)
        with self._lock:
            now = time.time()
            for task_id in [key for key, expiry in self._expiries.items() if expiry <= now]:
                self._expiries.pop(task_id, None)
                self._calls.pop(task_id, None)
            if self._calls.get(scope.task_id, 0) >= scope.max_tool_calls:
                decision = decision.model_copy(update={
                    "authorized": False, "policy_code": "DENY_ACTION_LIMIT",
                    "decision_reason": "Task tool action limit reached", "risk_level": "high",
                    "validated_arguments": {}, "violations": ["Task tool action limit reached"],
                })
                return ToolExecutionResult(decision=decision)
            self._calls[scope.task_id] = self._calls.get(scope.task_id, 0) + 1
            self._expiries[scope.task_id] = scope.expires_at
        arguments = dict(decision.validated_arguments)
        if request.tool_name == "simulated_external_export":
            arguments.pop("account_id")
        try:
            result = TOOL_REGISTRY[request.tool_name].handler(**arguments)
        except Exception:
            # Do not reflect tool exception text: it may contain customer data.
            return ToolExecutionResult(decision=decision, executed=True, error="Synthetic tool execution failed")
        return ToolExecutionResult(decision=decision, executed=True, result=result)
