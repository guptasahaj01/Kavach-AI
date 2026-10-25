# KAVACH v2 Automated Testing Strategy & Verification Suite

## 1. Test Architecture Overview

KAVACH v2 incorporates 54 automated tests across three distinct engineering tiers:
1. **Unit Tests (36 tests)**: Verifies deterministic normalization, regex rules, Indian financial PII/canary masking, DeBERTa model loading, context analyzer algorithms, and tool policy RBAC.
2. **Integration Tests (13 tests)**: Verifies real transformer inference, RAG provenance metadata enforcement, FastAPI endpoints contracts, and the mandatory detector-bypass test.
3. **End-to-End Scenarios (5 tests)**: Verifies Scenarios A through E simulating realistic real-world attack conditions.

---

## 2. Test Execution Command

```bash
# Run the complete test suite with verbose output
./venv/bin/pytest tests/ -v
```

### Measured Test Run Output
```
======================== 54 passed, 1 warning in 15.99s ========================
```

---

## 3. Test Inventory by Module

| Test Module | Test Count | Scope |
| :--- | :--- | :--- |
| `tests/unit/test_rules.py` | 16 | Normalization (NFKC, zero-width, homoglyphs, decoders), structured rules, PAN, Aadhaar Verhoeff, IFSC, Luhn Cards, and secret masking. |
| `tests/unit/test_ml_classifier.py` | 6 | Singleton ModelManager, DeBERTa inference, batch inference, truncation detection, and graceful degradation. |
| `tests/unit/test_context_analyzer.py` | 4 | Quotation extraction, educational query distinction, and out-of-band task misalignment detection. |
| `tests/unit/test_engine.py` | 4 | Central KavachSecurityEngine orchestration, multi-layer decision rationale, and latency reporting. |
| `tests/unit/test_tool_security.py` | 6 | Read-only vs restricted tools, RBAC role permissions, argument schemas, destination allowlists, and exfiltration blocking. |
| `tests/integration/test_rag_provenance.py` | 4 | Application-controlled provenance creation, poisoned chunk detection, quarantine mode, and sandwich boundary isolation. |
| `tests/integration/test_policy_bypass.py` | 1 | **Mandatory Security Test**: Intentionally bypassed detector -> LLM proposes unauthorized tool call -> policy engine independently rejects action (fail-closed). |
| `tests/integration/test_api_endpoints.py` | 8 | FastAPI endpoints: `/health`, `/api/v1/security/status`, `/api/v1/security/analyze`, `/api/v1/security/authorize-tool`, `/api/v1/config/public`, `/api/v1/benchmark/runs`. |
| `tests/e2e/test_end_to_end_scenarios.py` | 5 | End-to-End Scenarios A, B, C, D, and E. |

---

## 4. Mandatory Security Integration Test Details

Located in `tests/integration/test_policy_bypass.py`:
- **Scenario**: An indirect prompt injection in a retrieved document instructs the assistant to export private customer data to `https://attacker-c2-exfil.com/leak`.
- **Bypass**: The prompt-injection detection layer is replaced with a `PermissiveDetectorStub` that returns `flagged: false, recommended_action: "allow"`.
- **Proposed Action**: The LLM component follows the undetected instruction and proposes a tool action: `simulated_external_export(destination=..., data_payload=...)`.
- **Verification**: The independent runtime Layer 5 `ToolPolicyEngine` intercepts the action before execution, identifies that the destination is not in `APPROVED_DESTINATIONS`, and rejects the call (`DENY_PERMISSION`/`DENY_DESTINATION`).
- **Assertion**: Zero unauthorized tool invocations occur (`len(SIMULATED_TOOL_AUDIT_LOG)` remains unchanged).
