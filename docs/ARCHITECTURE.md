# KAVACH v2 Architecture: Context-Aware, Provenance-Driven AI Security Gateway

## Executive Summary

KAVACH v2 is a multi-layered, defense-in-depth AI security gateway engineered to defend Large Language Model (LLM) agents and Retrieval-Augmented Generation (RAG) applications against prompt injection attacks, roleplay overrides, and unauthorized tool execution.

The architecture adopts an asymmetric two-tiered compute model:
1. **Tier 1 (Sub-2ms Deterministic Plane):** Fast-rejection rules engine, input canonicalizer, homoglyph mapping, and PII/canary masking.
2. **Tier 2 (25–35ms Semantic Plane):** Local transformer-based classifier (`deepset/deberta-v3-base-injection`) evaluating deep latent intent on CPU or Apple Silicon (MPS).
3. **Context-Aware Analysis:** Differentiates active attacks from legitimate quotations and educational research discussions.
4. **Provenance-Aware RAG Protection:** Enforces application-controlled trust boundaries on retrieved chunks (`instruction_authority: false`).
5. **Deterministic Runtime Tool Policy:** Operates independently of LLM decisions with fail-closed RBAC, schema validation, and destination allowlists.
6. **Output Validation:** Post-generation canary verification (`KAVACH-7731`) and sensitive token filtering before response delivery.

---

## Architectural Diagram

```
                                      [ INBOUND REQUEST ]
                                               │
                                               ▼
                              [ INPUT CANONICALIZATION & NORMALIZATION ]
                              • NFKC Unicode Normalization
                              • Zero-width & invisible character stripping
                              • Obfuscation decoding (Base64, ROT13, Hex, URL)
                              • Bounded recursion (depth ≤ 3, length ≤ 64KB)
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 1: DETERMINISTIC RULES SCANNER (< 2ms)                                               │
│ • Structured findings schema (RuleMatch: rule_id, category, severity, span)                │
│ • Canonical signatures & delimiter escape patterns                                         │
│ • Indian financial PII & secret masks (PAN, Aadhaar with Verhoeff, IFSC, Cards with Luhn)  │
│ • Planted benchmark canary (KAVACH-7731) and secret key traps                              │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 2: PRETRAINED SEMANTIC ML CLASSIFIER (~25ms CPU/MPS)                                  │
│ • Singleton / Cached ModelManager with lazy loading and explicit readiness status          │
│ • Primary: deepset/deberta-v3-base-injection (ungated, local inference)                    │
│ • Apple Silicon (MPS) and CPU auto-detection                                               │
│ • Evaluates semantic intent (UNBOUNDED, DAN, roleplay overrides)                           │
│ • Token truncation detection and per-item latency measurement                               │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 3: CONTEXT-AWARE & TASK-ALIGNMENT ANALYZER                                            │
│ • Structural quotation & analytical framing detection (distinguishes research from exploit) │
│ • Validates instruction consistency between user request and candidate content              │
│ • Detects out-of-band side-effect directives (e.g. unprompted export directives)            │
│ • Emits transparent decisions: ALLOW, REVIEW, FLAG, BLOCK                                   │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 4: PROVENANCE-AWARE RAG ISOLATION                                                     │
│ • Application-assigned provenance metadata: document_id, chunk_id, trust_level              │
│ • Immutability: instruction_authority = FALSE (untrusted data cannot self-elevate)         │
│ • Boundary isolation (Sandwich Defense neutralizing recency bias)                          │
│ • Configurable quarantine of poisoned chunks                                                │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
                                      [ PROTECTED LLM ]
                                               │
                                               ▼
                                   [ PROPOSED TOOL ACTIONS ]
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 5: DETERMINISTIC RUNTIME TOOL POLICY ENGINE                                           │
│ • Independent of LLM decisions (LLM cannot grant itself authorization)                    │
│ • Role-Based Access Control: READ_ONLY_TOOLS vs RESTRICTED_TOOLS                           │
│ • Pydantic argument schema validation                                                      │
│ • Destination allowlist verification (denies unapproved exfiltration endpoints)            │
│ • Fail-closed semantics: explicit deny rules always supersede                              │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ LAYER 6: OUTPUT VALIDATION & SECRETS MASKING                                                │
│ • Post-generation canary detection (KAVACH-7731)                                           │
│ • Planted secret key masking (SECRET_KEY_BANK_ALPHA_99)                                     │
│ • Financial PII redaction on outbound text                                                  │
└──────────────────────────────────────────────┬──────────────────────────────────────────────┘
                                               │
                                               ▼
                                      [ DELIVERED RESPONSE ]
```

---

## Component Taxonomy

| Component | Module Path | Purpose |
| :--- | :--- | :--- |
| **Normalizer** | `kavach_guard/detectors/normalizer.py` | Canonicalizes Unicode, strips zero-width chars, decodes obfuscated payloads. |
| **Rule Engine** | `kavach_guard/detectors/rule_engine.py` | Screens for authority spoofing, task aborts, and canary traps. |
| **PII & Secrets** | `kavach_guard/detectors/pii_secrets.py` | Indian financial format checks (Aadhaar Verhoeff, PAN, IFSC). |
| **Model Manager** | `kavach_guard/detectors/model_manager.py` | Singleton lifecycle for DeBERTa transformer inference on CPU/MPS. |
| **Context Analyzer** | `kavach_guard/detectors/context_analyzer.py` | Distinguishes quotations from attacks; enforces task alignment. |
| **RAG Provenance** | `kavach_guard/rag_provenance.py` | Application-controlled trust metadata and sandwich boundaries. |
| **Tool Policy** | `kavach_guard/tool_security.py` | Fail-closed runtime authorization gate for proposed tool calls. |
| **Bank Simulator** | `kavach_guard/simulators/banking_tools.py` | Safe, isolated synthetic banking tools (never touches external network). |
| **Output Validator** | `kavach_guard/output_validator.py` | Post-generation canary and secret masking. |
| **Central Engine** | `kavach_guard/engine.py` | Orchestrates multi-layer decisions and telemetry. |
| **Audit DB** | `kavach_guard/db.py` | Asynchronous SQLite audit store (`kavach.db`). |
| **Gateway API** | `kavach_guard/server.py` | FastAPI server exposing documented `/api/v1/security/*` endpoints. |
| **Benchmark Suite** | `kavach_benchmark/baselines.py` | Evaluates B0 through B6 with Wilson 95% confidence intervals. |
