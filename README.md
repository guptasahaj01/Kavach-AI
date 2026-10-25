# KAVACH v2: Context-Aware, Provenance-Driven AI Security Gateway

> **A Multi-Tiered AI Security Defense Platform & Empirical Benchmark Suite for LLM Agents and Indian Retail Banking RAG Systems**  
> *Developed for VIT Vellore, School of Computer Science and Engineering (Team 10)*

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![FastAPI](https://img.shields.io/badge/FastAPI-2.0.0-009688.svg)](https://fastapi.tiangolo.com)
[![PyTorch](https://img.shields.io/badge/PyTorch-2.14.1-EE4C2C.svg)](https://pytorch.org)
[![HuggingFace](https://img.shields.io/badge/Transformers-5.20.2-yellow.svg)](https://huggingface.co)
[![Tests Passing](https://img.shields.io/badge/pytest-54%20passed-brightgreen.svg)](tests/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

---

## 🌟 Overview

**KAVACH v2** upgrades the prototype into a production-grade, multi-tier AI defense gateway that bridges the gap between empirical security research (a 72-configuration Indian banking RAG benchmark) and real-world runtime defense (inspired by platforms like Lakera AI, Llama Guard, and Cloudflare AI Gateway).

It addresses the fundamental flaw of simple keyword filters: **semantic persona overrides (e.g. UNBOUNDED, DAN) and indirect prompt injections bypass regex heuristics completely**. KAVACH v2 implements an asymmetric two-tiered compute model with context-aware analysis and deterministic pre-execution tool sandboxing.

### Core Defense Layers
1. **Layer 1: Deterministic Security Scanner & Normalizer (< 2ms)**: NFKC canonicalization, zero-width stripping, homoglyph mapping, multi-decoder (Base64, ROT13, Hex, URL), structured findings, Indian financial PII (PAN, Aadhaar with Verhoeff, IFSC, Cards with Luhn), and canary traps.
2. **Layer 2: Pretrained ML Injection Classifier (~25ms CPU/MPS)**: Real local transformer inference using `deepset/deberta-v3-base-injection` with Apple Silicon MPS hardware acceleration, truncation handling, and lazy-loaded singleton caching.
3. **Layer 3: Context-Aware Security Analysis**: Algorithmic distinction between active attacks and legitimate security research or educational quotations (eliminates false positives). Evaluates task-alignment against out-of-band side-effect commands.
4. **Layer 4: Provenance-Aware RAG Protection**: Application-controlled metadata tracking (`document_id`, `chunk_id`, `trust_level="untrusted_data"`, `instruction_authority=FALSE`). Prevents retrieved document text from self-elevating authority. Implements structural Sandwich Defense boundary isolation.
5. **Layer 5: Deterministic Runtime Tool Policy Engine**: Independent fail-closed authorization gate for proposed tool actions. Enforces RBAC (`READ_ONLY_TOOLS` vs `RESTRICTED_TOOLS`), Pydantic argument validation, and destination allowlists before any tool executes.
6. **Layer 6: Output Validation & Secrets Masking**: Post-generation canary verification (`KAVACH-7731`) and sensitive token filtering before response delivery.

---

## 🏗️ Target Architecture

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

## 📊 Real Measured Benchmark Results (B0 to B6)

*(Evaluated on Apple Silicon M-series hardware, macOS, Python 3.14.7, using Wilson 95% Score Confidence Intervals. No simulated or fabricated data.)*

| Baseline | Architecture | ASR (↓) [95% CI] | FPR (↓) [95% CI] | Precision | Recall | F1 Score (↑) | Median Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **B0** | No Defense | **100.0%** [81.6–100.0] | **0.0%** [0.0–39.0] | 0.000 | 0.000 | 0.000 | 0.00 ms |
| **B1** | Regex Only | **70.6%** [46.9–86.7] | **0.0%** [0.0–39.0] | 1.000 | 0.294 | 0.455 | 0.06 ms |
| **B2** | Embedding Similarity | **88.2%** [65.7–96.7] | **0.0%** [0.0–39.0] | 1.000 | 0.118 | 0.210 | 0.01 ms |
| **B3** | ML Classifier Only | **5.9%** [1.1–27.0] | **16.7%** [3.0–56.4] | 0.941 | 0.941 | 0.941 | 35.05 ms |
| **B4** | Regex + ML | **5.9%** [1.1–27.0] | **16.7%** [3.0–56.4] | 0.941 | 0.941 | 0.941 | 28.13 ms |
| **B5** | Regex + ML + Context | **5.9%** [1.1–27.0] | **0.0%** [0.0–39.0] | 1.000 | 0.941 | 0.970 | 28.97 ms |
| **B6** | **Full KAVACH v2** | **5.9%** [1.1–27.0] | **0.0%** [0.0–39.0] | **1.000** | **0.941** | **0.970** | **28.95 ms** |

---

## 🚀 Quickstart

### 1. Installation
```bash
# Clone and navigate
cd /path/to/lakera

# Activate virtual environment
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Start Backend & Security Console
```bash
./run_server.py
```
- Gateway Server: `http://127.0.0.1:8000`
- Swagger OpenAPI Docs: `http://127.0.0.1:8000/docs`
- Security Console UI: `http://127.0.0.1:8000/`

### 3. Run Benchmark Suite
```bash
./venv/bin/python3 -m kavach_benchmark.smoke_test
```

### 4. Run Automated Test Suite
```bash
./venv/bin/pytest tests/ -v
```

---

## 🛡️ Mandatory Security Test: Detector-Bypass Proof

A core architectural principle of KAVACH v2 is that **missed detection does not imply unauthorized action execution**.

In `tests/integration/test_policy_bypass.py`:
1. The prompt injection detector is intentionally bypassed using a permissive test stub.
2. The LLM blindly follows a malicious document directive and proposes an unauthorized tool call (`simulated_external_export` to an external endpoint).
3. The Layer 5 `ToolPolicyEngine` independently intercepts and rejects the action before execution (`DENY_PERMISSION`/`DENY_DESTINATION`).
4. Result: Zero unauthorized actions occur (fail-closed).

---

## 📚 Technical Documentation

- [System Architecture](docs/ARCHITECTURE.md)
- [Security Model & Threat Boundaries](docs/SECURITY_MODEL.md)
- [Benchmark Methodology & Results](docs/BENCHMARK_METHODOLOGY.md)
- [Setup & Deployment Guide](docs/SETUP.md)
- [Automated Testing Strategy](docs/TESTING.md)
- [Known Limitations & Future Work](docs/LIMITATIONS.md)
