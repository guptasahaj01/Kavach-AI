# KAVACH v2 Known Limitations & Future Research

## 1. Explicit Non-Claims (Honesty & Defensibility)

In alignment with academic integrity and rigorous security engineering:
- **KAVACH does NOT claim complete immunity from prompt injection attacks.** Prompt injection is an open theoretical problem stemming from the unified data/instruction architecture of transformer-based LLMs.
- KAVACH delivers **measurable empirical reduction in Attack Success Rate (from 100% in B0 to 5.9% in B6)** and guarantees **deterministic fail-closed containment of unauthorized tool actions** at runtime.

---

## 2. Technical Limitations & Edge Cases

### A. Low-Resource Regional Indian Languages
While KAVACH's Layer 1 normalizer and Layer 3 context analyzer support English and common Hindi/Hinglish transliterated attacks, adversarial payloads expressed entirely in low-resource regional Indian scripts (e.g., Tamil, Telugu, Bengali, Kannada) may evade English-centric transformer classifiers like `deberta-v3-base-injection`.
- *Mitigation*: Fall back to script-agnostic canary tracking, token entropy anomaly detection, and Layer 5 strict tool authorization.

### B. Probabilistic Nature of Context Boundaries
Sandwich prompting and structural delimiters (`[DOCUMENT_REF authority=FALSE]`) mitigate attention recency bias, but cannot theoretically guarantee that an LLM will never follow an embedded directive.
- *Mitigation*: KAVACH never treats prompt formatting as a security boundary. Hard security enforcement is delegated to Python code in Layer 5 (Tool Policy Engine).

### C. Conversational Multi-Turn Semantic Drift
In long multi-turn sessions (10+ turns), an attacker may gradually build up adversarial context using incremental, innocuous-looking prompts that individually score below detection thresholds.
- *Mitigation*: Session-level threat score accumulation and stateful conversation history tracking.

### D. Hardware Inference Latency for Long Documents
While median per-query latency is ~28.9ms on Apple Silicon (MPS), processing multi-chunk RAG documents with 5+ chunks of 512 tokens each on CPU hardware without hardware acceleration can incur 150–400ms latency.
- *Mitigation*: Batch tokenization, input length truncation (capped at 512 tokens), and fast-path rule rejection before invoking the ML model.

---

## 3. Future Research Directions

1. **Adversarial Multilingual Fine-Tuning**: Fine-tuning an XLM-RoBERTa or IndicBERT model specifically on synthetic Indian retail banking red-team datasets.
2. **Dynamic Agent Replay Testing**: Automated generation of multi-agent red-team dialogue trees to evaluate conversational jailbreak resilience.
3. **Information Flow Control (IFC)**: Formally tracking taint tags from retrieved document chunks through model output tokens to tool arguments.
