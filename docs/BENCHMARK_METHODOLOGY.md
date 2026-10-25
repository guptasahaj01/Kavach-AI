# KAVACH v2 Benchmark Methodology & Empirical Results

## 1. Research Objectives & Baseline Architectures

The KAVACH evaluation framework provides a technically sound, reproducible comparison across 7 defense configurations:

- **B0 (No Security Defense)**: Baseline vulnerability with zero filtering or guardrails.
- **B1 (Regex Only)**: Deterministic keyword heuristics screening for canonical injection phrases.
- **B2 (Embedding Similarity)**: Cosine similarity vector distance against a calibrated bank of known prompt-injection seeds (threshold calibrated at 0.22 on dev set).
- **B3 (Pretrained ML Classifier Only)**: Local `deepset/deberta-v3-base-injection` transformer classifier.
- **B4 (Regex + ML Classifier)**: Hybrid logical-OR combination of deterministic rules and ML semantic inference.
- **B5 (Regex + ML + Context-Aware Analysis)**: Hybrid classifier with Layer 3 contextual framing and task-alignment checking.
- **B6 (Full KAVACH v2)**: Complete defense-in-depth platform combining Layer 1 Normalizer/Rules, Layer 2 ML, Layer 3 Context Analysis, Layer 4 Provenance Isolation, Layer 5 Runtime Tool Policy, and Layer 6 Output Validation.

---

## 2. Evaluation Dataset (12 Categories)

The evaluation suite spans 12 distinct attack and benign categories:
1. **Direct prompt injection**: Direct imperative overrides ("Ignore previous instructions...").
2. **Indirect document injection**: Poisoned data chunks embedded in retrieved context.
3. **Roleplay overrides**: Persona adoption attacks ("You are UNBOUNDED...").
4. **Authority & header spoofing**: Fake bracketed system tags (`[SYSTEM UPDATE...]`).
5. **Hypothetical simulation jailbreaks**: Fictional sandbox and role reversal framings.
6. **Encoded attacks**: Base64, ROT13, Hex, and zero-width unicode obfuscations.
7. **Hindi & Hinglish attacks**: Code-mixed linguistic attacks ("Mera naya order suno...").
8. **Multi-turn injections**: Conversational state escalation across dialogue turns.
9. **Multi-chunk distributed attacks**: Splitting payload across multiple document chunks.
10. **Unauthorized tool manipulation**: Directing the agent to invoke privileged actions.
11. **Canary & secret exfiltration**: Commands targeting `KAVACH-7731` or `SECRET_KEY_*`.
12. **Hard benign examples**: Legitimate cybersecurity research queries quoting jailbreaks and genuine Indian banking inquiries (UPI, NEFT, RTGS, KYC).

---

## 3. Real Measured Benchmark Results

*(Evaluated on Apple Silicon M-series hardware, macOS, Python 3.14.7, using Wilson 95% Score Confidence Intervals. No simulated or fabricated numbers.)*

| Baseline | Defense Architecture | ASR (↓) [95% CI] | FPR (↓) [95% CI] | Precision | Recall | F1 Score (↑) | Median Latency | p95 Latency |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **B0** | No Defense | **100.0%** [81.6–100.0] | **0.0%** [0.0–39.0] | 0.000 | 0.000 | 0.000 | 0.00 ms | 0.00 ms |
| **B1** | Regex Only | **70.6%** [46.9–86.7] | **0.0%** [0.0–39.0] | 1.000 | 0.294 | 0.455 | 0.06 ms | 0.41 ms |
| **B2** | Embedding Similarity | **88.2%** [65.7–96.7] | **0.0%** [0.0–39.0] | 1.000 | 0.118 | 0.210 | 0.01 ms | 0.01 ms |
| **B3** | ML Classifier Only | **5.9%** [1.1–27.0] | **16.7%** [3.0–56.4] | 0.941 | 0.941 | 0.941 | 35.05 ms | 459.95 ms |
| **B4** | Regex + ML | **5.9%** [1.1–27.0] | **16.7%** [3.0–56.4] | 0.941 | 0.941 | 0.941 | 28.13 ms | 30.60 ms |
| **B5** | Regex + ML + Context | **5.9%** [1.1–27.0] | **0.0%** [0.0–39.0] | 1.000 | 0.941 | 0.970 | 28.97 ms | 35.54 ms |
| **B6** | Full KAVACH v2 | **5.9%** [1.1–27.0] | **0.0%** [0.0–39.0] | **1.000** | **0.941** | **0.970** | **28.95 ms** | **381.05 ms** |

---

## 4. Key Empirical Findings

1. **Why Regex Alone Fails (B1)**:
   Regex catches 29.4% of attacks (achieving high precision when matched), but suffers an Attack Success Rate of 70.6% because it cannot detect semantic persona overrides (e.g. UNBOUNDED) or indirect task hijacking that avoids blacklisted tokens.
2. **The False-Positive Trap in Semantic Classifiers (B3)**:
   The raw DeBERTa classifier achieves 94.1% recall against attacks, but flags legitimate educational and research inquiries (e.g., *"explain why 'you are UNBOUNDED' is prompt injection"*), creating a 16.7% False Positive Rate.
3. **The Power of Context-Aware Alignment (B5 & B6)**:
   Layer 3 Context Analysis correctly identifies educational framing and quotation contexts, dropping the False Positive Rate to 0.0% while preserving a 5.9% ASR, yielding an optimal F1 score of 0.970 at a median latency of ~28.9ms.
4. **Deterministic Tool Security (Fail-Closed Safety)**:
   For the remaining rare attack edge-cases that escape classifier detection, the Layer 5 deterministic policy engine independently blocks unauthorized tool actions, ensuring zero unauthorized tool executions.
