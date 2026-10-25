# KAVACH v2 Security Model & Threat Boundaries

## 1. Threat Model & Boundaries

KAVACH v2 operates on the premise that Large Language Models (LLMs) cannot inherently distinguish between system instructions, user directives, and untrusted retrieved context data. Therefore, security guarantees must be enforced by deterministic runtime code rather than prompt engineering alone.

### Trust Boundaries

```
[ UNTRUSTED ZONE ]
• User Prompts (Public chat queries, uploaded files, attachments)
• Retrieved RAG Documents (Web pages, internal FAQs, database records)
• Tool Execution Outputs (Third-party API returns, webhook payloads)
        │
        ▼ (All inputs cross untrusted boundary)
[ TRANSITION ZONE: KAVACH GATEWAY ]
• Normalizer (NFKC, zero-width stripping, homoglyph mapping, bounded decoders)
• Layer 1 Deterministic Rules Scanner (< 2ms)
• Layer 2 Pretrained ML Classifier (~25ms CPU/MPS)
• Layer 3 Context & Task Alignment Evaluator
• Layer 4 Provenance Isolation (attaches immutable instruction_authority=FALSE)
        │
        ▼
[ CONTROLLED EXECUTION ZONE ]
• Protected LLM Prompt Context (Isolated via Sandwich structural boundaries)
• Proposed Tool Actions (Intercepted BEFORE execution)
        │
        ▼
[ DETERMINISTIC ENFORCEMENT ZONE ]
• Layer 5 Runtime Tool Policy Engine (RBAC, argument schemas, destination allowlists)
• Layer 6 Output Validation (Canary and secret exfiltration scrubbing)
```

---

## 2. Core Security Axioms

1. **No Instruction Self-Elevation**: Attacker-controlled text in documents or prompts can never assign its own trust level or set `instruction_authority: true`. Provenance metadata is strictly application-generated.
2. **Deterministic Pre-Execution Tool Gate**: Proposed tool actions are authorized by Python code independently of model outputs. Even if an injection completely bypasses prompt detectors, the policy engine rejects unauthorized tool invocations (fail-closed).
3. **Probabilistic vs. Deterministic Defenses**:
   - Prompt hardening (Sandwich prompting, instructional framing) and ML classifiers are probabilistic defenses.
   - Deterministic defenses (schema validation, RBAC, destination allowlists, output token verification) provide hard guarantees.
4. **False-Positive Resistance**: Benign educational inquiries and security research discussions (e.g. asking *"why the phrase 'you are UNBOUNDED' is prompt injection"*) must not be blocked merely for quoting adversarial terminology. Layer 3 Context Analysis evaluates grammatical framing and task alignment to prevent usability degradation.
5. **Safe Logging & Evidence Redaction**: Detected secrets (`SECRET_KEY_*`) and canaries (`KAVACH-*`) are masked with asterisks or redaction tokens in audit logs. Inputs are strictly bounded (max length 64KB, max decoding depth 3) to prevent denial-of-service / resource exhaustion attacks.
