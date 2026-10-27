# Limits and next research steps

KAVACH is a research implementation with explicit application boundaries, not a claim of complete prompt-injection immunity or banking production readiness.

## Current limits

- Shipped banking facts, rates, and customer records are synthetic demonstration data. Regulatory labels do not establish current official guidance.
- Retrieval uses deterministic TF-IDF over public files. General ingestion permissions, tenant ACLs, authoritative source updates, and semantic retrieval evaluation are not implemented.
- The protected generator requires a running Ollama service and compatible model; sensitive workflows additionally require native tool-call support. No simulated fallback hides an unavailable service.
- `qwen2.5:3b` is an operational default, not evidence of superior security or reliable performance on all workflows. Models may fail the strict review schema, omit a required native tool call, or generate an unsupported answer. Invalid reviews remain held, and sensitive workflows require actual operation completion. Evaluate capability and security separately using matched scenarios and the installed model revision.
- Classifier/context decisions remain fallible, especially on unfamiliar languages, encodings, distributed instructions, and adversarial conversations.
- The default bounded context reviewer may reduce ML-only false positives but is itself exposed to prompt injection and can wrongly admit malicious material or withhold benign material. It has no tools, cannot override rule/coverage holds or expand task scope, and is capped at four reviews per request. Those constraints do not guarantee semantic correctness. Compare `KAVACH_CONTEXT_REVIEW=1` with `0` on held-out attacks and hard-benign tasks, including the added inference cost.
- Quarantine can remove useful evidence. When insufficient relevant material remains, the workflow requests review rather than inventing an answer.
- Provenance fields and source labels are not full taint tracking through arbitrary generated text. Output pattern matching is not comprehensive data-loss prevention.
- Authentication is an operator-configured opaque token map suitable for a local research gateway. Enterprise identity, rotation/revocation infrastructure, per-tenant storage isolation, and deployment hardening require additional work.
- Tools are local simulations. External export destinations are labels for allowed synthetic operations; no real data transmission, money transfer, or email implementation is supplied.
- The original detector corpus is very small. Its miss rate is not an end-to-end compromise rate.
- The historical 72-configuration results are simulated, with ineffective chunk-size variation on the existing short documents. Existing figures must not be used as real-model causal evidence.
- Controlled execution tests verify specific code invariants, not population-level attack effectiveness or universal security.

## Prioritized extensions

First expand independent held-out scenarios and measure legitimate task success under attack. Then compare classifiers and context policies using matched inputs and source-aware outcomes. Add multilingual and genuine multi-turn/multi-chunk attacks, source-grounding checks, and immutable run provenance. Consider dependency graphs, replay detection, or conservative data-flow labels when measured failures justify their complexity.

Retain the application-owned permission boundary regardless of detector choice. Real deployments must protect configuration, credentials, network access, sensitive storage, and trusted server code.
