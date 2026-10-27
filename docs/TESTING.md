# Verification strategy

Run the suite with an isolated audit database:

```bash
KAVACH_DB_PATH=/tmp/kavach-test.sqlite ./venv/bin/python3 -m pytest tests/ -q
```

For cached classifier weights, add `HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1`. Tests that exercise real classifier inference require a compatible cached checkpoint. The suite also uses controlled detector/model responses to force security edge cases; no paid generation service is required.

## Security invariants

Tests should exercise the same runtime and dispatcher called by the API:

- Educational-looking framing cannot exempt active malicious commands outside quotations.
- Model errors, partial inspection, and truncation remain explicit uncertainty.
- Only complete ML-only flags with zero rule matches can enter bounded advisory review; at most four reviews occur per protected request. Review output must be a strict `ALLOW`/`REVIEW` object, tool proposals and malformed output hold, and an advisory allow cannot broaden scope. Test enabled and strict modes plus reviewer-targeted injection attempts.
- Quarantined content is absent from the actual generation input.
- Original document/chunk identities survive retrieval and inspection.
- Caller-supplied role fields cannot increase authority.
- A customer can access an assigned record and cannot access a different record.
- Missing handlers/schemas, extra arguments, expired scopes, and unauthorized destinations fail closed.
- A denied tool proposal invokes no handler and produces no synthetic side effect.
- An authorized action can execute, providing a positive control.
- Tool results and final answers are checked before re-entry or delivery.
- Model-service failures and audit failures surface as explicit states.

The detector-bypass test must force permissive detection and a malicious proposal through the real workflow. Writing an `if authorized` branch only inside a test does not verify the application dispatcher.

## Frontend

```bash
cd frontend
npm run build
```

The console differentiates applied workflow stages, component readiness, detector results, and simulations. Missing values are not replaced with invented latency or a benign label. Authentication presets cannot assign a role.

## Manual real-model check

Start Ollama with a tool-capable model and the gateway. Use the Protected Assistant for public questions and configured synthetic account workflows. Confirm context preview/digest, citations, tool decisions, delivery status, and audit status. The diagnostic context is redacted where needed; exact model-input assertions belong in runtime tests. Inspect any `context_review` stages and compare with `KAVACH_CONTEXT_REVIEW=0` when evaluating the reviewer. This verifies local model integration; it does not replace a held-out adversarial campaign or factual-answer evaluation.

Run the small versioned real-model boundary campaign with `python -m kavach_benchmark.runtime_evaluation`; add `--detector-bypass` to force permissive inspection while retaining authorization and output validation. Inspect the unique run manifest and inconclusive outcomes before interpreting its summary. The evaluation tests use explicitly labeled model doubles to verify scoring and persistence without requiring a generator.
