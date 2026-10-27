# KAVACH: Protected Banking RAG and Tool Execution

KAVACH is a research gateway for studying prompt-injection detection and containment. It combines local semantic classification, source-aware retrieval, task-scoped synthetic tools, output checks, and request traces. Banking documents, rates, and customer records in this repository are demonstration data, not current official banking advice.

## The protected workflow

`POST /api/v1/rag/query` runs one enforced path:

**Authenticated identity → application-defined task scope → prompt inspection → retrieval → chunk inspection/quarantine → protected model context → proposed tools → authorization and synthetic execution → checked tool results → validated answer.**

Only accepted chunks enter generation. The protected route fixes its containment policy server-side; callers cannot disable it. A model proposes actions but cannot grant itself permissions or select an identity. Unauthorized calls are denied before execution. If inspection is incomplete, the model is unavailable, evidence is insufficient, or output checks fail, the response reports that state rather than substituting a simulated answer.

By default, `KAVACH_CONTEXT_REVIEW=1` enables a bounded advisory review for complete inspections flagged only by ML, with no rule findings. The configured real backend receives a separate structured review request without tools and may return only `ALLOW` or `REVIEW`, at most four times per protected request. Concrete rule findings and incomplete coverage remain enforced. Setting `KAVACH_CONTEXT_REVIEW=0` keeps the strict classifier gate. This fallible review can reduce false positives or admit malicious material incorrectly; its effect needs independent evaluation. It never changes account, destination, or tool permissions.

The generator uses Ollama's real `/api/chat` interface. Synthetic tools do not move money, send email, or contact export destinations. Exports record a local audit event and derive their payload from the server-authorized synthetic record.

The operational default is `qwen2.5:3b`. This is a local deployment choice, not a claim that the model is the best detector, reviewer, or attack-resistant generator. Sensitive workflows require native tool-call support, and advisory review requires the strict response schema. Malformed review responses remain held, and sensitive workflows are not marked completed unless their required operation actually executes.

## Quick start

The repository includes a Python environment on this workstation. For a fresh installation:

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Install and start Ollama separately, then install the configured generation model:

```bash
ollama pull qwen2.5:3b
ollama serve
```

Build the console:

```bash
cd frontend
npm install
npm run build
cd ..
```

Configure the gateway environment, then start it:

```bash
cp .env.example .env
set -a
source .env
set +a
./venv/bin/python3 run_server.py
```

Open [the console](http://127.0.0.1:8000/) or [API documentation](http://127.0.0.1:8000/docs). The first classifier initialization may download Hugging Face weights. An unavailable classifier yields a review outcome; it does not establish that input is safe.

## Identity and task scope

Without a bearer token, a caller has anonymous public-only access. Privileged identities are configured by the operator using `KAVACH_API_KEYS`; request-body fields such as `caller_role` never establish authority.

Example configuration using placeholder credentials that must be replaced:

```bash
export KAVACH_API_KEYS='{"replace-with-a-long-random-customer-token":{"principal_id":"customer-1","role":"authenticated_customer","account_ids":["CUST_1001"],"allowed_destinations":[]},"replace-with-a-different-auditor-token":{"principal_id":"auditor-1","role":"compliance_auditor","account_ids":["CUST_1001"],"allowed_destinations":["internal://audit-vault"]}}'
```

The console's access panel stores an entered token only for the current browser tab. Use a trusted HTTPS deployment when accessing a server over a network.

| Protected assistant workflow | Model action scope |
|---|---|
| `public_banking` | Answer directly from inspected retrieved facts; no model tools |
| `own_records` | Only the account-read tool for the selected assigned synthetic account |
| `audit_export` | Only the export tool for the selected assigned account and approved destination, for auditor/admin identities |

Scopes expire and bound tool calls. Restricted operations require both role permission and explicit resource permission. Unimplemented transfer, email, and record-modification tools remain unavailable even to an administrator.

## Console and API

The **Protected Assistant** shows the delivered answer, source IDs, a redacted context preview, an exact-input SHA-256 digest, tool decisions, and stage trace. The preview may differ from internal model input where disclosure checks redact sensitive text. **Tool Security** evaluates or executes proposals using the authenticated identity. **Prompt Analyzer** and **RAG Inspector** inspect supplied text; they do not execute a complete assistant task or the runtime's advisory review. The **Research Simulation Sandbox** intentionally exposes experimental defense controls and simulated outputs, separately from the protected route.

Diagnostic inspection reports the engine's strict decision. The protected runtime can additionally review eligible ML-only findings in its authenticated task context, so the same text may be held in the analyzer and accepted after an explicitly traced advisory review. This does not change tool permissions. The standalone Tool Security page can separately exercise public synthetic tools; those tools are not exposed to the protected public-RAG model.

Important endpoints:

- `GET /api/v1/security/identity`: resolved identity and available workflows.
- `POST /api/v1/rag/query`: protected model workflow.
- `POST /api/v1/security/authorize-tool`: policy evaluation without execution.
- `POST /api/v1/tools/execute`: authorization followed by local synthetic execution.
- `POST /api/v1/security/analyze`: detector evidence and decision.
- `POST /api/v1/security/analyze-document`: provenance-aware inspection preview.
- `GET /api/v1/security/status`: component readiness, not proof of checks applied to a request.

## Evaluation: three different kinds of evidence

1. **Execution-invariant tests:** exercise the protected workflow with controlled model proposals and synthetic handlers. They verify boundaries such as no execution after denial and no quarantined content reaching generation. Controlled model responses do not measure real-model attack success.
2. **Detector comparison:** `python -m kavach_benchmark.smoke_test` compares B0–B6 on the diagnostic corpus. The historical corpus has 17 attacks and six benign examples. The legacy `asr` field is a **detector miss rate**, not observed compromise. B2 is token Jaccard overlap, and B6 evaluates gateway inspection rather than every runtime layer.
3. **72-configuration simulation:** `python run_benchmark.py` defaults to a programmed susceptibility model. Existing results and figures in `outputs/` are historical simulation artifacts. They do not establish real-model robustness or latency. All current documents are shorter than every chunk-size setting.

Do not combine these evidence types into one security claim. Zero false positives on six benign examples is insufficient evidence of a zero population false-positive rate. Saved results are not automatically regenerated after code changes.

For a real-model boundary evaluation, run:

```bash
./venv/bin/python3 -m kavach_benchmark.runtime_evaluation
./venv/bin/python3 -m kavach_benchmark.runtime_evaluation --detector-bypass
```

Each command writes a unique run directory with a dataset/code manifest, per-scenario outcomes, and summary. The second deliberately bypasses inspection only inside the local evaluation harness, while preserving tool authorization and output checks. The six synthetic fixtures test forced-context boundaries, not retrieval recall or representative attack coverage. Missing model infrastructure remains inconclusive. Unit-test model doubles are labeled separately from real-model runs.

## Verification

```bash
KAVACH_DB_PATH=/tmp/kavach-test.sqlite ./venv/bin/python3 -m pytest tests/ -q
cd frontend
npm run build
```

See [setup](docs/SETUP.md), [architecture](docs/ARCHITECTURE.md), [security boundaries](docs/SECURITY_MODEL.md), [evaluation methodology](docs/BENCHMARK_METHODOLOGY.md), [testing](docs/TESTING.md), and [limitations](docs/LIMITATIONS.md).
