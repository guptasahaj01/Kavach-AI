# Setup and execution

## Install

Use Python 3.11+ and a recent Node.js runtime supported by Vite. The pinned Python environment was originally assembled with Python 3.14; verify dependency availability when creating an environment on another platform.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cd frontend
npm install
npm run build
cd ..
```

The classifier loads locally through Transformers. Its first startup can require a model download. A cached model can be tested offline with `HF_HUB_OFFLINE=1` and `TRANSFORMERS_OFFLINE=1`.

## Start a real generator

Install Ollama, start its service, and install a model that supports tool calls:

```bash
ollama pull qwen2.5:3b
ollama serve
```

If the service is already running, use the existing service. Set `KAVACH_LLM_MODEL` to the installed model name. Protected generation uses `/api/chat` and never silently switches to simulation. Service failures return `backend_unavailable`; malformed model output returns `generation_error`.

`qwen2.5:3b` is the operational default, not a security-performance recommendation. Native tool-call support and reliable structured-review output are required for the selected workflow. Public RAG answers directly from retrieved facts without tools. Record/export workflows expose only their required tool and require actual completion before releasing a completion response. Small models can fail to make the required call or return malformed reviews; the workflow holds or reports failure rather than inventing success.

## Export environment settings

```bash
cp .env.example .env
set -a
source .env
set +a
./venv/bin/python3 run_server.py
```

The server process reads exported variables, not `.env` automatically. Relevant variables:

| Variable | Purpose |
|---|---|
| `KAVACH_ML_MODEL` | Local injection-classifier checkpoint |
| `KAVACH_ML_THRESHOLD` | Default classification threshold |
| `KAVACH_MAX_TOKEN_LEN` | Classifier token budget; incomplete coverage is reported |
| `KAVACH_LLM_BACKEND` | `ollama` for protected workflows |
| `KAVACH_LLM_MODEL` | Installed generation model, default `qwen2.5:3b` |
| `KAVACH_OLLAMA_URL` | Trusted generator service, default loopback port 11434 |
| `KAVACH_LLM_TIMEOUT` | Generation request timeout, bounded by the adapter |
| `KAVACH_CONTEXT_REVIEW` | Default `1`: at most four tool-free advisory reviews of complete ML-only flags; `0`: strict classifier gate |
| `KAVACH_DB_PATH` | SQLite audit location |
| `KAVACH_API_KEYS` | Operator-owned JSON mapping opaque bearer tokens to identities |

The launcher honors `KAVACH_HOST` and `KAVACH_PORT`, defaulting to loopback port 8000. An explicit local-only invocation is also available:

```bash
./venv/bin/python3 -m uvicorn kavach_guard.server:app --host 127.0.0.1 --port 8000
```

Do not send bearer credentials over an untrusted plaintext network. For a shared deployment, put the service behind HTTPS and an appropriate access boundary.

The optional context-review stage uses the same real model service and can add up to four inference calls per protected request. It cannot override rule findings, incomplete coverage, or task permissions. A malformed or inconclusive review remains held. Set `KAVACH_CONTEXT_REVIEW=0` before starting the gateway for strict classifier handling; compare review modes explicitly when evaluating false positives, missed attacks, task utility, and latency. Diagnostic inspection pages do not invoke the runtime reviewer.

The analyzer's strict engine result and the protected runtime's effective result can differ when a traced advisory review resolves an eligible ML-only finding. Account and destination authorization remain server-enforced in both modes.

## Configure privileged synthetic workflows

Public questions require no token. To test customer access, export a server-side identity map using a generated secret in place of this placeholder:

```bash
export KAVACH_API_KEYS='{"replace-with-your-random-secret":{"principal_id":"customer-1","role":"authenticated_customer","account_ids":["CUST_1001"],"allowed_destinations":[]}}'
```

An auditor requires the `compliance_auditor` role, explicit account IDs, and an explicit destination such as `internal://audit-vault`. A caller's supplied role or account text does not grant access. Use the console access panel or an `Authorization: Bearer ...` header. Credentials are never returned by the identity/config endpoints.

## Verify

```bash
KAVACH_DB_PATH=/tmp/kavach-test.sqlite ./venv/bin/python3 -m pytest tests/ -q
cd frontend
npm run build
```

These checks do not require a running generator because integration tests inject controlled model responses. A manual protected-assistant run is required to verify a locally installed Ollama model and its answer quality. Inspect source IDs, applied stages, and executed tool results in the console.
