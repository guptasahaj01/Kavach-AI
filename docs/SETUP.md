# KAVACH v2 Setup & Execution Guide

## System Prerequisites
- macOS (tested on Apple Silicon arm64) or Linux x86_64
- Python 3.11 or later (tested on Python 3.14.7)
- Node.js 18+ and npm (for React developer console dashboard)
- 4GB+ RAM (no discrete CUDA GPU required; Apple Silicon MPS accelerated)

---

## 1. Environment Installation

```bash
# Clone or navigate into repository
cd /path/to/lakera

# Create and activate Python virtual environment
python3 -m venv venv
source venv/bin/activate

# Install locked dependencies
pip install -r requirements.txt
```

---

## 2. Configuration (`.env`)

Create a `.env` file from the example template:

```bash
cp .env.example .env
```

Configuration variables:
```bash
# Gateway Port & Host
KAVACH_HOST=127.0.0.1
KAVACH_PORT=8000

# Pretrained Transformer Classifier (Default: ungated, local)
KAVACH_ML_MODEL=deepset/deberta-v3-base-injection
KAVACH_ML_THRESHOLD=0.50
KAVACH_MAX_TOKEN_LEN=512

# Optional Hugging Face Token (required only if testing meta-llama/Llama-Prompt-Guard-2-22M or 86M)
# HF_TOKEN=your_token_here

# SQLite Persistence Path
KAVACH_DB_PATH=kavach.db
```

---

## 3. Running the Gateway Server

```bash
# Start FastAPI backend and serve built frontend
./run_server.py
```
The server will bind to `http://127.0.0.1:8000`.
- API Documentation (Swagger/OpenAPI): `http://127.0.0.1:8000/docs`
- Developer Security Console: `http://127.0.0.1:8000/`

---

## 4. Running the Smoke Benchmark (B0 to B6)

Execute the 7-baseline comparative benchmark across the 12 evaluation categories:

```bash
./venv/bin/python3 -m kavach_benchmark.smoke_test
```
This generates:
- Formatted console comparison table with Wilson 95% CIs
- `outputs/baseline_comparison.csv`
- `outputs/baseline_comparison.json`

---

## 5. Running Automated Pytest Suite

```bash
# Full test suite (54 tests across unit, integration, and E2E)
./venv/bin/pytest tests/ -v

# Mandatory detector-bypass policy test
./venv/bin/pytest tests/integration/test_policy_bypass.py -v

# End-to-end scenarios A through E
./venv/bin/pytest tests/e2e/test_end_to_end_scenarios.py -v
```

---

## 6. Building the Frontend Console

```bash
cd frontend
npm install
npm run build
cd ..
```
The built static bundle in `frontend/dist/` is automatically served on `http://127.0.0.1:8000/`.
