# Group 10: Review 3

Members: Sahaj Gupta (24BBS0166), Shllok Chaudhari (24BBS0113), Ankur Sinha (24BBS0102).

## Deliverable

KAVACH_Group10_Review3.pptx contains 26 editable slides, actual local screenshots, final test counts, a fresh detector comparison, saved real-model workflow results, limitations, future work and an EchoLeak case study. Individual responsibility allocations are suggestions that each member must confirm. The threat-model slide reconstructs the implemented security model because the original Review 1 submission was not supplied. Confirm incident uniqueness with the instructor.

## Run the live demo

From the repository root, install dependencies as described in the main README, start Ollama with qwen2.5:3b installed, build the console and start the server:

```bash
cd frontend
npm ci
npm run build
cd ..
./venv/bin/python3 run_server.py
```

Open http://127.0.0.1:8000. Demonstrate the analyzer, retrieved-document quarantine and an anonymous export denial. Banking documents/tools are synthetic examples of the gateway.

## Reproduce Review 3 evidence

```bash
./venv/bin/python3 -m pytest tests/ -q -p no:cacheprovider
PYTHONPATH=. ./venv/bin/python3 outputs/review3/reproduce.py
```

The incident script sends only synthetic data to the local server, checks a forbidden tool request and checks a synthetic secret in output. It performs no external exfiltration and does not recreate Copilot email ingestion or the Teams proxy.

Fresh detector comparison:

```bash
./venv/bin/python3 - <<'PY'
import json
from pathlib import Path
from kavach_benchmark.baselines import BaselineEvaluator
results = BaselineEvaluator().run_all_baselines()
Path('outputs/review3/current-baselines.json').write_text(json.dumps([x.model_dump() for x in results], indent=2))
PY
```

Evidence collected 02 Nov 2026: `current-baselines.json`, `incident-probes.json`, `test-results.txt` and screenshots in `assets/`. The deck separately identifies historical real-model results in `outputs/runtime_runs/`. It does not treat detector miss rate, programmed simulation and actual execution outcomes as interchangeable evidence.

## Case-study sources

- Microsoft advisory: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-32711
- Official Microsoft CVRF record: https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2025-Jun
- NVD: https://nvd.nist.gov/vuln/detail/CVE-2025-32711
- Checkmarx technical analysis: https://checkmarx.com/zero-post/echoleak-cve-2025-32711-show-us-that-ai-security-is-challenging/
- Reddy and Gujral case study: https://arxiv.org/html/2509.10540v1

Microsoft rated the vulnerability Critical (9.3). NVD displays a separate NIST assessment of 7.5. The slides attribute 9.3 to Microsoft. The January/May timeline comes from the technical case study, whereas the vendor confirms June 11 publication and mitigation. Sources vary in how they describe the May/June mitigation rollout. No confirmed in-the-wild loss is claimed.
