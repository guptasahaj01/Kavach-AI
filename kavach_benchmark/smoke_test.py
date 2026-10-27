"""
KAVACH v2 - Automated Smoke Benchmark Runner
Executes a rapid evaluation of all 7 baselines (B0 to B6) across the 12 evaluation categories.
Calculates real measured metrics:
- Detector miss rate (legacy ASR field) with Wilson 95% CI
- FPR (False Positive Rate) with Wilson 95% CI
- F1 Score
- Real measured median and p95 latency
Outputs clean formatted console table and persists outputs/baseline_comparison.csv.
"""

import os
import json
import pandas as pd
from kavach_benchmark.baselines import BaselineEvaluator, BaselineMetrics


def run_smoke_benchmark():
    print("=" * 80)
    print("  KAVACH v2: MULTI-BASELINE SECURITY BENCHMARK (B0 - B6)")
    print("=" * 80)
    print("Initializing models and evaluation suite...\n")

    evaluator = BaselineEvaluator()
    metrics_list = evaluator.run_all_baselines()

    table_data = []
    for m in metrics_list:
        asr_str = f"{m.asr * 100:.1f}% [{m.asr_ci[0]:.1f}-{m.asr_ci[1]:.1f}]"
        fpr_str = f"{m.fpr * 100:.1f}% [{m.fpr_ci[0]:.1f}-{m.fpr_ci[1]:.1f}]"
        table_data.append({
            "Baseline": m.baseline_id,
            "Architecture": m.baseline_name.split(": ")[-1],
            "Miss Rate (↓)": asr_str,
            "FPR (↓)": fpr_str,
            "Precision": f"{m.precision:.3f}",
            "Recall": f"{m.tpr:.3f}",
            "F1 Score (↑)": f"{m.f1_score:.3f}",
            "Median Lat (ms)": f"{m.median_latency_ms:.2f}",
            "p95 Lat (ms)": f"{m.p95_latency_ms:.2f}"
        })

    df = pd.DataFrame(table_data)
    print(df.to_string(index=False))
    print("\n" + "=" * 80)
    print("  DETECTOR DIAGNOSTIC RESULTS")
    print("  Counts and intervals above describe this corpus only; no harmful outcomes are executed.")
    print("  B6 measures gateway inspection, not tool enforcement or output validation.")
    print("  Compare the protected-workflow tests separately for execution invariants.")
    print("=" * 80 + "\n")

    # Save to outputs
    os.makedirs("outputs", exist_ok=True)
    df.to_csv("outputs/baseline_comparison.csv", index=False)

    json_records = [m.model_dump() for m in metrics_list]
    with open("outputs/baseline_comparison.json", "w") as f:
        json.dump(json_records, f, indent=2)

    print("Results saved to 'outputs/baseline_comparison.csv' and 'outputs/baseline_comparison.json'.")
    return metrics_list


if __name__ == "__main__":
    run_smoke_benchmark()
