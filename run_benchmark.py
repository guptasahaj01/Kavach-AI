#!/usr/bin/env python3
"""
Kavach-AI: Benchmark Runner
Runs the full 72-configuration measurement matrix and generates:
- outputs/trial_results.csv (14,400 raw trials)
- outputs/table_1_matrix.csv (Canonical Table I with 95% Wilson CIs)
- outputs/figures/figure_2_asr_vs_k.png
- outputs/figures/figure_3_security_usability.png
"""

import sys
import os

from kavach_benchmark.corpus_generator import generate_corpus
from kavach_benchmark.trial_harness import TrialHarness
from kavach_benchmark.kavach_analyze import analyze_trials

def main():
    print("=" * 70)
    print("       KAVACH-AI: EMPIRICAL BENCHMARK MEASUREMENT SUITE")
    print("=" * 70)

    # 1. Ensure corpus exists
    if not os.path.exists("data/manifest.json"):
        print("[1/3] Generating 100 Indian banking documents & poisoned twins...")
        generate_corpus("data")
    else:
        print("[1/3] Found existing banking corpus in data/.")

    # 2. Run 72-config trial harness
    print("[2/3] Executing 72-configuration matrix (200 trials per config)...")
    harness = TrialHarness(data_dir="data", output_dir="outputs")
    harness.run(sample_n=100)

    # 3. Analyze results & generate figures
    print("[3/3] Computing 95% Wilson Score intervals & rendering figures...")
    analyze_trials("outputs/trial_results.csv", "outputs")

    print("\n" + "=" * 70)
    print("SUCCESS: Benchmark complete!")
    print("  - Table I Matrix: outputs/table_1_matrix.csv")
    print("  - Figure 2: outputs/figures/figure_2_asr_vs_k.png")
    print("  - Figure 3: outputs/figures/figure_3_security_usability.png")
    print("=" * 70)

if __name__ == "__main__":
    main()
