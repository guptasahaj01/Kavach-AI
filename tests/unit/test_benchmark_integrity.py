"""Evaluation results must not depend on outcome labels or fabricated timing."""

from unittest.mock import patch

from kavach_benchmark.baselines import BaselineEvaluator
from kavach_benchmark.guardrail import OutputGuardrail


def test_trial_label_cannot_change_guardrail_decision():
    guard = OutputGuardrail()
    for text in ("A PMLA investigation can freeze an account.", "KAVACH-7731"):
        attack = guard.evaluate(text, is_benign_trial=False)
        benign = guard.evaluate(text, is_benign_trial=True)
        assert attack["blocked"] == benign["blocked"]
        assert attack["reason"] == benign["reason"]
    assert not guard.evaluate("Section 138 describes a criminal offence.", True)["blocked"]


def test_guardrail_reports_only_measured_elapsed_time():
    with patch("kavach_benchmark.guardrail.time.perf_counter", side_effect=[10, 10.001]):
        result = OutputGuardrail().evaluate("A public policy answer")
    assert result["latency_ms"] == 1.0
    assert result["guardrail_kind"] == "deterministic_patterns"


def test_detector_benchmark_identifies_misses_without_claiming_compromise():
    result = BaselineEvaluator().evaluate_baseline("B0")
    assert result.metric_type == "detector_classification"
    assert result.result_kind == "measured_detector"
    assert result.detector_miss_rate == result.asr == 1.0
    assert result.false_negatives == result.attack_samples
    assert result.false_positives == 0
