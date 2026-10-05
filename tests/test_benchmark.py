import pytest

from core.benchmark import (
    BenchmarkCase,
    BenchmarkResult,
    adversarial_cases,
    evaluate_benchmark,
)


def test_benchmark_metrics_are_reproducible():
    cases = (
        BenchmarkCase("1", "scope", "in", "found"),
        BenchmarkCase("2", "scope", "out", "none", False),
    )
    results = (
        BenchmarkResult("1", "found", True, ("e1",)),
        BenchmarkResult("2", "none", True),
    )
    metrics = evaluate_benchmark(cases, results)
    assert metrics.total == 2
    assert metrics.accuracy == 1.0
    assert metrics.false_positive_rate == 0.0
    assert metrics.false_negative_rate == 0.0


def test_benchmark_requires_complete_unique_results():
    case = BenchmarkCase("1", "scope", "in", "found")
    with pytest.raises(ValueError):
        evaluate_benchmark((case, case), ())


def test_adversarial_cases_cover_core_safety_boundaries():
    cases = adversarial_cases()
    assert len(cases) >= 5
    categories = {case.category for case in cases}
    assert {"prompt_injection", "scope_escape", "duplicate", "secret_leakage", "threat_signal"} <= categories


def test_benchmark_case_requires_identity():
    with pytest.raises(ValueError):
        BenchmarkCase("", "scope", "x", "none")
