"""Benchmark & evaluation suites for the firewall.

Subpackages:
    eval/          Deterministic detection-quality gate (labeled corpus,
                   F1/FP/latency metrics, PR scorecard) — ``python -m benchmarks.eval``.
    datasets/      Custom + public-corpus detection-accuracy sweeps.
    browser_perf/  Browser-mode response-streaming latency micro-benchmark.
    file_scanning/ Detection over documents/images (PDF/CSV/PNG/OCR).
"""
