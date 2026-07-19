from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from benchmarks.eval.corpus import corpus_checksum, load_corpus
from benchmarks.eval.metrics import Metrics, compute_metrics
from benchmarks.eval.runner import observe_corpus
from benchmarks.eval.scorecard import to_json, to_markdown_compare, to_markdown_single

_REGRESSION_EPS = 0.001

# Metrics that hard-fail CI when they regress vs main. These are deterministic
# on a fixed corpus, so a regression here is a real, reproducible change — not
# runner noise. Each entry: (metric, "up"|"down" direction that is BAD).
#   - bypass_rate up          → an attack that used to be caught now gets through
#   - false_positive_rate up  → benign traffic that used to pass now gets blocked
#   - recall down             → detections are being missed
#   - f1 down                 → overall detection quality dropped
# Latency is deliberately NOT gated: it is non-deterministic on shared runners
# and hard-failing on it produces flaky CI. It is surfaced in the scorecard
# table with a noise band instead.
_REGRESSION_CHECKS = (
    ("bypass_rate", "up"),
    ("false_positive_rate", "up"),
    ("recall", "down"),
    ("f1", "down"),
)


def _metrics_from_json(path: Path) -> Metrics:
    data = json.loads(path.read_text(encoding="utf-8"))["metrics"]
    return Metrics(**data)


def regressions(main: Metrics, pr: Metrics) -> list[str]:
    """Return a human-readable message for every metric that regressed past the
    epsilon, comparing PR against main. Empty list means no regression."""
    messages: list[str] = []
    for metric, bad_direction in _REGRESSION_CHECKS:
        base = getattr(main, metric)
        cur = getattr(pr, metric)
        if bad_direction == "up" and cur > base + _REGRESSION_EPS:
            messages.append(f"{metric} increased {base:.4f} → {cur:.4f} (vs main)")
        elif bad_direction == "down" and cur < base - _REGRESSION_EPS:
            messages.append(f"{metric} decreased {base:.4f} → {cur:.4f} (vs main)")
    return messages


def _evaluate(corpus_path: Path, out_path: Path, *, commit: str) -> Metrics:
    rows = load_corpus(corpus_path)
    observations, observed = observe_corpus(rows)
    latencies = [o.latency_ms for o in observations]
    metrics = compute_metrics(rows, observed, latencies)
    out_path.write_text(
        to_json(metrics, commit=commit, corpus_sha=corpus_checksum(rows), profile="core"),
        encoding="utf-8",
    )
    return metrics


def run_eval(
    corpus_path: Path,
    out_path: Path,
    *,
    baseline_path: Path | None,
    commit: str,
    fail_on_regression: bool,
) -> int:
    """Measure the current checkout and write results JSON.

    When a `baseline_path` is supplied this also renders a comparison table and
    can gate on regressions — kept for local use. CI compares two same-runner
    runs via the `compare` subcommand instead of a committed baseline.
    """
    metrics = _evaluate(corpus_path, out_path, commit=commit)
    baseline = _metrics_from_json(baseline_path) if baseline_path else None

    if baseline is None:
        print(to_markdown_single(metrics))
        return 0

    print(to_markdown_compare(baseline, metrics))
    if fail_on_regression:
        found = regressions(baseline, metrics)
        if found:
            print("REGRESSION vs baseline:")
            for msg in found:
                print(f"  - {msg}")
            return 1
    return 0


def compare(main_path: Path, pr_path: Path, *, fail_on_regression: bool) -> int:
    """Render main-vs-PR scorecard from two results files and gate on regressions."""
    main = _metrics_from_json(main_path)
    pr = _metrics_from_json(pr_path)
    print(to_markdown_compare(main, pr))
    if fail_on_regression:
        found = regressions(main, pr)
        if found:
            print("REGRESSION vs main:")
            for msg in found:
                print(f"  - {msg}")
            return 1
    return 0


def main() -> int:
    # Scorecard markdown contains non-ASCII (Δ/✅/⚠️); a Windows cp1252 console
    # would otherwise raise UnicodeEncodeError when we print it below.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(prog="benchmarks.eval")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run = sub.add_parser("run", help="run the deterministic eval on this checkout")
    run.add_argument("--corpus", type=Path, default=Path("benchmarks/eval/data/corpus.jsonl"))
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--baseline", type=Path, default=None)
    run.add_argument("--commit", type=str, default="local")
    run.add_argument("--fail-on-regression", action="store_true")

    cmp_ = sub.add_parser("compare", help="compare two results files (main vs PR)")
    cmp_.add_argument("--main", type=Path, required=True)
    cmp_.add_argument("--pr", type=Path, required=True)
    cmp_.add_argument("--fail-on-regression", action="store_true")

    args = parser.parse_args()
    if args.cmd == "compare":
        return compare(args.main, args.pr, fail_on_regression=args.fail_on_regression)
    return run_eval(
        args.corpus, args.out,
        baseline_path=args.baseline, commit=args.commit,
        fail_on_regression=args.fail_on_regression,
    )


if __name__ == "__main__":
    raise SystemExit(main())
