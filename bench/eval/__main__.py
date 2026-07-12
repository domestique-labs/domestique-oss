from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from bench.eval.corpus import corpus_checksum, load_corpus
from bench.eval.metrics import Metrics, compute_metrics
from bench.eval.runner import observe_corpus
from bench.eval.scorecard import to_json, to_markdown

_REGRESSION_EPS = 0.001


def _metrics_from_json(path: Path) -> Metrics:
    data = json.loads(path.read_text(encoding="utf-8"))["metrics"]
    return Metrics(**data)


def run_eval(
    corpus_path: Path,
    out_path: Path,
    *,
    baseline_path: Path | None,
    commit: str,
    fail_on_regression: bool,
) -> int:
    rows = load_corpus(corpus_path)
    observations, observed = observe_corpus(rows)
    latencies = [o.latency_ms for o in observations]
    metrics = compute_metrics(rows, observed, latencies)

    out_path.write_text(
        to_json(metrics, commit=commit, corpus_sha=corpus_checksum(rows), profile="core"),
        encoding="utf-8",
    )

    baseline = _metrics_from_json(baseline_path) if baseline_path else None
    print(to_markdown(metrics, baseline))

    if fail_on_regression and baseline is not None:
        if (metrics.bypass_rate > baseline.bypass_rate + _REGRESSION_EPS
                or metrics.false_positive_rate > baseline.false_positive_rate + _REGRESSION_EPS):
            print("REGRESSION: bypass_rate or false_positive_rate increased vs baseline")
            return 1
    return 0


def main() -> int:
    # Scorecard markdown contains non-ASCII (Δ/✅/⚠️); a Windows cp1252 console
    # would otherwise raise UnicodeEncodeError when we print it below.
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    parser = argparse.ArgumentParser(prog="bench.eval")
    sub = parser.add_subparsers(dest="cmd", required=True)
    run = sub.add_parser("run", help="run the deterministic eval")
    run.add_argument("--corpus", type=Path, default=Path("bench/eval/data/corpus.jsonl"))
    run.add_argument("--out", type=Path, required=True)
    run.add_argument("--baseline", type=Path, default=None)
    run.add_argument("--commit", type=str, default="local")
    run.add_argument("--fail-on-regression", action="store_true")
    args = parser.parse_args()
    return run_eval(
        args.corpus, args.out,
        baseline_path=args.baseline, commit=args.commit,
        fail_on_regression=args.fail_on_regression,
    )


if __name__ == "__main__":
    raise SystemExit(main())
