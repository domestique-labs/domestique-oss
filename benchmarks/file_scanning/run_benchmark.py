"""Run the file scanning benchmark and produce quality/latency metrics.

Usage:
    python -m benchmarks.file_scanning.run_benchmark [--dataset PATH]

Outputs:
    - Per-file results (detection, latency, correctness)
    - Aggregate metrics: precision, recall, F1, avg latency by file type
    - Confusion matrix for sensitive/clean classification
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from domestique_app.services.file_scanner import scan_file, FileType


def run_benchmark(dataset_dir: Path) -> dict:
    """Run the benchmark against all samples in the dataset.

    Returns:
        Dict with per-sample results and aggregate metrics.
    """
    manifest_path = dataset_dir / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"Manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text())
    samples = manifest["samples"]

    results = []
    tp, fp, tn, fn = 0, 0, 0, 0
    latencies_by_type: dict[str, list[float]] = {}
    category_tp: dict[str, int] = {}
    category_fn: dict[str, int] = {}
    category_fp: dict[str, int] = {}

    print(f"Running benchmark on {len(samples)} samples...")
    print(f"{'File':<20} {'Type':<12} {'Expected':<8} {'Got':<8} {'Time':<8} {'Status'}")
    print("-" * 80)

    for sample in samples:
        file_path = dataset_dir / sample["file"]
        if not file_path.exists():
            print(f"  SKIP: {sample['file']} not found")
            continue

        data = file_path.read_bytes()
        expected_sensitive = sample["contains_sensitive"]
        expected_categories = set(sample["categories"])

        # Scan
        result = scan_file(data, filename=sample["file"])

        # Evaluate
        predicted_sensitive = result.contains_sensitive
        predicted_categories = set(result.categories)

        # Classification metrics
        if expected_sensitive and predicted_sensitive:
            tp += 1
            status = "✓ TP"
        elif expected_sensitive and not predicted_sensitive:
            fn += 1
            status = "✗ FN"
        elif not expected_sensitive and predicted_sensitive:
            fp += 1
            status = "✗ FP"
        else:
            tn += 1
            status = "✓ TN"

        # Per-category metrics
        for cat in expected_categories:
            if cat in predicted_categories:
                category_tp[cat] = category_tp.get(cat, 0) + 1
            else:
                category_fn[cat] = category_fn.get(cat, 0) + 1

        for cat in predicted_categories - expected_categories:
            category_fp[cat] = category_fp.get(cat, 0) + 1

        # Latency tracking
        ftype = sample["type"]
        if ftype not in latencies_by_type:
            latencies_by_type[ftype] = []
        latencies_by_type[ftype].append(result.total_time_ms)

        # Display
        time_str = f"{result.total_time_ms:.1f}ms"
        print(f"  {sample['file']:<18} {ftype:<12} "
              f"{'yes' if expected_sensitive else 'no':<8} "
              f"{'yes' if predicted_sensitive else 'no':<8} "
              f"{time_str:<8} {status}")

        results.append({
            "file": sample["file"],
            "type": ftype,
            "expected_sensitive": expected_sensitive,
            "predicted_sensitive": predicted_sensitive,
            "expected_categories": list(expected_categories),
            "predicted_categories": list(predicted_categories),
            "total_time_ms": result.total_time_ms,
            "extraction_time_ms": result.extraction_time_ms,
            "detection_time_ms": result.detection_time_ms,
            "status": status,
            "detections_count": len(result.detections),
        })

    # Aggregate metrics
    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    print("\n" + "=" * 80)
    print("AGGREGATE METRICS")
    print("=" * 80)
    print(f"\n  Classification (file contains sensitive data?):")
    print(f"    Accuracy:  {accuracy:.1%}")
    print(f"    Precision: {precision:.1%}")
    print(f"    Recall:    {recall:.1%}")
    print(f"    F1 Score:  {f1:.1%}")
    print(f"\n  Confusion Matrix:")
    print(f"    TP={tp}  FP={fp}")
    print(f"    FN={fn}  TN={tn}")

    print(f"\n  Per-Category Detection Rate:")
    all_categories = sorted(set(list(category_tp.keys()) +
                                list(category_fn.keys()) +
                                list(category_fp.keys())))
    for cat in all_categories:
        cat_tp = category_tp.get(cat, 0)
        cat_fn = category_fn.get(cat, 0)
        cat_fp = category_fp.get(cat, 0)
        cat_recall = cat_tp / (cat_tp + cat_fn) if (cat_tp + cat_fn) > 0 else 0.0
        cat_prec = cat_tp / (cat_tp + cat_fp) if (cat_tp + cat_fp) > 0 else 0.0
        print(f"    {cat:<15} P={cat_prec:.0%}  R={cat_recall:.0%}  "
              f"(TP={cat_tp} FN={cat_fn} FP={cat_fp})")

    print(f"\n  Latency by File Type:")
    total_latencies = []
    for ftype, lats in sorted(latencies_by_type.items()):
        avg = sum(lats) / len(lats)
        p50 = sorted(lats)[len(lats) // 2]
        p95 = sorted(lats)[int(len(lats) * 0.95)] if len(lats) > 1 else lats[0]
        total_latencies.extend(lats)
        print(f"    {ftype:<12} avg={avg:.1f}ms  p50={p50:.1f}ms  "
              f"p95={p95:.1f}ms  (n={len(lats)})")

    if total_latencies:
        overall_avg = sum(total_latencies) / len(total_latencies)
        overall_p95 = sorted(total_latencies)[int(len(total_latencies) * 0.95)]
        print(f"    {'OVERALL':<12} avg={overall_avg:.1f}ms  "
              f"p95={overall_p95:.1f}ms  (n={len(total_latencies)})")

    # Build report
    report = {
        "metrics": {
            "accuracy": accuracy,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        },
        "category_metrics": {
            cat: {
                "precision": category_tp.get(cat, 0) / (category_tp.get(cat, 0) + category_fp.get(cat, 0))
                             if (category_tp.get(cat, 0) + category_fp.get(cat, 0)) > 0 else 0.0,
                "recall": category_tp.get(cat, 0) / (category_tp.get(cat, 0) + category_fn.get(cat, 0))
                          if (category_tp.get(cat, 0) + category_fn.get(cat, 0)) > 0 else 0.0,
            }
            for cat in all_categories
        },
        "latency": {
            ftype: {
                "avg_ms": sum(lats) / len(lats),
                "p50_ms": sorted(lats)[len(lats) // 2],
                "p95_ms": sorted(lats)[int(len(lats) * 0.95)] if len(lats) > 1 else lats[0],
                "count": len(lats),
            }
            for ftype, lats in latencies_by_type.items()
        },
        "results": results,
    }

    # Save report
    report_path = dataset_dir.parent / "benchmark_results.json"
    report_path.write_text(json.dumps(report, indent=2))
    print(f"\n  Report saved: {report_path}")

    return report


def main() -> None:
    parser = argparse.ArgumentParser(description="Run file scanning benchmark")
    parser.add_argument("--dataset", type=Path,
                        default=Path("benchmarks/file_scanning/dataset"))
    args = parser.parse_args()

    if not args.dataset.exists():
        print(f"Dataset not found at {args.dataset}")
        print("Run generate_benchmark.py first")
        sys.exit(1)

    run_benchmark(args.dataset)


if __name__ == "__main__":
    main()
