#!/usr/bin/env python3
"""
SENTRIX Benchmark Evaluation Runner
Executes offline benchmark datasets against the production SENTRIX scanning pipeline.
Generates comprehensive 3-class and binary metrics, confusion matrices, category breakdowns,
latency distributions, and false-positive/false-negative case analyses.
"""

import sys
import json
import asyncio
import argparse
from pathlib import Path
from typing import Dict, Any, List

# Ensure python path includes scanner app
current_dir = Path(__file__).resolve().parent
scanner_root = current_dir.parent
sys.path.insert(0, str(scanner_root))

from benchmarks.harness import OfflinePipelineRunner
from benchmarks.metrics import (
    calculate_three_class_metrics,
    calculate_binary_metrics,
    calculate_category_breakdown,
    calculate_latency_stats,
    CLASSES,
)


def format_confusion_matrix(matrix: Dict[str, Dict[str, int]]) -> str:
    """Formats 3x3 confusion matrix as a markdown table."""
    lines = []
    lines.append("| Actual \\ Predicted | BENIGN | SUSPICIOUS | MALICIOUS |")
    lines.append("| :--- | :---: | :---: | :---: |")
    for actual in CLASSES:
        row = f"| **{actual}** | {matrix[actual]['BENIGN']} | {matrix[actual]['SUSPICIOUS']} | {matrix[actual]['MALICIOUS']} |"
        lines.append(row)
    return "\n".join(lines)


def format_per_class_table(per_class: Dict[str, Dict[str, Any]]) -> str:
    """Formats per-class metrics as a markdown table."""
    lines = []
    lines.append("| Class | Support | TP | FP | FN | Precision | Recall | F1-Score |")
    lines.append("| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |")
    for c in CLASSES:
        d = per_class[c]
        p_pct = f"{d['precision'] * 100:.1f}%"
        r_pct = f"{d['recall'] * 100:.1f}%"
        f1_pct = f"{d['f1'] * 100:.1f}%"
        lines.append(f"| **{c}** | {d['support']} | {d['tp']} | {d['fp']} | {d['fn']} | {p_pct} | {r_pct} | {f1_pct} |")
    return "\n".join(lines)


def format_category_table(categories: Dict[str, Dict[str, Any]]) -> str:
    """Formats category breakdown as a markdown table."""
    lines = []
    lines.append("| Category | Cases | Correct | Incorrect | Accuracy |")
    lines.append("| :--- | :---: | :---: | :---: | :---: |")
    for cat, d in sorted(categories.items()):
        acc_pct = f"{d['accuracy'] * 100:.1f}%"
        lines.append(f"| `{cat}` | {d['total']} | {d['correct']} | {d['incorrect']} | {acc_pct} |")
    return "\n".join(lines)


async def run_benchmark(dataset_path: Path, output_report_path: Path) -> Dict[str, Any]:
    with open(dataset_path, "r", encoding="utf-8") as f:
        cases: List[Dict[str, Any]] = json.load(f)

    print(f"\n========================================================")
    print(f"SENTRIX Scanner Benchmark Evaluation")
    print(f"Dataset: {dataset_path.name} ({len(cases)} cases)")
    print(f"========================================================\n")

    runner = OfflinePipelineRunner()
    results: List[Dict[str, Any]] = []

    for i, case in enumerate(cases, 1):
        res = await runner.run_case(case)
        results.append(res)
        status_char = "✓" if res["isCorrect"] else "✗"
        print(f"[{i:02d}/{len(cases):02d}] {status_char} {res['id']}: {res['url'][:45]:<45} "
              f"GT={res['groundTruth']:<10} Pred={res['predictedVerdict']:<10} "
              f"Score={res['riskScore']:<3} ({res['latencyMs']:.1f}ms)")

    # Compute metrics
    three_class = calculate_three_class_metrics(results)
    binary_threat = calculate_binary_metrics(
        results,
        positive_classes=["SUSPICIOUS", "MALICIOUS"],
        metric_name="Threat Detection (Positive: SUSPICIOUS | MALICIOUS, Negative: BENIGN)"
    )
    binary_malicious = calculate_binary_metrics(
        results,
        positive_classes=["MALICIOUS"],
        metric_name="Strict Malicious Detection (Positive: MALICIOUS, Negative: BENIGN | SUSPICIOUS)"
    )
    categories = calculate_category_breakdown(results)
    latency = calculate_latency_stats(results)

    # Compile report structure
    report = {
        "dataset": {
            "file": dataset_path.name,
            "totalCases": len(cases),
        },
        "overall": {
            "accuracy": three_class["accuracy"],
            "macroF1": three_class["macro"]["f1"],
            "weightedF1": three_class["weighted"]["f1"],
        },
        "threeClass": three_class,
        "binaryThreat": binary_threat,
        "binaryMalicious": binary_malicious,
        "categories": categories,
        "latency": latency,
        "caseResults": results,
    }

    # Save to file
    with open(output_report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    # Print summary output
    print(f"\n--------------------------------------------------------")
    print(f"EVALUATION SUMMARY: {dataset_path.name}")
    print(f"--------------------------------------------------------")
    print(f"Overall 3-Class Accuracy: {three_class['accuracy'] * 100:.2f}%")
    print(f"Macro F1-Score:           {three_class['macro']['f1'] * 100:.2f}%")
    print(f"Weighted F1-Score:        {three_class['weighted']['f1'] * 100:.2f}%")
    print(f"Threat Binary F1:         {binary_threat['f1'] * 100:.2f}%")
    print(f"False Positive Rate:      {binary_threat['falsePositiveRate'] * 100:.2f}% (Threat Detection)")
    print(f"False Negative Rate:      {binary_threat['falseNegativeRate'] * 100:.2f}% (Threat Detection)")
    print(f"Latency P50: {latency['p50Ms']} ms | P90: {latency['p90Ms']} ms | Mean: {latency['meanMs']} ms")

    print(f"\n### 3x3 Confusion Matrix\n")
    print(format_confusion_matrix(three_class["confusionMatrix"]))

    print(f"\n### Per-Class Performance\n")
    print(format_per_class_table(three_class["perClass"]))

    print(f"\n### Category Breakdown\n")
    print(format_category_table(categories))

    # Identify mismatches
    mismatches = [r for r in results if not r["isCorrect"]]
    print(f"\n### Mismatches / Misclassifications ({len(mismatches)} total cases)\n")
    for m in mismatches:
        print(f"- **[{m['id']}]** `{m['url']}` (Category: `{m['category']}`)")
        print(f"  - Ground Truth: `{m['groundTruth']}` | Predicted: `{m['predictedVerdict']}` (Score: {m['riskScore']})")
        print(f"  - Triggered Factors: {', '.join(m['riskFactors']) if m['riskFactors'] else 'None'}\n")

    print(f"Full report saved to: {output_report_path}\n")
    return report


def main():
    parser = argparse.ArgumentParser(description="SENTRIX Offline Benchmark Evaluation")
    parser.add_argument(
        "--dataset",
        type=str,
        default="dataset_dev.json",
        help="Dataset JSON filename or path (default: dataset_dev.json)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default="baseline_dev_report.json",
        help="Output report filename or path (default: baseline_dev_report.json)"
    )
    args = parser.parse_args()

    bench_dir = Path(__file__).resolve().parent
    dataset_path = Path(args.dataset) if Path(args.dataset).is_absolute() else bench_dir / args.dataset
    output_path = Path(args.output) if Path(args.output).is_absolute() else bench_dir / args.output

    if not dataset_path.exists():
        print(f"Error: Dataset file not found at {dataset_path}")
        sys.exit(1)

    asyncio.run(run_benchmark(dataset_path, output_path))


if __name__ == "__main__":
    main()
