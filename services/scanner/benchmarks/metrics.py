from typing import List, Dict, Any
import statistics


CLASSES = ["BENIGN", "SUSPICIOUS", "MALICIOUS"]
FOUR_CLASSES = ["BENIGN", "UNVERIFIED_INFRASTRUCTURE", "SUSPICIOUS", "MALICIOUS"]
FIVE_CLASSES = ["BENIGN", "SUSPICIOUS", "MALICIOUS", "CONFIRMED_MALICIOUS", "INCONCLUSIVE"]
ALL_PRED_CLASSES = ["BENIGN", "SUSPICIOUS", "MALICIOUS", "CONFIRMED_MALICIOUS", "UNVERIFIED_INFRASTRUCTURE", "INCONCLUSIVE"]


def calculate_three_class_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes standard multi-class evaluation metrics for BENIGN, SUSPICIOUS, and MALICIOUS verdicts:
    - 3x3 (with informational unverified columns) confusion matrix
    - Per-class TP, FP, FN, TN, Precision, Recall, F1, Support with consistent denominators
    - Macro-averaged and Weighted-averaged Precision, Recall, F1
    - Overall 3-class Accuracy (unverified predictions count as incorrect against 3-class GT)
    """
    matrix: Dict[str, Dict[str, int]] = {
        actual: {pred: 0 for pred in ALL_PRED_CLASSES} for actual in CLASSES
    }

    # Count actual vs predicted
    for r in results:
        actual = r["groundTruth"]
        pred = r["predictedVerdict"]
        norm_pred = "MALICIOUS" if pred == "CONFIRMED_MALICIOUS" else pred
        if actual in matrix:
            if norm_pred not in matrix[actual]:
                matrix[actual][norm_pred] = 0
            matrix[actual][norm_pred] += 1

    total_samples = len(results)
    correct_samples = sum(matrix[c].get(c, 0) for c in CLASSES)
    accuracy = correct_samples / total_samples if total_samples > 0 else 0.0

    per_class = {}
    for c in CLASSES:
        tp = matrix[c].get(c, 0)
        # Support is strictly the total actual ground truth cases of class c
        support = sum(1 for r in results if r["groundTruth"] == c)
        # FN is all cases where ground truth was c but predicted was not c
        fn = support - tp
        # FP is all cases where ground truth was NOT c but predicted was c
        fp = sum(matrix[a].get(c, 0) for a in CLASSES if a != c)
        # TN is all cases where ground truth was NOT c and predicted was NOT c
        tn = sum(
            sum(v for p, v in matrix[a].items() if p != c)
            for a in CLASSES if a != c
        )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[c] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
        }

    # Macro averages
    macro_precision = sum(per_class[c]["precision"] for c in CLASSES) / len(CLASSES)
    macro_recall = sum(per_class[c]["recall"] for c in CLASSES) / len(CLASSES)
    macro_f1 = sum(per_class[c]["f1"] for c in CLASSES) / len(CLASSES)

    # Weighted averages (strictly normalized by total_samples == sum of supports)
    weighted_precision = sum(per_class[c]["precision"] * per_class[c]["support"] for c in CLASSES) / total_samples if total_samples else 0.0
    weighted_recall = sum(per_class[c]["recall"] * per_class[c]["support"] for c in CLASSES) / total_samples if total_samples else 0.0
    weighted_f1 = sum(per_class[c]["f1"] * per_class[c]["support"] for c in CLASSES) / total_samples if total_samples else 0.0

    informational_counts = {
        "UNVERIFIED_INFRASTRUCTURE": sum(1 for r in results if r.get("predictedVerdict") == "UNVERIFIED_INFRASTRUCTURE"),
        "INCONCLUSIVE": sum(1 for r in results if r.get("predictedVerdict") == "INCONCLUSIVE"),
    }

    return {
        "confusionMatrix": matrix,
        "perClass": per_class,
        "accuracy": round(accuracy, 4),
        "macro": {
            "precision": round(macro_precision, 4),
            "recall": round(macro_recall, 4),
            "f1": round(macro_f1, 4),
        },
        "weighted": {
            "precision": round(weighted_precision, 4),
            "recall": round(weighted_recall, 4),
            "f1": round(weighted_f1, 4),
        },
        "informationalCounts": informational_counts,
        "totalSamples": total_samples,
    }


def calculate_four_class_metrics(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Computes 4-class evaluation metrics where UNVERIFIED_INFRASTRUCTURE is an explicit ground-truth class:
    - 4x4 confusion matrix
    - Per-class TP, FP, FN, TN, Precision, Recall, F1, Support
    - Macro and weighted averages
    - 4-class overall accuracy
    """
    matrix: Dict[str, Dict[str, int]] = {
        actual: {pred: 0 for pred in FOUR_CLASSES} for actual in FOUR_CLASSES
    }

    for r in results:
        actual = r["groundTruth"]
        pred = r["predictedVerdict"]
        norm_pred = "MALICIOUS" if pred == "CONFIRMED_MALICIOUS" else pred
        if actual in matrix:
            if norm_pred not in matrix[actual]:
                matrix[actual][norm_pred] = 0
            matrix[actual][norm_pred] += 1

    total_samples = len(results)
    correct_samples = sum(matrix[c].get(c, 0) for c in FOUR_CLASSES)
    accuracy = correct_samples / total_samples if total_samples > 0 else 0.0

    per_class = {}
    for c in FOUR_CLASSES:
        tp = matrix[c].get(c, 0)
        support = sum(1 for r in results if r["groundTruth"] == c)
        fn = support - tp
        fp = sum(matrix[a].get(c, 0) for a in FOUR_CLASSES if a != c)
        tn = sum(
            sum(v for p, v in matrix[a].items() if p != c)
            for a in FOUR_CLASSES if a != c
        )

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        per_class[c] = {
            "tp": tp,
            "fp": fp,
            "fn": fn,
            "tn": tn,
            "precision": round(precision, 4),
            "recall": round(recall, 4),
            "f1": round(f1, 4),
            "support": support,
        }

    macro_precision = sum(per_class[c]["precision"] for c in FOUR_CLASSES) / len(FOUR_CLASSES)
    macro_recall = sum(per_class[c]["recall"] for c in FOUR_CLASSES) / len(FOUR_CLASSES)
    macro_f1 = sum(per_class[c]["f1"] for c in FOUR_CLASSES) / len(FOUR_CLASSES)

    weighted_precision = sum(per_class[c]["precision"] * per_class[c]["support"] for c in FOUR_CLASSES) / total_samples if total_samples else 0.0
    weighted_recall = sum(per_class[c]["recall"] * per_class[c]["support"] for c in FOUR_CLASSES) / total_samples if total_samples else 0.0
    weighted_f1 = sum(per_class[c]["f1"] * per_class[c]["support"] for c in FOUR_CLASSES) / total_samples if total_samples else 0.0

    return {
        "confusionMatrix": matrix,
        "perClass": per_class,
        "accuracy": round(accuracy, 4),
        "macro": {
            "precision": round(macro_precision, 4),
            "recall": round(macro_recall, 4),
            "f1": round(macro_f1, 4),
        },
        "weighted": {
            "precision": round(weighted_precision, 4),
            "recall": round(weighted_recall, 4),
            "f1": round(weighted_f1, 4),
        },
        "totalSamples": total_samples,
    }


def calculate_binary_metrics(results: List[Dict[str, Any]], positive_classes: List[str], metric_name: str) -> Dict[str, Any]:
    """
    Computes binary evaluation metrics given an explicit positive-class definition.
    - TP: Actual is positive AND Predicted is positive
    - FP: Actual is negative AND Predicted is positive (false alarm)
    - TN: Actual is negative AND Predicted is negative
    - FN: Actual is positive AND Predicted is negative (missed threat)
    """
    pos_set = set(positive_classes)

    tp = 0
    fp = 0
    tn = 0
    fn = 0

    for r in results:
        actual_is_pos = r["groundTruth"] in pos_set
        pred_is_pos = r["predictedVerdict"] in pos_set

        if actual_is_pos and pred_is_pos:
            tp += 1
        elif not actual_is_pos and pred_is_pos:
            fp += 1
        elif not actual_is_pos and not pred_is_pos:
            tn += 1
        else:
            fn += 1

    total = tp + fp + tn + fn
    accuracy = (tp + tn) / total if total > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    fnr = fn / (fn + tp) if (fn + tp) > 0 else 0.0

    return {
        "metricName": metric_name,
        "positiveClassDefinition": list(positive_classes),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": round(accuracy, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "specificity": round(specificity, 4),
        "f1": round(f1, 4),
        "falsePositiveRate": round(fpr, 4),
        "falseNegativeRate": round(fnr, 4),
        "total": total,
    }


def calculate_category_breakdown(results: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Breaks down performance by security category."""
    categories: Dict[str, Dict[str, Any]] = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {
                "total": 0,
                "correct": 0,
                "incorrect": 0,
                "groundTruthCounts": {},
                "predictedCounts": {},
                "mismatches": [],
            }
        c_data = categories[cat]
        c_data["total"] += 1
        gt = r["groundTruth"]
        pred = r["predictedVerdict"]
        c_data["groundTruthCounts"][gt] = c_data["groundTruthCounts"].get(gt, 0) + 1
        c_data["predictedCounts"][pred] = c_data["predictedCounts"].get(pred, 0) + 1

        if r["isCorrect"]:
            c_data["correct"] += 1
        else:
            c_data["incorrect"] += 1
            c_data["mismatches"].append({
                "id": r["id"],
                "url": r["url"],
                "groundTruth": gt,
                "predicted": pred,
                "score": r["riskScore"],
                "riskFactors": r["riskFactors"],
            })

    for cat, d in categories.items():
        d["accuracy"] = round(d["correct"] / d["total"], 4) if d["total"] > 0 else 0.0

    return categories


def calculate_latency_stats(results: List[Dict[str, Any]]) -> Dict[str, float]:
    """Computes execution latency distribution in milliseconds."""
    latencies = [r["latencyMs"] for r in results]
    if not latencies:
        return {"mean": 0.0, "min": 0.0, "max": 0.0, "p50": 0.0, "p90": 0.0, "p99": 0.0}

    latencies.sort()
    n = len(latencies)

    p50_idx = int(0.50 * (n - 1))
    p90_idx = int(0.90 * (n - 1))
    p99_idx = int(0.99 * (n - 1))

    return {
        "meanMs": round(statistics.mean(latencies), 2),
        "minMs": round(min(latencies), 2),
        "maxMs": round(max(latencies), 2),
        "p50Ms": round(latencies[p50_idx], 2),
        "p90Ms": round(latencies[p90_idx], 2),
        "p99Ms": round(latencies[p99_idx], 2),
    }
