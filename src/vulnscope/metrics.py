"""Binary detection metrics and validation-only threshold selection."""

from __future__ import annotations

import numpy as np


def _validate(labels: np.ndarray, scores: np.ndarray) -> None:
    if labels.ndim != 1 or scores.shape != labels.shape or not len(labels):
        raise ValueError("nonempty one-dimensional labels and scores are required")
    if not np.all((labels == 0) | (labels == 1)):
        raise ValueError("labels must be binary")
    if not np.all(np.isfinite(scores)) or np.any((scores < 0) | (scores > 1)):
        raise ValueError("scores must be finite values in [0, 1]")


def ranking_metrics(labels: np.ndarray, scores: np.ndarray) -> dict[str, float | None]:
    """Compute stepwise average precision and tie-aware ROC-AUC."""

    _validate(labels, scores)
    positives = int(labels.sum())
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        return {"average_precision": None if positives == 0 else 1.0, "roc_auc": None}
    order = np.argsort(-scores, kind="stable")
    sorted_scores = scores[order]
    sorted_labels = labels[order]
    tp = fp = 0
    ap = auc = 0.0
    previous_tpr = previous_fpr = 0.0
    start = 0
    while start < len(labels):
        end = start + 1
        while end < len(labels) and sorted_scores[end] == sorted_scores[start]:
            end += 1
        tp += int(sorted_labels[start:end].sum())
        fp += end - start - int(sorted_labels[start:end].sum())
        tpr = tp / positives
        fpr = fp / negatives
        ap += (tpr - previous_tpr) * (tp / (tp + fp))
        auc += (fpr - previous_fpr) * (tpr + previous_tpr) / 2
        previous_tpr, previous_fpr = tpr, fpr
        start = end
    return {"average_precision": ap, "roc_auc": auc}


def threshold_metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, float | int]:
    """Return confusion counts and rates; undefined ratios use zero."""

    _validate(labels, scores)
    if not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("threshold must be finite in [0, 1]")
    predicted = scores >= threshold
    tp = int(np.sum(predicted & (labels == 1)))
    fp = int(np.sum(predicted & (labels == 0)))
    tn = int(np.sum(~predicted & (labels == 0)))
    fn = int(np.sum(~predicted & (labels == 1)))
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": precision, "recall": recall, "f1": f1,
        "false_positive_rate": fp / (fp + tn) if fp + tn else 0.0,
        "false_negative_rate": fn / (fn + tp) if fn + tp else 0.0,
        "prevalence": (tp + fn) / len(labels),
        "flagged_fraction": (tp + fp) / len(labels),
        "balanced_accuracy": 0.5 * (recall + (tn / (tn + fp) if tn + fp else 0.0)),
    }


def choose_f1_threshold(labels: np.ndarray, scores: np.ndarray) -> tuple[float, dict[str, float | int]]:
    """Select F1, then precision, then higher threshold using validation only."""

    _validate(labels, scores)
    candidates = sorted({float(score) for score in scores} | {1.0})
    ranked = []
    for threshold in candidates:
        metrics = threshold_metrics(labels, scores, threshold)
        ranked.append((metrics["f1"], metrics["precision"], threshold, metrics))
    _, _, threshold, metrics = max(ranked, key=lambda item: item[:3])
    return threshold, metrics
