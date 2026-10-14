"""Select a review-workload threshold using validation labels and scores."""

from __future__ import annotations

import math

import numpy as np

from vulnscope.metrics import threshold_metrics


def choose_budget_threshold(
    labels: np.ndarray, scores: np.ndarray, max_flagged_fraction: float,
) -> tuple[float, dict[str, float | int]]:
    """Maximize validation recall within an alert budget, then minimize false alerts.

    A tied score group is indivisible. The returned threshold always selects
    complete groups and never exceeds the requested fraction on validation.
    """

    if not math.isfinite(max_flagged_fraction) or not 0 < max_flagged_fraction <= 1:
        raise ValueError("alert budget must be finite and in (0, 1]")
    if labels.ndim != 1 or scores.shape != labels.shape or not len(labels):
        raise ValueError("nonempty one-dimensional labels and scores are required")
    if not np.all((labels == 0) | (labels == 1)):
        raise ValueError("labels must be binary")
    if not np.all(np.isfinite(scores)) or np.any((scores < 0) | (scores > 1)):
        raise ValueError("scores must be finite values in [0, 1]")

    allowed = math.floor(len(labels) * max_flagged_fraction)
    candidates = sorted({float(score) for score in scores} | {1.0}, reverse=True)
    best: tuple[int, int, float, dict[str, float | int]] | None = None
    for threshold in candidates:
        metrics = threshold_metrics(labels, scores, threshold)
        flagged = int(metrics["tp"] + metrics["fp"])
        if flagged > allowed:
            continue
        key = (int(metrics["tp"]), -int(metrics["fp"]), threshold)
        if best is None or key > best[:3]:
            best = (*key, metrics)
    if best is None:
        raise ValueError("no threshold in [0, 1] can satisfy this budget")
    return best[2], best[3]
