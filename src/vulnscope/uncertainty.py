"""Paired project-level bootstrap for average-precision comparisons."""

from __future__ import annotations

from collections import defaultdict

import numpy as np

from vulnscope.metrics import ranking_metrics


def project_bootstrap_ap_difference(
    labels: np.ndarray, candidate: np.ndarray, reference: np.ndarray,
    projects: list[str], *, repeats: int = 1000, seed: int = 42,
) -> dict[str, object]:
    """Resample whole projects and summarize candidate-minus-reference AP."""

    if (labels.ndim != 1 or candidate.shape != labels.shape or reference.shape != labels.shape
            or len(projects) != len(labels) or repeats < 1):
        raise ValueError("labels, scores, projects, and repeat count are incompatible")
    groups: dict[str, list[int]] = defaultdict(list)
    for index, project in enumerate(projects):
        if not isinstance(project, str) or not project:
            raise ValueError("project names must be nonempty")
        groups[project].append(index)
    if len(groups) < 2:
        raise ValueError("at least two independent projects are required")
    # Validate all labels and scores once before any bootstrap draw.
    candidate_ap = ranking_metrics(labels, candidate)["average_precision"]
    reference_ap = ranking_metrics(labels, reference)["average_precision"]
    if candidate_ap is None or reference_ap is None:
        raise ValueError("both labels are required for AP comparison")
    arrays = [np.asarray(indices, dtype=np.int64) for _, indices in sorted(groups.items())]
    rng = np.random.default_rng(seed)
    differences = []
    skipped = 0
    for _ in range(repeats):
        sampled = np.concatenate([arrays[index] for index in rng.integers(0, len(arrays), size=len(arrays))])
        sample_labels = labels[sampled]
        if not 0 < int(sample_labels.sum()) < len(sample_labels):
            skipped += 1
            continue
        first = ranking_metrics(sample_labels, candidate[sampled])["average_precision"]
        second = ranking_metrics(sample_labels, reference[sampled])["average_precision"]
        differences.append(float(first - second))
    if not differences:
        raise ValueError("no bootstrap replicate contained both labels")
    return {
        "point_difference": float(candidate_ap - reference_ap),
        "ci_95": [float(value) for value in np.percentile(differences, [2.5, 97.5])],
        "probability_nonpositive_in_bootstrap": sum(value <= 0 for value in differences) / len(differences),
        "project_count": len(groups), "requested_replicates": repeats,
        "valid_replicates": len(differences), "skipped_single_class_replicates": skipped,
        "seed": seed,
    }
