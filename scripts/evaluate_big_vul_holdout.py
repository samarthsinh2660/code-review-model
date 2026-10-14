"""Score a fresh Big-Vul C hash cohort from unseen projects once."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path

import numpy as np

from vulnscope.external_data import load_external_jsonl
from vulnscope.lexical import Vocabulary, tokenize_cpp
from vulnscope.logistic import LogisticModel
from vulnscope.metrics import ranking_metrics, threshold_metrics


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {**ranking_metrics(labels, scores), **threshold_metrics(labels, scores, threshold)}


def run(
    source: Path, test_audit: Path, train_audit: Path,
    prepared_dir: Path, model_dir: Path, result_path: Path,
    *, policy_path: Path | None = None,
) -> dict[str, object]:
    """Require an intact frozen bundle and the reserved project/hash cohort."""

    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    bundle = json.loads((model_dir / "bundle.json").read_text())
    model_path = model_dir / "model.npz"
    policy = None
    expected_remainder = 1
    if policy_path is not None:
        policy = json.loads(policy_path.read_text())
        expected_remainder = 2
        if (policy.get("policy_version") != "bigvul-c-budget-5pct-v1"
                or policy.get("test_sample_modulus") != 10
                or policy.get("test_sample_remainder") != expected_remainder
                or policy.get("prepared_manifest_sha256") != _sha256(manifest_path)
                or policy.get("features_sha256") != _sha256(prepared_dir / "features.npz")
                or policy.get("model_sha256") != _sha256(model_path)
                or policy.get("bundle_sha256") != _sha256(model_dir / "bundle.json")):
            raise ValueError("alert policy does not match frozen training artifacts")
    if _sha256(manifest_path) != bundle.get("prepared_manifest_sha256"):
        raise ValueError("prepared manifest hash does not match bundle")
    if _sha256(model_path) != bundle.get("model_sha256"):
        raise ValueError("model hash does not match bundle")
    if _sha256(train_audit) != manifest.get("audit_sha256"):
        raise ValueError("training audit hash does not match manifest")
    train_audit_data = json.loads(train_audit.read_text())
    test_audit_data = json.loads(test_audit.read_text())
    if (test_audit_data.get("sample_modulus") != 10
            or test_audit_data.get("sample_remainder") != expected_remainder
            or (policy is None and manifest.get("test_sample_remainder") != expected_remainder)
            or test_audit_data.get("output_sha256") != _sha256(source)):
        raise ValueError("test hash cohort does not match frozen manifest")
    if train_audit_data.get("archive_sha256") != test_audit_data.get("archive_sha256"):
        raise ValueError("training and test cohorts came from different archives")
    roles = {name: set(manifest["projects"][name]) for name in ("train", "validation", "test")}
    if (roles["train"] & roles["validation"] or roles["train"] & roles["test"]
            or roles["validation"] & roles["test"]):
        raise ValueError("project roles overlap")
    if bundle.get("language") != "c" or bundle.get("feature_version") != manifest.get("feature_version"):
        raise ValueError("incompatible C model bundle")
    vocabulary_tokens = bundle.get("vocabulary")
    if (not isinstance(vocabulary_tokens, list) or not vocabulary_tokens
            or len(vocabulary_tokens) != len(set(vocabulary_tokens))
            or any(not isinstance(token, str) or not token for token in vocabulary_tokens)):
        raise ValueError("invalid frozen vocabulary")
    if vocabulary_tokens != manifest.get("vocabulary"):
        raise ValueError("bundle vocabulary does not match training manifest")
    threshold = bundle.get("threshold") if policy is None else policy.get("threshold")
    if type(threshold) not in (float, int) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("invalid frozen threshold")
    model = LogisticModel.load(model_path)
    if len(model.weights) != len(vocabulary_tokens):
        raise ValueError("model feature count does not match vocabulary")
    all_records = load_external_jsonl(source)
    for record in all_records:
        if int(record.normalized_sha256[:16], 16) % 10 != expected_remainder:
            raise ValueError("test row is outside frozen hash cohort")
    records = [record for record in all_records if record.language == "c" and record.repository in roles["test"]]
    if not records:
        raise ValueError("fresh cohort contains no C functions from reserved test projects")
    vocabulary = Vocabulary(tuple(vocabulary_tokens))
    features = np.log1p(np.asarray(vocabulary.transform(
        [tokenize_cpp(record.source_code) for record in records]
    ), dtype=np.float32))
    scores = model.predict_scores(features)
    labels = np.asarray([record.label for record in records], dtype=np.int8)
    by_project_indices: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        by_project_indices[record.repository].append(index)
    overall = _metrics(labels, scores, threshold)
    result = {
        "evaluation_type": "fresh-project-held-out-big-vul-c" if policy is None else "fresh-project-held-out-big-vul-c-budget",
        "model_version": bundle.get("model_version"),
        "policy_version": None if policy is None else policy["policy_version"],
        "policy_sha256": None if policy is None else _sha256(policy_path),
        "source_sha256": _sha256(source),
        "test_audit_sha256": _sha256(test_audit),
        "prepared_manifest_sha256": _sha256(manifest_path),
        "model_sha256": _sha256(model_path),
        "source_cohort_rows": len(all_records),
        "sample_count": len(records),
        "repository_count": len(by_project_indices),
        "threshold": threshold,
        "overall": overall,
        "false_findings_per_sampled_project": overall["fp"] / len(by_project_indices),
        "by_repository": {
            name: {"samples": len(indices), **_metrics(labels[indices], scores[indices], threshold)}
            for name, indices in sorted(by_project_indices.items())
        },
        "predictions": [
            {"source_id": record.source_id, "repository": record.repository,
             "label": record.label, "score": float(score), "flagged": bool(score >= threshold)}
            for record, score in zip(records, scores)
        ],
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/processed/big_vul_fresh_test.jsonl"))
    parser.add_argument("--test-audit", type=Path, default=Path("data/processed/big_vul_fresh_test_audit.json"))
    parser.add_argument("--train-audit", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/big_vul_c_holdout_v1.json"))
    args = parser.parse_args()
    result = run(args.source, args.test_audit, args.train_audit, args.prepared_dir, args.model_dir, args.result)
    print(json.dumps({key: value for key, value in result.items() if key not in {"predictions", "by_repository"}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
