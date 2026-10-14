"""Compare frozen C model rankings against function length on validation only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.external_data import load_external_jsonl
from vulnscope.lexical import tokenize_cpp
from vulnscope.logistic import LogisticModel
from vulnscope.metrics import ranking_metrics
from vulnscope.uncertainty import project_bootstrap_ap_difference


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _length_bins(train_lengths: np.ndarray, val_lengths: np.ndarray,
                 labels: np.ndarray, score_sets: dict[str, np.ndarray]) -> dict[str, object]:
    edges = np.quantile(train_lengths, [0.2, 0.4, 0.6, 0.8]).tolist()
    assignments = np.searchsorted(edges, val_lengths, side="right")
    groups = []
    auc_weighted = {name: 0.0 for name in score_sets}
    pair_total = 0
    for bin_index in range(5):
        subset = assignments == bin_index
        bin_labels = labels[subset]
        positives = int(bin_labels.sum())
        negatives = int(len(bin_labels) - positives)
        metrics = {name: ranking_metrics(bin_labels, scores[subset]) if len(bin_labels) else None
                   for name, scores in score_sets.items()}
        groups.append({"bin": bin_index, "samples": int(subset.sum()),
                       "positives": positives, "negatives": negatives,
                       "rankings": metrics})
        if positives and negatives:
            pairs = positives * negatives
            pair_total += pairs
            for name, item in metrics.items():
                auc_weighted[name] += float(item["roc_auc"]) * pairs
    return {"train_only_token_count_edges": edges, "bins": groups,
            "within_bin_pair_weighted_roc_auc": {
                name: total / pair_total if pair_total else None
                for name, total in auc_weighted.items()},
            "comparable_positive_negative_pairs": pair_total}


def run(source: Path, original_prepared_dir: Path, frequency_prepared_dir: Path,
        original_model_dir: Path, frequency_model_dir: Path, output: Path,
        *, bootstrap_repeats: int = 1000) -> dict[str, object]:
    original_path = original_prepared_dir / "manifest.json"
    frequency_path = frequency_prepared_dir / "manifest.json"
    original = json.loads(original_path.read_text())
    frequency = json.loads(frequency_path.read_text())
    original_bundle = json.loads((original_model_dir / "bundle.json").read_text())
    original_policy = json.loads((original_model_dir / "alert_policy_5pct.json").read_text())
    frequency_bundle = json.loads((frequency_model_dir / "bundle.json").read_text())
    if (_sha256(source) != original.get("source_sha256")
            or frequency.get("original_manifest_sha256") != _sha256(original_path)
            or original_bundle.get("prepared_manifest_sha256") != _sha256(original_path)
            or frequency_bundle.get("prepared_manifest_sha256") != _sha256(frequency_path)
            or _sha256(original_model_dir / "model.npz") != original_bundle.get("model_sha256")
            or _sha256(original_model_dir / "bundle.json") != original_policy.get("bundle_sha256")
            or _sha256(original_prepared_dir / "features.npz") != original_policy.get("features_sha256")
            or _sha256(original_model_dir / "model.npz") != original_policy.get("model_sha256")
            or _sha256(frequency_model_dir / "model.npz") != frequency_bundle.get("model_sha256")
            or _sha256(frequency_prepared_dir / "features.npz") != frequency_bundle.get("features_sha256")
            or original_bundle.get("vocabulary") != frequency_bundle.get("vocabulary")):
        raise ValueError("frozen source, split, model, or feature hashes do not match")
    with np.load(original_prepared_dir / "features.npz", allow_pickle=False) as arrays:
        original_x = arrays["X_validation"].copy()
        original_y = arrays["y_validation"].copy()
        original_ids = arrays["id_validation"].tolist()
    with np.load(frequency_prepared_dir / "features.npz", allow_pickle=False) as arrays:
        if any(name.startswith(("X_test", "y_test", "id_test")) for name in arrays.files):
            raise ValueError("test arrays must not enter validation comparison")
        frequency_x = arrays["X_validation"].copy()
        frequency_y = arrays["y_validation"].copy()
        frequency_ids = arrays["id_validation"].tolist()
        idf = arrays["idf"].copy()
    expected = [row for row in original["examples"] if row["split"] == "validation"]
    if (original_ids != frequency_ids or original_ids != [row["source_id"] for row in expected]
            or not np.array_equal(original_y, frequency_y)
            or original_y.tolist() != [row["label"] for row in expected]
            or frequency_x.shape[1] != len(frequency_bundle["vocabulary"])
            or not np.array_equal(idf, np.asarray(frequency_bundle["idf"], dtype=np.float32))):
        raise ValueError("validation rows or features do not match frozen split")
    if frequency_bundle["feature_variant"] == "tfidf":
        frequency_x *= idf
    elif frequency_bundle["feature_variant"] != "tf":
        raise ValueError("unsupported frequency variant")
    old_scores = LogisticModel.load(original_model_dir / "model.npz").predict_scores(original_x)
    new_scores = LogisticModel.load(frequency_model_dir / "model.npz").predict_scores(frequency_x)
    old_ap = ranking_metrics(original_y, old_scores)["average_precision"]
    if (old_ap is None or abs(old_ap - original_policy["validation"]["average_precision"]) > 1e-12):
        raise ValueError("frozen count-model validation ranking did not reproduce")
    by_id = {record.source_id: record for record in load_external_jsonl(source) if record.language == "c"}
    train_examples = [row for row in original["examples"] if row["split"] == "train"]
    train_lengths = np.asarray([len(tokenize_cpp(by_id[row["source_id"]].source_code))
                                for row in train_examples], dtype=np.float64)
    val_lengths = np.asarray([len(tokenize_cpp(by_id[row["source_id"]].source_code))
                              for row in expected], dtype=np.float64)
    length_scores = val_lengths / val_lengths.max()
    scores = {"old_count": old_scores, "new_frequency": new_scores, "length_only": length_scores}
    projects = [row["repository"] for row in expected]
    result = {
        "scope": "train/validation only; no final-test cohort opened",
        "source_sha256": _sha256(source),
        "original_model_sha256": _sha256(original_model_dir / "model.npz"),
        "frequency_model_sha256": _sha256(frequency_model_dir / "model.npz"),
        "validation_samples": len(original_y), "validation_projects": len(set(projects)),
        "rankings": {name: ranking_metrics(original_y, values) for name, values in scores.items()},
        "length_strata": _length_bins(train_lengths, val_lengths, original_y, scores),
        "project_bootstrap_ap_differences": {
            "new_minus_length": project_bootstrap_ap_difference(
                original_y, new_scores, length_scores, projects, repeats=bootstrap_repeats),
            "old_minus_length": project_bootstrap_ap_difference(
                original_y, old_scores, length_scores, projects, repeats=bootstrap_repeats),
            "new_minus_old": project_bootstrap_ap_difference(
                original_y, new_scores, old_scores, projects, repeats=bootstrap_repeats),
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--original-prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--frequency-prepared-dir", type=Path, default=Path("data/processed/big_vul_c_frequency"))
    parser.add_argument("--original-model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--frequency-model-dir", type=Path, default=Path("artifacts/models/big_vul_c_frequency_v1"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/big_vul_c_validation_length_v1.json"))
    args = parser.parse_args()
    result = run(args.source, args.original_prepared_dir, args.frequency_prepared_dir,
                 args.original_model_dir, args.frequency_model_dir, args.output)
    print(json.dumps({key: value for key, value in result.items() if key != "length_strata"},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
