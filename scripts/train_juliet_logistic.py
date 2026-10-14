"""Train the custom logistic baseline, select on validation, evaluate frozen test."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.logistic import LogisticModel, fit_logistic
from vulnscope.metrics import choose_f1_threshold, ranking_metrics, threshold_metrics


MODEL_VERSION = "juliet-01-logistic-v2"
L2_GRID = (0.0, 0.001, 0.01, 0.1)


def _evaluate(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {**ranking_metrics(labels, scores), **threshold_metrics(labels, scores, threshold)}


def run(prepared_dir: Path, model_dir: Path, result_path: Path) -> dict[str, object]:
    manifest_bytes = (prepared_dir / "manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest["feature_version"] != "cpp-body-lexical-v2":
        raise ValueError("incompatible feature version")
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as arrays:
        data = {name: arrays[name].copy() for name in (
            "X_train", "y_train", "id_train", "X_validation", "y_validation", "id_validation"
        )}
    vocabulary_size = manifest["vocabulary_size"]
    for split in ("train", "validation"):
        ids = [item["source_id"] for item in manifest["examples"] if item["split"] == split]
        if data[f"X_{split}"].shape != (len(ids), vocabulary_size):
            raise ValueError(f"feature matrix shape mismatch for {split}")
        if ids != data[f"id_{split}"].tolist():
            raise ValueError(f"source ID order mismatch for {split}")

    train_x, train_y = data["X_train"], data["y_train"]
    val_x, val_y = data["X_validation"], data["y_validation"]
    candidates = []
    selected_model = None
    selected_threshold = None
    best_key = None
    for l2 in L2_GRID:
        model, history = fit_logistic(
            train_x, train_y, val_x, val_y,
            learning_rate=0.1, l2=l2, batch_size=64,
            max_epochs=250, patience=25, seed=42,
        )
        train_scores = model.predict_scores(train_x)
        val_scores = model.predict_scores(val_x)
        threshold, validation_at_threshold = choose_f1_threshold(val_y, val_scores)
        ranking = ranking_metrics(val_y, val_scores)
        validation_loss = min(item["val_loss"] for item in history)
        candidate = {
            "l2": l2,
            "epochs_run": len(history),
            "best_validation_loss": validation_loss,
            "threshold": threshold,
            "train": _evaluate(train_y, train_scores, threshold),
            "validation": {**ranking, **validation_at_threshold},
            "history": history,
        }
        candidates.append(candidate)
        key = (ranking["average_precision"], -validation_loss, -l2)
        if best_key is None or key > best_key:
            best_key = key
            selected_model = model
            selected_threshold = threshold
            selected_candidate = candidate

    assert selected_model is not None and selected_threshold is not None
    # The test set is used here for the first and only final measurement in this run.
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as arrays:
        for name in ("X_test", "y_test", "id_test"):
            data[name] = arrays[name].copy()
    expected_test_ids = [item["source_id"] for item in manifest["examples"] if item["split"] == "test"]
    if data["X_test"].shape != (len(expected_test_ids), vocabulary_size) or data["id_test"].tolist() != expected_test_ids:
        raise ValueError("test feature matrix or source IDs do not match the frozen manifest")
    test_scores = selected_model.predict_scores(data["X_test"])
    test_metrics = _evaluate(data["y_test"], test_scores, selected_threshold)
    test_ids = data["id_test"].tolist()
    errors = []
    for source_id, label, score in zip(test_ids, data["y_test"], test_scores):
        predicted = bool(score >= selected_threshold)
        if predicted != bool(label):
            errors.append({"source_id": source_id, "label": int(label), "score": float(score)})
    errors.sort(key=lambda item: abs(item["score"] - selected_threshold), reverse=True)

    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.npz"
    selected_model.save(model_path)
    loaded = LogisticModel.load(model_path)
    if not np.array_equal(loaded.predict_scores(data["X_test"]), test_scores):
        raise ValueError("reloaded model predictions changed")
    bundle = {
        "model_version": MODEL_VERSION,
        "feature_version": manifest["feature_version"],
        "prepared_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "vocabulary": manifest["vocabulary"],
        "threshold": selected_threshold,
        "l2": selected_candidate["l2"],
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
    }
    (model_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = {
        "model_version": MODEL_VERSION,
        "selection_rule": "highest validation average precision, then lowest validation loss; F1 threshold from validation",
        "selected_l2": selected_candidate["l2"],
        "selected_threshold": selected_threshold,
        "selected_train": selected_candidate["train"],
        "selected_validation": selected_candidate["validation"],
        "test": test_metrics,
        "test_errors": errors,
        "candidate_runs": candidates,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/juliet_01"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/juliet_01_logistic"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/juliet_01_logistic.json"))
    args = parser.parse_args()
    result = run(args.prepared_dir, args.model_dir, args.result)
    print(json.dumps({key: value for key, value in result.items() if key not in {"test_errors", "candidate_runs"}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
