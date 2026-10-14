"""Train a C-only Big-Vul logistic baseline with project-held-out validation."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from vulnscope.logistic import LogisticModel, fit_logistic
from vulnscope.metrics import choose_f1_threshold, ranking_metrics, threshold_metrics


MODEL_VERSION = "bigvul-c-logistic-v1"
L2_GRID = (0.01, 0.1)


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {**ranking_metrics(labels, scores), **threshold_metrics(labels, scores, threshold)}


def run(
    prepared_dir: Path, model_dir: Path, result_path: Path,
    *, max_epochs: int = 80,
) -> dict[str, object]:
    """Select entirely from train/validation; the final test is a separate command."""

    manifest_path = prepared_dir / "manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    if (manifest.get("feature_version") != "cpp-body-lexical-v2"
            or manifest.get("source_sample_remainder") != 0
            or manifest.get("test_sample_remainder") != 1):
        raise ValueError("incompatible Big-Vul training manifest")
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as arrays:
        if any(name.startswith(("X_test", "y_test", "id_test")) for name in arrays.files):
            raise ValueError("test arrays must not be present during selection")
        data = {name: arrays[name].copy() for name in (
            "X_train", "y_train", "id_train", "X_validation", "y_validation", "id_validation"
        )}
    for split in ("train", "validation"):
        ids = [item["source_id"] for item in manifest["examples"] if item["split"] == split]
        if data[f"X_{split}"].shape != (len(ids), manifest["vocabulary_size"]):
            raise ValueError(f"{split} feature shape does not match manifest")
        if data[f"id_{split}"].tolist() != ids:
            raise ValueError(f"{split} source IDs do not match manifest")
        if set(data[f"y_{split}"].tolist()) != {0, 1}:
            raise ValueError(f"{split} must contain both classes")
    train_x, train_y = data["X_train"], data["y_train"]
    val_x, val_y = data["X_validation"], data["y_validation"]
    positive = int(train_y.sum())
    negative = len(train_y) - positive
    weight_grid = (1.0, math.sqrt(negative / positive))
    candidates = []
    best_key = None
    selected_model = None
    selected_candidate = None
    for positive_weight in weight_grid:
        sample_weights = np.where(train_y == 1, positive_weight, 1.0)
        for l2 in L2_GRID:
            model, history = fit_logistic(
                train_x, train_y, val_x, val_y,
                learning_rate=0.1, l2=l2, batch_size=256,
                max_epochs=max_epochs, patience=10, seed=42,
                train_sample_weights=sample_weights,
            )
            train_scores = model.predict_scores(train_x)
            val_scores = model.predict_scores(val_x)
            threshold, _ = choose_f1_threshold(val_y, val_scores)
            ranking = ranking_metrics(val_y, val_scores)
            val_loss = min(item["val_loss"] for item in history)
            candidate = {
                "l2": l2,
                "positive_weight": positive_weight,
                "epochs_run": len(history),
                "best_validation_loss": val_loss,
                "threshold": threshold,
                "train": _metrics(train_y, train_scores, threshold),
                "validation": _metrics(val_y, val_scores, threshold),
                "history": history,
            }
            candidates.append(candidate)
            key = (ranking["average_precision"], -val_loss, -l2, -positive_weight)
            if best_key is None or key > best_key:
                best_key = key
                selected_model = model
                selected_candidate = candidate
    assert selected_model is not None and selected_candidate is not None
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.npz"
    selected_model.save(model_path)
    if not np.array_equal(LogisticModel.load(model_path).predict_scores(val_x),
                          selected_model.predict_scores(val_x)):
        raise ValueError("reloaded model changed validation scores")
    bundle = {
        "model_version": MODEL_VERSION,
        "language": "c",
        "feature_version": manifest["feature_version"],
        "prepared_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
        "vocabulary": manifest["vocabulary"],
        "threshold": selected_candidate["threshold"],
        "l2": selected_candidate["l2"],
        "positive_weight": selected_candidate["positive_weight"],
    }
    (model_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = {
        "model_version": MODEL_VERSION,
        "selection_rule": "highest validation AP, then lowest validation loss; F1 threshold from validation",
        "candidate_runs": candidates,
        "selected_l2": selected_candidate["l2"],
        "selected_positive_weight": selected_candidate["positive_weight"],
        "selected_threshold": selected_candidate["threshold"],
        "selected_train": selected_candidate["train"],
        "selected_validation": selected_candidate["validation"],
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/big_vul_c_logistic_v1.json"))
    args = parser.parse_args()
    result = run(args.prepared_dir, args.model_dir, args.result)
    print(json.dumps({key: value for key, value in result.items() if key != "candidate_runs"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
