"""Select a custom C logistic model on length-normalized validation features."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
from pathlib import Path

import numpy as np

from vulnscope.alert_policy import choose_budget_threshold
from vulnscope.logistic import LogisticModel, fit_logistic
from vulnscope.metrics import ranking_metrics


MODEL_VERSION = "bigvul-c-frequency-v1"
L2_GRID = (0.01, 0.1)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def run(prepared_dir: Path, original_prepared_dir: Path, model_dir: Path,
        result_path: Path, *, max_epochs: int = 80) -> dict[str, object]:
    frequency_path = prepared_dir / "manifest.json"
    features_path = prepared_dir / "features.npz"
    original_path = original_prepared_dir / "manifest.json"
    manifest = json.loads(frequency_path.read_text())
    original = json.loads(original_path.read_text())
    if (manifest.get("feature_version") != "cpp-body-frequency-v1"
            or manifest.get("original_manifest_sha256") != _sha256(original_path)
            or manifest.get("vocabulary") != original.get("vocabulary")
            or manifest.get("test_sample_remainder") != 3):
        raise ValueError("frequency data does not match frozen C split")
    with np.load(features_path, allow_pickle=False) as arrays:
        if any(name.startswith(("X_test", "y_test", "id_test")) for name in arrays.files):
            raise ValueError("test arrays must not enter model selection")
        data = {name: arrays[name].copy() for name in (
            "X_train", "y_train", "id_train", "X_validation", "y_validation", "id_validation", "idf"
        )}
    if not np.array_equal(data["idf"], np.asarray(manifest["idf"], dtype=np.float32)):
        raise ValueError("stored IDF does not match manifest")
    for role in ("train", "validation"):
        expected = [row for row in original["examples"] if row["split"] == role]
        if (data[f"X_{role}"].shape != (len(expected), len(manifest["vocabulary"]))
                or data[f"id_{role}"].tolist() != [row["source_id"] for row in expected]
                or data[f"y_{role}"].tolist() != [row["label"] for row in expected]
                or set(data[f"y_{role}"].tolist()) != {0, 1}):
            raise ValueError(f"{role} arrays do not match frozen split")
    train_y = data["y_train"]
    val_y = data["y_validation"]
    positive = int(train_y.sum())
    weight_grid = (1.0, math.sqrt((len(train_y) - positive) / positive))
    candidates = []
    best_key = None
    selected_model = None
    selected = None
    for variant in ("tf", "tfidf"):
        scale = data["idf"] if variant == "tfidf" else 1.0
        train_x = data["X_train"] * scale
        val_x = data["X_validation"] * scale
        for positive_weight in weight_grid:
            weights = np.where(train_y == 1, positive_weight, 1.0)
            for l2 in L2_GRID:
                model, history = fit_logistic(
                    train_x, train_y, val_x, val_y,
                    learning_rate=0.1, l2=l2, batch_size=256,
                    max_epochs=max_epochs, patience=10, seed=42,
                    train_sample_weights=weights,
                )
                scores = model.predict_scores(val_x)
                threshold, budget_metrics = choose_budget_threshold(val_y, scores, 0.05)
                ranking = ranking_metrics(val_y, scores)
                val_loss = min(row["val_loss"] for row in history)
                candidate = {
                    "variant": variant, "l2": l2, "positive_weight": positive_weight,
                    "epochs_run": len(history), "best_validation_loss": val_loss,
                    "threshold": threshold,
                    "train_ranking": ranking_metrics(train_y, model.predict_scores(train_x)),
                    "validation": {**ranking, **budget_metrics},
                    "history": history,
                }
                candidates.append(candidate)
                key = (ranking["average_precision"], -val_loss, -l2, -positive_weight)
                if best_key is None or key > best_key:
                    best_key, selected_model, selected = key, model, candidate
    assert selected_model is not None and selected is not None
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.npz"
    selected_model.save(model_path)
    selected_x = data["X_validation"] * (data["idf"] if selected["variant"] == "tfidf" else 1.0)
    if not np.array_equal(LogisticModel.load(model_path).predict_scores(selected_x),
                          selected_model.predict_scores(selected_x)):
        raise ValueError("reloaded model changed validation scores")
    bundle = {
        "model_version": MODEL_VERSION, "language": "c",
        "feature_version": manifest["feature_version"],
        "feature_variant": selected["variant"],
        "vocabulary": manifest["vocabulary"], "idf": manifest["idf"],
        "threshold": selected["threshold"],
        "l2": selected["l2"], "positive_weight": selected["positive_weight"],
        "prepared_manifest_sha256": _sha256(frequency_path),
        "original_manifest_sha256": _sha256(original_path),
        "features_sha256": _sha256(features_path),
        "model_sha256": _sha256(model_path),
        "test_sample_modulus": 10, "test_sample_remainder": 3,
    }
    (model_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = {
        "model_version": MODEL_VERSION,
        "selection": "highest validation AP among TF/TF-IDF and fixed L2/weight grid; then validation loss; 5% validation alert budget",
        "candidate_runs": candidates,
        "selected_variant": selected["variant"],
        "selected_l2": selected["l2"],
        "selected_positive_weight": selected["positive_weight"],
        "selected_threshold": selected["threshold"],
        "selected_train_ranking": selected["train_ranking"],
        "selected_validation": selected["validation"],
        "prepared_manifest_sha256": _sha256(frequency_path),
        "model_sha256": _sha256(model_path),
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_frequency"))
    parser.add_argument("--original-prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_frequency_v1"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/big_vul_c_frequency_v1.json"))
    args = parser.parse_args()
    result = run(args.prepared_dir, args.original_prepared_dir, args.model_dir, args.result)
    print(json.dumps({key: value for key, value in result.items() if key != "candidate_runs"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
