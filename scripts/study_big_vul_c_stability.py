"""Repeat the frozen C model configuration at fixed seeds on train/validation."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.alert_policy import choose_budget_threshold
from vulnscope.logistic import fit_logistic
from vulnscope.metrics import ranking_metrics


SEEDS = (11, 42, 73)


def run(prepared_dir: Path, model_dir: Path, output: Path, *, max_epochs: int = 80) -> dict[str, object]:
    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    bundle = json.loads((model_dir / "bundle.json").read_text())
    if (hashlib.sha256(manifest_path.read_bytes()).hexdigest() != bundle.get("prepared_manifest_sha256")
            or hashlib.sha256((model_dir / "model.npz").read_bytes()).hexdigest() != bundle.get("model_sha256")
            or manifest.get("feature_version") != bundle.get("feature_version")
            or manifest.get("vocabulary") != bundle.get("vocabulary")
            or bundle.get("language") != "c"):
        raise ValueError("incompatible frozen C training artifacts")
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as arrays:
        if any(name.startswith(("X_test", "y_test", "id_test")) for name in arrays.files):
            raise ValueError("stability study must not access test arrays")
        train_x, train_y = arrays["X_train"].copy(), arrays["y_train"].copy()
        val_x, val_y = arrays["X_validation"].copy(), arrays["y_validation"].copy()
        train_ids, val_ids = arrays["id_train"].tolist(), arrays["id_validation"].tolist()
    for role, labels, ids in (("train", train_y, train_ids), ("validation", val_y, val_ids)):
        expected = [row for row in manifest["examples"] if row["split"] == role]
        if ids != [row["source_id"] for row in expected] or labels.tolist() != [row["label"] for row in expected]:
            raise ValueError(f"{role} arrays do not match manifest")
    if (train_x.shape[1] != len(bundle["vocabulary"])
            or val_x.shape[1] != len(bundle["vocabulary"])
            or set(train_y.tolist()) != {0, 1} or set(val_y.tolist()) != {0, 1}):
        raise ValueError("invalid training or validation arrays")
    positive_weight = float(bundle["positive_weight"])
    weights = np.where(train_y == 1, positive_weight, 1.0)
    runs = []
    for seed in SEEDS:
        model, history = fit_logistic(
            train_x, train_y, val_x, val_y,
            learning_rate=0.1, l2=float(bundle["l2"]), batch_size=256,
            max_epochs=max_epochs, patience=10, seed=seed,
            train_sample_weights=weights,
        )
        train_scores = model.predict_scores(train_x)
        val_scores = model.predict_scores(val_x)
        threshold, policy_metrics = choose_budget_threshold(val_y, val_scores, 0.05)
        runs.append({
            "seed": seed, "epochs_run": len(history), "best_validation_loss": min(row["val_loss"] for row in history),
            "train": ranking_metrics(train_y, train_scores),
            "validation": {**ranking_metrics(val_y, val_scores), **policy_metrics},
            "validation_budget_threshold": threshold,
        })
    result = {
        "study": "fixed-configuration-seed-sensitivity-train-validation-only",
        "model_sha256": hashlib.sha256((model_dir / "model.npz").read_bytes()).hexdigest(),
        "prepared_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "features_sha256": hashlib.sha256((prepared_dir / "features.npz").read_bytes()).hexdigest(),
        "seeds": list(SEEDS), "max_epochs": max_epochs, "runs": runs,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/big_vul_c_seed_stability_v1.json"))
    args = parser.parse_args()
    print(json.dumps(run(args.prepared_dir, args.model_dir, args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
