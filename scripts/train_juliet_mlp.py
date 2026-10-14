"""Compare custom MLPs on lexical, AST, and combined Juliet features."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.metrics import choose_f1_threshold, ranking_metrics, threshold_metrics
from vulnscope.mlp import MLP, fit_mlp


MODEL_VERSION = "juliet-01-mlp-v1"
REPRESENTATIONS = ("lexical", "ast", "combined")
HIDDEN_GRID = (8, 16)
L2_GRID = (0.001, 0.01, 0.1)


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {**ranking_metrics(labels, scores), **threshold_metrics(labels, scores, threshold)}


def run(prepared_dir: Path, model_dir: Path, result_path: Path) -> dict[str, object]:
    lexical_manifest_bytes = (prepared_dir / "manifest.json").read_bytes()
    lexical_manifest = json.loads(lexical_manifest_bytes)
    ast_manifest_bytes = (prepared_dir / "ast_manifest.json").read_bytes()
    ast_manifest = json.loads(ast_manifest_bytes)
    if lexical_manifest["feature_version"] != "cpp-body-lexical-v2" or ast_manifest["ast_feature_version"] != "clang18-body-counts-v1":
        raise ValueError("incompatible feature versions")
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as saved:
        lexical = {key: saved[key].copy() for key in saved.files if not key.endswith("_test")}
    with np.load(prepared_dir / "ast_features.npz", allow_pickle=False) as saved:
        ast = {key: saved[key].copy() for key in saved.files if not key.endswith("_test")}
    for split in ("train", "validation"):
        if not np.array_equal(lexical[f"id_{split}"], ast[f"id_{split}"]):
            raise ValueError(f"AST and lexical source IDs differ for {split}")

    def matrix(representation: str, split: str) -> np.ndarray:
        if representation == "lexical":
            return lexical[f"X_{split}"]
        if representation == "ast":
            return ast[f"A_{split}"]
        return np.concatenate((lexical[f"X_{split}"], ast[f"A_{split}"]), axis=1)

    candidates = []
    selected_model = None
    selected_config = None
    best_key = None
    for representation in REPRESENTATIONS:
        train_x, val_x = matrix(representation, "train"), matrix(representation, "validation")
        train_y, val_y = lexical["y_train"], lexical["y_validation"]
        for hidden in HIDDEN_GRID:
            for l2 in L2_GRID:
                model, history = fit_mlp(
                    train_x, train_y, val_x, val_y,
                    hidden_size=hidden, learning_rate=0.01, l2=l2,
                    batch_size=64, max_epochs=200, patience=20, seed=42,
                )
                validation_scores = model.predict_scores(val_x)
                threshold, _ = choose_f1_threshold(val_y, validation_scores)
                ranking = ranking_metrics(val_y, validation_scores)
                validation_loss = min(item["val_loss"] for item in history)
                candidate = {
                    "representation": representation,
                    "hidden_size": hidden,
                    "l2": l2,
                    "epochs_run": len(history),
                    "best_validation_loss": validation_loss,
                    "threshold": threshold,
                    "train": _metrics(train_y, model.predict_scores(train_x), threshold),
                    "validation": _metrics(val_y, validation_scores, threshold),
                    "history": history,
                }
                candidates.append(candidate)
                key = (ranking["average_precision"], -validation_loss, -hidden, -l2)
                if best_key is None or key > best_key:
                    best_key = key
                    selected_model = model
                    selected_config = candidate
    assert selected_model is not None and selected_config is not None

    # Reused Juliet test cohort: diagnostic result only, never a fresh final estimate.
    with np.load(prepared_dir / "features.npz", allow_pickle=False) as saved:
        for key in ("X_test", "y_test", "id_test"):
            lexical[key] = saved[key].copy()
    with np.load(prepared_dir / "ast_features.npz", allow_pickle=False) as saved:
        for key in ("A_test", "id_test"):
            ast[key] = saved[key].copy()
    if not np.array_equal(lexical["id_test"], ast["id_test"]):
        raise ValueError("AST and lexical test source IDs differ")
    test_scores = selected_model.predict_scores(matrix(selected_config["representation"], "test"))
    test_metrics = _metrics(lexical["y_test"], test_scores, selected_config["threshold"])
    model_dir.mkdir(parents=True, exist_ok=True)
    model_path = model_dir / "model.npz"
    selected_model.save(model_path)
    if not np.array_equal(MLP.load(model_path).predict_scores(matrix(selected_config["representation"], "test")), test_scores):
        raise ValueError("reloaded MLP predictions changed")
    bundle = {
        "model_version": MODEL_VERSION,
        "representation": selected_config["representation"],
        "lexical_manifest_sha256": hashlib.sha256(lexical_manifest_bytes).hexdigest(),
        "ast_manifest_sha256": hashlib.sha256(ast_manifest_bytes).hexdigest(),
        "threshold": selected_config["threshold"],
        "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
    }
    (model_dir / "bundle.json").write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n")
    result = {
        "model_version": MODEL_VERSION,
        "selection_rule": "validation average precision, then validation loss; F1 threshold on validation",
        "selected": {key: value for key, value in selected_config.items() if key != "history"},
        "test_exploratory": test_metrics,
        "candidates": candidates,
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/juliet_01"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/juliet_01_mlp"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/juliet_01_mlp.json"))
    args = parser.parse_args()
    result = run(args.prepared_dir, args.model_dir, args.result)
    print(json.dumps({key: value for key, value in result.items() if key != "candidates"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
