"""Freeze a 5% review budget from the Big-Vul C validation split only."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.alert_policy import choose_budget_threshold
from vulnscope.logistic import LogisticModel
from vulnscope.metrics import ranking_metrics


POLICY_VERSION = "bigvul-c-budget-5pct-v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fit_policy(prepared_dir: Path, model_dir: Path, output: Path, budget: float = 0.05) -> dict[str, object]:
    manifest_path = prepared_dir / "manifest.json"
    features_path = prepared_dir / "features.npz"
    model_path = model_dir / "model.npz"
    bundle = json.loads((model_dir / "bundle.json").read_text())
    manifest = json.loads(manifest_path.read_text())
    if (_sha256(manifest_path) != bundle.get("prepared_manifest_sha256")
            or _sha256(model_path) != bundle.get("model_sha256")
            or bundle.get("feature_version") != manifest.get("feature_version")
            or bundle.get("vocabulary") != manifest.get("vocabulary")
            or bundle.get("language") != "c"):
        raise ValueError("frozen model and prepared manifest do not match")
    with np.load(features_path, allow_pickle=False) as arrays:
        if any(name.startswith(("X_test", "y_test", "id_test")) for name in arrays.files):
            raise ValueError("test arrays must not be present during policy selection")
        val_x = arrays["X_validation"].copy()
        val_y = arrays["y_validation"].copy()
        val_ids = arrays["id_validation"].tolist()
    expected_ids = [row["source_id"] for row in manifest["examples"] if row["split"] == "validation"]
    expected_labels = [row["label"] for row in manifest["examples"] if row["split"] == "validation"]
    if (val_ids != expected_ids or val_y.tolist() != expected_labels
            or val_x.shape != (len(val_ids), len(bundle["vocabulary"]))):
        raise ValueError("validation arrays do not match the frozen manifest")
    model = LogisticModel.load(model_path)
    if len(model.weights) != len(bundle["vocabulary"]):
        raise ValueError("model feature count does not match vocabulary")
    scores = model.predict_scores(val_x)
    threshold, metrics = choose_budget_threshold(val_y, scores, budget)
    policy = {
        "policy_version": POLICY_VERSION,
        "selection": "maximize validation recall under alert budget; then minimize false alerts",
        "max_flagged_fraction": budget,
        "threshold": threshold,
        "validation": {**ranking_metrics(val_y, scores), **metrics},
        "validation_rows": len(val_y),
        "prepared_manifest_sha256": _sha256(manifest_path),
        "features_sha256": _sha256(features_path),
        "model_sha256": _sha256(model_path),
        "bundle_sha256": _sha256(model_dir / "bundle.json"),
        "test_sample_modulus": 10,
        "test_sample_remainder": 2,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(policy, indent=2, sort_keys=True) + "\n")
    return policy


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--model-dir", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1"))
    parser.add_argument("--output", type=Path, default=Path("artifacts/models/big_vul_c_logistic_v1/alert_policy_5pct.json"))
    args = parser.parse_args()
    print(json.dumps(fit_policy(args.prepared_dir, args.model_dir, args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
