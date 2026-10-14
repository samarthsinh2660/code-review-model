"""Frequency training selects only from train and validation arrays."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.train_big_vul_frequency import run
from vulnscope.logistic import LogisticModel


class BigVulFrequencyTrainingTests(unittest.TestCase):
    def test_freezes_model_and_rejects_test_arrays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = root / "prepared"
            old = root / "old"
            prepared.mkdir()
            old.mkdir()
            train_ids = [f"t{i}" for i in range(6)]
            val_ids = [f"v{i}" for i in range(4)]
            train_y = np.array([0, 1, 0, 1, 0, 1], dtype=np.int8)
            val_y = np.array([0, 1, 0, 1], dtype=np.int8)
            original = {"vocabulary": ["x", "y"], "examples": [
                {"source_id": source_id, "label": int(label), "split": role}
                for role, ids, labels in (("train", train_ids, train_y), ("validation", val_ids, val_y))
                for source_id, label in zip(ids, labels)
            ]}
            original_path = old / "manifest.json"
            original_path.write_text(json.dumps(original))
            manifest = {"feature_version": "cpp-body-frequency-v1",
                        "original_manifest_sha256": hashlib.sha256(original_path.read_bytes()).hexdigest(),
                        "vocabulary": ["x", "y"], "idf": [0.8, 1.2], "test_sample_remainder": 3}
            (prepared / "manifest.json").write_text(json.dumps(manifest))
            arrays = {
                "X_train": np.array([[0, 1], [1, 0], [0, 2], [2, 0], [0, 3], [3, 0]], dtype=np.float32),
                "y_train": train_y, "id_train": np.array(train_ids),
                "X_validation": np.array([[0, 1], [1, 0], [0, 2], [2, 0]], dtype=np.float32),
                "y_validation": val_y, "id_validation": np.array(val_ids),
                "idf": np.array([0.8, 1.2], dtype=np.float32),
            }
            np.savez_compressed(prepared / "features.npz", **arrays)
            model_dir = root / "model"
            result = run(prepared, old, model_dir, root / "result.json", max_epochs=5)
            self.assertIn(result["selected_variant"], ("tf", "tfidf"))
            self.assertNotIn("test", result["selected_validation"])
            self.assertEqual(len(LogisticModel.load(model_dir / "model.npz").weights), 2)
            np.savez_compressed(prepared / "features.npz", **arrays, X_test=np.array([[1, 1]]))
            with self.assertRaisesRegex(ValueError, "test arrays"):
                run(prepared, old, model_dir, root / "result.json", max_epochs=5)


if __name__ == "__main__":
    unittest.main()
