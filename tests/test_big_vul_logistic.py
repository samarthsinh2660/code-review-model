"""Training freezes validation-selected settings without opening a test set."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.train_big_vul_logistic import run
from vulnscope.logistic import LogisticModel


class BigVulLogisticTests(unittest.TestCase):
    def test_bundle_links_manifest_and_uses_only_train_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = root / "prepared"; prepared.mkdir()
            train_ids = [f"train-{i}" for i in range(6)]
            validation_ids = [f"validation-{i}" for i in range(4)]
            manifest = {
                "feature_version": "cpp-body-lexical-v2", "source_sample_remainder": 0,
                "test_sample_remainder": 1, "vocabulary": ["x", "y"], "vocabulary_size": 2,
                "examples": [{"source_id": item, "split": split} for split, ids in
                             (("train", train_ids), ("validation", validation_ids)) for item in ids],
            }
            manifest_path = prepared / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            np.savez_compressed(prepared / "features.npz",
                                X_train=np.asarray([[0, 1], [1, 0], [0, 2], [2, 0], [0, 3], [3, 0]], dtype=np.float32),
                                y_train=np.asarray([0, 1, 0, 1, 0, 1], dtype=np.int8),
                                id_train=np.asarray(train_ids),
                                X_validation=np.asarray([[0, 1], [1, 0], [0, 2], [2, 0]], dtype=np.float32),
                                y_validation=np.asarray([0, 1, 0, 1], dtype=np.int8),
                                id_validation=np.asarray(validation_ids))
            model_dir = root / "model"
            result = run(prepared, model_dir, root / "result.json", max_epochs=5)
            self.assertIn("selected_validation", result)
            self.assertNotIn("test", result)
            bundle = json.loads((model_dir / "bundle.json").read_text())
            self.assertEqual(bundle["prepared_manifest_sha256"], hashlib.sha256(manifest_path.read_bytes()).hexdigest())
            self.assertEqual(len(LogisticModel.load(model_dir / "model.npz").weights), 2)


if __name__ == "__main__":
    unittest.main()
