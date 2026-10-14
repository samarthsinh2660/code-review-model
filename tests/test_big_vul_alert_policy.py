"""The alert policy is selected only from frozen validation arrays."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.fit_big_vul_alert_policy import fit_policy
from vulnscope.logistic import LogisticModel


class BigVulAlertPolicyTests(unittest.TestCase):
    def test_policy_links_frozen_artifacts_and_rejects_test_arrays(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = root / "prepared"
            model_dir = root / "model"
            prepared.mkdir()
            model_dir.mkdir()
            manifest = {"feature_version": "cpp-body-lexical-v2", "vocabulary": ["x"],
                        "examples": [{"source_id": f"v{i}", "label": int(i == 0),
                                      "split": "validation"} for i in range(4)]}
            manifest_path = prepared / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            features_path = prepared / "features.npz"
            arrays = {"X_validation": np.array([[3.0], [2.0], [1.0], [0.0]]),
                      "y_validation": np.array([1, 0, 0, 0]),
                      "id_validation": np.array([f"v{i}" for i in range(4)])}
            np.savez_compressed(features_path, **arrays)
            model_path = model_dir / "model.npz"
            LogisticModel(np.array([1.0]), -2.0).save(model_path)
            bundle = {"language": "c", "feature_version": "cpp-body-lexical-v2",
                      "vocabulary": ["x"],
                      "prepared_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                      "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest()}
            (model_dir / "bundle.json").write_text(json.dumps(bundle))
            policy = fit_policy(prepared, model_dir, root / "policy.json", 0.25)
            self.assertEqual(policy["validation"]["tp"], 1)
            self.assertEqual(policy["validation"]["fp"], 0)
            self.assertEqual(policy["features_sha256"], hashlib.sha256(features_path.read_bytes()).hexdigest())
            np.savez_compressed(features_path, **arrays, X_test=np.array([[1.0]]))
            with self.assertRaisesRegex(ValueError, "test arrays"):
                fit_policy(prepared, model_dir, root / "policy.json", 0.25)


if __name__ == "__main__":
    unittest.main()
