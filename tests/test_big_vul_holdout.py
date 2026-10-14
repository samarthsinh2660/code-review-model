"""Final test accepts only the frozen remainder and project cohort."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.evaluate_big_vul_holdout import run
from vulnscope.external_data import normalized_hash
from vulnscope.logistic import LogisticModel


class BigVulHoldoutTests(unittest.TestCase):
    def fixture(self, root):
        root = Path(root)
        prepared = root / "prepared"; prepared.mkdir()
        model_dir = root / "model"; model_dir.mkdir()
        source = root / "test.jsonl"
        train_audit = root / "train_audit.json"
        train_audit.write_text(json.dumps({"archive_sha256": "a" * 64}))
        manifest = {"feature_version": "cpp-body-lexical-v2", "vocabulary": ["return"],
                    "audit_sha256": hashlib.sha256(train_audit.read_bytes()).hexdigest(),
                    "test_sample_modulus": 10, "test_sample_remainder": 1,
                    "projects": {"train": ["train-repo"], "validation": ["val-repo"], "test": ["test-repo"]}}
        manifest_path = prepared / "manifest.json"
        manifest_path.write_text(json.dumps(manifest))
        model_path = model_dir / "model.npz"
        LogisticModel(np.asarray([1.0]), 0.0).save(model_path)
        bundle = {"model_version": "fixture", "language": "c", "feature_version": "cpp-body-lexical-v2",
                  "prepared_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
                  "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
                  "vocabulary": ["return"], "threshold": 0.5}
        (model_dir / "bundle.json").write_text(json.dumps(bundle))
        codes = []
        value = 0
        while len(codes) < 2:
            code = f"int f{value}() {{ return {value}; }}"
            if int(normalized_hash(code)[:16], 16) % 10 == 1:
                codes.append(code)
            value += 1
        rows = [{"source_id": f"test-{i}", "repository": "test-repo", "commit": "fix",
                 "source_code": code, "label": i, "language": "c", "dataset_version": "fixture", "license_id": "fixture"}
                for i, code in enumerate(codes)]
        source.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        audit = root / "test_audit.json"
        audit.write_text(json.dumps({"archive_sha256": "a" * 64, "sample_modulus": 10, "sample_remainder": 1,
                                     "output_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}))
        return source, audit, train_audit, prepared, model_dir, root / "result.json"

    def test_frozen_cohort_scores_and_rejects_wrong_remainder(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            result = run(*args)
            self.assertEqual(result["sample_count"], 2)
            self.assertEqual(result["repository_count"], 1)
            test_audit = json.loads(args[1].read_text())
            test_audit["sample_remainder"] = 0
            args[1].write_text(json.dumps(test_audit))
            with self.assertRaisesRegex(ValueError, "test hash cohort"):
                run(*args)

    def test_project_role_overlap_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            manifest_path = args[3] / "manifest.json"
            manifest = json.loads(manifest_path.read_text())
            manifest["projects"]["train"].append("test-repo")
            manifest_path.write_text(json.dumps(manifest))
            bundle_path = args[4] / "bundle.json"
            bundle = json.loads(bundle_path.read_text())
            bundle["prepared_manifest_sha256"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            bundle_path.write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "project roles overlap"):
                run(*args)


if __name__ == "__main__":
    unittest.main()
