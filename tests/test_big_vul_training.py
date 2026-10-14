"""Project separation and train-only vocabulary for real-world training."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.prepare_big_vul_training import prepare_training


class BigVulTrainingTests(unittest.TestCase):
    def test_projects_are_disjoint_and_validation_tokens_are_unseen(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "external.jsonl"
            rows = []
            for project_index, project in enumerate("ABCDEF"):
                for label in (0, 1):
                    value = project_index * 10 + label
                    rows.append({"source_id": f"{project}-{label}", "repository": project,
                                 "commit": f"fix-{project}", "language": "c", "label": label,
                                 "source_code": f"int f{value}() {{ int marker_{project} = {value}; return marker_{project}; }}",
                                 "dataset_version": "fixture", "license_id": "fixture"})
            source.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            audit = root / "audit.json"
            audit.write_text(json.dumps({"sample_modulus": 10, "sample_remainder": 0,
                                         "output_sha256": hashlib.sha256(source.read_bytes()).hexdigest()}))
            output = root / "prepared"
            manifest = prepare_training(source, audit, output, min_df=1)
            projects = manifest["projects"]
            self.assertFalse(set(projects["train"]) & set(projects["validation"]))
            self.assertFalse(set(projects["train"]) & set(projects["test"]))
            self.assertFalse(set(projects["validation"]) & set(projects["test"]))
            self.assertEqual(set().union(*map(set, projects.values())), set("ABCDEF"))
            for project in projects["validation"] + projects["test"]:
                self.assertNotIn(f"marker_{project}", manifest["vocabulary"])
            with np.load(output / "features.npz", allow_pickle=False) as arrays:
                self.assertEqual(arrays["X_train"].shape[1], len(manifest["vocabulary"]))
                self.assertEqual(arrays["id_validation"].shape[0], manifest["splits"]["samples"]["validation"])
                self.assertFalse("X_test" in arrays)


if __name__ == "__main__":
    unittest.main()
