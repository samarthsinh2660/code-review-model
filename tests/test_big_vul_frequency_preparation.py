"""Frequency preparation retains frozen roles and fits IDF on train only."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import numpy as np

from scripts.prepare_big_vul_frequency import prepare


class BigVulFrequencyPreparationTests(unittest.TestCase):
    def test_no_test_arrays_and_validation_only_token_does_not_enter_idf(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source.jsonl"
            old = root / "old"
            old.mkdir()
            rows = [
                {"source_id": "t1", "repository": "a", "label": 1, "source_code": "int f(){int special=1; return special;}"},
                {"source_id": "t2", "repository": "a", "label": 0, "source_code": "int g(){return 0;}"},
                {"source_id": "v1", "repository": "b", "label": 1, "source_code": "int h(){int valonly=1; return valonly;}"},
                {"source_id": "v2", "repository": "b", "label": 0, "source_code": "int i(){return 2;}"},
                {"source_id": "x1", "repository": "c", "label": 0, "source_code": "int j(){return 3;}"},
            ]
            source.write_text("\n".join(json.dumps({**row, "commit": "fix", "language": "c",
                "dataset_version": "fixture", "license_id": "fixture"}) for row in rows) + "\n")
            manifest = {
                "source_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
                "source_sample_remainder": 0, "feature_version": "cpp-body-lexical-v2",
                "vocabulary": ["return", "special"], "vocabulary_size": 2,
                "examples": [{"source_id": row["source_id"], "repository": row["repository"],
                              "label": row["label"], "split": role}
                             for row, role in zip(rows, ("train", "train", "validation", "validation", "test"))],
            }
            (old / "manifest.json").write_text(json.dumps(manifest))
            prepared = root / "prepared"
            result = prepare(source, old, prepared)
            self.assertEqual(result["train_rows"], 2)
            self.assertEqual(result["validation_rows"], 2)
            self.assertGreater(result["idf"][1], result["idf"][0])
            with np.load(prepared / "features.npz", allow_pickle=False) as arrays:
                self.assertEqual(arrays["X_train"].shape, (2, 2))
                self.assertNotIn("X_test", arrays.files)
                self.assertEqual(arrays["id_validation"].tolist(), ["v1", "v2"])
            source.write_text(source.read_text() + "\n")
            with self.assertRaisesRegex(ValueError, "does not match"):
                prepare(source, old, prepared)


if __name__ == "__main__":
    unittest.main()
