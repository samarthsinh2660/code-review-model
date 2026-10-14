"""External evaluation reads a frozen bundle and rejects Juliet overlap."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

import numpy as np

from scripts.evaluate_external import run
from vulnscope.logistic import LogisticModel


class ExternalEvaluationTests(unittest.TestCase):
    def fixture(self, directory):
        root = Path(directory)
        dataset = root / "external.jsonl"
        bundle_dir = root / "bundle"
        prepared_dir = root / "prepared"
        bundle_dir.mkdir(); prepared_dir.mkdir()
        archive = root / "juliet.zip"
        source = b"int bad() { return 1; }\nint goodB2G() { return 0; }\n"
        path = "C/testcases/CWE1/test_01.c"
        with ZipFile(archive, "w") as target:
            target.writestr(path, source)
        assessment = root / "assessment.json"
        assessment.write_text(json.dumps({"retained_pairs": 1, "examples": [{
            "path": path, "language": "c", "pair": [
                {"function": "bad", "label": 1, "start_line": 1, "end_line": 1, "source_sha256": hashlib.sha256(source.splitlines(keepends=True)[0]).hexdigest()},
                {"function": "goodB2G", "label": 0, "start_line": 2, "end_line": 2, "source_sha256": hashlib.sha256(source.splitlines(keepends=True)[1]).hexdigest()},
            ],
        }]}))
        manifest = {"feature_version": "cpp-body-lexical-v2",
                    "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest(),
                    "assessment_sha256": hashlib.sha256(assessment.read_bytes()).hexdigest()}
        manifest_bytes = json.dumps(manifest).encode()
        (prepared_dir / "manifest.json").write_bytes(manifest_bytes)
        model_path = bundle_dir / "model.npz"
        LogisticModel(np.asarray([1.0, -1.0]), 0.0).save(model_path)
        bundle = {"model_version": "fixture", "feature_version": "cpp-body-lexical-v2",
                  "prepared_manifest_sha256": hashlib.sha256(manifest_bytes).hexdigest(),
                  "model_sha256": hashlib.sha256(model_path.read_bytes()).hexdigest(),
                  "vocabulary": ["return", "2"], "threshold": 0.5}
        (bundle_dir / "bundle.json").write_text(json.dumps(bundle))
        output = root / "result.json"
        return dataset, bundle_dir, prepared_dir, archive, assessment, output

    def test_frozen_scores_and_aggregate_results(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            rows = [
                {"source_id": "a", "repository": "r1", "commit": "a1", "source_code": "int f() { return 2; }", "label": 1, "language": "c", "dataset_version": "fixture", "license_id": "MIT"},
                {"source_id": "b", "repository": "r2", "commit": "b1", "source_code": "int g() { return 3; }", "label": 0, "language": "cpp", "dataset_version": "fixture", "license_id": "MIT"},
            ]
            args[0].write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            result = run(*args)
            self.assertEqual(result["sample_count"], 2)
            self.assertEqual(result["repository_count"], 2)
            self.assertEqual(set(result["by_language"]), {"c", "cpp"})
            self.assertEqual(result["overall"]["tp"], 1)
            self.assertEqual(result["overall"]["fp"], 1)
            self.assertEqual(result["threshold"], 0.5)
            self.assertEqual(json.loads(args[-1].read_text())["dataset_sha256"],
                             hashlib.sha256(args[0].read_bytes()).hexdigest())

    def test_rejects_exact_juliet_overlap_and_tampered_model(self):
        with tempfile.TemporaryDirectory() as directory:
            args = self.fixture(directory)
            args[0].write_text(json.dumps({"source_id": "a", "repository": "r1", "commit": "a1",
                "source_code": "int copied() { return 1; }", "label": 1, "language": "c",
                "dataset_version": "fixture", "license_id": "MIT"}) + "\n")
            with self.assertRaisesRegex(ValueError, "overlaps Juliet"):
                run(*args)
            self.assertFalse(args[-1].exists())
            args[0].write_text(args[0].read_text().replace("return 1", "return 2"))
            bundle = json.loads((args[1] / "bundle.json").read_text())
            bundle["model_sha256"] = "0" * 64
            (args[1] / "bundle.json").write_text(json.dumps(bundle))
            with self.assertRaisesRegex(ValueError, "model hash"):
                run(*args)


if __name__ == "__main__":
    unittest.main()
