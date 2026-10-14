"""Near-duplicate audit keeps project roles and sample provenance intact."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.audit_big_vul_near_duplicates import run
from vulnscope.external_data import normalized_hash


class BigVulNearAuditTests(unittest.TestCase):
    def test_rejects_changed_cohort_and_overlapping_projects(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = root / "prepared"
            prepared.mkdir()
            train_source = root / "train.jsonl"
            fresh_source = root / "fresh.jsonl"
            audit_path = root / "train_audit.json"
            fresh_audit_path = root / "fresh_audit.json"
            def record(source_id, project, code, label):
                return {"source_id": source_id, "repository": project, "commit": "fix",
                        "source_code": code, "label": label, "language": "c",
                        "dataset_version": "fixture", "license_id": "fixture"}
            rows = [record("train", "train-project", "int f() { return 1; }", 1),
                    record("validation", "val-project", "int g() { return 2; }", 0)]
            train_source.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
            value = 0
            while True:
                code = f"int h() {{ return {value}; }}"
                if int(normalized_hash(code)[:16], 16) % 10 == 2:
                    break
                value += 1
            fresh_source.write_text(json.dumps(record("fresh", "test-project", code, 0)) + "\n")
            audit_path.write_text(json.dumps({"archive_sha256": "a" * 64}))
            fresh_audit_path.write_text(json.dumps({
                "archive_sha256": "a" * 64, "sample_modulus": 10, "sample_remainder": 2,
                "output_sha256": hashlib.sha256(fresh_source.read_bytes()).hexdigest(),
            }))
            manifest = {
                "source_sha256": hashlib.sha256(train_source.read_bytes()).hexdigest(),
                "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                "projects": {"train": ["train-project"], "validation": ["val-project"],
                             "test": ["test-project"]},
                "examples": [
                    {"source_id": row["source_id"], "repository": row["repository"],
                     "label": row["label"], "split": split}
                    for row, split in zip(rows, ("train", "validation"))
                ],
            }
            manifest_path = prepared / "manifest.json"
            manifest_path.write_text(json.dumps(manifest))
            args = (train_source, fresh_source, audit_path, fresh_audit_path,
                    prepared, root / "result.json")
            result = run(*args)
            self.assertEqual(result["comparisons"]["train_fresh_test"]["matched_pairs"], 0)
            changed_audit = json.loads(fresh_audit_path.read_text())
            changed_audit["sample_remainder"] = 1
            fresh_audit_path.write_text(json.dumps(changed_audit))
            with self.assertRaisesRegex(ValueError, "outside remainder"):
                run(*args)
            changed_audit["sample_remainder"] = 2
            fresh_audit_path.write_text(json.dumps(changed_audit))
            manifest["projects"]["test"].append("train-project")
            manifest_path.write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "project roles overlap"):
                run(*args)


if __name__ == "__main__":
    unittest.main()
