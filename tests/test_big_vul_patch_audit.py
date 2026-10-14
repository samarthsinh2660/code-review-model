"""Patch review sampling cannot use held-out rows or model scores."""

import csv
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from scripts.audit_big_vul_patches import change_summary, run, select_review_examples
from vulnscope.external_data import normalized_hash


class BigVulPatchAuditTests(unittest.TestCase):
    def test_sample_is_balanced_project_capped_and_excludes_test(self):
        examples = [
            {"source_id": f"source-{label}-{project}-{index}", "repository": project,
             "label": label, "split": "train" if index == 0 else "validation"}
            for label in (0, 1) for project in ("a", "b", "c") for index in (0, 1)
        ]
        examples += [{"source_id": f"test-{label}", "repository": "test", "label": label,
                      "split": "test"} for label in (0, 1)]
        chosen = select_review_examples(examples, per_label=3, max_per_project=1)
        self.assertEqual(sum(item["label"] == 0 for item in chosen), 3)
        self.assertEqual(sum(item["label"] == 1 for item in chosen), 3)
        self.assertTrue(all(item["split"] != "test" for item in chosen))
        for label in (0, 1):
            self.assertEqual(len({item["repository"] for item in chosen if item["label"] == label}), 3)
        self.assertEqual(chosen, select_review_examples(list(reversed(examples)), per_label=3, max_per_project=1))

    def test_change_extent_counts_replacement_and_unchanged(self):
        changed = change_summary("one\ntwo\nthree", "one\nfixed\nthree")
        self.assertEqual((changed["changed_before_lines"], changed["changed_after_lines"]), (1, 1))
        self.assertTrue(changed["diff_excerpt"])
        unchanged = change_summary("same", "same")
        self.assertEqual(unchanged["changed_before_lines"], 0)
        self.assertEqual(unchanged["diff_excerpt"], [])

    def test_archive_rows_are_verified_and_reported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            prepared = root / "prepared"
            prepared.mkdir()
            archive = root / "archive.zip"
            before = ("int f() { return 0; }", "int g() { return 3; }")
            rows = [
                {"project": "alpha", "commit_id": "fix", "lang": "C", "vul": "1", "func_before": before[0],
                 "func_after": "int f() { return 1; }", "CVE ID": "CVE-fixture"},
                {"project": "beta", "commit_id": "fix2", "lang": "C", "vul": "0", "func_before": before[1],
                 "func_after": before[1], "CVE ID": ""},
            ]
            stream = io.StringIO()
            writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
            writer.writeheader()
            writer.writerows(rows)
            with ZipFile(archive, "w") as zip_file:
                zip_file.writestr("MSR_data_cleaned.csv", stream.getvalue())
            audit_path = root / "audit.json"
            audit_path.write_text(json.dumps({"archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}))
            examples = [
                {"source_id": f"bigvul2:{i}:{normalized_hash(source)[:16]}",
                 "repository": row["project"], "label": int(row["vul"]), "split": "train"}
                for i, (source, row) in enumerate(zip(before, rows), 1)
            ]
            (prepared / "manifest.json").write_text(json.dumps({
                "audit_sha256": hashlib.sha256(audit_path.read_bytes()).hexdigest(),
                "examples": examples,
            }))
            summary = run(archive, audit_path, prepared, root / "packet.json",
                          root / "summary.json", per_label=1)
            self.assertEqual(summary["by_label"]["1"]["changed_functions"], 1)
            self.assertEqual(summary["by_label"]["0"]["changed_functions"], 0)
            self.assertEqual(len(json.loads((root / "packet.json").read_text())), 2)
            altered = json.loads((prepared / "manifest.json").read_text())
            altered["examples"][0]["repository"] = "wrong"
            (prepared / "manifest.json").write_text(json.dumps(altered))
            with self.assertRaisesRegex(ValueError, "does not match"):
                run(archive, audit_path, prepared, root / "packet.json",
                    root / "summary.json", per_label=1)


if __name__ == "__main__":
    unittest.main()
