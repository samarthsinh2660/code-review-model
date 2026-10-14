"""Big-Vul conversion keeps explicit labels, provenance, and exclusions."""

import csv
import io
import json
import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from scripts.prepare_big_vul_external import prepare


class BigVulExternalTests(unittest.TestCase):
    def test_hash_remainders_are_disjoint_and_invalid_remainder_fails(self):
        fields = ["project", "commit_id", "lang", "vul", "func_before", "func_after"]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = io.StringIO()
            writer = csv.DictWriter(data, fieldnames=fields)
            writer.writeheader()
            for index in range(30):
                code = f"int sample{index}() {{ return {index}; }}"
                writer.writerow({"project": "repo", "commit_id": "fix", "lang": "C",
                                 "vul": "0", "func_before": code, "func_after": code})
            archive = root / "input.zip"
            with ZipFile(archive, "w") as z:
                z.writestr("MSR_data_cleaned.csv", data.getvalue())
            outputs = []
            for remainder in (0, 1):
                output = root / f"out{remainder}.jsonl"
                prepare(archive, output, root / f"report{remainder}.json", 2, remainder)
                outputs.append({json.loads(line)["source_id"] for line in output.read_text().splitlines()})
            self.assertEqual(len(outputs[0] | outputs[1]), 30)
            self.assertFalse(outputs[0] & outputs[1])
            with self.assertRaisesRegex(ValueError, "sample_remainder"):
                prepare(archive, root / "bad.jsonl", root / "bad.json", 2, 2)

    def test_unchanged_positive_and_changed_negative_are_excluded(self):
        fields = ["project", "commit_id", "lang", "vul", "func_before", "func_after"]
        rows = [
            {"project": "repo", "commit_id": "fix", "lang": "C", "vul": "1",
             "func_before": "int first() { return 1; }", "func_after": "int first() { return 1; }"},
            {"project": "repo", "commit_id": "fix", "lang": "C", "vul": "0",
             "func_before": "int second() { return 2; }", "func_after": "int second() { return 3; }"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            data = io.StringIO()
            writer = csv.DictWriter(data, fieldnames=fields)
            writer.writeheader(); writer.writerows(rows)
            archive = root / "input.zip"
            with ZipFile(archive, "w") as z:
                z.writestr("MSR_data_cleaned.csv", data.getvalue())
            result = prepare(archive, root / "out.jsonl", root / "report.json", sample_modulus=1)
            self.assertEqual(result["exclusions"]["positive_unchanged"], 1)
            self.assertEqual(result["exclusions"]["negative_changed"], 1)
            self.assertEqual(result["retained_rows"], 0)

    def test_audit_excludes_conflicts_and_keeps_one_same_label_copy(self):
        fields = ["", "project", "commit_id", "parentID", "file_name", "lang", "vul", "func_before", "func_after"]
        rows = [
            {"": "0", "project": "repo-a", "commit_id": "fix-a", "parentID": "base-a", "lang": "C", "vul": "1", "func_before": "int bad() { return 1; }", "func_after": "int bad() { return 0; }"},
            {"": "1", "project": "repo-a", "commit_id": "fix-a", "lang": "C", "vul": "1", "func_before": "int bad2() { return 1; }", "func_after": "int bad2() { return 0; }"},
            {"": "2", "project": "repo-b", "commit_id": "fix-b", "lang": "CPP", "vul": "0", "func_before": "int safe() { return 2; }", "func_after": "int safe() { return 2; }"},
            {"": "3", "project": "repo-b", "commit_id": "fix-b", "lang": "CPP", "vul": "1", "func_before": "int risky() { return 2; }", "func_after": "int risky() { return 3; }"},
            {"": "4", "project": "repo-c", "commit_id": "fix-c", "lang": "C++", "vul": "0", "func_before": "int unique() { return 3; }", "func_after": "int unique() { return 3; }"},
            {"": "5", "project": "", "commit_id": "fix-d", "lang": "C", "vul": "0", "func_before": "int missing() { return 4; }"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive = root / "input.zip"
            data = io.StringIO()
            writer = csv.DictWriter(data, fieldnames=fields)
            writer.writeheader(); writer.writerows(rows)
            with ZipFile(archive, "w") as z:
                z.writestr("MSR_data_cleaned.csv", data.getvalue())
            output = root / "external.jsonl"
            report_path = root / "audit.json"
            report = prepare(archive, output, report_path, sample_modulus=1)
            retained = [json.loads(line) for line in output.read_text().splitlines()]
            self.assertEqual(report["source_rows"], 6)
            self.assertEqual(report["exclusions"]["normalized_label_conflict"], 2)
            self.assertEqual(report["exclusions"]["same_label_duplicate"], 1)
            self.assertEqual(report["exclusions"]["missing_project"], 1)
            self.assertEqual(report["retained_rows"], 2)
            self.assertEqual({row["language"] for row in retained}, {"c", "cpp"})
            self.assertEqual({row["label"] for row in retained}, {0, 1})
            self.assertEqual(report_path.exists(), True)


if __name__ == "__main__":
    unittest.main()
