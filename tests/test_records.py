"""Contract tests for records shared by training and scanning."""

import json
import unittest

from vulnscope.records import Finding, FunctionRecord, ScanReport, SkippedFile


class FunctionRecordTests(unittest.TestCase):
    def test_scanned_function_has_unknown_label(self) -> None:
        record = FunctionRecord(
            language="c",
            file_path="src/check.c",
            source_code="int check(void) { return 1; }",
            start_line=2,
            end_line=2,
        )
        self.assertIsNone(record.label)
        self.assertIsNone(record.group_id)

    def test_labelled_function_requires_traceable_source_and_group(self) -> None:
        fields = dict(
            language="c",
            file_path="sample.c",
            source_code="void bad(void) {}",
            start_line=1,
            end_line=1,
            label=1,
        )
        with self.assertRaises(ValueError):
            FunctionRecord(**fields)
        record = FunctionRecord(
            **fields, source_id="juliet:case-1", group_id="family-1",
            dataset_version="juliet-1.3", license_id="CC0-1.0",
        )
        self.assertEqual(record.label, 1)

    def test_invalid_label_and_source_span_are_rejected(self) -> None:
        base = dict(language="go", file_path="main.go", source_code="func f() {}", start_line=1, end_line=1)
        with self.assertRaises(ValueError):
            FunctionRecord(**base, label=2, source_id="x", group_id="g")
        with self.assertRaises(ValueError):
            FunctionRecord(**{**base, "start_line": 3, "end_line": 2})
        with self.assertRaises(ValueError):
            FunctionRecord(**{**base, "source_code": " "})


class FindingTests(unittest.TestCase):
    def test_threshold_and_report_include_coverage(self) -> None:
        finding = Finding(
            language="c", file_path="src/check.c", start_line=2, end_line=4,
            score=0.7, threshold=0.7, model_version="c-v1", function_name="check",
        )
        self.assertTrue(finding.flagged)
        report = ScanReport(
            findings=(finding,),
            skipped_files=(SkippedFile(file_path="src/other.rs", reason="unsupported language"),),
            scanned_files=1,
        )
        payload = json.loads(json.dumps(report.to_dict()))
        self.assertEqual(payload["summary"]["flagged_functions"], 1)
        self.assertEqual(payload["summary"]["skipped_files"], 1)
        self.assertEqual(payload["skipped_files"][0]["reason"], "unsupported language")
        self.assertEqual(payload["findings"][0]["start_line"], 2)

    def test_invalid_score_is_rejected(self) -> None:
        fields = dict(
            language="c", file_path="x.c", start_line=1, end_line=1,
            threshold=0.5, model_version="c-v1",
        )
        for score in (-0.1, 1.1, float("nan")):
            with self.subTest(score=score), self.assertRaises(ValueError):
                Finding(**fields, score=score)


if __name__ == "__main__":
    unittest.main()
