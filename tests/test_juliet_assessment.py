"""Guard Juliet pair selection against unverified negative labels."""

import io
import unittest
from zipfile import ZipFile

from scripts.assess_juliet_01 import assess


class JulietAssessmentTests(unittest.TestCase):
    def setUp(self):
        self.archive_bytes = io.BytesIO()
        with ZipFile(self.archive_bytes, "w") as archive:
            archive.writestr(
                "C/testcases/CWE1/example_01.c",
                "void bad() {\n  flaw();\n}\nvoid goodB2G() {\n  /* FIX: guard */\n  guarded();\n}\n",
            )
        self.entry = {
            "path": "C/testcases/CWE1/example_01.c",
            "language": "c",
            "parse_ok": True,
            "mapping": {
                "matched": [{"line": 2, "function": "bad", "location": "body"}],
                "unmatched": [],
                "ambiguous": [],
            },
            "functions": [
                {"name": "bad", "declaration_start_line": 1, "start_line": 1, "end_line": 3},
                {"name": "goodB2G", "declaration_start_line": 4, "start_line": 4, "end_line": 7},
            ],
        }

    def _assess(self):
        report = {"sample_rule": "all _01 C/C++ source files", "files": [self.entry]}
        with ZipFile(io.BytesIO(self.archive_bytes.getvalue())) as archive:
            return assess(report, archive)

    def test_retains_direct_bad_fixed_sink_pair(self):
        result = self._assess()
        self.assertEqual(result["retained_pairs"], 1)
        self.assertEqual([item["label"] for item in result["examples"][0]["pair"]], [1, 0])
        self.assertEqual(result["conflicting_exact_code_labels"], 0)

    def test_missing_fixed_sink_is_not_a_negative(self):
        self.entry["functions"].pop()
        result = self._assess()
        self.assertEqual(result["retained_functions"], 0)
        self.assertEqual(result["rejected_files_by_reason"], {"fixed_sink_missing_or_ambiguous": 1})

    def test_unmatched_flaw_disqualifies_pair(self):
        self.entry["mapping"]["unmatched"] = [99]
        result = self._assess()
        self.assertEqual(result["retained_pairs"], 0)
        self.assertEqual(result["rejected_files_by_reason"], {"flaw_mapping_incomplete": 1})


if __name__ == "__main__":
    unittest.main()
