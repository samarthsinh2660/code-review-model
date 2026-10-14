"""Preparation rejects labels that become contradictory after masking."""

import unittest

from scripts.prepare_juliet_01 import prepare
from vulnscope.records import FunctionRecord


class PreparationTests(unittest.TestCase):
    def test_conflicting_normalized_code_is_rejected(self):
        records = [
            FunctionRecord(
                language="c", file_path=f"C/testcases/CWE1/{label}.c",
                source_code=f"void {'bad' if label else 'goodB2G'}() {{ free(data); }}",
                start_line=1, end_line=1, label=label, source_id=f"id{label}",
                group_id="CWE1", dataset_version="fixture", license_id="CC0-1.0",
            )
            for label in (0, 1)
        ]
        with self.assertRaisesRegex(ValueError, "conflicting labels"):
            prepare(records)


if __name__ == "__main__":
    unittest.main()
