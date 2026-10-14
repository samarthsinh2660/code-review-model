"""A real-world evaluation row must have explicit labels and provenance."""

import json
import tempfile
import unittest
from pathlib import Path

from vulnscope.external_data import load_external_jsonl


def row(**changes):
    value = {
        "source_id": "sample-1", "repository": "owner/project", "commit": "abc123",
        "source_code": "int f() { return 1; }", "label": 1, "language": "c",
        "dataset_version": "fixture-1", "license_id": "MIT",
    }
    value.update(changes)
    return value


class ExternalDataTests(unittest.TestCase):
    def load(self, rows):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "examples.jsonl"
            path.write_text("\n".join(json.dumps(item) for item in rows) + "\n")
            return load_external_jsonl(path)

    def test_valid_rows_preserve_provenance(self):
        records = self.load([row(), row(source_id="sample-2", label=0, source_code="int g() { return 2; }")])
        self.assertEqual([record.label for record in records], [1, 0])
        self.assertEqual(records[0].repository, "owner/project")

    def test_missing_provenance_is_rejected_with_line(self):
        with self.assertRaisesRegex(ValueError, "line 1.*repository"):
            self.load([row(repository="")])

    def test_duplicate_id_and_normalized_code_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate source_id"):
            self.load([row(), row(label=0)])
        with self.assertRaisesRegex(ValueError, "normalized function"):
            self.load([row(), row(source_id="sample-2", label=0, source_code="int g() { return 1; }")])

    def test_boolean_label_and_unsupported_language_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "label"):
            self.load([row(label=True)])
        with self.assertRaisesRegex(ValueError, "language"):
            self.load([row(language="go")])


if __name__ == "__main__":
    unittest.main()
