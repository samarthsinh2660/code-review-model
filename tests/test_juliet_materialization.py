"""The prepared records must match the audited archive bytes."""

import hashlib
import io
import unittest
from zipfile import ZipFile

from vulnscope.juliet import materialize_pairs


class JulietMaterializationTests(unittest.TestCase):
    def setUp(self):
        self.path = "C/testcases/CWE1/example_01.c"
        self.bad = b"void bad() {}\n"
        self.good = b"void goodB2G() {/* FIX: safe */}\n"
        self.zip_bytes = io.BytesIO()
        with ZipFile(self.zip_bytes, "w") as archive:
            archive.writestr(self.path, self.bad + self.good)
        self.assessment = {
            "retained_pairs": 1,
            "examples": [{
                "path": self.path,
                "language": "c",
                "pair": [
                    {"label": 1, "function": "bad", "start_line": 1, "end_line": 1, "source_sha256": hashlib.sha256(self.bad).hexdigest()},
                    {"label": 0, "function": "goodB2G", "start_line": 2, "end_line": 2, "source_sha256": hashlib.sha256(self.good).hexdigest()},
                ],
            }],
        }

    def _load(self):
        with ZipFile(io.BytesIO(self.zip_bytes.getvalue())) as archive:
            return materialize_pairs(self.assessment, archive)

    def test_materializes_pair_with_shared_group_and_provenance(self):
        records = self._load()
        self.assertEqual([record.label for record in records], [1, 0])
        self.assertEqual([record.group_id for record in records], ["CWE1", "CWE1"])
        self.assertEqual(records[0].source_code, self.bad.decode())
        self.assertTrue(records[0].source_id.startswith("juliet13:"))

    def test_rejects_stale_assessment_hash(self):
        self.assessment["examples"][0]["pair"][0]["source_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "source hash mismatch"):
            self._load()


if __name__ == "__main__":
    unittest.main()
