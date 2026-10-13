"""Small archive fixtures for the Juliet inventory utility."""

import tempfile
import unittest
from pathlib import Path
from zipfile import ZipFile

from scripts.audit_juliet_archive import audit_archive


class ArchiveAuditTests(unittest.TestCase):
    def test_counts_sources_duplicates_and_label_markers(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sample.zip"
            with ZipFile(archive, "w") as zip_file:
                zip_file.writestr("C/testcases/CWE123_A/s01/one.c", "/* POTENTIAL FLAW */\nint a;\n")
                zip_file.writestr("C/testcases/CWE123_A/s01/two.c", "/* POTENTIAL FLAW */\nint a;\n")
                zip_file.writestr("C/testcases/CWE123_A/s01/three.cpp", "/* FIX: checked */\nint b;\n")
                zip_file.writestr("C/README.txt", "not source code")

            result = audit_archive(archive)

        self.assertEqual(result["file_entries"], 4)
        self.assertEqual(result["source_files"], 3)
        self.assertEqual(result["c_files"], 2)
        self.assertEqual(result["cpp_files"], 1)
        self.assertEqual(result["cwe_directories"], 1)
        self.assertEqual(result["exact_duplicate_source_files"], 1)
        self.assertEqual(result["potential_flaw_marker_files"], 2)
        self.assertEqual(result["fix_marker_files"], 1)

    def test_rejects_wrong_published_hash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sample.zip"
            with ZipFile(archive, "w") as zip_file:
                zip_file.writestr("C/README.txt", "contents")
            with self.assertRaises(ValueError):
                audit_archive(archive, expected_sha256="0" * 64)

    def test_checks_manifest_references_and_flaw_lines(self) -> None:
        manifest = """<container>
          <testcase><file path="one.c"><flaw line="2" name="CWE-123"/></file></testcase>
          <testcase><file path="missing.c"><flaw line="1" name="CWE-123"/></file></testcase>
          <testcase><file path="two.cpp"><flaw line="5" name="CWE-123"/></file></testcase>
        </container>"""
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "sample.zip"
            with ZipFile(archive, "w") as zip_file:
                zip_file.writestr("C/testcases/CWE123_A/s01/one.c", "line 1\nline 2\n")
                zip_file.writestr("C/testcases/CWE123_A/s01/two.cpp", "only line\n")
                zip_file.writestr("C/manifest.xml", manifest)
            result = audit_archive(archive)

        self.assertTrue(result["manifest_present"])
        self.assertEqual(result["manifest_testcases"], 3)
        self.assertEqual(result["manifest_file_references"], 3)
        self.assertEqual(result["manifest_flaw_lines"], 3)
        self.assertEqual(result["manifest_missing_file_references"], 1)
        self.assertEqual(result["manifest_flaw_lines_out_of_bounds"], 1)


if __name__ == "__main__":
    unittest.main()
