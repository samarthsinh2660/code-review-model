"""Inventory a Juliet ZIP without extracting or labelling its functions."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path, PurePosixPath
from zipfile import BadZipFile, ZipFile


CHUNK_SIZE = 1024 * 1024
MARKER_OVERLAP = 32


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def audit_archive(path: Path, expected_sha256: str | None = None) -> dict[str, object]:
    """Return archive-level counts; source-file duplicates are byte-exact only."""

    archive_sha256 = _file_sha256(path)
    if expected_sha256 is not None and archive_sha256 != expected_sha256.lower():
        raise ValueError(
            f"SHA-256 mismatch: expected {expected_sha256.lower()}, got {archive_sha256}"
        )

    file_entries = 0
    uncompressed_bytes = 0
    c_files = 0
    cpp_files = 0
    exact_duplicate_source_files = 0
    potential_flaw_marker_files = 0
    fix_marker_files = 0
    unsafe_member_names = 0
    cwe_directories: set[str] = set()
    seen_source_hashes: set[str] = set()
    manifest_testcases = 0
    manifest_file_references = 0
    manifest_flaw_lines = 0
    manifest_cases_without_flaw = 0
    manifest_missing_file_references = 0
    manifest_ambiguous_file_references = 0
    manifest_invalid_flaw_line_values = 0
    manifest_flaw_lines_out_of_bounds = 0
    flaw_lines_by_path: dict[str, list[int]] = defaultdict(list)

    with ZipFile(path) as archive:
        members = archive.infolist()
        member_names = {member.filename for member in members}
        manifest_present = "C/manifest.xml" in member_names
        if manifest_present:
            testcase_paths_by_name: dict[str, list[str]] = defaultdict(list)
            for member in members:
                parts = PurePosixPath(member.filename).parts
                if (
                    not member.is_dir()
                    and len(parts) >= 4
                    and parts[:2] == ("C", "testcases")
                    and PurePosixPath(member.filename).suffix.lower() in {".c", ".cpp", ".h"}
                ):
                    testcase_paths_by_name[parts[-1]].append(member.filename)

            with archive.open("C/manifest.xml") as manifest_stream:
                parser = ET.iterparse(manifest_stream, events=("start", "end"))
                _, manifest_root = next(parser)
                for event, case in parser:
                    if event != "end" or case.tag != "testcase":
                        continue
                    manifest_testcases += 1
                    case_flaws = 0
                    for file_element in case.findall("file"):
                        manifest_file_references += 1
                        filename = file_element.get("path", "")
                        matching_paths = testcase_paths_by_name.get(filename, [])
                        if not matching_paths:
                            manifest_missing_file_references += 1
                        elif len(matching_paths) > 1:
                            manifest_ambiguous_file_references += 1
                        for flaw in file_element.findall("flaw"):
                            manifest_flaw_lines += 1
                            case_flaws += 1
                            try:
                                line = int(flaw.get("line", ""))
                            except ValueError:
                                manifest_invalid_flaw_line_values += 1
                                continue
                            if len(matching_paths) == 1:
                                flaw_lines_by_path[matching_paths[0]].append(line)
                    if case_flaws == 0:
                        manifest_cases_without_flaw += 1
                    case.clear()
                    manifest_root.clear()

        for member in members:
            if member.is_dir():
                continue
            file_entries += 1
            uncompressed_bytes += member.file_size
            posix_path = PurePosixPath(member.filename)
            if posix_path.is_absolute() or ".." in posix_path.parts or "\\" in member.filename:
                unsafe_member_names += 1

            parts = posix_path.parts
            is_testcase = len(parts) >= 4 and parts[:2] == ("C", "testcases")
            suffix = posix_path.suffix.lower()
            is_source = is_testcase and suffix in {".c", ".cpp"}
            if is_source:
                cwe_directories.add(parts[2])
                if suffix == ".c":
                    c_files += 1
                else:
                    cpp_files += 1

            digest = hashlib.sha256() if is_source else None
            has_potential_flaw = False
            has_fix = False
            previous_tail = b""
            linebreak_count = 0
            last_byte: int | None = None
            with archive.open(member) as stream:
                for chunk in iter(lambda: stream.read(CHUNK_SIZE), b""):
                    if member.filename in flaw_lines_by_path:
                        linebreak_count += chunk.count(b"\n")
                        last_byte = chunk[-1]
                    if digest is not None:
                        digest.update(chunk)
                        searchable = previous_tail + chunk
                        has_potential_flaw |= b"POTENTIAL FLAW" in searchable
                        has_fix |= b"FIX:" in searchable
                        previous_tail = searchable[-MARKER_OVERLAP:]

            if member.filename in flaw_lines_by_path:
                line_count = linebreak_count + (last_byte is not None and last_byte != 10)
                manifest_flaw_lines_out_of_bounds += sum(
                    line < 1 or line > line_count
                    for line in flaw_lines_by_path[member.filename]
                )

            if digest is not None:
                file_hash = digest.hexdigest()
                if file_hash in seen_source_hashes:
                    exact_duplicate_source_files += 1
                else:
                    seen_source_hashes.add(file_hash)
                potential_flaw_marker_files += has_potential_flaw
                fix_marker_files += has_fix

    return {
        "archive_sha256": archive_sha256,
        "file_entries": file_entries,
        "uncompressed_bytes": uncompressed_bytes,
        "source_files": c_files + cpp_files,
        "c_files": c_files,
        "cpp_files": cpp_files,
        "cwe_directories": len(cwe_directories),
        "exact_duplicate_source_files": exact_duplicate_source_files,
        "potential_flaw_marker_files": potential_flaw_marker_files,
        "fix_marker_files": fix_marker_files,
        "unsafe_member_names": unsafe_member_names,
        "manifest_present": manifest_present,
        "manifest_testcases": manifest_testcases,
        "manifest_file_references": manifest_file_references,
        "manifest_flaw_lines": manifest_flaw_lines,
        "manifest_cases_without_flaw": manifest_cases_without_flaw,
        "manifest_missing_file_references": manifest_missing_file_references,
        "manifest_ambiguous_file_references": manifest_ambiguous_file_references,
        "manifest_invalid_flaw_line_values": manifest_invalid_flaw_line_values,
        "manifest_flaw_lines_out_of_bounds": manifest_flaw_lines_out_of_bounds,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path, help="Juliet ZIP path")
    parser.add_argument("--expected-sha256", help="published archive SHA-256")
    args = parser.parse_args(argv)
    try:
        result = audit_archive(args.archive, args.expected_sha256)
    except (BadZipFile, ET.ParseError, OSError, ValueError) as error:
        print(f"audit failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
