"""Sample Juliet function spans and map manifest flaw lines with Clang."""

from __future__ import annotations

import argparse
import bisect
import json
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

from scripts.audit_juliet_archive import _file_sha256


FUNCTION_KINDS = {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl", "CXXDestructorDecl"}
BODY_KINDS = {"CompoundStmt", "CXXTryStmt"}


def _line_at(offset: int, newline_offsets: list[int]) -> int:
    return bisect.bisect_left(newline_offsets, offset) + 1


def function_bodies(ast: dict, source: bytes) -> list[dict[str, object]]:
    """Return bodies whose Clang name offset resolves to this source's bytes."""

    newlines = [index for index, byte in enumerate(source) if byte == 10]
    bodies: list[dict[str, object]] = []
    stack = [ast]
    while stack:
        node = stack.pop()
        stack.extend(node.get("inner", []))
        if node.get("kind") not in FUNCTION_KINDS:
            continue
        name = node.get("name", "")
        offset = node.get("loc", {}).get("offset")
        if not name or not isinstance(offset, int):
            continue
        encoded_name = name.encode("utf-8")
        if source[offset : offset + len(encoded_name)] != encoded_name:
            continue
        for child in node.get("inner", []):
            if child.get("kind") not in BODY_KINDS:
                continue
            span = child.get("range", {})
            begin = span.get("begin", {}).get("offset")
            end = span.get("end", {}).get("offset")
            declaration_begin = node.get("range", {}).get("begin", {}).get("offset")
            if (
                not isinstance(begin, int) or not isinstance(end, int)
                or not isinstance(declaration_begin, int)
                or not (0 <= declaration_begin <= begin <= end < len(source))
            ):
                continue
            bodies.append({
                "name": name,
                "declaration_start_line": _line_at(declaration_begin, newlines),
                "start_line": _line_at(begin, newlines),
                "end_line": _line_at(end, newlines),
            })
            break
    return sorted(bodies, key=lambda body: (body["start_line"], body["name"]))


def map_flaw_lines(bodies: list[dict[str, object]], flaw_lines: list[int]) -> dict[str, object]:
    """Match each flaw line to a unique function definition, preserving failures."""

    matched = []
    unmatched = []
    ambiguous = []
    for line in flaw_lines:
        candidates = [
            body for body in bodies
            if body["declaration_start_line"] <= line <= body["end_line"]
        ]
        if len(candidates) == 1:
            body = candidates[0]
            matched.append({
                "line": line,
                "function": body["name"],
                "location": "body" if line >= body["start_line"] else "signature",
            })
        elif not candidates:
            unmatched.append(line)
        else:
            ambiguous.append({"line": line, "functions": [body["name"] for body in candidates]})
    return {"matched": matched, "unmatched": unmatched, "ambiguous": ambiguous}


def select_paths(names: list[str], per_language: int, all_01: bool = False) -> list[str]:
    """Choose deterministic single-file-style `_01` sources."""

    if all_01:
        return [
            path for path in sorted(set(names))
            if path.startswith("C/testcases/")
            and len(path.split("/")) >= 4
            and Path(path).suffix.lower() in {".c", ".cpp"}
            and Path(path).stem.endswith("_01")
        ]
    choices: dict[str, dict[str, str]] = {".c": {}, ".cpp": {}}
    for path in sorted(set(names)):
        parts = path.split("/")
        if len(parts) < 4 or parts[:2] != ["C", "testcases"] or not Path(path).stem.endswith("_01"):
            continue
        suffix = Path(path).suffix.lower()
        if suffix in choices:
            choices[suffix].setdefault(parts[2], path)
    return [
        path for suffix in (".c", ".cpp")
        for _, path in sorted(choices[suffix].items())[:per_language]
    ]


def _manifest_lines(archive: ZipFile, selected: list[str]) -> dict[str, list[int]]:
    by_name = {Path(path).name: path for path in selected}
    result: dict[str, list[int]] = defaultdict(list)
    with archive.open("C/manifest.xml") as stream:
        parser = ET.iterparse(stream, events=("start", "end"))
        _, root = next(parser)
        for event, case in parser:
            if event != "end" or case.tag != "testcase":
                continue
            for file_element in case.findall("file"):
                path = by_name.get(file_element.get("path", ""))
                if path is not None:
                    result[path].extend(int(flaw.get("line", "")) for flaw in file_element.findall("flaw"))
            case.clear()
            root.clear()
    return result


def audit_sample(
    archive_path: Path,
    per_language: int,
    expected_sha256: str | None = None,
    all_01: bool = False,
) -> dict[str, object]:
    if per_language < 1:
        raise ValueError("per-language must be positive")
    if expected_sha256 and _file_sha256(archive_path) != expected_sha256.lower():
        raise ValueError("archive SHA-256 mismatch")

    with ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix="vulnscope_juliet_") as tmp:
        selected = select_paths(archive.namelist(), per_language, all_01)
        flaw_lines = _manifest_lines(archive, selected)
        root = Path(tmp)
        support_dir = root / "C" / "testcasesupport"
        support_dir.mkdir(parents=True)
        for member in archive.namelist():
            if member.startswith("C/testcasesupport/") and member.endswith(".h"):
                (support_dir / Path(member).name).write_bytes(archive.read(member))

        files = []
        for member in selected:
            source = archive.read(member)
            path = root / member
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source)
            is_cpp = path.suffix == ".cpp"
            command = [
                "clang++" if is_cpp else "clang",
                "-std=gnu++11" if is_cpp else "-std=gnu11",
                "-Xclang", "-ast-dump=json", "-fsyntax-only",
                "-I", str(support_dir), str(path),
            ]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            entry: dict[str, object] = {
                "path": member,
                "language": "cpp" if is_cpp else "c",
                "flaw_lines": flaw_lines.get(member, []),
                "parse_ok": completed.returncode == 0,
            }
            if completed.returncode == 0:
                bodies = function_bodies(json.loads(completed.stdout), source)
                entry["function_count"] = len(bodies)
                entry["mapping"] = map_flaw_lines(bodies, entry["flaw_lines"])
                entry["functions"] = bodies
            else:
                entry["error_excerpt"] = "\n".join(completed.stderr.splitlines()[:3])
            files.append(entry)

    parsed = [entry for entry in files if entry["parse_ok"]]
    return {
        "sample_rule": (
            "all _01 C/C++ source files" if all_01
            else "first sorted _01 file per CWE, up to per_language for each C/C++"
        ),
        "per_language": None if all_01 else per_language,
        "sampled_files": len(files),
        "parsed_files": len(parsed),
        "failed_files": len(files) - len(parsed),
        "functions_in_parsed_files": sum(entry["function_count"] for entry in parsed),
        "flaw_lines_in_parsed_files": sum(len(entry["flaw_lines"]) for entry in parsed),
        "matched_flaw_lines": sum(len(entry["mapping"]["matched"]) for entry in parsed),
        "unmatched_flaw_lines": sum(len(entry["mapping"]["unmatched"]) for entry in parsed),
        "ambiguous_flaw_lines": sum(len(entry["mapping"]["ambiguous"]) for entry in parsed),
        "files": files,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--per-language", type=int, default=10)
    parser.add_argument("--all-01", action="store_true", help="audit every _01 source file")
    parser.add_argument("--expected-sha256")
    args = parser.parse_args(argv)
    try:
        report = audit_sample(args.archive, args.per_language, args.expected_sha256, args.all_01)
    except (OSError, ValueError, ET.ParseError, json.JSONDecodeError) as error:
        print(f"function audit failed: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
