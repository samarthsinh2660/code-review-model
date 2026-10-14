"""Audit and sample Big-Vul functions for frozen external evaluation."""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
import sys
from collections import Counter
from pathlib import Path
from zipfile import ZipFile

from vulnscope.external_data import normalized_hash


MEMBER = "MSR_data_cleaned.csv"
REQUIRED = {"project", "commit_id", "lang", "vul", "func_before", "func_after"}
LANGUAGES = {"C": "c", "CPP": "cpp", "C++": "cpp"}


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _rows(archive: Path):
    csv.field_size_limit(sys.maxsize)
    with ZipFile(archive) as zip_file:
        if zip_file.namelist() != [MEMBER]:
            raise ValueError(f"expected one ZIP member named {MEMBER}")
        with zip_file.open(MEMBER) as raw:
            reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig", newline=""))
            if not REQUIRED.issubset(reader.fieldnames or []):
                raise ValueError(f"missing CSV columns: {sorted(REQUIRED - set(reader.fieldnames or []))}")
            yield from enumerate(reader, 1)


def _candidate(row: dict[str, str]) -> tuple[str | None, str | None]:
    """Return normalized hash or one explicit exclusion reason."""

    if row.get("vul") not in ("0", "1"):
        return None, "invalid_label"
    if row.get("lang") not in LANGUAGES:
        return None, "unsupported_language"
    for field in ("project", "commit_id", "func_before"):
        if not row.get(field, "").strip():
            return None, f"missing_{field}"
    if not row.get("func_after", "").strip():
        return None, "missing_func_after"
    if "\ufffd" in row["func_before"]:
        return None, "invalid_source_encoding"
    if row["vul"] == "1" and row["func_before"] == row["func_after"]:
        return None, "positive_unchanged"
    if row["vul"] == "0" and row["func_before"] != row["func_after"]:
        return None, "negative_changed"
    try:
        return normalized_hash(row["func_before"]), None
    except ValueError:
        return None, "missing_function_body"


def prepare(
    archive: Path, output: Path, report: Path,
    sample_modulus: int = 10, sample_remainder: int = 0,
) -> dict[str, object]:
    """Two passes prevent conflicting normalized labels entering the cohort."""

    if sample_modulus < 1 or not 0 <= sample_remainder < sample_modulus:
        raise ValueError("sample_modulus must be positive and sample_remainder must be in range")
    archive_hash = _sha256(archive)
    with ZipFile(archive) as source:
        member_size = source.getinfo(MEMBER).file_size
    first_labels: dict[str, str] = {}
    conflicts: set[str] = set()
    exclusions: Counter[str] = Counter()
    source_labels: Counter[str] = Counter()
    source_languages: Counter[str] = Counter()
    source_projects: Counter[str] = Counter()
    missing_metadata: Counter[str] = Counter()
    source_rows = 0
    for number, row in _rows(archive):
        source_rows = number
        source_labels[row.get("vul", "")] += 1
        source_languages[row.get("lang", "")] += 1
        source_projects[row.get("project", "")] += 1
        for field in ("parentID", "file_name", "CVE ID", "CWE ID"):
            if not row.get(field, "").strip():
                missing_metadata[field] += 1
        digest, reason = _candidate(row)
        if reason:
            exclusions[reason] += 1
            continue
        previous = first_labels.setdefault(digest, row["vul"])
        if previous != row["vul"]:
            conflicts.add(digest)
    output.parent.mkdir(parents=True, exist_ok=True)
    emitted: set[str] = set()
    retained_labels: Counter[str] = Counter()
    retained_languages: Counter[str] = Counter()
    retained_projects: Counter[str] = Counter()
    with output.open("w", encoding="utf-8") as target:
        for number, row in _rows(archive):
            digest, reason = _candidate(row)
            if reason:
                continue
            if digest in conflicts:
                exclusions["normalized_label_conflict"] += 1
                continue
            if digest in emitted:
                exclusions["same_label_duplicate"] += 1
                continue
            emitted.add(digest)
            if int(digest[:16], 16) % sample_modulus != sample_remainder:
                exclusions["outside_deterministic_sample"] += 1
                continue
            language = LANGUAGES[row["lang"]]
            item = {
                "source_id": f"bigvul2:{number}:{digest[:16]}",
                "repository": row["project"],
                "commit": row["commit_id"],
                "source_code": row["func_before"],
                "label": int(row["vul"]),
                "language": language,
                "dataset_version": "Big-Vul MSR_data_cleaned",
                "license_id": "upstream-source-rights-unverified",
            }
            target.write(json.dumps(item, ensure_ascii=False) + "\n")
            retained_labels[row["vul"]] += 1
            retained_languages[language] += 1
            retained_projects[row["project"]] += 1
    details = {
        "source": "Big-Vul cleaned function export",
        "archive_sha256": archive_hash,
        "archive_member": MEMBER,
        "archive_member_bytes": member_size,
        "sample_modulus": sample_modulus,
        "sample_remainder": sample_remainder,
        "sample_rule": "int(first_16_hex_chars_of_normalized_body_sha256, 16) % sample_modulus == sample_remainder",
        "source_rows": source_rows,
        "source_labels": dict(sorted(source_labels.items())),
        "source_languages": dict(sorted(source_languages.items())),
        "source_project_count": len(source_projects),
        "missing_metadata": dict(sorted(missing_metadata.items())),
        "normalized_conflicting_hashes": len(conflicts),
        "exclusions": dict(sorted(exclusions.items())),
        "retained_rows": sum(retained_labels.values()),
        "retained_labels": dict(sorted(retained_labels.items())),
        "retained_languages": dict(sorted(retained_languages.items())),
        "retained_project_count": len(retained_projects),
        "retained_projects": dict(sorted(retained_projects.items())),
        "output_sha256": _sha256(output),
    }
    if sum(exclusions.values()) + details["retained_rows"] != source_rows:
        raise ValueError("audit accounting does not match source row count")
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text(json.dumps(details, indent=2, sort_keys=True) + "\n")
    return details


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--report", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--sample-modulus", type=int, default=10)
    parser.add_argument("--sample-remainder", type=int, default=0)
    args = parser.parse_args()
    details = prepare(args.archive, args.output, args.report, args.sample_modulus, args.sample_remainder)
    print(json.dumps({key: value for key, value in details.items() if key != "retained_projects"}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
