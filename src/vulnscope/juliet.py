"""Materialize the audited Juliet `_01` pair subset with provenance checks."""

from __future__ import annotations

import hashlib
from pathlib import PurePosixPath
from zipfile import ZipFile

from vulnscope.records import FunctionRecord


def materialize_pairs(assessment: dict[str, object], archive: ZipFile) -> list[FunctionRecord]:
    """Read exactly the pairs approved by the Phase 1 assessment."""

    examples = assessment["examples"]
    if assessment["retained_pairs"] != len(examples):
        raise ValueError("pair assessment count is inconsistent")
    records: list[FunctionRecord] = []
    for example in examples:
        path = example["path"]
        parts = PurePosixPath(path).parts
        if len(parts) < 4 or parts[:2] != ("C", "testcases") or not PurePosixPath(path).stem.endswith("_01"):
            raise ValueError(f"unexpected Juliet path: {path}")
        language = "cpp" if path.endswith(".cpp") else "c" if path.endswith(".c") else None
        if language != example["language"]:
            raise ValueError(f"language mismatch: {path}")
        code_lines = archive.read(path).splitlines(keepends=True)
        pair = example["pair"]
        if len(pair) != 2 or {item["label"] for item in pair} != {0, 1}:
            raise ValueError(f"expected one positive and one negative: {path}")
        for item in pair:
            start, end = item["start_line"], item["end_line"]
            if not (1 <= start <= end <= len(code_lines)):
                raise ValueError(f"invalid source span: {path}")
            raw = b"".join(code_lines[start - 1 : end])
            digest = hashlib.sha256(raw).hexdigest()
            if digest != item["source_sha256"]:
                raise ValueError(f"source hash mismatch: {path}:{start}")
            records.append(FunctionRecord(
                language=language,
                file_path=path,
                source_code=raw.decode("utf-8"),
                start_line=start,
                end_line=end,
                function_name=item["function"],
                label=item["label"],
                source_id=f"juliet13:{path}:{start}:{digest[:16]}",
                group_id=parts[2],
                dataset_version="Juliet C/C++ 1.3 _01 direct pair",
                license_id="CC0-1.0",
            ))
    return records
