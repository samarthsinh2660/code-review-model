"""Assess conservative positive/fixed-sink pairs in a Juliet _01 audit."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile


def _role(name: str) -> str | None:
    if name == "bad" or name.endswith("_bad"):
        return "bad"
    if name == "goodB2G" or name.endswith("_goodB2G"):
        return "fixed_sink"
    return None


def _function_source(lines: list[bytes], function: dict[str, object]) -> bytes:
    start = function["declaration_start_line"]
    end = function["end_line"]
    if not (1 <= start <= end <= len(lines)):
        raise ValueError("function line span is outside its source file")
    return b"".join(lines[start - 1 : end])


def assess(report: dict[str, object], archive: ZipFile) -> dict[str, object]:
    """Retain only direct annotated bad/fixed-sink pairs; give rejection counts."""

    if report.get("sample_rule") != "all _01 C/C++ source files":
        raise ValueError("assessment requires an all-_01 function audit")
    rejected: Counter[str] = Counter()
    examples: list[dict[str, object]] = []
    code_labels: dict[str, set[int]] = defaultdict(set)
    code_counts: Counter[str] = Counter()
    for entry in report["files"]:
        if not entry["parse_ok"]:
            rejected["parse_failed"] += 1
            continue
        mapping = entry["mapping"]
        if mapping["unmatched"] or mapping["ambiguous"]:
            rejected["flaw_mapping_incomplete"] += 1
            continue
        positive_names = {item["function"] for item in mapping["matched"]}
        if len(positive_names) != 1:
            rejected["not_one_positive_function"] += 1
            continue
        positive_name = next(iter(positive_names))
        functions = entry["functions"]
        positives = [function for function in functions if function["name"] == positive_name]
        if len(positives) != 1 or _role(positive_name) != "bad":
            rejected["positive_role_unclear"] += 1
            continue
        fixed_sinks = [function for function in functions if _role(function["name"]) == "fixed_sink"]
        if len(fixed_sinks) != 1:
            rejected["fixed_sink_missing_or_ambiguous"] += 1
            continue
        source_lines = archive.read(entry["path"]).splitlines(keepends=True)
        positive_code = _function_source(source_lines, positives[0])
        negative_code = _function_source(source_lines, fixed_sinks[0])
        if b"FIX:" not in negative_code:
            rejected["fixed_sink_without_fix_marker"] += 1
            continue
        pair = []
        for label, function, code in ((1, positives[0], positive_code), (0, fixed_sinks[0], negative_code)):
            digest = hashlib.sha256(code).hexdigest()
            code_labels[digest].add(label)
            code_counts[digest] += 1
            pair.append({
                "label": label,
                "function": function["name"],
                "start_line": function["declaration_start_line"],
                "end_line": function["end_line"],
                "source_sha256": digest,
            })
        examples.append({"path": entry["path"], "language": entry["language"], "pair": pair})

    return {
        "selection_rule": "one manifest-annotated bad definition plus one goodB2G definition with FIX marker in same parsed _01 file",
        "audited_files": len(report["files"]),
        "retained_pairs": len(examples),
        "retained_functions": 2 * len(examples),
        "retained_by_language": dict(sorted(Counter(example["language"] for example in examples).items())),
        "rejected_files_by_reason": dict(sorted(rejected.items())),
        "exact_duplicate_functions": sum(count - 1 for count in code_counts.values()),
        "conflicting_exact_code_labels": sum(len(labels) > 1 for labels in code_labels.values()),
        "examples": examples,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("audit_report", type=Path)
    args = parser.parse_args()
    with args.audit_report.open() as stream:
        report = json.load(stream)
    with ZipFile(args.archive) as archive:
        result = assess(report, archive)
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
