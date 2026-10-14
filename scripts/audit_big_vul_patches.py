"""Select reproducible train/validation rows and inspect original fix metadata."""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

from scripts.prepare_big_vul_external import _rows, _sha256
from vulnscope.external_data import normalized_hash


SOURCE_ID = re.compile(r"^bigvul2:(\d+):([0-9a-f]{16})$")
FIELDS = ("CVE ID", "CWE ID", "file_name", "parentID", "codeLink", "commit_message")


def select_review_examples(examples: list[dict[str, object]], per_label: int = 20,
                           max_per_project: int = 2) -> list[dict[str, object]]:
    """Use ID hashing and a per-project cap, never model scores or test rows."""

    if per_label < 1 or max_per_project < 1:
        raise ValueError("sample counts must be positive")
    selected = []
    for label in (0, 1):
        eligible = [item for item in examples if item["split"] in ("train", "validation")
                    and item["label"] == label]
        eligible.sort(key=lambda item: (hashlib.sha256(item["source_id"].encode()).hexdigest(), item["source_id"]))
        project_counts: Counter[str] = Counter()
        chosen = []
        for item in eligible:
            project = str(item["repository"])
            if project_counts[project] < max_per_project:
                chosen.append(item)
                project_counts[project] += 1
            if len(chosen) == per_label:
                break
        if len(chosen) != per_label:
            raise ValueError(f"too few label-{label} projects for requested review sample")
        selected.extend(chosen)
    return selected


def change_summary(before: str, after: str) -> dict[str, object]:
    left, right = before.splitlines(), after.splitlines()
    matcher = difflib.SequenceMatcher(a=left, b=right, autojunk=False)
    changed_before = changed_after = 0
    for tag, a0, a1, b0, b1 in matcher.get_opcodes():
        if tag != "equal":
            changed_before += a1 - a0
            changed_after += b1 - b0
    difference = list(difflib.unified_diff(left, right, fromfile="before", tofile="after", n=2, lineterm=""))
    return {
        "before_lines": len(left), "after_lines": len(right),
        "changed_before_lines": changed_before, "changed_after_lines": changed_after,
        "line_similarity": matcher.ratio(),
        "diff_excerpt": difference[:80], "diff_excerpt_truncated": len(difference) > 80,
    }


def run(archive: Path, training_audit: Path, prepared_dir: Path,
        review_packet: Path, summary_path: Path, *, per_label: int = 20) -> dict[str, object]:
    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    audit = json.loads(training_audit.read_text())
    if (_sha256(archive) != audit.get("archive_sha256")
            or hashlib.sha256(training_audit.read_bytes()).hexdigest() != manifest.get("audit_sha256")):
        raise ValueError("archive or audit hash does not match frozen training manifest")
    selected = select_review_examples(manifest["examples"], per_label=per_label)
    numbers = {}
    for item in selected:
        match = SOURCE_ID.fullmatch(item["source_id"])
        if match is None:
            raise ValueError("invalid Big-Vul source ID")
        number = int(match.group(1))
        if number in numbers:
            raise ValueError("duplicate source row number")
        numbers[number] = (item, match.group(2))
    packet = []
    for number, row in _rows(archive):
        if number in numbers:
            item, expected_prefix = numbers[number]
            if (row["project"] != item["repository"] or row["vul"] != str(item["label"])
                    or row["lang"] != "C"
                    or normalized_hash(row["func_before"])[:16] != expected_prefix):
                raise ValueError(f"archive row {number} does not match sampled manifest record")
            metadata = {field: row.get(field, "").strip() for field in FIELDS}
            packet.append({
                "source_id": item["source_id"], "split": item["split"],
                "project": item["repository"], "label": item["label"],
                "commit": row["commit_id"], "metadata": metadata,
                **change_summary(row["func_before"], row["func_after"]),
            })
        if number >= max(numbers):
            break
    if len(packet) != len(selected):
        raise ValueError("not all sampled rows were found in archive")
    packet.sort(key=lambda item: item["source_id"])
    by_label: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in packet:
        by_label[str(item["label"])].append(item)
    summary = {
        "method": "SHA-256 ID order, at most two rows per project and label, train/validation only",
        "archive_sha256": audit["archive_sha256"],
        "prepared_manifest_sha256": hashlib.sha256(manifest_path.read_bytes()).hexdigest(),
        "per_label": per_label,
        "by_label": {
            label: {
                "samples": len(rows),
                "projects": len({item["project"] for item in rows}),
                "changed_functions": sum(item["changed_before_lines"] > 0 or item["changed_after_lines"] > 0 for item in rows),
                "missing_fields": {field: sum(not item["metadata"][field] for item in rows) for field in FIELDS},
                "source_ids": [item["source_id"] for item in rows],
            }
            for label, rows in sorted(by_label.items())
        },
        "limits": "Code changes and advisory metadata are evidence to inspect, not proof that the function caused the vulnerability or that unchanged functions are safe.",
    }
    review_packet.parent.mkdir(parents=True, exist_ok=True)
    summary_path.parent.mkdir(parents=True, exist_ok=True)
    review_packet.write_text(json.dumps(packet, indent=2, ensure_ascii=False, sort_keys=True) + "\n")
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", type=Path, default=Path("data/raw/big-vul/MSR_data_cleaned.zip"))
    parser.add_argument("--training-audit", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--review-packet", type=Path, default=Path("data/processed/big_vul_patch_review.json"))
    parser.add_argument("--summary", type=Path, default=Path("experiments/results/big_vul_c_patch_audit_v1.json"))
    parser.add_argument("--per-label", type=int, default=20)
    args = parser.parse_args()
    result = run(args.archive, args.training_audit, args.prepared_dir,
                 args.review_packet, args.summary, per_label=args.per_label)
    print(json.dumps({**result, "by_label": {
        key: {name: value for name, value in item.items() if name != "source_ids"}
        for key, item in result["by_label"].items()}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
