"""Audit likely cross-split C code clones with verified token-shingle overlap."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from vulnscope.external_data import load_external_jsonl
from vulnscope.lexical import tokenize_cpp
from vulnscope.near_duplicates import find_near_pairs


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _labelled_pairs(left, right, result):
    return [
        {"left_source_id": left[item["train_index"]].source_id,
         "right_source_id": right[item["query_index"]].source_id,
         "left_project": left[item["train_index"]].repository,
         "right_project": right[item["query_index"]].repository,
         "left_label": left[item["train_index"]].label,
         "right_label": right[item["query_index"]].label,
         "jaccard": item["jaccard"]}
        for item in result["pairs"]
    ]


def run(training_source: Path, fresh_source: Path, training_audit: Path,
        fresh_audit: Path, prepared_dir: Path, output: Path) -> dict[str, object]:
    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    train_audit = json.loads(training_audit.read_text())
    test_audit = json.loads(fresh_audit.read_text())
    remainder = test_audit.get("sample_remainder")
    if (_sha256(training_source) != manifest.get("source_sha256")
            or _sha256(training_audit) != manifest.get("audit_sha256")
            or _sha256(fresh_source) != test_audit.get("output_sha256")
            or test_audit.get("sample_modulus") != 10
            or type(remainder) is not int or remainder not in (1, 2)
            or train_audit.get("archive_sha256") != test_audit.get("archive_sha256")):
        raise ValueError("source, audit, or manifest hashes do not match")
    roles = {role: set(manifest["projects"][role]) for role in ("train", "validation", "test")}
    if any(roles[a] & roles[b] for a, b in (("train", "validation"), ("train", "test"), ("validation", "test"))):
        raise ValueError("project roles overlap")
    examples = {item["source_id"]: item for item in manifest["examples"]}
    source_records = [record for record in load_external_jsonl(training_source) if record.language == "c"]
    if {record.source_id for record in source_records} != set(examples):
        raise ValueError("training source IDs do not match manifest")
    for record in source_records:
        item = examples.get(record.source_id)
        if item is None or item["repository"] != record.repository or item["label"] != record.label:
            raise ValueError("training source record does not match manifest")
    train = [record for record in source_records if examples[record.source_id]["split"] == "train"]
    validation = [record for record in source_records if examples[record.source_id]["split"] == "validation"]
    fresh_records = load_external_jsonl(fresh_source)
    if any(int(record.normalized_sha256[:16], 16) % 10 != remainder for record in fresh_records):
        raise ValueError(f"fresh source is outside remainder {remainder}")
    fresh_test = [record for record in fresh_records if record.language == "c" and record.repository in roles["test"]]
    if not train or not validation or not fresh_test:
        raise ValueError("all audited roles need C functions")
    train_tokens = [tokenize_cpp(record.source_code) for record in train]
    val_tokens = [tokenize_cpp(record.source_code) for record in validation]
    test_tokens = [tokenize_cpp(record.source_code) for record in fresh_test]
    comparisons = {}
    for name, left, right, left_tokens, right_tokens in (
        ("train_validation", train, validation, train_tokens, val_tokens),
        ("train_fresh_test", train, fresh_test, train_tokens, test_tokens),
        ("validation_fresh_test", validation, fresh_test, val_tokens, test_tokens),
    ):
        audit = find_near_pairs(left_tokens, right_tokens)
        pairs = _labelled_pairs(left, right, audit)
        comparisons[name] = {
            **{key: value for key, value in audit.items() if key != "pairs"},
            "matched_pairs": len(pairs),
            "matched_query_functions": len({item["right_source_id"] for item in pairs}),
            "conflicting_label_pairs": sum(item["left_label"] != item["right_label"] for item in pairs),
            "pairs": pairs,
        }
    alias_roles: dict[str, list[tuple[str, str]]] = {}
    for role, projects in roles.items():
        for project in projects:
            key = re.sub("[^a-z]", "", project.casefold())
            if key:
                alias_roles.setdefault(key, []).append((role, project))
    cross_role_aliases = [sorted(items) for items in alias_roles.values()
                          if len({role for role, _ in items}) > 1]
    result = {
        "method": "bottom-16 distinct 5-token shingle hashes nominate candidates; exact shingle Jaccard >= 0.8 confirms",
        "limitations": "Candidate search can miss near clones, especially short functions and hash sketches omitted by posting caps; code semantics are not checked.",
        "training_source_sha256": _sha256(training_source),
        "fresh_source_sha256": _sha256(fresh_source),
        "fresh_sample_remainder": remainder,
        "prepared_manifest_sha256": _sha256(manifest_path),
        "cross_role_normalized_project_aliases": cross_role_aliases,
        "comparisons": comparisons,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-source", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--fresh-source", type=Path, default=Path("data/processed/big_vul_budget_test.jsonl"))
    parser.add_argument("--training-audit", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--fresh-audit", type=Path, default=Path("data/processed/big_vul_budget_test_audit.json"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/big_vul_c_near_duplicates_v1.json"))
    args = parser.parse_args()
    result = run(args.training_source, args.fresh_source, args.training_audit,
                 args.fresh_audit, args.prepared_dir, args.output)
    print(json.dumps({**result, "comparisons": {
        name: {key: value for key, value in comparison.items() if key != "pairs"}
        for name, comparison in result["comparisons"].items()}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
