"""Measure how much Big-Vul label ranking comes from function length alone."""

from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from pathlib import Path

import numpy as np

from vulnscope.external_data import load_external_jsonl
from vulnscope.lexical import tokenize_cpp
from vulnscope.metrics import ranking_metrics


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _summarize(rows: list[tuple[int, int]]) -> dict[str, object]:
    if not rows or {label for label, _ in rows} != {0, 1}:
        raise ValueError("length audit requires both labels")
    labels = np.asarray([label for label, _ in rows], dtype=np.int8)
    lengths = np.asarray([length for _, length in rows], dtype=np.float64)
    scores = lengths / lengths.max()
    return {
        "samples": len(rows), "positives": int(labels.sum()),
        "median_tokens_by_label": {
            str(label): statistics.median(length for item_label, length in rows if item_label == label)
            for label in (0, 1)
        },
        "length_only_ranking": ranking_metrics(labels, scores),
    }


def run(training_source: Path, fresh_source: Path, prepared_dir: Path, output: Path) -> dict[str, object]:
    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if _sha256(training_source) != manifest.get("source_sha256"):
        raise ValueError("training source does not match manifest")
    roles = {item["source_id"]: item["split"] for item in manifest["examples"]}
    by_role: dict[str, list[tuple[int, int]]] = {role: [] for role in ("train", "validation")}
    seen: set[str] = set()
    for record in load_external_jsonl(training_source):
        if roles.get(record.source_id) in by_role:
            by_role[roles[record.source_id]].append((record.label, len(tokenize_cpp(record.source_code))))
            seen.add(record.source_id)
    if seen != {source_id for source_id, role in roles.items() if role in by_role}:
        raise ValueError("training source IDs do not match manifest")
    held_out_projects = set(manifest["projects"]["test"])
    fresh_rows = [
        (record.label, len(tokenize_cpp(record.source_code)))
        for record in load_external_jsonl(fresh_source)
        if record.language == "c" and record.repository in held_out_projects
    ]
    result = {
        "audit": "token-count ranking diagnostic; no learned parameters or threshold",
        "training_source_sha256": _sha256(training_source),
        "fresh_source_sha256": _sha256(fresh_source),
        "prepared_manifest_sha256": _sha256(manifest_path),
        "train": _summarize(by_role["train"]),
        "validation": _summarize(by_role["validation"]),
        "fresh_test": _summarize(fresh_rows),
        "note": "Fresh-test diagnostic was run after the model and alert policy were frozen; it does not select either.",
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--training-source", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--fresh-source", type=Path, default=Path("data/processed/big_vul_budget_test.jsonl"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--output", type=Path, default=Path("experiments/results/big_vul_c_length_audit_v1.json"))
    args = parser.parse_args()
    print(json.dumps(run(args.training_source, args.fresh_source, args.prepared_dir, args.output), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
