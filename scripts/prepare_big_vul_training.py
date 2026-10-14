"""Freeze Big-Vul C project splits and fit lexical features on train only."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path

import numpy as np

from vulnscope.external_data import load_external_jsonl
from vulnscope.lexical import Vocabulary, tokenize_cpp
from vulnscope.splitting import SPLIT_NAMES, assign_splits


FEATURE_VERSION = "cpp-body-lexical-v2"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare_training(
    source: Path, audit: Path, output_dir: Path,
    *, max_features: int = 1024, min_df: int = 5,
) -> dict[str, object]:
    """Do not materialize features for the reserved test projects."""

    audit_data = json.loads(audit.read_text())
    source_hash = _sha256(source)
    legacy_zero = (
        "sample_remainder" not in audit_data
        and audit_data.get("sample_rule") == "int(first_16_hex_chars_of_normalized_body_sha256, 16) % sample_modulus == 0"
    )
    if (audit_data.get("sample_modulus") != 10 or audit_data.get("sample_remainder", 0) != 0
            or ("sample_remainder" not in audit_data and not legacy_zero)
            or audit_data.get("output_sha256") != source_hash):
        raise ValueError("training source is not the audited hash-remainder-0 cohort")
    records = [record for record in load_external_jsonl(source) if record.language == "c"]
    if not records:
        raise ValueError("no C functions in training source")
    splits, split_stats = assign_splits(records, [record.repository for record in records])
    project_roles: dict[str, set[str]] = defaultdict(set)
    for record, split in zip(records, splits):
        project_roles[split].add(record.repository)
    if set(project_roles) != set(SPLIT_NAMES):
        raise ValueError("all project roles must be populated")
    tokens = [tokenize_cpp(record.source_code) for record in records]
    vocabulary = Vocabulary.fit(
        [document for document, split in zip(tokens, splits) if split == "train"],
        max_features=max_features, min_df=min_df,
    )
    if not vocabulary.tokens:
        raise ValueError("training vocabulary is empty")
    arrays = {}
    for split in ("train", "validation"):
        indices = [index for index, role in enumerate(splits) if role == split]
        arrays[f"X_{split}"] = np.log1p(np.asarray(
            vocabulary.transform([tokens[index] for index in indices]), dtype=np.float32
        ))
        arrays[f"y_{split}"] = np.asarray([records[index].label for index in indices], dtype=np.int8)
        arrays[f"id_{split}"] = np.asarray([records[index].source_id for index in indices])
    examples = [
        {"source_id": record.source_id, "repository": record.repository,
         "label": record.label, "split": split}
        for record, split in zip(records, splits)
    ]
    manifest = {
        "dataset": "Big-Vul C research cohort",
        "source_sha256": source_hash,
        "audit_sha256": _sha256(audit),
        "source_sample_modulus": 10,
        "source_sample_remainder": 0,
        "test_sample_modulus": 10,
        "test_sample_remainder": 1,
        "feature_version": FEATURE_VERSION,
        "vocabulary": list(vocabulary.tokens),
        "vocabulary_size": len(vocabulary.tokens),
        "min_df": min_df,
        "max_features": max_features,
        "projects": {split: sorted(project_roles[split]) for split in SPLIT_NAMES},
        "splits": split_stats,
        "examples": examples,
        "languages": dict(Counter(record.language for record in records)),
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output_dir / "features.npz", **arrays)
    (output_dir / "manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--audit", type=Path, default=Path("data/processed/big_vul_audit.json"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    args = parser.parse_args()
    manifest = prepare_training(args.source, args.audit, args.output_dir)
    print(json.dumps({key: value for key, value in manifest.items() if key not in {"examples", "vocabulary", "projects"}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
