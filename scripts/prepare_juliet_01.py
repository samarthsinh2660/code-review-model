"""Freeze the audited Juliet `_01` split and lexical feature matrices."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import Counter, defaultdict
from pathlib import Path
from zipfile import ZipFile

import numpy as np

from scripts.audit_juliet_archive import _file_sha256
from vulnscope.juliet import materialize_pairs
from vulnscope.lexical import Vocabulary, tokenize_cpp
from vulnscope.records import FunctionRecord
from vulnscope.splitting import SPLIT_NAMES, assign_splits, group_near_duplicates


JULIET_SHA256 = "ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb"
FEATURE_VERSION = "cpp-body-lexical-v2"


def prepare(records: list[FunctionRecord]) -> tuple[dict[str, np.ndarray], dict[str, object]]:
    """Build split arrays with vocabulary fitted on training functions only."""

    tokens = [tokenize_cpp(record.source_code) for record in records]
    normalized_labels: dict[tuple[str, ...], set[int]] = defaultdict(set)
    normalized_counts: Counter[tuple[str, ...]] = Counter()
    for record, document in zip(records, tokens):
        normalized_labels[document].add(record.label)
        normalized_counts[document] += 1
    conflicts = sum(len(labels) > 1 for labels in normalized_labels.values())
    if conflicts:
        raise ValueError(f"{conflicts} normalized code sequences have conflicting labels")
    final_groups, group_stats = group_near_duplicates(records)
    splits, split_stats = assign_splits(records, final_groups)
    training_tokens = [document for document, split in zip(tokens, splits) if split == "train"]
    vocabulary = Vocabulary.fit(training_tokens, max_features=4096, min_df=2)
    if not vocabulary.tokens:
        raise ValueError("no training vocabulary survived filtering")
    arrays = {}
    for name in SPLIT_NAMES:
        indices = [index for index, split in enumerate(splits) if split == name]
        counts = np.asarray(vocabulary.transform([tokens[index] for index in indices]), dtype=np.float32)
        arrays[f"X_{name}"] = np.log1p(counts)
        arrays[f"y_{name}"] = np.asarray([records[index].label for index in indices], dtype=np.int8)
        arrays[f"id_{name}"] = np.asarray([records[index].source_id for index in indices])
    examples = [
        {
            "source_id": record.source_id,
            "path": record.file_path,
            "function_name": record.function_name,
            "start_line": record.start_line,
            "end_line": record.end_line,
            "language": record.language,
            "label": record.label,
            "group_id": final_group,
            "split": split,
        }
        for record, final_group, split in zip(records, final_groups, splits)
    ]
    metadata = {
        "feature_version": FEATURE_VERSION,
        "tokenizer": "function-body-only C/C++ tokens; comments removed; generated identifiers and string/char values masked; log1p counts",
        "vocabulary": list(vocabulary.tokens),
        "vocabulary_size": len(vocabulary.tokens),
        "grouping": group_stats,
        "normalized_exact_duplicate_functions": sum(count - 1 for count in normalized_counts.values()),
        "normalized_conflicting_labels": conflicts,
        "splits": split_stats,
        "examples": examples,
    }
    return arrays, metadata


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("assessment", type=Path)
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed/juliet_01"))
    args = parser.parse_args()
    archive_sha256 = _file_sha256(args.archive)
    if archive_sha256 != JULIET_SHA256:
        raise ValueError("Juliet archive SHA-256 does not match the audited release")
    assessment_bytes = args.assessment.read_bytes()
    assessment = json.loads(assessment_bytes)
    with ZipFile(args.archive) as archive:
        records = materialize_pairs(assessment, archive)
    arrays, metadata = prepare(records)
    metadata["archive_sha256"] = archive_sha256
    metadata["assessment_sha256"] = hashlib.sha256(assessment_bytes).hexdigest()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(args.output_dir / "features.npz", **arrays)
    (args.output_dir / "manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    summary = {key: value for key, value in metadata.items() if key not in {"examples", "vocabulary"}}
    print(json.dumps(summary, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
