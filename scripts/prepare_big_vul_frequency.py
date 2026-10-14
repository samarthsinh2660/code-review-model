"""Prepare frozen Big-Vul C train/validation token-frequency features."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

import numpy as np

from vulnscope.external_data import load_external_jsonl
from vulnscope.frequency_features import fit_idf, transform_frequency
from vulnscope.lexical import Vocabulary, tokenize_cpp


FEATURE_VERSION = "cpp-body-frequency-v1"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prepare(source: Path, original_prepared_dir: Path, output_dir: Path) -> dict[str, object]:
    original_path = original_prepared_dir / "manifest.json"
    original = json.loads(original_path.read_text())
    if (_sha256(source) != original.get("source_sha256")
            or original.get("source_sample_remainder") != 0
            or original.get("feature_version") != "cpp-body-lexical-v2"):
        raise ValueError("source does not match frozen Big-Vul C split")
    vocabulary = Vocabulary(tuple(original["vocabulary"]))
    if len(vocabulary.tokens) != original.get("vocabulary_size"):
        raise ValueError("frozen vocabulary size does not match manifest")
    by_id = {record.source_id: record for record in load_external_jsonl(source) if record.language == "c"}
    if set(by_id) != {item["source_id"] for item in original["examples"]}:
        raise ValueError("C source IDs do not match frozen split")
    documents = {}
    labels = {}
    ids = {}
    for role in ("train", "validation"):
        examples = [item for item in original["examples"] if item["split"] == role]
        for item in examples:
            record = by_id[item["source_id"]]
            if record.repository != item["repository"] or record.label != item["label"]:
                raise ValueError(f"{role} record does not match frozen manifest")
        documents[role] = [tokenize_cpp(by_id[item["source_id"]].source_code) for item in examples]
        labels[role] = np.asarray([item["label"] for item in examples], dtype=np.int8)
        ids[role] = np.asarray([item["source_id"] for item in examples])
    idf = fit_idf(documents["train"], vocabulary)
    arrays = {"idf": idf}
    for role in ("train", "validation"):
        arrays[f"X_{role}"] = transform_frequency(documents[role], vocabulary)
        arrays[f"y_{role}"] = labels[role]
        arrays[f"id_{role}"] = ids[role]
    result = {
        "feature_version": FEATURE_VERSION,
        "transform": "log1p(100 * token_count / all_body_token_count); optional train-only mean-normalized smoothed IDF",
        "original_manifest_sha256": _sha256(original_path),
        "source_sha256": _sha256(source),
        "vocabulary": list(vocabulary.tokens),
        "idf": idf.tolist(),
        "train_rows": len(labels["train"]),
        "validation_rows": len(labels["validation"]),
        "test_sample_modulus": 10,
        "test_sample_remainder": 3,
    }
    output_dir.mkdir(parents=True, exist_ok=True)
    np.savez_compressed(output_dir / "features.npz", **arrays)
    (output_dir / "manifest.json").write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path("data/processed/big_vul_external.jsonl"))
    parser.add_argument("--original-prepared-dir", type=Path, default=Path("data/processed/big_vul_c_training"))
    parser.add_argument("--output-dir", type=Path, default=Path("data/processed/big_vul_c_frequency"))
    args = parser.parse_args()
    result = prepare(args.source, args.original_prepared_dir, args.output_dir)
    print(json.dumps({key: value for key, value in result.items() if key not in {"vocabulary", "idf"}},
                     indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
