"""Apply the frozen Juliet logistic bundle to an audited external JSONL export."""

from __future__ import annotations

import argparse
import hashlib
import json
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

import numpy as np

from vulnscope.external_data import load_external_jsonl, normalized_hash
from vulnscope.juliet import materialize_pairs
from vulnscope.lexical import Vocabulary, tokenize_cpp
from vulnscope.logistic import LogisticModel
from vulnscope.metrics import ranking_metrics, threshold_metrics


FEATURE_VERSION = "cpp-body-lexical-v2"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _metrics(labels: np.ndarray, scores: np.ndarray, threshold: float) -> dict[str, object]:
    return {**ranking_metrics(labels, scores), **threshold_metrics(labels, scores, threshold)}


def run(
    dataset: Path, bundle_dir: Path, prepared_dir: Path,
    archive: Path, assessment: Path, result_path: Path,
) -> dict[str, object]:
    """Evaluate without fitting, selecting a threshold, or changing the bundle."""

    bundle = json.loads((bundle_dir / "bundle.json").read_text())
    manifest_path = prepared_dir / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    if bundle.get("feature_version") != FEATURE_VERSION or manifest.get("feature_version") != FEATURE_VERSION:
        raise ValueError("incompatible feature version")
    if _sha256(manifest_path) != bundle.get("prepared_manifest_sha256"):
        raise ValueError("prepared manifest hash does not match frozen bundle")
    model_path = bundle_dir / "model.npz"
    if _sha256(model_path) != bundle.get("model_sha256"):
        raise ValueError("model hash does not match frozen bundle")
    if _sha256(archive) != manifest.get("archive_sha256"):
        raise ValueError("Juliet archive hash does not match prepared manifest")
    if _sha256(assessment) != manifest.get("assessment_sha256"):
        raise ValueError("Juliet assessment hash does not match prepared manifest")

    vocabulary_tokens = bundle.get("vocabulary")
    if (not isinstance(vocabulary_tokens, list) or not vocabulary_tokens
            or any(not isinstance(token, str) or not token for token in vocabulary_tokens)
            or len(vocabulary_tokens) != len(set(vocabulary_tokens))):
        raise ValueError("invalid bundle vocabulary")
    threshold = bundle.get("threshold")
    if type(threshold) not in (float, int) or not np.isfinite(threshold) or not 0 <= threshold <= 1:
        raise ValueError("invalid frozen threshold")
    model = LogisticModel.load(model_path)
    if len(model.weights) != len(vocabulary_tokens):
        raise ValueError("model weights do not match frozen vocabulary")
    vocabulary = Vocabulary(tuple(vocabulary_tokens))

    with ZipFile(archive) as source:
        reference = materialize_pairs(json.loads(assessment.read_text()), source)
    juliet_hashes = {normalized_hash(record.source_code) for record in reference}
    records = load_external_jsonl(dataset)
    overlap = [record.source_id for record in records if record.normalized_sha256 in juliet_hashes]
    if overlap:
        raise ValueError(f"external data overlaps Juliet normalized functions: {overlap[:5]}")

    features = np.log1p(np.asarray(vocabulary.transform(
        [tokenize_cpp(record.source_code) for record in records]
    ), dtype=np.float32))
    scores = model.predict_scores(features)
    labels = np.asarray([record.label for record in records], dtype=np.int8)
    repositories: dict[str, list[int]] = defaultdict(list)
    languages: dict[str, list[int]] = defaultdict(list)
    for index, record in enumerate(records):
        repositories[record.repository].append(index)
        languages[record.language].append(index)
    by_repository = {}
    for name, indices in sorted(repositories.items()):
        by_repository[name] = {"samples": len(indices), **_metrics(labels[indices], scores[indices], threshold)}
    by_language = {
        name: {"samples": len(indices), **_metrics(labels[indices], scores[indices], threshold)}
        for name, indices in sorted(languages.items())
    }
    overall = _metrics(labels, scores, threshold)
    result = {
        "evaluation_type": "independent-external-research",
        "model_version": bundle.get("model_version"),
        "feature_version": FEATURE_VERSION,
        "dataset_sha256": _sha256(dataset),
        "prepared_manifest_sha256": _sha256(manifest_path),
        "model_sha256": _sha256(model_path),
        "juliet_reference_samples": len(reference),
        "normalized_exact_overlap": 0,
        "sample_count": len(records),
        "repository_count": len(repositories),
        "threshold": threshold,
        "overall": overall,
        "false_findings_per_repository": overall["fp"] / len(repositories),
        "by_repository": by_repository,
        "by_language": by_language,
        "predictions": [
            {"source_id": record.source_id, "repository": record.repository,
             "label": record.label, "score": float(score), "flagged": bool(score >= threshold)}
            for record, score in zip(records, scores)
        ],
    }
    result_path.parent.mkdir(parents=True, exist_ok=True)
    result_path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("dataset", type=Path, help="audited C/C++ function JSONL")
    parser.add_argument("assessment", type=Path, help="Juliet pair assessment used in preparation")
    parser.add_argument("--bundle-dir", type=Path, default=Path("artifacts/models/juliet_01_logistic_v2"))
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/juliet_01"))
    parser.add_argument("--archive", type=Path, default=Path("data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip"))
    parser.add_argument("--result", type=Path, default=Path("experiments/results/external_logistic.json"))
    args = parser.parse_args()
    result = run(args.dataset, args.bundle_dir, args.prepared_dir, args.archive, args.assessment, args.result)
    print(json.dumps({key: value for key, value in result.items() if key not in {"predictions", "by_repository"}}, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
