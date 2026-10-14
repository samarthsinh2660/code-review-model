"""Build source-local Clang AST count features for frozen Juliet records."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from collections import defaultdict
from pathlib import Path
from zipfile import ZipFile

import numpy as np

from scripts.audit_juliet_archive import _file_sha256
from scripts.prepare_juliet_01 import JULIET_SHA256
from vulnscope.ast_features import FEATURE_NAMES, ast_body_counts


AST_FEATURE_VERSION = "clang18-body-counts-v1"


def prepare_ast(archive_path: Path, prepared_dir: Path) -> dict[str, object]:
    manifest = json.loads((prepared_dir / "manifest.json").read_text())
    if _file_sha256(archive_path) != JULIET_SHA256:
        raise ValueError("Juliet archive SHA-256 does not match the audited release")
    by_path: dict[str, list[dict]] = defaultdict(list)
    for example in manifest["examples"]:
        by_path[example["path"]].append(example)
    vectors: dict[str, tuple[int, ...]] = {}
    failures = []
    with ZipFile(archive_path) as archive, tempfile.TemporaryDirectory(prefix="vulnscope_ast_") as directory:
        root = Path(directory)
        support = root / "C" / "testcasesupport"
        support.mkdir(parents=True)
        for member in archive.namelist():
            if member.startswith("C/testcasesupport/") and member.endswith(".h"):
                (support / Path(member).name).write_bytes(archive.read(member))
        for member, examples in sorted(by_path.items()):
            source = archive.read(member)
            path = root / member
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source)
            cpp = path.suffix == ".cpp"
            command = [
                "clang++" if cpp else "clang", "-std=gnu++11" if cpp else "-std=gnu11",
                "-Xclang", "-ast-dump=json", "-fsyntax-only", "-I", str(support), str(path),
            ]
            completed = subprocess.run(command, capture_output=True, text=True, check=False)
            if completed.returncode:
                failures.append({"path": member, "reason": "\n".join(completed.stderr.splitlines()[:3])})
                continue
            ast = json.loads(completed.stdout)
            for example in examples:
                try:
                    vectors[example["source_id"]] = ast_body_counts(
                        ast, source, example["function_name"], example["start_line"]
                    )
                except ValueError as error:
                    failures.append({"path": member, "source_id": example["source_id"], "reason": str(error)})
    if failures:
        (prepared_dir / "ast_failures.json").write_text(json.dumps(failures, indent=2) + "\n")
        raise ValueError(f"AST extraction failed for {len(failures)} files/functions; see ast_failures.json")
    if len(vectors) != len(manifest["examples"]):
        raise ValueError("AST feature count does not match frozen records")

    train_ids = [item["source_id"] for item in manifest["examples"] if item["split"] == "train"]
    train_raw = np.log1p(np.asarray([vectors[source_id] for source_id in train_ids], dtype=np.float64))
    mean = train_raw.mean(axis=0)
    std = train_raw.std(axis=0)
    std[std < 1e-8] = 1.0
    arrays = {}
    for split in ("train", "validation", "test"):
        ids = [item["source_id"] for item in manifest["examples"] if item["split"] == split]
        raw = np.log1p(np.asarray([vectors[source_id] for source_id in ids], dtype=np.float64))
        arrays[f"A_{split}"] = ((raw - mean) / std).astype(np.float32)
        arrays[f"id_{split}"] = np.asarray(ids)
    np.savez_compressed(prepared_dir / "ast_features.npz", **arrays)
    metadata = {
        "ast_feature_version": AST_FEATURE_VERSION,
        "feature_names": FEATURE_NAMES,
        "files_parsed": len(by_path),
        "functions_extracted": len(vectors),
        "train_mean": mean.tolist(),
        "train_std": std.tolist(),
        "parser": "Clang 18, gnu11/gnu++11, source-local body AST",
    }
    (prepared_dir / "ast_manifest.json").write_text(json.dumps(metadata, indent=2, sort_keys=True) + "\n")
    return {key: value for key, value in metadata.items() if key not in {"train_mean", "train_std"}}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--prepared-dir", type=Path, default=Path("data/processed/juliet_01"))
    args = parser.parse_args()
    print(json.dumps(prepare_ast(args.archive, args.prepared_dir), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
