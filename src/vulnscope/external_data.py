"""Strict, source-neutral input for an independent C/C++ evaluation."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from vulnscope.lexical import tokenize_cpp


def normalized_hash(source_code: str) -> str:
    """Hash the exact token sequence used for lexical model input."""

    tokens = tokenize_cpp(source_code)
    encoded = json.dumps(tokens, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True, slots=True)
class ExternalFunction:
    source_id: str
    repository: str
    commit: str
    source_code: str
    label: int
    language: str
    dataset_version: str
    license_id: str
    normalized_sha256: str


_TEXT_FIELDS = ("source_id", "repository", "commit", "source_code", "dataset_version", "license_id")


def load_external_jsonl(path: Path) -> list[ExternalFunction]:
    """Require independent, deduplicated, explicitly labelled function rows."""

    rows: list[ExternalFunction] = []
    seen_ids: set[str] = set()
    seen_code: set[str] = set()
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                raw = json.loads(line)
                if not isinstance(raw, dict):
                    raise ValueError("row must be a JSON object")
                for field in _TEXT_FIELDS:
                    if not isinstance(raw.get(field), str) or not raw[field].strip():
                        raise ValueError(f"{field} must be nonempty text")
                if type(raw.get("label")) is not int or raw["label"] not in (0, 1):
                    raise ValueError("label must be integer 0 or 1")
                if raw.get("language") not in ("c", "cpp"):
                    raise ValueError("language must be c or cpp")
                if raw["source_id"] in seen_ids:
                    raise ValueError("duplicate source_id")
                digest = normalized_hash(raw["source_code"])
                if digest in seen_code:
                    raise ValueError("duplicate normalized function")
                rows.append(ExternalFunction(**{field: raw[field] for field in _TEXT_FIELDS},
                                             label=raw["label"], language=raw["language"],
                                             normalized_sha256=digest))
                seen_ids.add(raw["source_id"])
                seen_code.add(digest)
            except (ValueError, TypeError, KeyError) as error:
                raise ValueError(f"line {number}: {error}") from error
    if not rows:
        raise ValueError("external dataset is empty")
    return rows
