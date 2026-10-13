"""Small, validated records shared by data preparation and inference.

Locations use one-based, inclusive line numbers. A missing label is unknown,
not a negative example. Scores are model outputs, not calibrated probabilities.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite


VALID_LANGUAGES = frozenset({"c", "cpp", "javascript", "typescript", "go"})


def _require_text(value: str, field_name: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field_name} must be non-empty text")


def _validate_span(start_line: int, end_line: int) -> None:
    if (
        type(start_line) is not int
        or type(end_line) is not int
        or start_line < 1
        or end_line < start_line
    ):
        raise ValueError("line span must use positive, one-based inclusive lines")


def _validate_language(language: str) -> None:
    if language not in VALID_LANGUAGES:
        raise ValueError(f"unsupported language identifier: {language!r}")


@dataclass(frozen=True, slots=True)
class FunctionRecord:
    """One parsed function, optionally paired with an audited binary label."""

    language: str
    file_path: str
    source_code: str
    start_line: int
    end_line: int
    function_name: str | None = None
    label: int | None = None
    source_id: str | None = None
    group_id: str | None = None
    repository: str | None = None
    commit: str | None = None
    dataset_version: str | None = None

    def __post_init__(self) -> None:
        _validate_language(self.language)
        _require_text(self.file_path, "file_path")
        _require_text(self.source_code, "source_code")
        _validate_span(self.start_line, self.end_line)
        if self.function_name is not None:
            _require_text(self.function_name, "function_name")
        if self.label is not None:
            if type(self.label) is not int or self.label not in (0, 1):
                raise ValueError("label must be 0, 1, or None")
            _require_text(self.source_id, "source_id for labelled record")
            _require_text(self.group_id, "group_id for labelled record")


@dataclass(frozen=True, slots=True)
class Finding:
    """One function score and its frozen, language-specific decision threshold."""

    language: str
    file_path: str
    start_line: int
    end_line: int
    score: float
    threshold: float
    model_version: str
    function_name: str | None = None

    def __post_init__(self) -> None:
        _validate_language(self.language)
        _require_text(self.file_path, "file_path")
        _validate_span(self.start_line, self.end_line)
        _require_text(self.model_version, "model_version")
        if self.function_name is not None:
            _require_text(self.function_name, "function_name")
        for name, value in (("score", self.score), ("threshold", self.threshold)):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError(f"{name} must be a finite number in [0, 1]")
            if not isfinite(value) or not 0 <= value <= 1:
                raise ValueError(f"{name} must be a finite number in [0, 1]")

    @property
    def flagged(self) -> bool:
        return self.score >= self.threshold


@dataclass(frozen=True, slots=True)
class SkippedFile:
    """A file for which the scanner made no safety claim."""

    file_path: str
    reason: str

    def __post_init__(self) -> None:
        _require_text(self.file_path, "file_path")
        _require_text(self.reason, "reason")


@dataclass(frozen=True, slots=True)
class ScanReport:
    """JSON-ready findings and explicit coverage counts for a scan."""

    findings: tuple[Finding, ...]
    skipped_files: tuple[SkippedFile, ...]
    scanned_files: int

    def __post_init__(self) -> None:
        if type(self.scanned_files) is not int or self.scanned_files < 0:
            raise ValueError("scanned_files must be a non-negative integer")

    def to_dict(self) -> dict[str, object]:
        return {
            "summary": {
                "scanned_files": self.scanned_files,
                "skipped_files": len(self.skipped_files),
                "scored_functions": len(self.findings),
                "flagged_functions": sum(finding.flagged for finding in self.findings),
            },
            "findings": [
                {
                    "language": finding.language,
                    "file_path": finding.file_path,
                    "function_name": finding.function_name,
                    "start_line": finding.start_line,
                    "end_line": finding.end_line,
                    "score": finding.score,
                    "threshold": finding.threshold,
                    "flagged": finding.flagged,
                    "model_version": finding.model_version,
                }
                for finding in self.findings
            ],
            "skipped_files": [
                {"file_path": skipped.file_path, "reason": skipped.reason}
                for skipped in self.skipped_files
            ],
        }
