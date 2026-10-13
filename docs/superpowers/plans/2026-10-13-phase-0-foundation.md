# Phase 0 Foundation Implementation Plan

> **For agentic workers:** Execute these tasks in order and review each deliverable. Steps use checkbox (`- [x]`) syntax for tracking. This run uses inline execution; no subagent dispatch is required.

**Goal:** Establish a runnable Python project with stable function and finding records, safe data/artifact layout, and reproducible setup instructions.

**Architecture:** A small `src/vulnscope` package defines records shared by later dataset adapters and scanners. The first tests use Python's standard-library `unittest` so the foundation runs without downloading dependencies. Training, parsing, and scanning are outside Phase 0.

**Tech Stack:** Python 3.12+, standard-library dataclasses, JSON, `unittest`, Git ignore rules.

## Global Constraints

- Core ML classifiers will be implemented by this project; no packaged classifier enters the core path.
- Label `None` means unknown/unlabelled and must never be converted to negative.
- Function locations use one-based inclusive line numbers.
- Raw datasets and trained artifacts are ignored by Git.
- C/C++ is the first candidate language; JS/TS and Go are later audited additions.

---

## File map

| File | Responsibility |
|---|---|
| `pyproject.toml` | Project metadata and `src` package discovery |
| `.gitignore` | Exclude environment, caches, raw/processed data, and artifacts |
| `README.md` | Setup, test command, repository layout, and project status |
| `src/vulnscope/__init__.py` | Package identity |
| `src/vulnscope/records.py` | Validated function, finding, and skipped-file records |
| `tests/test_records.py` | Contract tests for labels, spans, and report serialization |
| `data/README.md`, `artifacts/README.md`, `experiments/README.md` | Explain local data, model-bundle, and run-record conventions |

## Task 1: Runnable package and ignored storage

**Files:** Create `pyproject.toml`, `.gitignore`, `README.md`, `src/vulnscope/__init__.py`, and the three storage README files.

**Interfaces:** The package imports as `vulnscope` after `python3 -m pip install -e .`, or with `PYTHONPATH=src`. No runtime dependency is required in Phase 0.

- [x] **Step 1:** Add project metadata for Python `>=3.12`, a `src` package layout, and no classifier dependency.
- [x] **Step 2:** Ignore `data/raw`, `data/interim`, `data/processed`, `artifacts/models`, virtual environments, and Python caches; keep their README files trackable.
- [x] **Step 3:** Document environment setup and the no-install test command `PYTHONPATH=src python3 -m unittest discover -s tests -v`.
- [x] **Step 4:** Run `python3 -m compileall -q src` and check that the package imports with `PYTHONPATH=src`.

## Task 2: Common record contract

**Files:** Create `src/vulnscope/records.py` and `tests/test_records.py`.

**Interfaces:**

- `FunctionRecord(language, file_path, source_code, start_line, end_line, function_name=None, label=None, source_id=None, group_id=None, repository=None, commit=None, dataset_version=None, license_id=None)` represents labelled or scanned functions. Labelled records require source ID, group ID, dataset version, and license ID.
- `Finding(language, file_path, start_line, end_line, score, threshold, model_version, function_name=None)` represents one scored function and exposes a `flagged` property.
- `SkippedFile(file_path, reason)` records coverage failures.
- `ScanReport(findings, skipped_files, scanned_files)` serializes to a JSON-ready dictionary with a coverage summary.

- [x] **Step 1:** Write tests: a scanned function keeps `label=None`; labelled records require source/group IDs; invalid labels and line spans fail; a finding's `flagged` value follows its score and threshold; a report exposes skipped files instead of declaring them safe.
- [x] **Step 2:** Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` and confirm that tests fail before records exist.
- [x] **Step 3:** Implement frozen data classes with validation in `__post_init__`, `Finding.flagged`, and `ScanReport.to_dict()` using plain JSON-compatible values.
- [x] **Step 4:** Run the same test command and confirm all tests pass.
- [x] **Step 5:** Run `python3 -m compileall -q src tests` and inspect `git status --short` for ignored data/artifact paths.

## Phase 0 completion check

- [x] README instructions work from a clean source tree with local Python 3.12+.
- [x] Tests establish the record and report contract needed by later phases.
- [x] No dataset, model training, parser, or scanner behavior is claimed yet.
