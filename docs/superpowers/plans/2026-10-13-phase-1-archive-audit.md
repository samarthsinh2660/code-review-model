# Phase 1 Juliet Archive Audit Implementation Plan

> **For agentic workers:** Execute the tasks in order and review each deliverable. Steps use checkbox (`- [x]`) syntax. This run uses inline execution.

**Goal:** Produce reproducible, archive-level evidence for the acquired Juliet release without extracting or labelling its functions.

**Architecture:** A standard-library script streams every ZIP member, verifies CRC while reading, checks the whole-file SHA-256, and emits JSON counts. A tiny synthetic ZIP test verifies duplicate and marker counting. The script does not claim function-level labels or near-duplicate rates.

**Tech Stack:** Python 3.12+, `zipfile`, `hashlib`, `collections`, `argparse`, `unittest`.

## Global Constraints

- The official Juliet 1.3 SHA-256 is `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`.
- Read ZIP members in memory-efficient chunks; never execute or extract dataset code.
- Keep archive-level duplicate counts distinct from function-level duplicate counts.
- Keep raw archives and generated audit JSON outside Git; put curated findings in `docs/dataset-audit.md`.

---

## Task 1: Archive audit utility

**Files:** Create `scripts/audit_juliet_archive.py` and `tests/test_archive_audit.py`.

**Interfaces:** `audit_archive(path: Path, expected_sha256: str | None = None) -> dict[str, object]`; CLI accepts archive path and optional expected SHA-256, prints sorted JSON, exits nonzero for a mismatch or corrupt ZIP.

- [x] **Step 1:** Write a test ZIP with two identical `.c` files, one different `.cpp` file, and one text file; assert 4 files, 3 source files, 1 exact duplicate source file, one CWE directory, and the expected marker counts.
- [x] **Step 2:** Assert that a wrong expected SHA-256 raises `ValueError`.
- [x] **Step 3:** Run `PYTHONPATH=src python3 -m unittest discover -s tests -v` and confirm the new tests fail because the script is absent.
- [x] **Step 4:** Implement streamed archive hashing and ZIP member reads. Count total/source entries, C versus C++ files, CWE directories, `POTENTIAL FLAW`/`FIX:` marker files, exact duplicate source files, unsafe member names, and uncompressed bytes. Keep no code contents in the report.
- [x] **Step 5:** Run all tests and compile the script.

## Task 2: Measured audit record

**Files:** Update `docs/dataset-audit.md`.

- [x] **Step 1:** Run the utility on the official ZIP with the published SHA-256.
- [x] **Step 2:** Record measured archive/file counts and sample observations. Distinguish archive-level facts from unmeasured function labels, parser success, class balance, and near duplicates.
- [x] **Step 3:** Review the next dataset decision gate and keep training disabled until function-level labels are defensible.

## Task 3: Manifest consistency audit

**Why added:** The acquired ZIP contains `C/manifest.xml` with file-specific flaw lines. These are stronger label evidence than generated names or comments, but the manifest must be checked against the actual files before use.

**Files:** Modify `scripts/audit_juliet_archive.py`, `tests/test_archive_audit.py`, and `docs/dataset-audit.md`.

**Interfaces:** The existing `audit_archive()` result gains manifest test-case, file-reference, flaw-line, missing-reference, and out-of-bounds-line counts when a manifest is present. Tiny synthetic ZIPs without a manifest remain valid.

- [x] **Step 1:** Add a synthetic manifest test with a valid flaw line, a missing file reference, and an out-of-bounds flaw line; assert each count.
- [x] **Step 2:** Run the test to verify it fails before the manifest logic exists.
- [x] **Step 3:** Parse the manifest, resolve its filenames against ZIP testcase members, and compare flaw line numbers to actual file lengths without executing or extracting code.
- [x] **Step 4:** Run all tests and the audit on the official archive.
- [x] **Step 5:** Record manifest results and what they do and do not establish about function labels.
