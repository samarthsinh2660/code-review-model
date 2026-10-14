# Phase 5 Big-Vul audit and evaluation implementation plan

**Goal:** Audit the supplied Big-Vul function export and measure the frozen Juliet model on a reproducible, independent C/C++ cohort.

**Architecture:** Stream the 10.8 GB CSV inside the verified ZIP. Record source hash, schema, class/project coverage, missing metadata, and normalized duplicate conflicts. Materialize a deterministic, label-independent sample of valid functions with traceable exclusion counts, then apply the existing frozen external evaluator without fitting or threshold changes. Keep the original ZIP immutable and outputs ignored by Git.

**Tech Stack:** Python 3.12 `csv`, `zipfile`, `hashlib`, `json`, NumPy in the existing evaluator, `unittest` fixtures.

## Global Constraints

- `func_before` and `vul` are the candidate function code and label; `func_after` is not a feature.
- `project` and `commit_id` supply repository and fix-commit provenance; missing `parentID` is reported, not invented.
- Rows lacking code, project, commit, or binary label are excluded with a reason.
- Keep C, CPP, and C++ mapped to `c`/`cpp`; report actual class and language counts.
- Do not upsample positives or tune from external labels. A deterministic hash sample must use row identity, never label.
- Reject normalized duplicate code with conflicting labels; retain one representative of same-label duplicates.
- Record source ZIP SHA-256, member name/size, extraction and rejection counts, and audit limitations.
- Run all tests, compile checks, integration evaluation, and diff review before a commit. Git metadata writes are currently blocked by the sandbox.

## Task 1: Stream and audit the export

**Files:** Create `scripts/prepare_big_vul_external.py`; test `tests/test_big_vul_external.py`.

**Interface:** `prepare(archive: Path, output: Path, report: Path, sample_modulus: int = 10) -> dict` reads the ZIP member without extraction, validates required columns, computes normalized code hashes, detects conflicts and duplicates, and writes a sampled JSONL with source, repository, commit, language, version, license provenance and explicit label.

- [x] Create a tiny ZIP fixture with positive/negative, duplicate, conflicting, missing-provenance, and C++ rows.
- [x] Run focused tests to confirm the adapter is absent.
- [x] Implement streaming audit and deterministic selection; run focused tests.
- [x] Run on the supplied archive; inspect source counts, exclusions, and sample balance.

## Task 2: Frozen real-world evaluation

**Files:** Modify `docs/phase-5-generalization.md`, `docs/dataset-audit.md`, and `docs/phases.md`.

- [x] Run `scripts.evaluate_external` on the prepared Big-Vul sample using the untouched Juliet bundle.
- [x] Check normalized overlap, parser/tokenizer coverage, aggregate and per-project metrics, and errors.
- [x] Document source hash, retained sample size, prevalence, metrics, label limitations, and scanner decision.
- [x] Run all unit tests, compile checks, `git diff --check`, and review the complete code path.
- [ ] Commit the Phase 5 work when Git metadata becomes writable.
