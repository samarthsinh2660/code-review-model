# Phase 5 external evaluation implementation plan

**Goal:** Evaluate the frozen Juliet logistic bundle on independently audited C/C++ functions without fitting or tuning on them.

**Architecture:** A small JSONL adapter validates explicit labels and source provenance. The evaluator loads the saved bundle and model, checks the Juliet assessment/archive for exact normalized cross-source overlap, applies the frozen tokenizer and vocabulary, and reports ranking, threshold, repository, and coverage results. The input adapter does not invent negative labels or infer vulnerability from a patch.

**Tech stack:** Python 3.12, NumPy, standard-library JSONL and ZIP handling, existing `vulnscope` feature/model/metric functions, `unittest` fixtures.

## Constraints

- Require `source_id`, `repository`, `commit`, `source_code`, `label`, `language`, `dataset_version`, and `license_id` in every input row.
- Accept only `c` and `cpp` rows with explicit binary labels; reject duplicate source IDs and conflicting normalized labels.
- Refuse evaluation if an external normalized function exactly matches any Juliet function used in the experiment.
- Verify model and prepared-manifest hashes before scoring; never call a fitting or threshold-selection function.
- Keep output under ignored `experiments/results/`; do not claim a deployment gate passes from a fixture.
- Run all tests, review the diff, and commit this phase only when Git metadata is writable.

## Task 1: Validate external function rows

**Files:** Create `src/vulnscope/external_data.py`; test `tests/test_external_data.py`.

**Interface:** `load_external_jsonl(path: Path) -> list[ExternalFunction]` returns immutable fields needed for evaluation. Parse each JSON object, report line-numbered errors, and reject blank datasets, missing or malformed provenance, non-binary labels, repeated IDs, and contradictory normalized source.

- [x] Write fixtures with valid rows, missing provenance, duplicate IDs, and conflicting normalized labels.
- [x] Run `PYTHONPATH=src python3 -m unittest tests.test_external_data -v`; confirm failure before implementation.
- [x] Implement the validator and rerun the focused test.

## Task 2: Frozen bundle and overlap evaluation

**Files:** Create `scripts/evaluate_external.py`; test `tests/test_external_evaluation.py`.

**Interface:** `run(dataset: Path, bundle_dir: Path, prepared_dir: Path, archive: Path, assessment: Path, result_path: Path) -> dict` verifies SHA-256 links, materializes Juliet comparison functions, rejects normalized exact overlap, transforms external code with saved vocabulary, and writes aggregate/per-repository metrics and score examples.

- [x] Write a tiny saved-model fixture and a synthetic Juliet reference ZIP/assessment; assert frozen scores and overlap rejection.
- [x] Run the focused test; confirm failure before implementation.
- [x] Implement scoring and summary; rerun the focused test.

## Task 3: Document and verify

**Files:** Modify `docs/phase-5-generalization.md`, `README.md`, `docs/phases.md`.

- [x] Document the JSONL contract, invocation, and requirement for a separate license/label audit of the actual export.
- [x] Run `PYTHONPATH=src python3 -m unittest discover -s tests -q`, `python3 -m compileall -q src scripts tests`, and `git diff --check`.
- [x] Review data access, scoring, hashing, and result wording; record any untested external-data limitation.
- [ ] Commit the Phase 5 code and docs once Git metadata writes are available.
