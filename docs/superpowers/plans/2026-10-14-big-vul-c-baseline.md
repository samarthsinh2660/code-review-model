# Big-Vul C baseline implementation plan

> **For agentic workers:** Implement inline in this session. Each task below ends with focused tests and review.

**Goal:** Train a custom C vulnerability baseline on Big-Vul and evaluate once on fresh functions from projects absent from training and validation.

**Architecture:** Freeze project assignments from the already audited hash-remainder-0 cohort. Use its training and validation projects only for vocabulary fitting, model fitting, hyperparameter selection, and threshold selection. Generate a separate hash-remainder-1 cohort after model selection and evaluate only its test projects. Exact normalized code cannot cross the two hash cohorts; complete projects cannot cross the three sets.

**Tech Stack:** Python 3.12, NumPy, existing lexical tokenizer, `Vocabulary`, `assign_splits`, custom logistic model and metrics, `unittest`.

## Global Constraints

- The Big-Vul label is a changed-line proxy, not proof of vulnerability or safety.
- Retain natural class prevalence in validation and test; never fit vocabulary on either.
- The previous Big-Vul transfer sample may be used for new training/validation, but none of it may be called a fresh final test for this model.
- Choose model settings and threshold from validation only. Open remainder-1 test data only after freezing the bundle.
- Report C results separately. The small C++ cohort is not enough to declare C++ scanner support.
- Keep source code and generated artifacts ignored by Git; version only code, tests, plans, and measured summaries.
- Run all tests, compile checks, artifact checks, and code review before any commit.

---

### Task 1: Make hash sampling select a different remainder

**Files:** Modify `scripts/prepare_big_vul_external.py`; modify `tests/test_big_vul_external.py`.

**Interfaces:** `prepare(..., sample_modulus: int = 10, sample_remainder: int = 0) -> dict` preserves the current default and accepts `0 <= sample_remainder < sample_modulus`. The audit records the exact remainder and rule.

- [x] Add a fixture asserting remainder 0 and 1 produce disjoint normalized hashes, and an invalid remainder raises `ValueError`.
- [x] Run the focused test and confirm the new arguments fail before implementation.
- [x] Add the parameter and CLI option, then rerun the focused test.
- [x] Confirm the existing default remains reproducible from the retained sample hash.

### Task 2: Freeze project splits and training-only lexical features

**Files:** Create `scripts/prepare_big_vul_training.py`; create `tests/test_big_vul_training.py`.

**Interfaces:** `prepare_training(source: Path, output_dir: Path) -> dict` loads the audited remainder-0 JSONL, assigns whole projects with `assign_splits`, saves train/validation matrices and source IDs, and writes a manifest containing project lists for all three roles. It excludes remainder-0 test-project rows from model selection. `Vocabulary.fit` runs only on training tokens with `max_features=1024`, `min_df=5`.

- [x] Add a fixture with several projects and train-only marker tokens; assert project isolation and vocabulary exclusion.
- [x] Run the focused test and confirm the module is absent.
- [x] Implement the manifest and matrices, then rerun the focused test.
- [x] Run on `data/processed/big_vul_external.jsonl` and inspect project, sample, label, and vocabulary counts.

### Task 3: Train, select, and freeze a custom C model

**Files:** Create `scripts/train_big_vul_logistic.py`; create `tests/test_big_vul_logistic.py`.

**Interfaces:** `run(prepared_dir: Path, model_dir: Path, result_path: Path) -> dict` tries the predeclared unweighted L2 grid `(0.01, 0.1)` and train-derived positive weighting factors `(1, sqrt(negative/positive))`. It selects by validation AP, then validation F1 threshold, saves model and vocabulary bundle, and records training/validation metrics. It does not load a test matrix.

- [x] Add a small training fixture checking bundle hashes, source-ID order, and absence of test metrics.
- [x] Run the focused test and confirm the module is absent.
- [x] Add train-only sample weights to `fit_logistic` with a gradient/validation test, then implement the run script.
- [x] Train on the prepared C cohort; inspect losses, prevalence, AP, precision, recall, and flagged fraction.

### Task 4: Open and score the fresh project-held-out test once

**Files:** Create `scripts/evaluate_big_vul_holdout.py`; create `tests/test_big_vul_holdout.py`; modify `docs/phases.md` and add `docs/phase-5b-real-world-baseline.md`.

**Interfaces:** The evaluator requires the frozen bundle, split manifest, and newly generated remainder-1 JSONL. It accepts only C examples from manifest test projects, rejects project overlap and hash-cohort mismatch, applies the frozen vocabulary/model/threshold, and writes a one-time research result with overall and per-project metrics and errors.

- [x] Add a fixture showing a forbidden training project and wrong hash remainder are rejected.
- [x] Run the focused test and confirm the module is absent.
- [x] Implement the evaluator and run the focused test.
- [x] Generate remainder 1 from the original ZIP with the frozen audit rules; evaluate once and record its SHA-256, counts, metrics, and limitations.
- [x] Run the full suite, compile and diff checks, and review all new code and artifacts.
- [ ] Commit when Git metadata writes are available.
