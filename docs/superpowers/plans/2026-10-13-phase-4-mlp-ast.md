# Phase 4 custom MLP and AST features implementation plan

**Goal:** Compare a small custom MLP and Clang AST-derived features against the Phase 3 body-only logistic baseline on the same grouped split.

**Architecture:** Implement one-hidden-layer NumPy MLP with explicit forward and backward passes, validation-loss early stopping, and persistence. Reparse only the 549 retained Juliet files with Clang, locate the audited function definitions, and count selected AST node kinds within each body. Fit any AST scaling on training records only. Evaluate lexical, AST, and combined features using the frozen source IDs and validation data; treat the reused synthetic test as exploratory.

**Tech stack:** Python 3.12, NumPy, local Clang 18, unittest.

## Constraints

- Do not call a packaged classifier for the core model.
- Keep source ID order and split assignments identical to Phase 2.
- Exclude function names, paths, comments, and raw labels from AST features.
- Audit AST parser failures; never turn them into negative records or zero vectors silently.
- Check MLP analytical gradients numerically and artifact reload equality.
- Choose representation, width, regularization, and threshold on validation only. Test output is exploratory because this Juliet cohort was previously opened.
- Run all tests and review every changed file before a phase commit, if Git access permits.

## Tasks

- [x] Implement the NumPy MLP and focused gradient/persistence tests.
- [x] Implement source-local AST body feature counts and fixture tests.
- [x] Build an AST matrix for every retained record, with parser coverage and source ID checks.
- [x] Run lexical, AST, and combined validation comparisons with a small fixed MLP grid.
- [x] Record results, error analysis, and any parser/overfit limitations; decide whether an ensemble is justified.
- [x] Run tests, compile checks, and data integrity checks. Commit remains unavailable because this session cannot write `.git/index.lock`.
- [ ] Commit Phase 4 when Git metadata becomes writable.
