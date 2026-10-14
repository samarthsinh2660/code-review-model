# Phase 1 dataset decision implementation plan

**Goal:** Decide whether a defensible Juliet C/C++ subset can support the first custom-model experiment, using measured function labels, parse coverage, and leakage checks.

**Architecture:** Extend the existing Clang/manifest audit from a small feasibility sample to every single-file `_01` case. Keep all parse failures and uncertain labels visible. A candidate positive needs a manifest flaw line uniquely inside its definition; a candidate negative must be an explicitly named fixed-sink good counterpart in the same Juliet testcase and pass structural checks. This is an audited synthetic subset, not a real-world security ground truth.

**Tech stack:** Python standard library, Clang 18 AST JSON, unittest. No classifier is introduced in Phase 1.

## Constraints

- Verify the published Juliet archive SHA-256 before analysis.
- Never infer a negative from an absent manifest flaw line alone.
- Do not execute Juliet source code or include data archives in Git.
- Keep generated names, comments, and CWE paths out of later model features.
- Report exact counts and parser limitations; no full-suite claim from `_01` cases.
- Run the full test suite and review the staged diff before committing.

## Tasks

- [x] Add an all-`_01` selection mode and deterministic selection tests.
- [x] Qualify explicit manifest-annotated bad/fixed-sink pairs; test missing counterparts and ambiguous annotations. The audit provides line spans rather than byte spans.
- [x] Run the verified archive audit for all `_01` files, save the machine report outside Git, and manually review representative retained and rejected cases.
- [x] Count retained positive and fixed-sink negative candidates by language/CWE, exact code duplicates and conflicts, plus parse and rejection reasons.
- [x] Document the first-language/dataset decision and next split gate in `docs/dataset-audit.md` and `docs/phases.md`.
- [x] Run all tests, syntax checks, and `git diff --check`; review the Phase 1 changes. Commit remains unavailable because this session cannot write `.git/index.lock`.
- [ ] Commit Phase 1 when Git metadata becomes writable.
