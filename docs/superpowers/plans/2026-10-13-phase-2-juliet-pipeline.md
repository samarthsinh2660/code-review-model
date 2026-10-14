# Phase 2 Juliet data and lexical-feature implementation plan

**Goal:** Turn the Phase 1 Juliet `_01` pairs into a reproducible, leakage-aware train/validation/test dataset and frozen lexical features.

**Architecture:** Read the verified archive plus the ignored Phase 1 pair assessment. Materialize labelled `FunctionRecord` objects with provenance. Tokenize function code while masking generated label-bearing identifiers and discarding comments; preserve operators, API identifiers, and numeric literals. Group all functions from the same CWE and any cross-CWE near-duplicate code before splitting. Fit vocabulary on training records only, then save split IDs and feature metadata outside Git.

**Tech stack:** Python 3.12 standard library, NumPy only for resulting arrays; unittest fixtures for leakage and split boundaries.

## Constraints

- Do not use source path, CWE, names, comments, label, or split ID as model features.
- Keep vulnerable/fixed pairs together, and never split exact or near-duplicate families.
- Do not infer labels outside the Phase 1 pair assessment.
- Use natural retained class prevalence for validation/test and report actual counts.
- Verify archive SHA-256, pair evidence, and retained record provenance.
- Run all tests and inspect generated manifests and source diff before any Phase 2 commit.

## Tasks

- [x] Implement a C/C++ lexical tokenizer with comment/string handling and generated-name masking; test realistic false-leakage cases.
- [x] Materialize paired `FunctionRecord`s from the fixed assessment, verifying source spans and hashes; test stale assessment rejection.
- [x] Build exact/near-duplicate links and CWE groups, then freeze a deterministic group-aware split; test pair/group isolation and class support.
- [x] Fit a capped vocabulary on train only, transform all splits, and save feature ordering/version; test validation-only token exclusion.
- [x] Run the complete preparation on Juliet, record counts, split sizes, class ratios, vocabulary size, near-duplicate clusters, and any exclusions.
- [x] Run tests, compile checks, data invariant checks, and diff review; document the results. Commit remains unavailable because this session cannot write `.git/index.lock`.
- [ ] Commit Phase 2 when Git metadata becomes writable.
