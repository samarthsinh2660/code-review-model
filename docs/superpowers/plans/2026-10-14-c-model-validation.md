# C Model Validation Implementation Plan

**Goal:** Measure the C baseline's uncertainty and review workload without using the previously examined test cohort to select a model or threshold.

**Architecture:** Keep the trained Big-Vul C model and vocabulary frozen. Build a validation-only alert-budget policy, freeze its threshold and artifact hashes, then evaluate that policy on a newly sampled hash cohort from reserved projects. Run a separate training-seed sensitivity study on train/validation only. Report limitations and leave scanner support gated by label quality and independent-source evidence.

**Tech Stack:** Python 3.12, NumPy, `unittest`, local Big-Vul ZIP and existing project artifacts.

## Global constraints

- No final-test data in model or threshold selection.
- Preserve project roles, source hashes, and natural class prevalence.
- Keep large data and model artifacts outside Git; commit scripts, tests, and report only after all tests pass.
- Scores are review leads, not calibrated vulnerability probabilities.

## Task 1: Validation-only review-budget policy

- [x] Add tests for exact budget enforcement, deterministic tie handling, and invalid inputs.
- [x] Implement a threshold selector that maximizes validation recall subject to a fixed upper bound on flagged fraction; choose the highest threshold among equivalent outcomes.
- [x] Fit a 5% alert-budget threshold from the frozen model's validation scores and save a policy manifest with model, training-manifest, and feature-array hashes.
- [x] Run targeted and full tests.

## Task 2: Fresh held-out policy evaluation

- [x] Generate hash remainder 2 from the verified source ZIP; verify disjointness from remainders 0 and 1.
- [x] Add tests that reject wrong sample remainder, changed policy/model, and project-role overlap.
- [x] Evaluate the frozen policy on C functions from reserved test projects in remainder 2, reporting AP, confusion counts, precision, recall, alert fraction, and per-project outcomes.
- [x] Run targeted and full tests.

## Task 3: Training stability and research decision

- [x] Repeat the selected model's fit at fixed seeds using only train and validation arrays; report validation AP and alert-policy metrics without selecting the best seed.
- [x] Review representative positive and negative source examples and document what their labels can and cannot establish.
- [x] Update the phase report and roadmap with measured evidence, limits, and scanner decision.
- [ ] Run syntax, tests, diff checks, and code review; commit the completed phase.
