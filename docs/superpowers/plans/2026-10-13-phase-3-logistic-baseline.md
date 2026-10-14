# Phase 3 custom logistic baseline implementation plan

**Goal:** Train and evaluate our own transparent NumPy logistic regression on the frozen Juliet lexical features.

**Architecture:** A small model module implements stable logits, weighted/unweighted binary cross-entropy, analytical gradients, minibatch updates, L2 regularization, and save/load. A separate evaluation module computes ranking and threshold metrics. The run script compares a small fixed hyperparameter grid using validation only, freezes one model and threshold, then opens the test arrays once for the final report.

**Tech stack:** Python 3.12, NumPy, unittest. No packaged classifier is the core model.

## Constraints

- Use the Phase 2 manifest and arrays without resplitting or fitting vocabulary again.
- Start with an unweighted baseline; any class weights come from training labels only.
- Validate analytical gradients numerically on a tiny example.
- Choose regularization, epoch, and threshold using validation data only.
- Report precision, recall, F1, AP, ROC-AUC, confusion counts, prevalence, and false-positive/negative rates with explicit zero-denominator conventions.
- Keep artifacts outside Git; commit only code, plans, and small result reports after tests and review, if Git access permits.

## Tasks

- [x] Implement stable NumPy logistic loss, gradients, minibatch training, history, prediction, and persistence; test gradients and reload equality.
- [x] Implement metrics and validation threshold policy; test hand-calculated cases against independent expectations.
- [x] Write a reproducible run script that checks Phase 2 feature/version compatibility and searches a small validation-only grid.
- [x] Train the unweighted baseline, choose a threshold, and evaluate the initial frozen test once. A discovered declaration shortcut invalidated that first result; the corrected run is explicitly exploratory because the test cohort was already accessed.
- [x] Record split metrics, model/threshold choice, learning curves, error examples, and limitations in a Phase 3 report.
- [x] Run all tests, compile checks, integration checks, and diff review. Commit remains unavailable because this session cannot write `.git/index.lock`.
- [ ] Commit Phase 3 when Git metadata becomes writable.
