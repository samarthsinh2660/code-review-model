# Big-Vul C baseline with unseen-project evaluation

**Status:** Research experiment completed 2026-10-14. The model ranks Big-Vul proxy labels better than prevalence, but its alert burden and label/provenance limits do not justify enabling a scanner.

## Frozen design

The [Big-Vul source audit](phase-5-generalization.md) supplied a deduplicated 1-in-10 hash cohort (remainder 0). Only its C records were used here. Whole projects were assigned deterministically by sample count to train, validation, or a reserved test role. The remainder-0 functions of test-role projects were not used in model fitting or selection. A separate hash cohort (remainder 1) was generated from the same verified ZIP **after** the model and threshold were frozen; only its C functions from reserved test projects formed the final test. Project roles are disjoint, and exact normalized body hashes cannot cross hash remainders. Near duplicates across projects have not been quantified.

| Role | Functions | Proxy positives | Projects used | Purpose |
|---|---:|---:|---:|---|
| Train, remainder 0 | 11,866 | 577 (4.86%) | 79 | Vocabulary and model fitting |
| Validation, remainder 0 | 2,543 | 186 (7.31%) | 94 | Model and threshold selection |
| Reserved project role, remainder 0 | 2,542 | 176 (6.92%) | 95 | Split design only; no model features or scores used |
| Fresh final test, remainder 1 | 2,583 | 158 (6.12%) | 91 | One final measurement |

The actual fresh test used 91 of the 95 reserved projects because four had no retained C function in hash remainder 1. The sample-1 JSONL SHA-256 is `4e522d3d0db988b7891165ad2a46ff0b446c314cb4eb6d9b3fcd2b0ae7c342a4`; its audit repeats the original ZIP SHA-256 `be96d4133fe4e75a2c5dd3f36eae22939612083cd1f7bcaa3bb5ce782316e0f2`. The reserved projects had appeared in the earlier Juliet-model transfer audit, so this is fresh **code for this model**, not project identities untouched by the overall research process. Project assignment was deterministic and did not use that earlier model's scores.

The body-only lexical tokenizer and a 1,024-token vocabulary were fitted on train only (`min_df=5`). Counts use `log1p`. The custom NumPy logistic regression compared L2 `0.01`/`0.1` and unweighted versus a positive weight of `sqrt(train negatives / train positives)` = 4.4232. The positive weight comes only from training. Validation AP chose the unweighted L2 `0.1` model; validation F1 chose threshold `0.10775`. Training ran for the predefined maximum 80 epochs. This is one seed, not a convergence or stability study.

## Measured results at the frozen threshold

| Measure | Train | Validation | Fresh unseen-project test |
|---|---:|---:|---:|
| Average precision | 0.1239 | 0.2298 | **0.2473** |
| ROC-AUC | 0.6913 | 0.7300 | 0.7806 |
| Precision | 0.1554 | 0.2037 | **0.1986** |
| Recall | 0.2340 | 0.4731 | **0.5316** |
| F1 | 0.1867 | 0.2848 | 0.2892 |
| False-positive rate | 0.0650 | 0.1459 | 0.1398 |
| Flagged fraction | 0.0732 | 0.1699 | 0.1638 |
| Label prevalence | 0.0486 | 0.0731 | 0.0612 |

Fresh-test confusion counts were **TP 84, FP 339, TN 2,086, FN 74**. AP 0.247 exceeds the 0.061 prevalence baseline. About one in five flags matches a Big-Vul positive label, but about **16% of all functions are flagged**, averaging 3.73 labelled negatives per sampled test project. That is not a full-repository scan finding rate. Project outcomes vary: qemu had 2 TP, 24 FP, and 9 FN on 326 functions; ImageMagick had 26 TP, 61 FP, and 8 FN on 210; ImageMagick6 had 0 TP, 23 FP, and 1 FN on 42. Some projects have no positive labels, making per-project AP undefined or uninformative.

A post-test feature-collision check found **41 of 2,583** test functions with the same 1,024-token vector as at least one training function (2 positive, 39 negative). Removing those 41 for a sensitivity calculation left AP **0.250** on 2,542 functions, close to the primary AP 0.247. This check does not rule out near-duplicate source code, which still needs a dedicated audit. It was not used to change the model or threshold.

Example false positives under the dataset label are `bigvul2:5231:01a8a1d2bfb1b4c1` (php, score 0.827) and `bigvul2:88898:e85a0a89a491ca8d` (ImageMagick6, 0.754). Example false negatives are `bigvul2:177972:c038a947d1fe1b7b` (qemu, 0.027) and `bigvul2:180482:a40bb840a7649e99` (iperf, 0.028). These are source-row references, not manually confirmed security judgments.

## Reproduce and limits

```sh
PYTHONPATH=src python3 -m scripts.prepare_big_vul_training
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_big_vul_logistic
PYTHONPATH=src python3 -m scripts.prepare_big_vul_external data/raw/big-vul/MSR_data_cleaned.zip --sample-remainder 1 --output data/processed/big_vul_fresh_test.jsonl --report data/processed/big_vul_fresh_test_audit.json
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.evaluate_big_vul_holdout
```

The training manifest, matrices, bundles, full candidate histories, audits, and prediction tables are ignored generated artifacts. The scripts verify their hashes and reject mismatched sample remainders or overlapping project roles. This test is held out by **project within Big-Vul**; it is not a separate source or later-period evaluation. Big-Vul `vul` labels reflect changed-line localization around vulnerability fixes, and many rows lack `parentID` or file paths. Upstream source-code rights have not been verified. Lexical tokenization coverage was checked, but full Clang parser coverage and near-duplicate rates were not measured for this real-world cohort. The score is not calibrated as a vulnerability probability.

**Decision:** Keep this as a C research baseline. Do not enable the scanner yet. The next study should manually review label quality, quantify near-duplicate leakage and project aliasing, reduce alert burden through validation-only policy selection, test stability across seeds, and use a fresh external or later-period source before claiming deployable performance. The tiny Big-Vul C++ subset provides no C++ model support; JS/TS and Go still need audited datasets.
