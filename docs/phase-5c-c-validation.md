# C baseline validation: alert budget, seed stability, and length shortcut

**Status:** Completed 2026-10-14 as a research diagnostic. The frozen C model is still not enabled for repository scanning.

## Review-budget policy and fresh evaluation

The existing `bigvul-c-logistic-v1` weights and train-only vocabulary were kept unchanged. On the original 2,543-function validation split, a new policy chose the threshold that maximized recall while flagging at most **5%** of validation functions. Tied scores were kept together, and equal-recall policies favored fewer false alerts. The frozen threshold was **0.18024868096417201**. It produced 35 TP, 91 FP, 2,266 TN, and 151 FN on validation: precision **0.278**, recall **0.188**, and flagged fraction **4.95%**. The model, manifest, feature array, bundle, and policy hashes were recorded before the new final cohort was evaluated.

A fresh deterministic hash remainder **2** was generated from the same verified Big-Vul ZIP. Its JSONL SHA-256 is `5d4e62d91f1549995c993b249796d7d4d34c6eace7404730f7cba669263f7e45`. It is disjoint in normalized token hashes from the earlier remainder-0 training/validation cohort and remainder-1 final test. The evaluation used 2,562 C functions from 91 reserved test-role projects; 161 carried positive proxy labels. No remainder-2 labels or scores entered threshold selection.

| Measure | Validation | Fresh remainder-2 test |
|---|---:|---:|
| Average precision | 0.230 | 0.282 |
| ROC-AUC | 0.730 | 0.767 |
| Precision at frozen budget threshold | 0.278 | **0.326** |
| Recall at frozen budget threshold | 0.188 | **0.280** |
| Flagged fraction | 4.95% | **5.39%** |
| Proxy-label prevalence | 7.31% | 6.28% |
| False-positive rate | 3.86% | 3.87% |

The fresh-test confusion counts are **TP 45, FP 93, TN 2,308, FN 116**. This is approximately 1.02 labelled negatives flagged per sampled project; it is not a full-repository alert rate. The budget constrains validation, so the test flagged fraction can exceed 5%. This policy trades recall for review volume. It must not be described as a more accurate model than the earlier F1 policy: the model is unchanged and the two thresholds were measured on different fresh cohorts.

Representative dataset-labelled errors include false positives `bigvul2:69270:dd5c1451191502dc` (firejail, score 0.694) and `bigvul2:96708:5214f79f771238ec` (ImageMagick6, 0.649), and false negatives `bigvul2:178208:0fe185050a6cd210` (php, 0.029) and `bigvul2:180466:129fb5b943f6840e` (iperf, 0.030). These are row references, not independently adjudicated security cases.

## Stability and function-size diagnostic

The chosen configuration (unweighted, L2 0.1) was refitted at seeds **11, 42, 73** using only the existing train/validation arrays. Validation AP was **0.22984, 0.22977, 0.22787**. Each run selected its own validation-only 5% budget threshold; resulting validation precision ranged **0.276–0.291** and recall **0.188–0.199**. This shows little sensitivity to minibatch order for these three seeds, but says nothing about different project splits or independent data sources. Two runs stopped early at epochs 54 and 46; seed 42 reached the 80-epoch cap.

Function length is a major confounder. Median body-token counts for labelled negative versus positive functions were **90 versus 281** in validation and **90 versus 353** in the fresh test. Ranking functions by token count alone, with no learned parameters, gave validation AP **0.205** and fresh-test AP **0.268**, close to the trained model's **0.230** and **0.282**. The fresh-test length calculation was a post-test diagnostic and did not alter the frozen policy. The small gap does not establish that the model learned vulnerability semantics beyond function size. A future experiment must compare against a length-controlled baseline on a new untouched source or split.

A source spot check covered the first five retained positive and five retained negative C examples in the training cohort. Positive functions ranged from 10 to 1,443 lines in that small check; negatives ranged from 8 to 156. The snippets alone cannot confirm exploitability or establish that a `vul=0` function is safe. The export's labels reflect changed-line localization around fixes. The original archive still has 169,571 rows without `parentID`, 19,065 without `file_name`, and source rights remain unverified. A normalized project-name check found `ImageMagick` and `ImageMagick6` as a possible alias pair, both in the reserved test role; it found no cross-role pair under lowercasing and removal of digits/punctuation. This is not a full project-identity or near-duplicate audit.

## Reproduce and decision

```sh
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.fit_big_vul_alert_policy
PYTHONPATH=src python3 -m scripts.prepare_big_vul_external data/raw/big-vul/MSR_data_cleaned.zip --sample-remainder 2 --output data/processed/big_vul_budget_test.jsonl --report data/processed/big_vul_budget_test_audit.json
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.evaluate_big_vul_budget
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.study_big_vul_c_stability
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.audit_big_vul_length
```

Generated policies, full predictions, and result JSON files remain ignored artifacts. **Decision:** keep C as a research baseline and the scanner disabled. The next C study needs a formal near-duplicate audit, deeper manual label review against patches, a length-controlled new experiment, and an independent or later-period evaluation. The existing remainder-1 and remainder-2 tests have now been examined and cannot be used as fresh final tests for a redesigned model.
