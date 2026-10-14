# Phase 3: custom logistic baseline

**Status:** Implemented and run on 2026-10-13. The credible result is a weak exploratory synthetic baseline. No model is approved for vulnerability scanning.

```sh
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_juliet_logistic --model-dir artifacts/models/juliet_01_logistic_v2 --result experiments/results/juliet_01_logistic_v2.json
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The NumPy classifier implements its own stable sigmoid, binary cross-entropy, analytical gradients, minibatch updates, L2 penalty, validation-loss checkpointing, and model persistence. A finite-difference test checks gradients, and a reload test checks exact scores. The metric implementation uses tie-aware average precision and ROC-AUC; a separate reference comparison matched scikit-learn on a tied-score fixture. The training script tries L2 values `0`, `0.001`, `0.01`, and `0.1` with one fixed seed and learning rate. Validation average precision chooses the model, then validation F1 chooses its threshold. The test split is never used in those choices.

## Leakage finding and corrected result

The first feature version let function declarations into the token bag. `static` appeared in **every negative and no positive** in all three splits, giving an invalid near-perfect model. Its selected test F1 was 0.951, but the coefficient on `static` dominated; this is template recognition, not vulnerability detection. We removed declaration tokens, versioned the body-only feature pipeline, and reran the experiment. The original test access means the corrected test score below is exploratory, not a fresh confirmatory estimate.

| Body-only v2 measure | Train | Validation | Juliet test (exploratory) |
|---|---:|---:|---:|
| Average precision | 0.636 | 0.630 | 0.671 |
| ROC-AUC | 0.735 | 0.573 | 0.592 |
| F1 at validation threshold 0.342 | 0.670 | 0.690 | 0.656 |
| Precision | 0.505 | 0.534 | 0.506 |
| Recall | 0.997 | 0.975 | 0.930 |
| False-positive rate | 0.979 | 0.852 | 0.907 |
| Flagged fraction | 0.988 | 0.914 | 0.919 |

The selected L2 value was `0.1`. On the exploratory test, the confusion counts were TP 80, FP 78, TN 8, FN 6. The threshold flags almost everything; its precision is near the subset's artificial 50% prevalence. An always-positive classifier would have F1 0.667 on this balanced test, so the selected threshold does not improve that simple decision baseline there. The ranking AP of 0.671 is above the 0.5 prevalence baseline, but with only 11 independent groups and no real-world evaluation it is not enough to deploy.

The two validation groups contain 122 and 40 functions. At the selected threshold, the larger group has a **100% false-positive rate**; the smaller has 40%. Exploratory test groups range from 14 to 80 functions and also show large differences. This group dependence and the tiny number of held-out groups limit any aggregate score.

**Decision:** Keep the logistic code and artifact as a research baseline. Do not enable scanner support from this model. Phase 4 may test structural features and a small custom MLP on validation data. A new independent source is needed before a final generalization claim or shipping a detector.
