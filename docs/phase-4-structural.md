# Phase 4: AST and custom MLP comparison

**Status:** Completed on 2026-10-13 for the audited Juliet `_01` subset. No representation or MLP result supports deployment.

```sh
PYTHONPATH=src python3 -m scripts.prepare_juliet_ast data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_juliet_mlp
```

The Clang 18 AST pass reparsed all **549 retained files** and found the **1,098 audited function bodies**. It counted 19 selected node kinds, including calls, branches, casts, array subscripts, allocation/deletion, and returns. Training-only means and standard deviations scaled `log1p` counts. The AST matrices preserve Phase 2 source-ID order. No parser or function-matching failure occurred in this retained subset; excluded Windows-specific and other parse failures remain excluded.

The one-hidden-layer MLP implements its own affine/ReLU forward pass, binary cross-entropy, backpropagation, minibatch updates, L2 regularization, early stopping, and save/load. Finite-difference gradient and reload tests pass. We tried hidden widths 8 and 16 and L2 values 0.001, 0.01, and 0.1 for lexical, AST, and combined features, using the same grouped train/validation split. Validation average precision selected the candidate.

| Representation | Best validation AP | Validation ROC-AUC | Validation F1 | Train AP |
|---|---:|---:|---:|---:|
| Lexical MLP | 0.576 | 0.580 | 0.703 | 0.664 |
| AST MLP | 0.530 | 0.539 | 0.672 | 0.802 |
| Combined MLP | 0.567 | 0.587 | 0.684 | 0.654 |
| Body-only logistic baseline | **0.630** | 0.573 | 0.690 | 0.636 |

The AST MLP has a large train/validation AP gap, suggesting poor transfer between held-out CWE groups. The selected lexical MLP (8 hidden units, L2 0.001) flagged 85% of validation functions. On the already-accessed Juliet test cohort, its exploratory AP was 0.571, precision 0.500, recall 0.884, F1 0.639, and false-positive rate 0.884. These figures are not a fresh confirmatory test.

**Decision:** Keep logistic regression as the strongest measured ranking baseline on validation. The MLP and AST features did not justify extra complexity. Do not deploy an ensemble or scanner from these results. Obtain an independent real-world C/C++ evaluation source, audit it, and revisit the model only if performance and alert burden support a useful review workflow.
