# C length-controlled feature experiment

**Status:** Validation-stage experiment completed 2026-10-14. The normalized-feature candidate failed its validation gate, so no new final-test cohort was generated or scored. The C scanner remains disabled.

## Frozen setup

This experiment reused the existing Big-Vul C project split, the training-only 1,024-token vocabulary, and the 11,866 train / 2,543 validation functions. It did not read either prior final cohort. The new feature transform was `log1p(100 × token count / total body-token count)`. A second variant multiplied each feature by smoothed inverse document frequency fitted **only on training functions** and divided by its training-vocabulary mean. Neither variant exposes repository, path, CVE, or explicit function length as a feature, although vocabulary richness can still correlate with length.

A fixed custom-NumPy logistic grid compared plain normalized frequency and frequency × IDF, L2 values `0.01`/`0.1`, and positive weights `1`/`sqrt(train negatives / train positives)`. Validation AP chose the candidate; a validation-only 5% alert budget chose its threshold. The selected normalized candidate was **frequency × IDF, L2 0.1, positive weight 4.423**, with threshold **0.19344**. Its model, feature, split, and vocabulary hashes were frozen in an ignored research bundle. This bundle is **not** a deployable scanner model.

## Validation evidence

| Ranking on the same 2,543 validation functions | AP | ROC-AUC |
|---|---:|---:|
| Frozen count model from the prior experiment | **0.2298** | 0.7300 |
| Token length alone; no fitted classifier | 0.2055 | 0.7278 |
| Selected normalized-frequency model | **0.1306** | 0.6750 |

At its 5% validation policy, the normalized model flagged **4.88%** of functions, with precision **0.185**, recall **0.124**, 23 TP, 101 FP, 2,256 TN, and 163 FN. Its training AP was **0.144**. Normalization reduced the length shortcut but also discarded much of the measured ranking signal. None of the eight predefined candidates beat the frozen count model or length-only ranking on validation.

A paired 1,000-repeat **project bootstrap on validation** gave AP differences: normalized minus length **−0.0749** (95% percentile interval **−0.1355 to −0.0370**), normalized minus count **−0.0992** (**−0.1550 to −0.0630**), and count minus length **+0.0243** (**+0.0012 to +0.0418**). These intervals describe variation across the existing validation projects. Because the count model and normalized candidate were selected using this validation split, they are **not independent confirmatory intervals**.

Using five length bands cut at train-only body-token counts **20, 41, 78, and 157**, the pair-weighted within-band ROC-AUC values were **0.598** for length alone, **0.603** for the count model, and **0.550** for normalized frequency. The top band is broad, so this is a diagnostic rather than complete adjustment for function size. The count model's small AP lead over length does not establish robust vulnerability-specific learning.

## Stop decision and reproduction

The predefined validation gate required the new model to beat **both** the frozen count model and length-only ranking before using a fresh final cohort. It failed. **Hash remainder 3 was not generated or evaluated** and remains available for a future frozen candidate. The old count model is still a research baseline, not an approved scanner model.

```sh
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.prepare_big_vul_frequency
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_big_vul_frequency
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.compare_big_vul_validation_length
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

Generated feature arrays, full training histories, validation comparisons, and the unsuccessful candidate bundle remain ignored artifacts. Further C work should prioritize stronger label provenance and an **independent source** or genuinely later time period, plus features that can demonstrate incremental value beyond size on held-out projects. Repeatedly searching this same validation split for a higher AP would make its score less trustworthy.
