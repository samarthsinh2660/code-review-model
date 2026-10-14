# Phase 5: generalization and ensemble gate

**Status:** Big-Vul was supplied and evaluated on 2026-10-14. The frozen Juliet model transfers poorly. Phase 5's deployable-model exit gate fails, and scanner support remains disabled.

The same-group validation comparison used the saved body-only logistic and lexical MLP models. Equal-weight soft voting produced validation AP **0.630**, essentially the logistic AP **0.630** (MLP **0.576**). Validation F1 was **0.690** for the vote and logistic model, with about **91%** of functions flagged. The vote offers no meaningful improvement and is not promoted. Stacking would add complexity without a supported benefit and is not attempted.

The Juliet test cohort was used during the Phase 3 leakage investigation, so additional analysis of that cohort would be exploratory. Both component models have poor validation alert burden. The selected logistic model is a research artifact, and no bundle is approved for deployment.

## Big-Vul acquisition and audit

The [author-described cleaned function CSV](https://github.com/kchabra/Big-Vul/blob/master/README.md) was supplied as `data/raw/big-vul/MSR_data_cleaned.zip` (SHA-256 `be96d4133fe4e75a2c5dd3f36eae22939612083cd1f7bcaa3bb5ce782316e0f2`). ZIP integrity passed. It contains one `MSR_data_cleaned.csv` member, 10,785,616,314 bytes uncompressed. The source has **188,636** rows across **310** project names: 177,736 `vul=0` and 10,900 `vul=1`; 185,997 rows are marked `C`, 2,636 `CPP`, and 3 `C++`. The source's `vul` label means a changed line was localized inside the function before a vulnerability fix. It is an imperfect proxy for true function vulnerability. An unchanged function in the same commit may still contain another flaw.

The streaming adapter uses `func_before` as code and `vul` as the label. It requires a project, fix `commit_id`, both before/after functions, and a body brace; it excludes 20 positive rows whose before/after code is identical and 3 rows lacking a body. Exact normalized body-token duplicates receive one representative; conflicting labels remove **all** affected rows. There were 1,386 conflicting body hashes covering **9,408** rows and 6,643 additional same-label copies. A deterministic 1-in-10 code-hash sample of the remaining unique functions produced **17,189** rows from **274** projects: 949 positive and 16,240 negative (5.52% prevalence). The sample contains 16,951 C and 238 C++ functions. A body-token hash deliberately ignores declarations and generated Juliet cues, so some real functions with the same body collapse; that conservative choice avoids duplicate-driven score inflation.

The source is not fully traceable to each function's original revision: `parentID` is blank in 169,571 rows and `file_name` in 19,065 rows. The adapter preserves `project` and fix `commit_id`, and records these missing fields rather than inventing them. The repository's MIT license is visible, but the rights for embedded code from upstream projects were not verified. The converted rows mark that limitation explicitly. No raw source or generated evaluation file is committed.

Reproduce the preparation and frozen evaluation:

```sh
PYTHONPATH=src python3 -m scripts.prepare_big_vul_external data/raw/big-vul/MSR_data_cleaned.zip
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.evaluate_external data/processed/big_vul_external.jsonl data/processed/juliet_01_pair_assessment.json --result experiments/results/big_vul_external_logistic.json
```

The detailed ignored outputs are `data/processed/big_vul_audit.json` and `experiments/results/big_vul_external_logistic.json`. The sample JSONL SHA-256 is `5adcd01488b4d0cd25dc558d6bcb445f4430d5df28d4070adcb387f35832e056`. The evaluator verified the frozen manifest/model hashes and found zero exact normalized overlaps with the 1,098 retained Juliet functions. Every retained sample tokenized; this is lexical coverage, not full C/C++ parser validation. Near-duplicate and patch-family rates beyond exact normalized copies were not measured.

## Frozen external result

| Measure | Big-Vul sample |
|---|---:|
| Vulnerable prevalence | 5.52% |
| Average precision | 0.0364 |
| ROC-AUC | 0.3040 |
| Precision at frozen threshold 0.3424 | 0.0433 |
| Recall | 0.7113 |
| F1 | 0.0816 |
| False-positive rate | 0.9183 |
| Flagged fraction | 0.9069 |
| Confusion counts | TP 675, FP 14,913, TN 1,327, FN 274 |

Average precision is **below the 0.0552 prevalence baseline**, and ranking ROC-AUC is below 0.5. The model flags about 54 labelled negatives per sampled project on average; that number is **not** a measured finding rate for a full repository scan. C-only AP was 0.0366 on 16,951 functions; the tiny C++ subset had AP 0.0286 on 238 functions and 10 positives. Large sampled projects also had many false flags: Chrome 6,203 and Linux 3,988. Example false positives include `bigvul2:64051:608be8ef03fe9ed6` (FFmpeg, score 0.5170) and `bigvul2:16578:fb34034bcc8aeba2` (htcondor, 0.5161). Example false negatives include `bigvul2:178488:43d11606e5cb00ae` (php, 0.1099) and `bigvul2:181150:ca16c2f30043dcb6` (ImageMagick, 0.1375). These identifiers trace to source CSV row numbers and the ignored prediction file; they are examples under Big-Vul's proxy labels, not individually confirmed security judgments.

**Decision:** The Juliet-trained logistic model is unsuitable for scanning real repositories. The MLP was weaker on Juliet validation, so no ensemble is promoted. The [separate Big-Vul C experiment](phase-5b-real-world-baseline.md) uses a new project split and a fresh code-hash cohort; it remains a research baseline. A genuinely separate source or later-period test is still needed before reconsidering scanner support.

## Next evidence for a new model

1. Inspect positive and negative examples manually, including functions changed by security patches and unchanged functions near them; verify upstream source rights for any redistributed artifacts.
2. Create repository/commit-family groups and a new train/validation/test split from a real-world source. Keep all function versions from one fix together and quantify near duplicates.
3. Train and select using train/validation only, then evaluate once on a fresh, separately held-out source or later time period. Measure parser coverage and realistic scan alert burden.
4. Enable scanner support only if the fresh result makes its review workload useful and limitations can be stated honestly.

Neither JS/TS nor Go has a local audited function-level dataset yet, so their model phases cannot be presented as complete.

## Frozen external evaluation input

After independently auditing the selected export's source, license, label meaning, and provenance, convert retained **function-level** examples to one JSON object per line with these required fields:

```json
{"source_id":"stable-example-id","repository":"owner/project","commit":"fix-or-parent-commit","source_code":"int check() { return 0; }","label":0,"language":"c","dataset_version":"source-release-id","license_id":"verified-license-id"}
```

Each label must be explicit `0` or `1`. A missing label is never a negative. The adapter rejects empty or duplicate IDs, duplicate normalized functions, malformed rows, missing provenance, and languages outside C/C++. It is deliberately source-neutral: the source-specific audit must justify how a `func_before`/`func_after` or similar field became that binary label. `source_code` must be one complete function definition, with its body present. The evaluator checks exact normalized overlap against every retained Juliet function; near-duplicate and patch-family checks remain part of the dataset audit.

Run the **unchanged** research model and threshold with:

```sh
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.evaluate_external data/processed/external_audited.jsonl data/processed/juliet_01_pair_assessment.json
```

For another audited source, the result is written to ignored `experiments/results/external_logistic.json`. It records input, Juliet manifest, and model hashes, aggregate, per-language, and per-repository metrics, false findings per repository, scores, and source IDs. This command never fits a tokenizer/model or selects a threshold. The Big-Vul run above used this same command and failed the deployable-model gate. Raw scores are not calibrated probabilities, and the synthetic Juliet threshold transferred poorly to Big-Vul's class prevalence.
