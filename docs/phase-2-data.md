# Phase 2: frozen Juliet `_01` data and lexical features

**Status:** Prepared on 2026-10-13 from the verified Juliet C/C++ 1.3 archive and Phase 1's audited direct-pair assessment. The generated arrays and manifests live under ignored `data/processed/juliet_01/`; rerun the commands below to recreate them.

```sh
PYTHONPATH=src python3 -m scripts.prepare_juliet_01 data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip data/processed/juliet_01_pair_assessment.json
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

## Provenance and selection

The preparation command verifies the official archive SHA-256, checks every selected function's source-byte SHA-256 against the Phase 1 assessment, and materializes exactly 549 `bad`/fixed-sink pairs (1,098 function records). Each record keeps its source file, inclusive line span, label, language, Juliet version, CC0 rights marker, and a stable source ID. The assessment JSON hash is stored in the generated manifest.

This is a **paired synthetic subset** with 50% positives by construction. Its validation/test prevalence reflects this subset, **not** vulnerability prevalence in real repositories. Precision from these splits must not be presented as expected precision on a production scan.

## Leakage controls and split

The C/C++ tokenizer uses **function bodies only**, removes comments, and replaces generated CWE and `bad`/`good` identifiers with a neutral token. String/character contents are masked; operators, API identifiers, preprocessor tokens, and numeric constants remain. A vocabulary scan found no tokens containing `bad`, `good`, `fix`, `flaw`, or `cwe` after this rule. This lexical filter is still heuristic; future feature experiments must repeat a leakage audit. Body-only features exclude declaration-level vulnerabilities, which are outside the retained direct-pair subset.

All pairs from one CWE begin in the same group. Function token 5-gram Jaccard similarity at or above 0.8 links groups transitively before splitting. The data contains 57 extra functions with identical normalized token sequences and no conflicting normalized labels. There are 652 near-duplicate function pairs across provisional CWE groups, forming 31 group links; 26 provisional CWE groups become 11 final groups. The threshold is a conservative operational rule, not a proof that lower-similarity code is independent.

| Split | Groups | Functions | Positives | Negatives | Share |
|---|---:|---:|---:|---:|---:|
| Train | 5 | 764 | 382 | 382 | 69.6% |
| Validation | 2 | 162 | 81 | 81 | 14.8% |
| Test | 4 | 172 | 86 | 86 | 15.7% |

Only the training functions fit the vocabulary (190 tokens, minimum document frequency 2). All splits use frozen `log1p` token counts in the same column order. `manifest.json` records source IDs, labels, groups, split assignments, vocabulary, feature version, archive hash, and assessment hash; `features.npz` contains the matrices and labels. The test set must remain unused for model selection or threshold tuning.

**Correction record:** An initial version included function declarations. Its `static` token perfectly separated all retained positives and negatives, so its high logistic score was invalid as a vulnerability signal. We changed the feature definition to body-only, versioned it as `cpp-body-lexical-v2`, reran grouping and preparation, and kept the original result as an invalidated experiment. The test split was accessed in that diagnostic run; subsequent scores on this same Juliet `_01` cohort are exploratory and cannot be described as a fresh untouched final evaluation. A new independent evaluation source is needed for a confirmatory claim.

## Remaining limits

- Only 11 independent split groups remain, and validation contains two. Estimates can vary strongly with which weakness families are held out. Report per-group errors and uncertainty.
- The selected functions are deliberately balanced and synthetic. A separate real-world dataset is needed to measure transfer and realistic alert burden.
- The first lexical model will score C/C++ functions. It cannot establish exact vulnerable lines, CWE labels, or support for JS/TS and Go.
