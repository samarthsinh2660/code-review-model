# C data-quality audit: near clones and patch-label evidence

**Status:** Completed 2026-10-14 as a post-evaluation diagnostic. The existing C model, 5% alert threshold, and final-test measurements were not changed.

## Cross-split near-clone search

The audit used the 11,866 C training functions, 2,543 C validation functions, and both already examined fresh test cohorts: 2,583 C functions in remainder 1 and 2,562 in remainder 2. It hashed distinct consecutive **5-token shingles**, indexed each function by its 16 lowest hashes, required at least two shared index hashes to nominate a pair, and verified nominated pairs by exact shingle Jaccard similarity **≥ 0.80**. At least three distinct shingles were required. No posting list reached the cap of 5,000, so no signature was suppressed by that cap. This is a deterministic candidate search, not exhaustive proof that no near clone exists.

| Roles compared | Candidate pairs measured after size check | Confirmed pairs ≥0.80 | Functions too short for index |
|---|---:|---:|---:|
| Train → validation | 2,142 | 0 | 240 train; 18 validation |
| Train → remainder-1 test | 2,302 | 0 | 240 train; 15 test |
| Validation → remainder-1 test | 847 | **1** | 18 validation; 15 test |
| Train → remainder-2 test | 2,492 | 0 | 240 train; 18 test |
| Validation → remainder-2 test | 864 | **1** | 18 validation; 18 test |

The remainder-1 pair is validation `bigvul2:36664:46fd9cd83cad9026` from `cgminer` and test `bigvul2:36600:18be34d8a7144d4b` from `sgminer`, both labelled negative (Jaccard **0.9241**). The remainder-2 pair is validation `bigvul2:64719:c797c500e3f18ba6` from `oniguruma` and test `bigvul2:87888:de3252f0a5d91adc` from `Onigmo`, also both negative (Jaccard **0.9758**); both extracts start with `fetch_name_with_level`. These are cross-project code relationships that a simple normalized project-name check missed. Excluding each matched test function as a post-test sensitivity calculation changes remainder-1 AP from **0.2473** to **0.2481**, and remainder-2 AP from **0.28180** to **0.28195**. Neither match explains the model's measured ranking, and neither was used to change the model or policy.

The search can miss pairs whose bottom-hash sketches fail to nominate them, functions with fewer than three distinct shingles, semantic clones with different token sequences, and relationships through files or project history. A zero match count in the train comparisons is **not** proof of a leak-free split. The 0.80 cutoff also does not certify anything about pairs below that similarity.

## Original-patch review sample

The review selected **20 positive and 20 negative** train/validation source IDs by a fixed SHA-256 order, with at most two rows from each project per label. It did not select from test or use model scores. The script streamed the verified Big-Vul ZIP, checked row number, project, language, label, and normalized source hash, then stored a review packet under ignored `data/processed/`. Positives span 16 projects; negatives span 17.

| Sample observation | Positive `vul=1` | Negative `vul=0` |
|---|---:|---:|
| Function changed between before/after | 20/20 | 0/20 |
| CVE ID missing | 0/20 | 0/20 |
| CWE ID missing | 3/20 | 2/20 |
| File path missing | 5/20 | 3/20 |
| Parent commit ID missing | **15/20** | **17/20** |
| Commit message missing | 5/20 | 3/20 |

The changed/unchanged counts are expected from the existing preparation rule, which excluded positive rows with identical before/after code and negative rows with differing code. They are **not** an independent validation of vulnerability labels. A spot inspection of five positive diffs found examples of an added stream-type check (`bigvul2:177755:bfedef69824c4c56`), added path-length handling (`bigvul2:177797:6a8f4716c463f486`), a buffer-handling rewrite (`bigvul2:177865:a2771d3b5b0c0774`), and function refactoring (`bigvul2:178433:f8a6b8b626920948`, `bigvul2:178645:3ba46f65e6ed669c`). These are visible code changes, not independently verified vulnerability causes. Negative rows are unchanged functions associated with CVE fix records; unchanged does not mean proven safe. Missing parent IDs and file paths constrain patch lineage and location checks.

## Reproduce and decision

```sh
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.audit_big_vul_near_duplicates
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.audit_big_vul_near_duplicates --fresh-source data/processed/big_vul_fresh_test.jsonl --fresh-audit data/processed/big_vul_fresh_test_audit.json --output experiments/results/big_vul_c_near_duplicates_test1_v1.json
PYTHONPATH=src python3 -m scripts.audit_big_vul_patches
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

The full near-pair table, selected IDs, and review packet are ignored artifacts. **Decision:** keep the C scanner disabled. The current project split avoids the high-similarity train-to-test pairs found by this audit, but forked projects can cross roles and the label definition remains a proxy. The next model experiment must address the function-length shortcut, use a fresh untouched cohort or independent source, and report results against a length-only comparator. The previously examined remainder-1 and remainder-2 cohorts cannot become fresh final tests for that redesign.
