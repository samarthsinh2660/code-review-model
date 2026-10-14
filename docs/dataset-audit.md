# First dataset audit: C/C++ candidates

**Status:** The official Juliet archive is verified, and a conservative `_01` paired subset has been audited, prepared, and used for exploratory training. Big-Vul supplied an independent real-world transfer check; the current model failed that check and is not approved for scanning. The full Juliet suite remains unaudited. The detailed Juliet counts and label rules below apply only to the retained `_01` subset.

## Candidate A: NIST Juliet C/C++ 1.3

| Field | Current evidence |
|---|---|
| Official source | [SARD suite 112](https://samate.nist.gov/SARD/test-suites/112) |
| Release | Juliet C/C++ 1.3, submitted 2017-10-01 |
| Archive | [Official ZIP](https://samate.nist.gov/SARD/downloads/test-suites/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip); NIST page lists 146 MB |
| Published SHA-256 | `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb` |
| Published scope | 64,099 test cases across 118 CWEs on the NIST page; this is **not** the retained function count |
| Rights | NIST page describes US public-domain status and CC0 1.0 for any claimed foreign rights; archive contents still need inspection |
| Local status | Present at `data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip`; SHA-256 matches NIST and every ZIP member was read without a CRC error |

### Reproducible archive measurements

Run from the project root:

```sh
python3 -m scripts.audit_juliet_archive data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
```

| Measurement | Value | Meaning |
|---|---:|---|
| ZIP file entries | 106,093 | Files, excluding directory entries |
| Uncompressed bytes | 463,729,469 | Sum of member sizes; no extraction required |
| C testcase source files | 54,484 | `.c` members under `C/testcases/` |
| C++ testcase source files | 46,747 | `.cpp` members under `C/testcases/` |
| Total C/C++ testcase source files | 101,231 | Multiple files can belong to one test case |
| CWE directories containing source | 118 | Directory names, not a validated label distribution |
| Byte-identical duplicate source files | 79 | Extra files sharing a complete source-file SHA-256; **not** function or near-duplicate counts |
| Source files containing `POTENTIAL FLAW` | 77,022 | Marker occurrence, not positive labels |
| Source files containing `FIX:` | 72,959 | Marker occurrence, not negative labels; a file may have both markers |
| Unsafe ZIP member names | 0 | No absolute, parent-traversal, or backslash member names found by the script |

### Manifest consistency measurements

The archive contains `C/manifest.xml`, which assigns flaw line numbers to testcase files. The same audit script checks each referenced filename and compares each flaw line with the matching source file's actual line count.

| Measurement | Value | Meaning |
|---|---:|---|
| Manifest testcase nodes | 64,123 | 24 more than the 64,099 cases on the NIST suite page |
| Manifest file references | 105,234 | Files named inside testcase nodes |
| Flaw-line annotations | 65,263 | A testcase can have more than one flaw line |
| Missing referenced files | 51 | All belong to the 24 manifest cases with no flaw annotations; these cases are absent from this ZIP |
| Ambiguous filename references | 0 | Every present referenced testcase filename resolves uniquely |
| Invalid flaw-line values | 0 | Every `line` attribute parsed as an integer |
| Flaw lines outside file bounds | 0 | Every resolved flaw line lies within its file's line count |

This supports using **manifest flaw lines** as candidate positive locations. The 64,123 minus 24 absent cases equals the published 64,099 cases; this arithmetic is an inference from the archive and NIST page, not a claim that all cases yield a valid function sample. A function can contain a manifest flaw line only after a parser maps source spans correctly. Functions without a flaw line are **not automatically verified negatives**; some are wrappers, helpers, or other parts of the same vulnerable testcase.

The archive tool is [scripts/audit_juliet_archive.py](../scripts/audit_juliet_archive.py). It streams each member and does not execute or extract test code. Counts are reproducible from this exact release hash.

### Phase 1 first-dataset decision: constrained `_01` pairs

We audited **all 1,666 `_01` C/C++ source files** in the verified archive using [the function-span audit](../scripts/audit_juliet_functions.py). This is a subset of Juliet's 101,231 testcase source files, selected to avoid the additional cross-file call-chain problem during the first experiment. It is not a full Juliet parser-coverage result.

```sh
python3 -m scripts.audit_juliet_functions data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --all-01 --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb > data/processed/juliet_01_function_audit.json
python3 -m scripts.assess_juliet_01 data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip data/processed/juliet_01_function_audit.json > data/processed/juliet_01_pair_assessment.json
```

| Measurement | Value | Meaning |
|---|---:|---|
| `_01` source files | 1,666 | 1,258 C and 408 C++ |
| Parsed | 1,423 | 1,059 C and 364 C++ |
| Parse failures | 243 | 199 C and 44 C++; at least 205 show unavailable Windows headers/types in their first error |
| Function definitions in parsed files | 4,900 | Not all labelled or suitable for training |
| Manifest flaw lines in parsed files | 1,464 | All map uniquely; 1,459 in bodies, 5 on signatures |
| Retained direct pairs | 549 | One manifest-annotated `bad` definition and one `goodB2G` fixed-sink definition with a `FIX:` marker in the same file |
| Retained candidate functions | 1,098 | Exactly 549 positives and 549 negatives; 397 C pairs, 152 C++ pairs across 26 CWEs |
| Rejected files by rule | 243 parse failures; 835 missing/ambiguous fixed-sink counterpart; 39 unclear positive role | These are counts for `_01` only; no missing label was turned into safe code |
| Exact duplicate retained function bodies | 14 extra copies | Raw byte equality; near duplicates remain to be measured |
| Conflicting labels on byte-identical code | 0 | Within the retained candidate set |

We manually checked retained CWE121 array bounds, CWE190 overflow, CWE401 memory leak, and CWE762 mismatched allocation/free pairs. In each, the manifest points at the bad definition and the fixed-sink counterpart contains the local guard or correct operation. This spot check supports the **candidate** rule, but cannot establish semantic correctness for all 549 pairs. The assessment [script](../scripts/assess_juliet_01.py) records each pair's source lines and byte hash; its generated JSON is ignored by Git.

**Decision:** Use this constrained Juliet `_01` pair subset for the first C/C++ *synthetic* model experiment, subject to Phase 2 duplicate-family grouping and source normalization. Group whole pairs and, conservatively, all pairs from the same CWE together for the first split; then check for exact/near duplicates crossing those groups. With 26 represented CWEs, a grouped train/validation/test split is feasible but its actual size and class coverage must be measured before training. CWE-held-out results test transfer to different weakness families, not familiar-CWE generalization. A separate real-world source is still required before any claim about production-code detection. Generated names/comments must be removed from features without removing security-relevant operators, APIs, constants, or control flow. If Phase 2 finds that groups collapse or labels do not survive closer inspection, reopen this choice before training.

### Small parser feasibility check

For a preliminary check, we extracted 20 deterministic `_01` source files into `/tmp` (10 C and 10 C++, selected by sorted CWE/name) along with Juliet's support headers and ran local Clang 18 in syntax-only mode. **16 of 20 parsed**. Three failures involved Windows-only APIs/headers (`HMODULE`, `winsock2.h`, `windows.h`) on this Linux host; one used an old C++ dynamic exception specification rejected by Clang's default C++17 mode. This is a deliberately small, alphabetically biased sample, **not** an estimate of full parser coverage. The full audit must record platform/compiler mode and per-file failure reasons; unsupported files cannot silently become negative examples.

We followed this with a repeatable function-span audit using Clang 18 in `gnu11`/`gnu++11` mode. Run:

```sh
python3 -m scripts.audit_juliet_functions data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --per-language 10 --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
```

It selects the first sorted `_01` source file from each CWE, up to ten C files and ten C++ files. It extracts only those files and the archive's support headers into a temporary directory, parses them, and compares manifest flaw lines with AST function-definition spans. The JSON report includes each path, function span, matched flaw, and parser error excerpt.

| Measurement | Value | Interpretation |
|---|---:|---|
| Sampled files | 20 | Ten C and ten C++; deterministic and alphabetically biased |
| Parsed files | 17 | Three C files failed on Windows-specific identifiers or headers |
| Function definitions found in parsed files | 58 | Includes wrappers and safe-looking helpers; **not** 58 labelled training records |
| Manifest flaw lines in parsed files | 19 | All mapped to exactly one function definition |
| Flaw lines inside function bodies | 18 | Candidate positive locations |
| Flaw lines on a function signature | 1 | CWE397 case marks `throw (...)` on the declaration line |
| Unmatched or ambiguous flaw lines | 0 | Only within the 17 parsed files |

An expanded run with `--per-language 50` yielded **76 files**, not 100, because this selection rule found only 26 C++ CWE directories with `_01` cases. Of those 76, **55 parsed** (29/50 C and 26/26 C++), yielding **196 function definitions**. All **57 manifest flaw lines** in parsed files mapped uniquely: 55 in bodies and two on signatures. Of the 21 parse failures, 20 concern unavailable Windows headers or identifiers on Linux; one calls `gets`, which Clang rejects as undeclared in the selected C mode. These are observed counts for this biased `_01` sample only. The other case styles, multi-file definitions, macro-heavy cases, and overall C/C++ coverage remain unmeasured.

Using C++11 mode resolved the earlier dynamic-exception-specification parser failure. This does not establish full-suite parser coverage. The source-offset check rejects most header declarations and the audit exposes line locations, but macro-expanded definitions and unusual Clang locations still need coverage review before a production extractor is trusted.

We manually inspected the CWE121 array-index case in this sample. Its manifest line 112 points to an unchecked `buffer[data]` write in the `bad` function. `goodG2B` has a similar write with `data` fixed to 7 earlier in the same function, while `goodB2G` checks the index bound before writing. The public `good` function only calls those helpers. This illustrates why neither absence of a manifest flaw line nor a `good`/`bad` name alone establishes a function-level negative label. The CWE397 case also shows that limiting annotations to body braces would miss a real flaw on the function signature.

### Label and split risks found in the source documentation

The [Juliet C/C++ user guide](https://samate.nist.gov/SARD/downloads/documents/Juliet_Test_Suite_v1.2_for_C_Cpp_-_User_Guide.pdf) describes primary `bad`/`good` functions, secondary functions, source/sink helpers, multi-file cases, and bad-only cases. It says a primary bad function may call the function that contains the flaw; a primary good function may only call secondary good functions. These details come from the v1.2 guide; the [v1.3 changes document](https://samate.nist.gov/SARD/downloads/documents/Juliet_1.3_Changes_From_1.2.pdf) indicates the suite evolved from those structures. We must inspect actual v1.3 files before applying a label rule.

**Consequence:** A simple rule such as “every function with `bad` in its name is a positive and every `good` function is a negative” would introduce label leakage and may label wrapper/helper functions incorrectly. Direct inspection of one single-file case and two multi-file/virtual-method cases confirms generated headers include template filenames, `BadSource`/`GoodSource`, and `POTENTIAL FLAW`/`FIX:` comments. One multi-file primary function calls a sink in another source file. A first experiment may need a carefully audited subset of single-file cases where the flaw or non-flaw is inside the extracted function body. Keep all variants of one template/test case in the same group. Strip or mask generated label-bearing names/comments only after confirming the transformation preserves security-relevant code. Report exclusions.

Juliet remains useful for a controlled parser and model experiment, but a good Juliet score cannot establish real-world performance. Reserve an audited real-world C/C++ source for that check.

## Candidate B: Big-Vul

The [author-described cleaned function export](https://github.com/kchabra/Big-Vul/blob/master/README.md) is now present as `data/raw/big-vul/MSR_data_cleaned.zip`. Its SHA-256 is `be96d4133fe4e75a2c5dd3f36eae22939612083cd1f7bcaa3bb5ce782316e0f2`; ZIP integrity passed. The 188,636 rows have explicit `func_before`, `func_after`, `vul`, `project`, and `commit_id` fields. The labels are proxies based on changed lines in vulnerability fixes, not proof that every `vul=0` function is safe. Of the source rows, 10,900 are positive. The [Phase 5 report](phase-5-generalization.md) records exact duplicate/conflict counts, missing provenance, the 17,189-row deterministic external sample, and frozen Juliet-model results. Upstream rights for individual code snippets and full patch-family/near-duplicate relationships remain unverified.

## Candidate C: CodeXGLUE / Devign

The [defect-detection task](https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection) documents function-level `func` and binary `target` fields and a train/validation/test release. [CodeXGLUE](https://github.com/microsoft/CodeXGLUE) states that its code and dataset use different licenses (MIT for code, C-UDA for data). We have **not** checked the underlying source metadata or license implications for our use, nor audited duplicates or repository separation. It remains an alternative benchmark, not a source to merge automatically.

## Remaining checks after acquisition

1. Record the local acquisition date and preserve the verified ZIP unchanged. The official source, release, published SHA-256, rights statement, ZIP integrity, file counts, and archive-level exact duplicates have been checked.
2. Map manifest flaws and fixed-sink counterparts for the chosen `_01` subset; the candidate counts above satisfy this for that subset. Full Juliet and multi-file styles remain unaudited.
3. Measure normalized near duplicates, confirm split groups and retained counts after deduplication, and broaden manual review in Phase 2.
4. Audit a **fresh** real-world C/C++ test source before making a confirmatory claim for any new model trained or tuned using Big-Vul.

The first synthetic experiment source was selected as described above. Big-Vul has supplied a separate transfer check; the Juliet model failed that check and remains disabled. Any new model needs its own leakage-aware split and fresh final evaluation.
