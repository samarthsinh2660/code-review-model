# First dataset audit: C/C++ candidates

**Status:** Archive-level audit and a small function-span feasibility sample completed 2026-10-13. The official Juliet ZIP is present and verified. Full-suite function counts after filtering, function-level duplicate rates, parser coverage, and defensible positive/negative counts have **not** been measured. The dataset has not been chosen for training.

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

The [author repository](https://github.com/nqaisme/big-vul-dataset) describes C/C++ vulnerability records, source changes, and linked function exports. Its README describes `func_before`, `func_after`, changed lines, and a `vul` field. The repository shows an MIT license. We have **not** downloaded or sampled the export, verified the exact license of every source-code snippet, checked available repository/commit IDs in the function file, or counted duplicates. It is a candidate primary real-world dataset or separate external evaluation set, not yet selected for either role.

## Candidate C: CodeXGLUE / Devign

The [defect-detection task](https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection) documents function-level `func` and binary `target` fields and a train/validation/test release. [CodeXGLUE](https://github.com/microsoft/CodeXGLUE) states that its code and dataset use different licenses (MIT for code, C-UDA for data). We have **not** checked the underlying source metadata or license implications for our use, nor audited duplicates or repository separation. It remains an alternative benchmark, not a source to merge automatically.

## Decision needed after acquisition

1. Record the local acquisition date and preserve the verified ZIP unchanged. The official source, release, published SHA-256, rights statement, ZIP integrity, file counts, and archive-level exact duplicates have been checked.
2. Map manifest flaw lines to parsed function spans, then measure retained positive and defensible negative function counts, C versus C++ counts, parse success, function-level exact/near duplicates, conflicting labels, and provenance completeness.
3. Manually inspect examples from positive, negative, multi-file, and unusual categories. Verify where the flaw actually resides before assigning function labels.
4. Write the inclusion/exclusion rules and a group-aware split proposal. Check whether there are enough independent positive and negative groups for validation and test.
5. Select the first training dataset and a **separate** real-world generalization test. If the label rule cannot be defended, change the source choice before training.

The dataset decision is **open**. Archive-level counts and source-file duplicates do not satisfy the function-level label and split gate. No model training should use a source merely because it is listed in the idea document.
