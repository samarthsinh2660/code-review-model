# VulnScope resource inventory

**Checked:** 2026-10-13. This is a resource map for the full [phase roadmap](phases.md) and [ML methodology](ml-methodology.md), not a claim that every dataset is already usable. Record exact release, retrieval date, license terms, file hash, and retained sample counts during each dataset audit. Links and upstream terms can change.

## 1. Resources needed to begin

| Resource | Purpose | Status |
|---|---|---|
| [Python](https://www.python.org/downloads/) and [venv](https://docs.python.org/3/library/venv.html) | Training, data pipeline, CLI, and optional API | Python 3.12.3 is installed locally; project version policy still needs to be pinned |
| [NumPy](https://numpy.org/doc/stable/) | Array operations for classifiers implemented by us | Selected; package/version not installed or pinned by this repo |
| [pytest](https://docs.pytest.org/en/stable/) | Tests for data, gradients, persistence, and inference | Selected; package/version not installed or pinned by this repo |
| [Git](https://git-scm.com/doc) | Versioned code and experiment configurations | Installed locally; this project directory is not yet a Git repository |
| [NIST Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) | First candidate for a controlled C/C++ benchmark | Source page verified; **not downloaded or audited** |
| Storage for raw data, processed data, and artifacts | Keep immutable source copies and experiment outputs outside Git | About 157 GiB available on the local project filesystem at check time; actual dataset footprint must be measured |

**First acquisition order:** create a provenance record, download one fixed Juliet release, verify its published SHA-256, inspect its layout and labels, then decide whether it is the primary training source. The [NIST page](https://samate.nist.gov/SARD/test-suites/112) lists a 146 MB download and SHA-256 `ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb`; these describe the upstream archive, not a locally verified copy. Its page states public-domain/CC0 terms. Do not download every candidate before Phase 1 chooses what is usable.

## 2. Dataset and advisory sources

| Resource | Use in project | Access and rights check | Phase |
|---|---|---|---|
| [Juliet C/C++ 1.3](https://samate.nist.gov/SARD/test-suites/112) | Synthetic C/C++ positive/negative cases, CWE organization, first parser and split audit | Download and checksum on official page; public-domain/CC0 statement there. Derive function labels carefully, especially multi-file cases. | 1–5 |
| [Big-Vul author repository](https://github.com/nqaisme/big-vul-dataset) | Real-world C/C++ vulnerable/fixed functions and patch metadata; candidate external test | Repository has CSV and author-linked function exports; repository shows MIT license. Check the downloaded file's provenance and redistribution terms before reuse. | 1, 5 |
| [CodeXGLUE defect detection / Devign](https://github.com/microsoft/CodeXGLUE/tree/main/Code-Code/Defect-detection) | Alternative C/C++ benchmark and comparison | Task page gives function-level JSONL and a download route. [CodeXGLUE](https://github.com/microsoft/CodeXGLUE) states code is MIT and datasets are under C-UDA; review dataset terms and split metadata. | 1, 5 |
| [JsVul repository](https://github.com/jsvul/jsvul) and [linked Zenodo release](https://doi.org/10.5281/zenodo.18195838) | Candidate JS/TS function-level vulnerable/fixed data and curation method | Repository states GPLv3 for its code and links to Zenodo. The Zenodo record could not be opened during this check; verify release availability, data-specific license, files, hashes, and upstream rights in Phase 7. | 7 |
| [SecBench.JS author repository](https://github.com/cristianstaicu/SecBench.js) | Targeted JavaScript benchmark/evaluation cases | Author repository is reachable; review individual package licenses and benchmark use terms before copying data. The original URL in `idea.md` returned 404 and has been corrected. | 7 |
| [Go vulnerability database](https://go.dev/doc/security/vuln/database) and [bulk archive](https://vuln.go.dev/vulndb.zip) | Go advisory IDs, affected modules/symbols, and fix leads | Official docs provide OSV records and bulk ZIP. Advisory/symbol metadata is **not** an automatically labelled before/after function dataset. [OSV source listing](https://google.github.io/osv.dev/data/) lists the Go data as CC-BY 4.0. | 8 |
| [OSV schema](https://ossf.github.io/osv-schema/) and [OSV data/API](https://google.github.io/osv.dev/data/) | Join IDs, affected versions, and references across advisory sources | Schema and bulk export documented. Preserve source attribution and check each upstream record's terms. | 7–8 |
| [GitHub Advisory Database](https://github.com/advisories) | Go/JS advisory and patch leads | Site identifies CC-BY 4.0 for advisory content; advisories alone are not function labels. | 7–8 |
| [NVD API](https://nvd.nist.gov/developers/vulnerabilities) | CVE/CWE metadata and references | Metadata enrichment only; inspect API rules when used. | 7–8 |
| [MITRE CWE list](https://cwe.mitre.org/data/index.html) | Consistent weakness names and category hierarchy | Use as a taxonomy reference, not as labelled source code. | 1, 7–9 |

**Dataset decision:** Juliet is the initial candidate for the first controlled experiment; Big-Vul or a repository-held-out real-world source should test transfer. These sources must remain distinct until labels, duplicates, and licenses have been audited. Devign is an alternative benchmark, not extra training data by default.

## 3. Parsing and feature resources

| Resource | Planned role | When needed |
|---|---|---|
| [Tree-sitter parser documentation](https://tree-sitter.github.io/tree-sitter/using-parsers/) and [Python bindings](https://tree-sitter.github.io/py-tree-sitter/) | Common syntax-tree and source-position interface; validate parser errors and grammar coverage against real samples | Phase 2 onward |
| [C grammar](https://github.com/tree-sitter/tree-sitter-c) and [C++ grammar](https://github.com/tree-sitter/tree-sitter-cpp) | First-language function extraction and AST features | Phases 2, 4 |
| [JavaScript grammar](https://github.com/tree-sitter/tree-sitter-javascript) and [TypeScript/TSX grammars](https://github.com/tree-sitter/tree-sitter-typescript) | JS/TS extraction and AST features | Phase 7 |
| [Go grammar](https://github.com/tree-sitter/tree-sitter-go) or standard-library [go/parser](https://pkg.go.dev/go/parser) | Go function extraction and source positions; select one after comparing handling of Go files and syntax errors | Phase 8 |
| [TypeScript compiler API](https://github.com/microsoft/TypeScript/wiki/Using-the-Compiler-API) | Optional type-aware TS features if AST-only results justify the extra complexity | Optional, Phase 7 |

Tree-sitter is a parser, not a vulnerability detector. Pin compatible parser and grammar versions when implementing adapters. The initial lexical tokenizer and AST feature definitions remain project code.

## 4. Training, evaluation, and delivery resources

| Resource | Planned role | Status |
|---|---|---|
| Python standard library, NumPy | Custom logistic regression, MLP, losses, optimizers, ensemble, persistence | Core implementation required in Phases 3–5 |
| [pandas](https://pandas.pydata.org/docs/) | Optional table inspection and data cleaning | Support tool; avoid making training dependent on a specific dataset's CSV shape |
| [Matplotlib](https://matplotlib.org/stable/) | Optional learning curves, PR/ROC curves, and report figures | Phase 3 onward |
| [pytest](https://docs.pytest.org/en/stable/) | Tests for labels, split leakage, numerical gradients, serialization, and CLI scans | Phase 0 onward |
| [FastAPI](https://fastapi.tiangolo.com/) | Optional API sharing the CLI inference core | After Phase 6 CLI works |
| [Docker](https://docs.docker.com/) | Reproducible packaging and demonstration | Optional Phase 9; installed locally |

Implement the core classifiers and their training loops ourselves as required by `idea.md`. Reference classifier packages may be used only for clearly labelled comparisons if project rules permit them. Evaluation code must be inspectable and checked on small known examples; external metric libraries can be used as a cross-check rather than the only source of results.

## 5. Compute and environment check

Local observation on 2026-10-13: Python 3.12.3, Git 2.43.0, Node 24.15.0, Go 1.26.2, Clang 18.1.3, and Docker 29.1.3 are installed. The host reports 15 GiB total RAM and about 157 GiB free space on the project filesystem. `nvidia-smi` could not communicate with an NVIDIA driver, so plan the NumPy baselines for CPU. Available RAM and disk space fluctuate; measure dataset size and peak memory before expanding the corpus.

The [JsVul curation repository](https://github.com/jsvul/jsvul) documents Python 3.13+, Node 24+, SQLite, and `gsutil` for **rerunning its full upstream pipeline**. Our first JS/TS experiment should inspect the published dataset release before deciding whether any of that upstream reconstruction stack is needed. Local Python 3.12.3 does not meet that curation pipeline's stated floor.

## 6. Records to capture when each resource is acquired

For every dataset or downloaded artifact, record: source URL, exact release or commit, retrieval date, license and attribution, file size and SHA-256, schema, label meaning, original and retained counts, rejected-record reasons, and where the immutable raw copy is stored. For trained models, record code commit, config, random seed, dataset/split manifest hash, feature vocabulary/parser versions, training metrics, chosen threshold, test results, and artifact hash.

## 7. Open checks before implementation uses external data

1. Confirm Juliet's downloaded archive hash and inspect whether its `bad`/`good` naming maps cleanly to function-level labels and groups.
2. Confirm Big-Vul export accessibility, exact file schema, project/commit metadata, and the terms covering the chosen copy.
3. Confirm the JsVul Zenodo release resolves, identify its data license, and inspect the JSONL schema; the linked record was inaccessible during this inventory.
4. Decide whether SecBench.JS cases are suitable for static function-level evaluation; executable exploit cases may need different scoring.
5. Decide whether Go advisories contain enough traceable patch/function evidence for defensible labels. Keep Go model training and scanner support gated on that audit.
6. Pin dependency versions only when a parser and dataset combination has been tested, then record them in the project environment file.

This inventory gathers sources and prerequisites; it does not replace the per-source data-quality and license audit in Phases 1, 7, and 8.

## 8. Research and evaluation references

| Reference | Why it matters here |
|---|---|
| [Allamanis, *The Adverse Effects of Code Duplication in Machine Learning Models of Code*](https://www.miltos.allamanis.com/publicationfiles/allamanis2019adverse/allamanis2019adverse.pdf) | Rationale for exact/near deduplication before evaluation |
| [Croft et al., *Data Quality for Software Vulnerability Datasets*](https://ieeexplore.ieee.org/document/10172650/) | Evidence that source-code vulnerability datasets need label and duplicate audits |
| [Ding et al., *Vulnerability Detection with Code Language Models: How Far Are We?*](https://arxiv.org/abs/2403.18624) | Example of deduplication, chronological splits, and realistic evaluation; its pretrained model is not our planned core |
| [scikit-learn cross-validation guide](https://scikit-learn.org/stable/modules/cross_validation.html) | Group-aware and approximately stratified split design; reference only, not a required classifier dependency |
| [scikit-learn common pitfalls](https://scikit-learn.org/stable/common_pitfalls.html) | Train-only fitting of vocabularies, scalers, and feature selection |
| [scikit-learn precision-recall guide](https://scikit-learn.org/stable/auto_examples/model_selection/plot_precision_recall.html) | Metric definitions and threshold trade-offs under class imbalance |
| [scikit-learn calibration guide](https://scikit-learn.org/stable/modules/calibration.html) | Reliability checks before interpreting a score as a probability |
