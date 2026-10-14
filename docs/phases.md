# VulnScope project phases

This roadmap turns [the project idea](idea.md) into work that can be completed and reviewed one phase at a time. The [architecture](architecture.md) explains the components and the [ML methodology](ml-methodology.md) fixes the research protocol. The initial path uses C/C++ for the first end-to-end experiment. Dataset feasibility may change the first language, but that decision must be recorded in Phase 1.

## Working rules

- Build and train the core classifiers ourselves. NumPy and parser libraries may support the work; a packaged classifier or pretrained detector is not the core model.
- Start with binary, function-level classification. Add CWE labels and line ranking only when suitable data and evaluation support them.
- Preserve source, repository, commit, license, and label provenance for every usable sample.
- Keep related functions and vulnerable/fixed pairs together when splitting data. Fit learned preprocessing on training data only; use validation data for tuning and leave the test set untouched until final evaluation.
- Treat every prediction as a review lead. An unflagged function is not proven safe.
- Aim for a group-aware 70/15/15 train/validation/test split when the data supports it; preserve natural class prevalence in validation/test and report actual counts. Keep an external or later-period evaluation separate.
- Establish an unweighted baseline before trying train-only class weights. Select model settings and an operating threshold on validation data, then freeze them before the final test.
- Finish each phase with its stated evidence and review its results before starting the next one. Do not claim a target accuracy in advance.

## Phase 0 — Project foundation

**Goal:** Make the research and code reproducible from the start.

**Work:** Establish the Python project, dependency and environment instructions, test runner, configuration layout, data/artifact ignore rules, and a short experiment-record format. Define the function record and finding formats before building adapters around them.

**Deliverables:** A runnable project skeleton, README setup instructions, initial tests, and documented data/artifact conventions.

**Exit gate:** Another developer can set up the environment and run the empty or initial test suite from the README. No datasets or trained artifacts are committed by accident.

## Phase 1 — Dataset feasibility and first-language decision

**Goal:** Select one primary dataset and understand what its labels actually mean.

**Work:** Audit the C/C++ candidates in `idea.md` first, continuing [the initial source review](dataset-audit.md). Check access and redistribution terms, fixed release or version, schema, language coverage, positive/negative label definitions, missing values, class balance, conflicting labels, duplicate and near-duplicate rates, and whether functions and source locations can be recovered. For Juliet, validate `C/manifest.xml` flaw lines against parsed function spans and audit safe counterparts; do not treat every function lacking a flaw line as negative. Inspect a sample manually for label-bearing filenames/comments, template shortcuts, bad-only cases, and wrappers whose flaw is in another function or file. Record whether real-world examples can be reserved for external evaluation. If C/C++ data is unsuitable, audit the JS/TS candidate before changing the first-language order.

**Deliverables:** `docs/dataset-audit.md`, a small repeatable inspection script, source/version/hash records, retained-count estimates, and a written choice of first dataset and language.

**Exit gate:** We can explain each retained label, reproduce the audit, and identify a feasible leakage-aware split. If this gate fails, revise the source choice before training.

## Phase 2 — Data pipeline and lexical features

**Goal:** Produce repeatable function-level examples and feature matrices for the chosen dataset.

**Work:** Ingest and validate records; preserve provenance; extract functions and locations; detect exact and near duplicates; group related examples, vulnerable/fixed pairs, and generated variants; create group-aware train, validation, and test partitions; then fit a tokenizer, capped lexical vocabulary, and any scaling on training data only. Exclude provenance and label-derived fields from features. Track rejected records, parsing failures, per-split counts, and class prevalence.

**Deliverables:** Versioned data-preparation configuration, manifest of retained and rejected records, split summaries, lexical feature matrices, and tests for labels, grouping, parsing failures, and train-only fitting.

**Exit gate:** A clean run produces the same record counts and split assignments. Duplicate families and vulnerable/fixed pairs cannot cross split boundaries; train-only preprocessing and usable class coverage are verified.

## Phase 3 — First custom model and baseline evaluation

**Goal:** Train a transparent binary classifier on the first language.

**Work:** Implement logistic regression with NumPy: numerically stable forward pass and binary cross-entropy, analytical gradients, optimizer loop, L2 comparison, thresholding, and artifact save/load. Check gradients numerically. Train an unweighted baseline, then compare train-derived class weighting if needed. Choose the operating threshold on validation data. Evaluate precision, recall, F1, average precision/PR-AUC, ROC-AUC, confusion matrix, class prevalence, and false-positive/false-negative rates.

**Deliverables:** Custom model and training code, model persistence tests, reproducible experiment configuration, validation curves, and a baseline results table.

**Exit gate:** Training and inference reproduce from documented inputs and seeds; an artifact reload gives the same predictions; baseline metrics and failure examples are recorded. Results may be weak, but they must be credible.

## Phase 4 — Structural features and second custom model

**Goal:** Test whether syntax structure and a more expressive model help.

**Work:** Extract explicit AST-derived features with a language parser. Implement a small NumPy MLP with forward pass, backpropagation, minibatches, L2 regularization, validation-loss early stopping, and checkpointing. Compare logistic regression and MLP on lexical features, AST features, and their combination using fixed splits. Inspect training/validation gaps and ablate code-length features.

**Deliverables:** Parser/AST feature tests, custom MLP and gradient tests, experiment configurations, comparison table, and error analysis.

**Exit gate:** The comparison uses the same fixed splits, and any improvement is backed by measured results rather than architecture assumptions.

## Phase 5 — Generalization and ensemble experiments

**Goal:** Learn whether the detector works beyond near-duplicate or familiar repositories.

**Work:** Evaluate on held-out repositories, a later time period, or a distinct real-world dataset when the audited data permits it; report synthetic and real-world results separately. Compare individual models with equal-weight soft voting and validation-tuned voting. Attempt stacking only if out-of-fold base predictions can be generated without leakage. Inspect precision/recall at the frozen threshold, false findings per scan, and score calibration before describing a score as a probability of real-world risk.

**Deliverables:** Generalization report, per-source and per-CWE breakdowns where sample sizes allow, individual-versus-ensemble table, threshold rationale, and representative false positives and false negatives.

**Exit gate:** The best deployable model is chosen from evidence. A weaker ensemble is discarded. Test data was not used to select model, weights, or threshold.

## Phase 6 — First usable scanner

**Goal:** Let a developer scan supported source code with the trained first-language model.

**Work:** Package the selected model and preprocessing artifacts behind a CLI. Scan a file or local repository, identify supported functions, apply the frozen threshold, and emit JSON findings with file/function locations, score, model version, and limitations. Mark unsupported or unparsed files as unscanned. Add an API only after the CLI inference path is stable.

**Deliverables:** Versioned inference artifact, CLI, JSON schema/example, integration tests, and usage documentation. A small FastAPI service may share the same inference core if time permits.

**Exit gate:** A fresh environment can load the artifact and scan a sample without training. Training and inference produce matching features for the same function.

## Phase 7 — JavaScript and TypeScript expansion

**Goal:** Add JS and TS through their own audited data and language adapter.

**Work:** Audit the JsVul release and any supplementary benchmark before ingestion, including temporal split, pair overlap, and source-specific label definitions. Add function extraction and lexical/AST features for both languages; document TypeScript-specific behavior. Train and evaluate separate JS and TS baselines first, then test a combined model if the data supports it. Route inference only to models validated for the detected language and feature version.

**Deliverables:** JS/TS audit, adapters, tests, per-language artifacts, metrics, and scanner support.

**Exit gate:** JS and TS each have reproducible results and clear support status. No C/C++ performance is presented as evidence for JS/TS performance.

## Phase 8 — Go expansion

**Goal:** Add Go only after function-level examples and labels can be justified.

**Work:** Use Go advisories as leads to affected repositories and fixes, not as automatic function labels. Link versions, commits, and changed functions; retain provenance and manually review a sample. Group patches and related function versions before splitting. Add a Go parser/feature adapter, train a Go-specific baseline, and evaluate it on held-out repositories where possible.

**Deliverables:** Go label-construction and audit report, Go dataset manifest, adapter tests, model artifact, metrics, and scanner support if results warrant it.

**Exit gate:** Every training label has traceable evidence and label uncertainty is documented. If data quality is inadequate, publish the finding and keep Go scanning disabled.

## Phase 9 — Final research report and demonstration

**Goal:** Present reproducible findings and a usable demonstration.

**Work:** Consolidate dataset provenance, split method, experiment configurations, model comparisons, generalization results, latency, and limitations. Demonstrate a repository scan and how a developer reviews a finding. Package the service or container only if it adds value to the demonstration.

**Deliverables:** Final report, reproducibility instructions, saved result tables/plots, demonstration example, and a clear list of supported languages and model versions.

**Exit gate:** Every performance claim traces to an experiment and a defined test set; another developer can reproduce the principal results or understand any unavailable external data.

## Optional work after the core path

CWE classification, line or region ranking, patch comparison, control/data-flow features, a custom tree learner, GitHub pull-request integration, a web interface, user feedback, and LLM-assisted explanations are separate extensions. Each needs its own data, success criteria, and evaluation before it is described as supported.

## Current next step

Phases 0–4 are implemented. [Phase 5](phase-5-generalization.md) found that the Juliet model transfers poorly to Big-Vul. A [Big-Vul C baseline](phase-5b-real-world-baseline.md) reached AP 0.247 on an initial fresh unseen-project cohort. A [second validation-only policy study](phase-5c-c-validation.md) reduced the alert fraction to 5.39% on a new cohort, with precision 0.326 and recall 0.280. Three training seeds gave similar validation ranking, but a function-length-only ranking came close to the model. A [near-clone and patch-label audit](phase-5d-c-data-quality.md) found two high-similarity validation-to-test functions across fork-like projects and confirmed that a sampled `vul=0` label means unchanged in a fix record, not proven safe. A [length-normalized feature experiment](phase-5e-c-length-controlled.md) fell below the length-only ranking on validation, so its fresh final cohort was preserved. Source rights, independent-source generalization, and stronger labels remain unresolved. The detector remains disabled and Phase 6's scanner gate is not met.
