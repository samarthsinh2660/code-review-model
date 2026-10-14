# C Length-Controlled Experiment Implementation Plan

**Goal:** Test whether a custom C model ranks Big-Vul proxy labels beyond the strong function-length shortcut.

**Architecture:** Reuse the frozen project split and train-only 1,024-token vocabulary. Prepare normalized token-frequency features and train-only IDF, fit a small predefined custom-logistic grid on train/validation, and choose one model plus a 5% alert threshold using validation only. Compare it with the earlier frozen count model and a token-length ranking on validation. Open a new hash-remainder-3 cohort only if the new model beats both validation comparators; otherwise preserve the cohort for a stronger future candidate. Keep both earlier final cohorts out of all selection.

**Tech Stack:** Python 3.12, NumPy, `unittest`, existing Big-Vul ZIP and project artifacts.

## Constraints

- Do not change old model bundles, earlier test reports, or project roles.
- Fit vocabulary and IDF on training only; preserve natural validation/test prevalence.
- Length-only comparison is a ranking baseline, not an automatically deployable detector.
- Treat remainder 3 as a one-time final test only after a new model clears the validation gate; otherwise leave it ungenerated.
- No scanner enablement without evidence from independent-source evaluation and label-quality work.

## Tasks

- [x] Add tested normalized-frequency and train-only-IDF transformations, plus a prepared train/validation manifest linked to the frozen split.
- [x] Train and freeze a predefined TF/TF-IDF logistic grid with validation AP selection and a validation-only 5% alert policy; verify artifact reload and hashes.
- [x] Compare the new TF model, old count model, and length-only ranking on validation, with project-bootstrap uncertainty for AP differences. The TF model failed the gate, so stop without generating remainder 3.
- [x] Document measured results and limits, run the full suite, and review code.
- [ ] Commit the completed research phase when Git metadata is writable.
