# C Data Quality Audit Implementation Plan

**Goal:** Quantify likely source-code overlap across project-held-out splits and inspect Big-Vul proxy-label evidence before changing the model.

**Architecture:** Use deterministic token 5-gram sketches to nominate cross-split near-duplicate candidates, then verify candidates by exact shingle Jaccard similarity. Keep the source code and patch review packet in ignored artifacts; commit only aggregate counts, examples by source ID, code, tests, and the research decision. Select review rows from train/validation only, then stream their original before/after metadata from the verified ZIP.

**Tech Stack:** Python 3.12 standard library, NumPy already in the project, `unittest`.

## Constraints

- No model or threshold selection from the already examined test cohorts.
- Similarity search is a candidate audit, not a proof that all near duplicates were found.
- Preserve dataset/archive hashes, sample IDs, project roles, and label meaning.
- Do not commit raw source code or patch material from the archive.

## Tasks

- [x] Implement tested token-shingle and deterministic sketch helpers. Audit train-to-validation and train-to-both-final-cohort pairs at a declared Jaccard threshold; report candidate coverage, matches, labels, and projects.
- [x] Deterministically select a balanced train/validation review sample. Stream original CSV rows once, verify sampled code hashes and labels, record before/after change extent and provenance fields, and save an ignored review packet.
- [x] Inspect a small set of sampled patches, document exact observations and limits, update the roadmap, run the full test suite and code review.
- [ ] Commit this audit phase once Git metadata is writable.
