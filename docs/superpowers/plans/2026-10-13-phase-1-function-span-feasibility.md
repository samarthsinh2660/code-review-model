# Phase 1 function-span feasibility plan

**Goal:** Measure whether Juliet manifest flaw lines can be mapped to source-defined function bodies in a deterministic, small C/C++ sample. Do not emit training labels yet.

**Approach:** Use the verified archive and local Clang AST JSON. Extract only the chosen source files and support headers into a temporary directory. Match AST source offsets to the original file bytes, then map each manifest flaw line to a parsed function body. Report parser failures and ambiguous or unmatched lines explicitly.

## Tasks

- [x] Write unit tests for source-offset filtering, definition span mapping, and ambiguous/unmatched flaw lines using tiny AST fixtures.
- [x] Implement a CLI that chooses a fixed number of `_01` source files for each language from sorted archive paths, resolves their manifest flaw lines, and runs Clang in C11/C++11 mode.
- [x] Emit aggregate counts and per-file diagnostics without labelling functions that lack flaw annotations as safe.
- [x] Run the CLI on the official archive and inspect representative positive, safe-looking, wrapper, and parser-failure examples.
- [x] Update `docs/dataset-audit.md` and the Phase 1 decision gate with measured results and remaining limitations.
- [x] Run focused and full tests, plus `git diff --check`.
