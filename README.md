# VulnScope

VulnScope is a research prototype for custom-trained, function-level source-code vulnerability detection. The first planned language is C/C++; JavaScript/TypeScript and Go follow only after their data and models are audited. A model finding is a lead for developer review, not proof of a vulnerability or safety.

## Current status

Phase 0 establishes the Python package, shared records, storage conventions, and initial tests. There is no trained detector or scanner yet. Read [the architecture](docs/architecture.md), [ML methodology](docs/ml-methodology.md), and [phase roadmap](docs/phases.md) before adding a dataset or model.

## Requirements and setup

- Python 3.12 or newer.
- No external runtime package is needed for Phase 0.

Run the initial tests without installing the package:

```sh
PYTHONPATH=src python3 -m unittest discover -s tests -v
```

To import the package from another working directory, create a virtual environment and install it locally:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -c "import vulnscope; print(vulnscope.__version__)"
```

## Repository conventions

- `src/vulnscope/` holds the project code. The initial `records.py` defines the contract for later data adapters and scan reports.
- `tests/` contains tests that run without real vulnerability datasets.
- `data/` is for raw, interim, and processed datasets. Its dataset contents are ignored by Git; see [data/README.md](data/README.md).
- `artifacts/` is for generated model bundles and temporary outputs. Large outputs are ignored by Git; see [artifacts/README.md](artifacts/README.md).
- `experiments/` stores run conventions and, later, result summaries; see [experiments/README.md](experiments/README.md).

Dataset licenses, hashes, label meanings, split manifests, feature definitions, and model versions must be recorded before results are claimed.

## First dataset audit

The acquired Juliet C/C++ 1.3 archive can be checked without extraction:

```sh
python3 -m scripts.audit_juliet_archive data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
```

See [the audit](docs/dataset-audit.md) for measured file counts and why these files are not yet training examples.
