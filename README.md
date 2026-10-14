# VulnScope

VulnScope is a research prototype for custom-trained, function-level source-code vulnerability detection. The first planned language is C/C++; JavaScript/TypeScript and Go follow only after their data and models are audited. A model finding is a lead for developer review, not proof of a vulnerability or safety.

## Current status

The foundation and first C/C++ data pipeline are implemented. Custom NumPy logistic and MLP experiments, plus an AST comparison, have run. The Juliet-trained model transferred poorly to Big-Vul. A Big-Vul C baseline was evaluated on fresh project-held-out functions. A 5% validation alert-budget policy reduced review volume on a second fresh cohort, but a function-length-only ranking nearly matched the model, so the detector remains **disabled as a scanner**. Read the [phase roadmap](docs/phases.md), [dataset audit](docs/dataset-audit.md), [transfer report](docs/phase-5-generalization.md), [real-world C baseline](docs/phase-5b-real-world-baseline.md), [validation study](docs/phase-5c-c-validation.md), and [data-quality audit](docs/phase-5d-c-data-quality.md).

## Requirements and setup

- Python 3.12 or newer.
- NumPy 2.x for preparation and training.
- Clang 18 (`clang` and `clang++`) for the Juliet function and AST audits.

Run all tests:

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

- `src/vulnscope/` holds validated records, lexical/AST features, split rules, metrics, and custom model code.
- `tests/` contains tests that run without real vulnerability datasets.
- `data/` is for raw, interim, and processed datasets. Its dataset contents are ignored by Git; see [data/README.md](data/README.md).
- `artifacts/` is for generated model bundles and temporary outputs. Large outputs are ignored by Git; see [artifacts/README.md](artifacts/README.md).
- `experiments/` stores run conventions and ignored full result JSON; see [experiments/README.md](experiments/README.md).

Dataset licenses, hashes, label meanings, split manifests, feature definitions, and model versions must be recorded before results are claimed.

## First dataset audit

The acquired Juliet C/C++ 1.3 archive can be checked without extraction:

```sh
python3 -m scripts.audit_juliet_archive data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb
```

For the reproducible Juliet `_01` research path, place the verified archive at the path above, create `data/processed/`, then run these in order:

```sh
mkdir -p data/processed
python3 -m scripts.audit_juliet_functions data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip --all-01 --expected-sha256 ada9d7e1c323d283446df3f55bdee0d00bda1fed786785fe98764d58688f38eb > data/processed/juliet_01_function_audit.json
python3 -m scripts.assess_juliet_01 data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip data/processed/juliet_01_function_audit.json > data/processed/juliet_01_pair_assessment.json
PYTHONPATH=src python3 -m scripts.prepare_juliet_01 data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip data/processed/juliet_01_pair_assessment.json
PYTHONPATH=src python3 -m scripts.prepare_juliet_ast data/raw/2017-10-01-juliet-test-suite-for-c-cplusplus-v1-3.zip
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_juliet_logistic --model-dir artifacts/models/juliet_01_logistic_v2 --result experiments/results/juliet_01_logistic_v2.json
OPENBLAS_NUM_THREADS=1 PYTHONPATH=src python3 -m scripts.train_juliet_mlp
```

Detailed counts and limitations are in the [Phase 2](docs/phase-2-data.md), [Phase 3](docs/phase-3-logistic.md), [Phase 4](docs/phase-4-structural.md), and [Phase 5](docs/phase-5-generalization.md) notes.

The [Phase 5 note](docs/phase-5-generalization.md) also specifies the strict JSONL contract and command for evaluating a separately audited C/C++ source with the frozen research bundle. No external dataset is bundled with this repository.
