# CallKin

Research tools for grouping Rust monomorphized functions using call relations and function bodies. Evaluations use known function lists and boundaries.

## Quick start

Python 3.12+. Commands below are for Linux or WSL.

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python scores.py family_graph_03 --candidate-scope subject
```

## Tests

```bash
python tests/run_all.py
python experiments/concrete-null/test_concrete_null_test.py
```

## Documentation

- [Methods and pipeline](docs/document.md)
- [Results](docs/results/README.md) and [Concrete Null Test](experiments/concrete-null/README.md)
- [CallKin-Real](https://github.com/xdfyrj/CallKin-Real): analysis directly from stripped binaries
- [MIT license](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md)
