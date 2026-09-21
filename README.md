# CallKin

CallKin is a research toolkit for grouping Rust monomorphized functions by
call relations and machine-code bodies. It builds anonymous graph/body
artifacts and compares the groups with a symbol-derived source-origin proxy
from the same build.

The evaluation uses candidate addresses and function boundaries from a
non-stripped symbol oracle. The grouping engine receives no names, concrete
types, or ground-truth families. Results cover observed out-of-line functions.
This repository does not discover functions from a stripped binary;
[CallKin-Real](https://github.com/xdfyrj/CallKin-Real) adds that path. Neither
tool recovers generic types or source code.

## Quick start

Use Python 3.12+ on Linux or WSL. The score command uses bundled artifacts:

```bash
python3.12 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python scores.py family_graph_03 --candidate-scope subject
```

Run the default checks:

```bash
python tests/run_all.py
python experiments/concrete-null/test_concrete_null_test.py
```

To compile and run one case from source:

```bash
python3 compile.py billing-client subject --profile plain --build O3S
python3 run_case.py billing-client --profile plain --build O3S \
  --candidate-scope rust-nonstd --track angr --anchor-policy role \
  --mode out-in --json-output
```

With no output path, the result is
`results/billing-client/plain/angr.role.out-in.json`. The build manifest is
`build_info/plain/billing-client.O3S.json`; related artifacts include
`ground_truth/rust-nonstd/plain/billing-client.O3S.gt.json`,
`fixtures/angr/role/rust-nonstd/plain/billing-client.O3S.fixture.json`, and
`extractions/angr/plain/billing-client.O3S.raw.json`.

## Documentation

Start with the [documentation index](docs/README.md), then read the
[overview and workflow](docs/document.md). The overview covers V0, V1, the
truth boundary, artifact flow, and limits; the longer pages are references.

- [Retained results](docs/results/README.md) and their provenance
- [Concrete null test](experiments/concrete-null/README.md)
- [WL-depth protocol](docs/protocols/wl-depth.md)
- [Third-party notices](THIRD_PARTY_NOTICES.md)

## Scope and reproducibility

V0 is the relation-only baseline: extraction, graph projection, CG-WL, and
scoring. V1 is a separate body-aware path: local body evidence, bounded
candidate retrieval, and conservative family building. V1 does not alter the
V0 fixture or feed ground truth into the engine.

Bundled tests need the recorded fixtures. New extraction also needs a Rust
toolchain, GNU `nm` and `strip`, radare2, and the packages in
`requirements.txt`. PE/PDB and full body/extraction caches are optional and
are not in the default checkout.

`docs/results/` contains retained research outputs, not fresh measurements of
this checkout. New runs have new execution identities; compare their inputs
and provenance with retained reports.

CallKin is released under the [MIT license](LICENSE).
