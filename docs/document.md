# CallKin overview

CallKin studies when optimized Rust binaries still contain enough evidence to
group out-of-line monomorphized functions by a symbol-derived source-origin
proxy. This page explains the two evaluation paths, the truth boundary, the
artifacts they exchange, and the limits of the results.

## What the repository measures

CallKin has two related paths:

- **V0** groups functions from directed call relations. It is the stable
  relation-only baseline.
- **V1** adds local function-body evidence to retrieve and compare a bounded
  set of candidate pairs, then builds conservative families.

Neither path claims to recover generic types or source history. A function that
was inlined or removed before the final linked binary cannot appear in the
current ground truth.

## V0: relation-only grouping

A normal V0 run has five stages.

1. **Build.** `compile.py` produces one non-stripped ELF and a byte-matched
   `strip --strip-all` copy. `build_info/<profile>/<case>.<build>.json` records
   commands, hashes, compiler details, and the build identity.
2. **Truth-side inventory.** `gt_extractor.py` reads demangled text symbols from
   the non-stripped ELF. It writes an origin partition for scoring, an
   anonymized candidate list, and a scope-independent function-boundary list.
3. **Evidence extraction.** `binary_extractor.py` reads the stripped ELF with
   radare2, Capstone, and ELF relocation data. The optional `angr` track adds
   only an unresolved call or tail-call whose target set resolves to one known
   function. Raw evidence is kept separate from projection policy.
4. **Projection.** `graph_projector.py` turns raw evidence plus the candidate
   list into a fixture. A `candidate` has a non-self resolved relation, an
   `anchor` supplies context without being scored, and an `abstain` target has
   no usable non-self relation. The `direct`, `direct-in`, and `angr` tracks
   choose different evidence closures. `address` and `role` choose anchor
   colors.
5. **Grouping and scoring.** `engine.py` runs directed weighted CG-WL using
   one of `full`, `out`, `in`, or `out-in`. `scores.py` is the only stage that
   joins predicted clusters to ground-truth origins. It also reports coverage
   and abstention so conditional F1 is not read as source-level recall.

The engine reads fixture data only. Origin names, concrete generic arguments,
and GT family membership never enter grouping.

## V1: body-aware follow-up

The papers use stage names, while older code and artifacts use F-numbers.

| stage | code | main files | task |
| --- | --- | --- | --- |
| Normalize | F1-F3 | `body_extractor.py`, `body_evidence.py` | decode functions, normalize instructions, and build CFGs |
| Retrieve | F5 | `v1_candidates.py`, `v1_retrieval_views.py` | select likely pairs from Token, CFG, and Relation views |
| Align | F4 | `body_similarity.py` | compare two bodies in detail |
| Decide | F6 | `v1_engine.py` | classify pairs and form complete-link families |
| Rescue | F7 | `family_template.py`, `family_rescue.py` | test whether strict fragments share a supported variation pattern |

Normalize and Retrieve reduce the number of expensive comparisons. Decide
returns `match`, `reject`, `unknown`, or `abstain`; it merges two groups only
when every required cross-pair matches. Rescue writes a separate artifact and
does not rewrite the strict F6 partition. Direct FLIRT labels and F10 name
propagation are post-grouping overlays, so they do not change V0 colors or V1
families.

Scripts under `analysis/` measure candidate recall, collisions, pair outcomes,
and rescue behavior. Some read ground truth for scoring, but predictions are
built without it.

A representative V1 sequence is:

```bash
python3 body_extractor.py ripgrep-main --build O3S --profile plain \
  --candidate-scope rust-nonstd \
  --raw-graph /path/to/ripgrep-main.O3S.raw.json

python3 analysis/v1_feasibility.py ripgrep-main --build O3S --profile plain \
  --candidate-scope rust-nonstd \
  --body-evidence body_evidence/plain/ripgrep-main.O3S.body.json \
  --ground-truth ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json

python3 v1_candidates.py ripgrep-main --build O3S --profile plain \
  --body-evidence body_evidence/plain/ripgrep-main.O3S.body.json \
  --fixture /path/to/ripgrep-main.O3S.fixture.json \
  --mode out-in --track angr --candidate-scope rust-nonstd \
  --anchor-policy role --top-k 16 \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidates.json

python3 v1_engine.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidates.json \
  --body-evidence body_evidence/plain/ripgrep-main.O3S.body.json \
  --config configs/v1.json \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.families.json
```

These commands require the corresponding body and fixture artifacts. They are
reference-stage commands; the one-command V0 path is `run_case.py`.

## Truth boundary

The non-stripped ELF is an evaluation oracle, not an input to the grouping
algorithm. It supplies:

- candidate start addresses and sizes;
- all observed Rust function boundaries used to interpret stripped addresses;
- normalized source-origin groups for the scorer.

The grouping input receives anonymized IDs, sizes, boundaries, transfer evidence,
and policy metadata. It does not receive full demangled candidate symbols,
origin names, concrete types, source-level mono-item counts, or GT membership.

This makes the result a conditional recovery measurement among functions that
survived out of line in one linked build. It is not an end-to-end stripped-only
function recovery result. `rust-nonstd` is a namespace rule, not a perfect
dependency ownership oracle. Multiple-target or unresolved indirect transfers
are not asserted as exact edges. See [CallKin-Real](https://github.com/xdfyrj/CallKin-Real)
for the separate stripped-only path.

## Artifacts and outputs

Artifacts share a `<case>.<build>` stem and are separated by profile, scope, and
analysis track.

| Path | Meaning |
| --- | --- |
| `gt_bin/<profile>/<case>.<build>.gt.bin` | non-stripped binary used for truth-side extraction |
| `bin/<profile>/<case>.<build>.fixture.bin` | stripped binary used for evidence extraction |
| `build_info/<profile>/<case>.<build>.json` | build commands, hashes, and tool identity |
| `ground_truth/<scope>/<profile>/<case>.<build>.gt.json` | scoring-only origin partition |
| `users/<scope>/<profile>/<case>.<build>.users.json` | anonymized candidate addresses and sizes |
| `boundaries/<profile>/<case>.<build>.boundaries.json` | function boundary oracle |
| `extractions/<track>/<profile>/<case>.<build>.raw.json` | raw transfer evidence |
| `fixtures/<track>/<anchor>/<scope>/<profile>/<case>.<build>.fixture.json` | projected CG-WL graph |
| `results/<case>/<profile>/*.json` | scores, coverage, and run summary |
| `body_evidence/<scope>/<profile>/*.body.json` | V1 local body evidence |
| `configs/v1.json` | V1 comparison policy |

A retained result under `docs/results/` is a completed research output with its
original provenance. Re-running the source creates a new execution identity;
compare inputs and hashes before comparing metrics.

## Parameters that change an experiment

| Axis | Values | `run_case.py` default |
| --- | --- | --- |
| profile | `plain`, `min` | `plain` |
| build | `O3S`, `O3KS` | `O3S` |
| candidate scope | `subject`, `rust-nonstd` | `rust-nonstd` |
| extraction track | `direct`, `direct-in`, `angr` | `angr` |
| anchor policy | `address`, `role` | `role` |
| CG-WL mode | `full`, `out`, `in`, `out-in` | `out-in` |

`O3KS` adds `--cfg keep` to the build. `plain` and `min` also change
optimization, LTO, panic, and candidate survival, so their F1 values do not
share a fixed denominator. Keep the build, scope, track, anchor policy, and
mode fixed when comparing a result.

## Reading a result

Pairwise precision, recall, F1, and ARI describe the scored candidate subset.
Coverage fields describe how much of the target universe was actually decided.
An abstain is not made into a singleton prediction: it remains visible in
target and same-family-pair coverage. A high conditional F1 can coexist with
low effective recovery when many targets have no resolved relation.

The retained result README explains the historical reports and their limits:
[docs/results/README.md](results/README.md). The scoring contract and exact
metric definitions are in [scoring.md](scoring.md).

## Reference map

- [Artifacts and provenance](artifacts.md): path grammar, schemas, joins, and
  stale-artifact checks.
- [Compilation](compilation.md): `compile.py`, profiles, staging, and manifests.
- [Ground truth and candidate selection](ground_truth.md): symbol normalization,
  scope rules, and anonymized inventories.
- [Binary extraction](binary_extraction.md): radare2, relocation resolution,
  angr, projection tracks, and anchors.
- [CG-WL](CG-WL.md): seed colors, weighted refinement, modes, and fixpoint.
- [Scoring](scoring.md): pairwise metrics, coverage, and result JSON.
- [FLIRT audit](flirt_audit.md): direct-FLIRT evidence and its audit-only boundary.
- [Windows PE GT](pe_gt.md): the separate PDB/RVA inventory experiment.
- [WL-depth protocol](protocols/wl-depth.md): the preregistered depth comparison.
- [Concrete null test](../experiments/concrete-null/README.md): retained body
  counterexamples.

The long documents are implementation references. Start here, then open only the
reference that answers the next concrete question.
