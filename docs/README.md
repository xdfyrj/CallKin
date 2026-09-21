# Documentation

Start with [CallKin overview](document.md). It explains the V0 relation-only
pipeline, the V1 body-aware stages, the evaluation truth boundary, artifact
paths, the symbol-derived source-origin proxy, and the limits of the results.

The longer documents below are reference material. Open the one that matches
the question you are investigating.

## Core workflow

- [Compilation](compilation.md): `compile.py`, build profiles, matched ELF
  pairs, manifests, and staging checks.
- [Ground truth and candidate selection](ground_truth.md): symbol
  normalization, scopes, anonymized users, and boundary inventories.
- [Binary extraction](binary_extraction.md): radare2, relocations, angr,
  projection tracks, anchors, and abstention.
- [Artifacts and provenance](artifacts.md): path grammar, schemas, hashes,
  joins, and stale-artifact checks.
- [CG-WL](CG-WL.md): seeds, weighted refinement, modes, and fixpoints.
- [Scoring](scoring.md): pairwise metrics, coverage, and result JSON.

## Research tracks

- [Retained results](results/README.md): completed JSON outputs and their
  provenance.
- [WL-depth protocol](protocols/wl-depth.md): the pinned depth comparison
  protocol and interpretation rules.
- [FLIRT audit](flirt_audit.md): direct-FLIRT labels as an audit and overlay
  path. They do not alter V0 candidate selection.
- [Windows PE GT](pe_gt.md): the separate PDB/RVA inventory experiment. It is
  not a PE call-graph backend.
- [Concrete null test](../experiments/concrete-null/README.md): retained
  generic/concrete function-body counterexamples.

The overview is the entry point. These pages preserve implementation details,
schemas, and historical experiment contracts for readers who need to inspect
or reproduce a particular stage.
