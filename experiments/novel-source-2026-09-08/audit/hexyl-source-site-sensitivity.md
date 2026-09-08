# Hexyl source-site split sensitivity

This is a versioned posthoc sensitivity for the frozen Hexyl v0.17.0 relation study. It derives [hexyl.gt.v2.json](hexyl.gt.v2.json) and [hexyl.linkage.v2.json](hexyl.linkage.v2.json) from the retained O3S GT/linkage files. Only the two members of normalized `hexyl::run::{{closure}}` are split:

- `FUN_0015b260` -> `hexyl::run::{{closure}}@src/main.rs:342` (the `reader.seek(...).map_err(...)` closure).
- `FUN_0015b1a0` -> `hexyl::run::{{closure}}@src/main.rs:353` (the `parse_byte_count` closure).

All other address records, aliases, and raw mangled identities are copied unchanged. The source-site evidence and pinned-file hashes are in [hexyl-source-audit.json](hexyl-source-audit.json). This is source-site evidence, not a DefId or semantic MonoItem oracle. The two `anyhow::context` members remain a plausible generic/callsite pair and are not split.

## Frozen scoring result

The six retained predictions were rescored with the existing legacy scorer under `/usr/bin/python3.12` (3.12.3). Accepted clusters, eligibility, candidates, and predictions are unchanged. The old pair is absent from every accepted cluster, so the split changes one unpredicted positive pair into a negative pair in every arm:

- all pairs: `161028 -> 161028`; neutral pairs: `591 -> 591` (`567` ambiguous + `24` duplicate);
- scored pairs: `160437 -> 160437`; positive pairs `P: 727 -> 726`; negative pairs `N: 159710 -> 159711`;
- every arm: `TP` and `FP` unchanged, `FN -1`, `TN +1`.

The exact primary metrics are below (`before -> after`). Exact-group rate and macro-origin recall are included because they also depend on the positive-origin denominator.

| arm | TP/FP/FN/TN | precision | recall | F1 | exact-group | macro-origin recall |
| --- | --- | --- | --- | --- | --- | --- |
| `V0-relation` | `168/168/559/159542 -> 168/168/558/159543` | `0.5 -> 0.5` | `0.2310866574965612 -> 0.23140495867768596` | `0.3160865475070555 -> 0.3163841807909605` | `0.24390243902439024 -> 0.25` | `0.3621695377792939 -> 0.3712237762237762` |
| `exact-token-hash` | `369/84/358/159626 -> 369/84/357/159627` | `0.8145695364238411 -> 0.8145695364238411` | `0.5075653370013755 -> 0.5082644628099173` | `0.6254237288135593 -> 0.6259541984732825` | `0.14634146341463414 -> 0.15` | `0.33775127311712677 -> 0.3461950549450549` |
| `B2-body-score` | `8/17/719/159693 -> 8/17/718/159694` | `0.32 -> 0.32` | `0.011004126547455296 -> 0.011019283746556474` | `0.02127659574468085 -> 0.02130492676431425` | `0.07317073170731707 -> 0.075` | `0.10278745644599303 -> 0.10535714285714286` |
| `B2-token-cfg` | `8/19/719/159691 -> 8/19/718/159692` | `0.2962962962962963 -> 0.2962962962962963` | `0.011004126547455296 -> 0.011019283746556474` | `0.021220159151193633 -> 0.021248339973439574` | `0.07317073170731707 -> 0.075` | `0.10278745644599303 -> 0.10535714285714286` |
| `C3-token-cfg-relation` | `8/17/719/159693 -> 8/17/718/159694` | `0.32 -> 0.32` | `0.011004126547455296 -> 0.011019283746556474` | `0.02127659574468085 -> 0.02130492676431425` | `0.07317073170731707 -> 0.075` | `0.10278745644599303 -> 0.10535714285714286` |
| `C3-rescue` | `8/17/719/159693 -> 8/17/718/159694` | `0.32 -> 0.32` | `0.011004126547455296 -> 0.011019283746556474` | `0.02127659574468085 -> 0.02130492676431425` | `0.07317073170731707 -> 0.075` | `0.10278745644599303 -> 0.10535714285714286` |

The rank order is unchanged for precision, recall, F1, exact-group rate, and macro-origin recall. The JSON records the orders and uses arm name as the deterministic tie-breaker.

## Three views

The inherited project-owned mask has 37 targets (664 scored pairs). Its one old positive is exactly the split pair, so `P: 1 -> 0`, `FN: 1 -> 0`, and `TN: 663 -> 664`; `TP` stays 0 and `FP` stays arm-specific (`0`, `3`, or `1`). After the split, project recall, macro-origin recall, and exact-group rate are `NA` because there is no positive pair. F1 remains the scorer's zero/undefined result according to whether that view has false positives.

The inherited previously-unobserved normalized-origin mask has 49 targets (1174 scored pairs). The two old closure members are still in the mask because the new site labels are absent from the frozen 4530-origin exposure inventory. Its positive count becomes `P: 2 -> 1` and `FN: 2 -> 1`; `TP` and `FP` are unchanged, `TN +1`, precision stays unchanged, and recall/F1/macro/exact remain zero. The remaining positive is the plausible `anyhow::context` pair.

The complete per-arm/per-view counts, neutral-pair conservation, positive-first-outcome counts, hashes, and rank arrays are in [hexyl-source-site-sensitivity.json](hexyl-source-site-sensitivity.json). Re-run the bounded verifier with:

```text
/usr/bin/python3.12 experiments/novel-source-2026-09-08/audit/verify_hexyl_source_site.py
```

The verifier has an exact Python 3.12.3 guard, checks the old/new split-pair labels and expected deltas, and refuses to overwrite a changed retained artifact. No primary GT/linkage, prediction, score, helper, source label inventory, build, or core file was modified.
