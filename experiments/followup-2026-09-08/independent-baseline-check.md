# Independent zoxide exact-baseline sanity check

Date: 2026-09-08

Scope: internal independent reconstruction of the zoxide exact normalized-instruction baseline. This is neither external nor independent-human validation. I did not use `score_followup.metrics` and did not inspect other cases’ new outputs.

## Finding

The archived score is reproducible from its 762 predicted pairs:

| Artifact | TP | FP | FN | TN | Precision | Recall | F1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Archived attempt 1 | 562 | 167 | 680 | 222,665 | 0.770919 | 0.452496 | 0.570269 |
| Narrow mnemonic/operand sensitivity | 562 | 170 | 680 | 222,662 | 0.767760 | 0.452496 | 0.569402 |

The three-FP difference is sensitivity to the token definition. The frozen protocol specifies exact equality of nonempty normalized instruction tokens and excludes symbols, answers, and F6 slot conditions, but it does not enumerate the fields that constitute a token. The narrower reconstruction suggested by the verification prompt uses `body_similarity._instruction_token`:

```text
mnemonic_class + normalized operands
```

The archived prediction exactly matches grouping by `build_token_profiles(...).exact_token_hash` in `run_followup.py`. That token includes constant-shape and control-flow fields. Commit `06c905a` had already selected this implementation before results, so it is the frozen primary baseline rather than a post-results implementation change. The protocol’s missing field-level definition remains a reproducibility weakness.

This is not evidence of symbol or ground-truth leakage. The 562 true positives are real consequences of large exact-body groups, especially generic helper implementations.

## Reproduction invariants

The SHA-256 values for the frozen body, ground truth, and linkage files matched `inputs.json`:

- Body: `e1776d94199d13d2f995097f191ac78f5de3a5f5c00df80bd7dd78dd42a182cd`
- Ground truth: `b5e641338cd098ead94ea299b7dccd3a4ca2b8242743656762cf8f01617d967d`
- Linkage: `aea76c11cb78074695ea2ac4acc8f08026f61d81fa747d9d42948bf82f3da579`
- Archived prediction: `5baffb76a904f5a73f8a3e5977c3930377d308adc5d581d084dc057032edac23`

The body, ground truth, and linkage ID sets are identical and contain 674 functions, yielding 226,801 unordered pairs. The linkage scorer labels 1,242 positive, 222,832 negative, and 2,727 neutral pairs, so 224,074 pairs enter the primary score.

Eligibility was reconstructed as complete decode, zero opaque indirect jumps, and a nonempty instruction-token sequence. Of 674 functions, 535 are eligible and 139 are excluded for opaque indirect jumps. There are no incomplete, empty, or missing bodies.

Grouping the 535 eligible bodies by the frozen retrieval token hash creates 63 groups and 762 pairs, exactly matching the archived prediction pair-for-pair. The narrower mnemonic/operand sensitivity creates 66 groups and 765 predicted pairs.

## The three omitted pairs

All three pairs are primary negatives. Their mnemonic and operand sequences are identical, while one immediate constant has a different constant-shape class. They belong to the narrow sensitivity result, not the frozen primary baseline.

| Pair | Origins | Difference in richer token |
| --- | --- | --- |
| `FUN_001bb770` / `FUN_001bc560` | `Error::argument_conflict` / `Error::subcommand_conflict` | instruction 97: `int:one` versus `int:zero` |
| `FUN_001bd230` / `FUN_001be020` | `Error::unrecognized_subcommand` / `Error::no_equals` | instruction 75: `int:zero` versus `int:one` |
| `FUN_001bfe90` / `FUN_001bfeb0` | `StderrLock::is_terminal` / `StdoutLock::is_terminal` | instruction 1: constant 2 (`int:small`) versus 1 (`int:one`) |

No true-positive or false-negative count changes because the frozen richer key excludes only these three negative pairs relative to the narrow sensitivity.

## Largest contributors

| Representative | Members | Token length | Predicted pairs | TP | FP | Neutral | Main origins |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `FUN_0016b2f0` | 26 | 3 | 325 | 192 | 133 | 0 | 19 `anyhow::error::object_ref`; 7 `ContextError<C,E>::source` |
| `FUN_0016b430` | 19 | 3 | 171 | 171 | 0 | 0 | `anyhow::error::object_boxed` |
| `FUN_0015f4b0` | 9 | 4 | 36 | 35 | 0 | 1 | `AnyValueParser::type_id` |
| `FUN_0016f7a0` | 9 | 32 | 36 | 36 | 0 | 0 | `ContextError<C,E>::fmt` |
| `FUN_0015c620` | 6 | 2 | 15 | 3 | 12 | 0 | four origins sharing `XOR reg32 reg32; RET` |

The 26-member three-token group alone creates 42.7% of all archived predicted pairs and 133 of 167 false positives (79.6%). Its token sequence is:

```text
LEA reg64 general_pointer64
LEA reg64 ip_data_slot64
RET
```

It combines 19 `anyhow::error::object_ref` members with seven `ContextError<C,E>::source` members. The 19-member `object_boxed` group contributes 171 true positives, and the two largest groups together contribute 363 of 562 true positives. The large TP count relative to the strict result (18 TP, 15 FP, 1,224 FN as supplied in the task) is thus explained by repeated exact machine-body shapes in large generic families.

## Leakage check

The body function records contain address, body, CFG, quality, size, byte hash, and summary fields. They contain no symbol or source-origin field. Both exact grouping reconstructions use only function ID, body eligibility, and normalized instruction records. The archived pair set can be reproduced exactly with `build_token_profiles` before loading ground truth or linkage; those artifacts are needed only for scoring and contributor diagnosis.

I found no evidence that symbols, source labels, identities, or ground truth entered the baseline grouping. This data-flow check cannot prove the absence of contamination outside the frozen artifacts, but it rules out leakage through the inspected grouping implementation and input schema.

## Conclusion

The published attempt-1 numbers are internally correct for the archived artifact and its pre-results frozen TokenProfile definition. The protocol’s phrase “normalized instruction tokens” was insufficiently explicit because it did not list the token fields. Under a narrower mnemonic/operand-only sensitivity, zoxide scores TP 562, FP 170, FN 680, and F1 0.569402. The unexpectedly high recall is dominated by exact short-body generic-helper groups, not by detected symbol or ground-truth leakage.
