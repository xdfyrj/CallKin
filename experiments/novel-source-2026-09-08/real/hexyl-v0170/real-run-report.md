# CallKin-Real hexyl-v0170 stripped-only run

The run completed with exit status `0` under CPython `3.12.3`, CallKin-Real
HEAD `68ffa8dc1285546a1db52096a905a36fec094bd6`, and study commit
`aa119815c94c3d307d57cb6f4d339617971ff6a6`. The only analysis input was the
stripped ELF SHA-256
`b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a`.
`--no-flirt --component-budgeted-v1` and `top_k=16` were used. No GT,
boundary, linkage, or controlled cache was read until the Real outputs had
been hashed.

The outer wrapper elapsed time was 874 seconds. The `run.json` CallKin-Real
discovery/body/graph/stage-writing phase recorded 558.688 seconds, while the
full `analyze.py` pipeline recorded 870.901 seconds in `run.manifest.json`;
the difference is F5/F6/F7/relaxed processing and manifest completion after
the lower-level run record. Maximum RSS was 6,556,504 KiB under the 12-GiB
address-space and 3,600-second wall limits. Six known angr diagnostics were
retained in `real-run.stderr.log`: one unsupported jump-table operation and
five CFG return-edge warnings.

## Discovery and body coverage

Real discovered 7,056 functions: 5,514 grouping members, 906 context-only
nodes, and 636 abstentions. It produced 6,151 body records, of which 5,515
decoded completely and 636 were incomplete. The standard evaluator found 567
of 568 GT-labelled IDs, with one discovery miss (`FUN_0017b990`) and complete
body coverage `0.8961` over the GT discovery denominator. Every produced
function satisfied the static-VA `FUN_{va+0x100000}` encoding check.

The GT and linkage sets agree exactly on 568 IDs. Real’s 567/568 intersection
and one miss are discovery outcomes, not join failures. Real members absent
from GT are diagnostic and are not automatic false positives.

The provided boundary artifact contains 2,018 extents. Real found 2,015;
1,105 had exact sizes and 910 had size differences. On the 568 GT targets,
567 were found, 238 had exact sizes, and 329 had size differences. This is a
posthoc boundary diagnostic only; the boundary artifact never entered Real
discovery or inference.

## Budgeted grouping

F5 formed 3,594 candidate components. Component budgeting selected 3,567
components (4,896 members) and deferred 27 components (618 members). The
deferred component/function lists are preserved in
`real-run-validation.json`. This is intentional partial processing; a
whole-queue or resource failure would instead be `NA`.

Strict F6 processed the 5,514-member grouping universe and accepted 106
families covering 346 members. It recorded 2,882 detailed comparisons and
2,512,526 alignment cells, with no budget-blocked merge. F7 used 1,807
comparisons and 1,077,296 cells; all 19 rescue components were rejected and no
additional family was rescued. Direct labels and propagation are unavailable
because FLIRT was disabled.

## Primary standard-evaluator score

The primary score is over GT-labelled IDs overlapping the Real grouping-member
universe (`509` scored members; `532` neutral pairs).

| method | precision | recall | F1 | TP | FP | FN |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| V0 relation-only | 0.3725 | 0.2279 | 0.2828 | 165 | 278 | 559 |
| V1 strict | 0.5000 | 0.0097 | 0.0190 | 7 | 7 | 717 |
| V1 strict + rescue | 0.5000 | 0.0097 | 0.0190 | 7 | 7 | 717 |
| V1 relaxed provisional | 0.5000 | 0.0097 | 0.0190 | 7 | 7 | 717 |

The posthoc supplementary full-568 view treats missing GT IDs as unresolved,
ignores Real members outside GT rather than charging them as FPs, and reports
591 neutral pairs. V0 is precision `0.3725`, recall `0.2270`, F1 `0.2821`
(165/278/562 TP/FP/FN); strict, rescue, and relaxed are precision `0.5000`,
recall `0.0096`, F1 `0.0189` (7/7/720 TP/FP/FN).

The complete standard score is `evaluation.json`; the supplementary and
boundary diagnostics are in `real-run-supplementary.json`. The pre-score
output inventory is `real-run-output-hashes.txt`.

Controlled extraction used Python `3.10.14`; controlled inference used
Python `3.12.3`; this Real run used Python `3.12.3` for all stages. The Rust
binary/compiler condition is unchanged, while Real discovery, `subject`
scope, address anchors, and component budgeting differ from the controlled
provided-boundary policy. The results are separate-condition descriptive
measurements and do not support a causal cross-condition quality claim. The
primary original GT remains frozen; any source-corrected sensitivity analysis
requires separate authorization.
