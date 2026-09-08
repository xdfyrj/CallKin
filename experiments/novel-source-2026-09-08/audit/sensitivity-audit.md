# fd source ambiguity sensitivity

The authorized secondary overlay [fd.source-ambiguity.v2.linkage.json](fd.source-ambiguity.v2.linkage.json) is derived from the frozen `fd.linkage.v1.json`. It adds `<regex_automata::meta::regex::Regex as core::clone::Clone>::clone::{{closure}}` to `FUN_003b0160`, preserves its operational mangled identity and every other address, and records the pinned source/evidence hashes. The frozen primary GT/linkage, predictions, metrics, and the 13-file exposure inventory were not changed. No DefId or semantic MonoItem oracle was used.

The legacy scorer reproduced the stored corrected-primary and original-v1 secondary rows for all seven frozen fd predictions before applying the overlay. With the overlay, `label_pair` makes every pair touching `FUN_003b0160` ambiguous-neutral. Before/after scored-universe totals are:

| universe | P | N | neutral | scored | all pairs |
| --- | ---: | ---: | ---: | ---: | ---: |
| primary v1 | 3,179 | 2,446,152 | 18,200 | 2,449,331 | 2,467,531 |
| ambiguity v2 | 3,177 | 2,443,941 | 20,413 | 2,447,118 | 2,467,531 |

For the 2,221 pairs touching the address, the old labels were 2 positive, 2,211 negative, and 8 already ambiguous-neutral. The overlay changes all 2,221 to ambiguous-neutral, removing 2 positive and 2,211 negative pairs from the scored universe. Conservation holds in both views.

| arm | before TP/FP/FN/TN | after TP/FP/FN/TN | before F1 / macro_R / exact | after F1 / macro_R / exact |
| --- | --- | --- | --- | --- |
| C3-k16 | 87/56/3092/2446096 | 87/56/3090/2443885 | 0.052378/0.061283/0.042017 | 0.052410/0.061283/0.042017 |
| B2-body-score | 74/64/3105/2446088 | 72/64/3105/2443877 | 0.044619/0.068209/0.042017 | 0.043465/0.068209/0.042017 |
| random-0 | 54/53/3125/2446099 | 53/53/3124/2443888 | 0.032867/0.038491/0.016807 | 0.032288/0.035690/0.016807 |
| random-1 | 52/58/3127/2446094 | 52/58/3125/2443883 | 0.031621/0.051105/0.033613 | 0.031640/0.056708/0.033613 |
| random-2 | 49/60/3130/2446092 | 49/60/3128/2443881 | 0.029805/0.044472/0.025210 | 0.029823/0.050074/0.025210 |
| random-3 | 46/55/3133/2446097 | 45/55/3132/2443886 | 0.028049/0.037599/0.016807 | 0.027464/0.034798/0.016807 |
| random-4 | 47/51/3132/2446101 | 46/51/3131/2443890 | 0.028685/0.043727/0.025210 | 0.028100/0.040926/0.025210 |

The complete stage counts, precision/recall, candidate-positive sensitivity, per-origin values, and rank orders are in [sensitivity.json](sensitivity.json). Rank order is unchanged for precision, recall, F1, macro_R, and exact-group rate; C3 remains above B2 on F1 and below B2 on macro_R. The executable [verify_source_ambiguity.py](verify_source_ambiguity.py) rechecks source hash, all three 38-byte bodies, both relevant vtables, frozen primary/original rows, overlay preservation, and universe conservation.

Exact verification command: `python3.10 experiments/novel-source-2026-09-08/audit/verify_source_ambiguity.py` (the script requires Python 3.10.14). Python 3.12 can differ from the frozen rows only in final IEEE-754 bits of `macro_origin_recall` on four rows; integer label/count results and ambiguity conclusions are unchanged. The verifier intentionally rejects other versions instead of applying a blanket float tolerance.
