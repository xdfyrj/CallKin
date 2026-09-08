# Results tables

Original retained GT; source-correction sensitivity is in audit-sensitivity.json.
Cases are previously exposed development data. NA denotes a non-completed inference, not zero accuracy.
Timing is a single observation with up to two concurrent cases; shared retrieval preparation is reported separately.

| Case | Method | Status | TP | FP | FN | P | R | F1 | Macro R | Exact group |
|---|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| zoxide | body2-k16 | completed | 19 | 19 | 1223 | 0.5000 | 0.0153 | 0.0297 | 0.0842 | 0.0566 |
| zoxide | body2-k32 | completed | 19 | 19 | 1223 | 0.5000 | 0.0153 | 0.0297 | 0.0842 | 0.0566 |
| zoxide | body2-k8 | completed | 18 | 16 | 1224 | 0.5294 | 0.0145 | 0.0282 | 0.0833 | 0.0566 |
| zoxide | combined3-k16 | completed | 18 | 15 | 1224 | 0.5455 | 0.0145 | 0.0282 | 0.0833 | 0.0566 |
| zoxide | combined3-k32 | completed | 18 | 15 | 1224 | 0.5455 | 0.0145 | 0.0282 | 0.0833 | 0.0566 |
| zoxide | combined3-k8 | completed | 18 | 15 | 1224 | 0.5455 | 0.0145 | 0.0282 | 0.0833 | 0.0566 |
| zoxide | exact | completed | 562 | 167 | 680 | 0.7709 | 0.4525 | 0.5703 | 0.2681 | 0.1509 |
| zoxide | rescue-k16 | completed | 18 | 15 | 1224 | 0.5455 | 0.0145 | 0.0282 | 0.0833 | 0.0566 |
| zoxide | v0 | completed | 161 | 221 | 1081 | 0.4215 | 0.1296 | 0.1983 | 0.2867 | 0.1132 |
| fd | body2-k16 | completed | 93 | 81 | 3087 | 0.5345 | 0.0292 | 0.0555 | 0.0775 | 0.0500 |
| fd | body2-k32 | budget-refused | NA | NA | NA | NA | NA | NA | NA | NA |
| fd | body2-k8 | completed | 91 | 80 | 3089 | 0.5322 | 0.0286 | 0.0543 | 0.0774 | 0.0500 |
| fd | combined3-k16 | completed | 87 | 56 | 3093 | 0.6084 | 0.0274 | 0.0524 | 0.0608 | 0.0417 |
| fd | combined3-k32 | completed | 87 | 59 | 3093 | 0.5959 | 0.0274 | 0.0523 | 0.0608 | 0.0333 |
| fd | combined3-k8 | completed | 87 | 55 | 3093 | 0.6127 | 0.0274 | 0.0524 | 0.0608 | 0.0417 |
| fd | exact | completed | 803 | 2816 | 2377 | 0.2219 | 0.2525 | 0.2362 | 0.2590 | 0.1333 |
| fd | rescue-k16 | completed | 87 | 56 | 3093 | 0.6084 | 0.0274 | 0.0524 | 0.0608 | 0.0417 |
| fd | v0 | completed | 1843 | 4554 | 1337 | 0.2881 | 0.5796 | 0.3849 | 0.3619 | 0.1333 |
| ripgrep-main | body2-k16 | budget-refused | NA | NA | NA | NA | NA | NA | NA | NA |
| ripgrep-main | body2-k32 | budget-refused | NA | NA | NA | NA | NA | NA | NA | NA |
| ripgrep-main | body2-k8 | budget-refused | NA | NA | NA | NA | NA | NA | NA | NA |
| ripgrep-main | combined3-k16 | completed | 428 | 425 | 3429 | 0.5018 | 0.1110 | 0.1817 | 0.1349 | 0.1037 |
| ripgrep-main | combined3-k32 | budget-refused | NA | NA | NA | NA | NA | NA | NA | NA |
| ripgrep-main | combined3-k8 | completed | 421 | 424 | 3436 | 0.4982 | 0.1092 | 0.1791 | 0.1334 | 0.1037 |
| ripgrep-main | exact | completed | 795 | 431270 | 3062 | 0.0018 | 0.2061 | 0.0036 | 0.3044 | 0.1951 |
| ripgrep-main | rescue-k16 | completed | 753 | 425 | 3104 | 0.6392 | 0.1952 | 0.2991 | 0.1395 | 0.1098 |
| ripgrep-main | v0 | completed | 302 | 57162 | 3555 | 0.0053 | 0.0783 | 0.0098 | 0.2576 | 0.1280 |
