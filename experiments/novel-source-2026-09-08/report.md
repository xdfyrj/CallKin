# CallKin 신규 소스 검증 최종 보고서

기록일: 2026-09-09

상태: 세 controlled source case의 여섯 arm, 총 18개 prediction과 score 완료

이 보고서는 `hexyl-v0170`, `hyperfine-v1200`, `tokei-v1500`의 고정된 결과를
정리한다. 세 project는 일부 dependency와 author lineage를 공유하므로 서로
독립적인 new origin 표본으로 세지 않는다. CallKin-Real은 stripped-only 별도
조건이며 controlled 결과와 합치지 않는다.

## 핵심 판단

C3는 B2보다 일관된 F1 개선을 보이지 않았다. Hexyl에서만 FP가 2개 줄어
0.02122015915에서 0.02127659574로 소폭 상승했고, hyperfine과 tokei에서는
B2보다 낮았다. B2-body-score는 C3의 candidate count, eligibility, cost-stratum
quota를 상속한 matched control이다. Rescue는 세 case에서 모두 rescued family를
만들지 않았다. Exact token hash는 hexyl과 hyperfine에서 강했지만, tokei에서는
V0보다 낮았다.

## Controlled primary metrics

Primary label은 각 case의 original symbol-normalization GT와 linkage다. 기존
positive, negative, duplicate-neutral, unresolved-neutral, ambiguous-neutral
규칙을 그대로 적용했다. 표의 수치는 CSV와 score JSON을 소수점 여섯 자리로
표시한 값이다.

| case | arm | targets | positive pairs | Precision | Recall | F1 | macro_R | exact_group_rate | TP / FP / FN |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| hexyl-v0170 | V0-relation | 568 | 727 | 0.500000 | 0.231087 | 0.316087 | 0.362170 | 0.243902 | 168 / 168 / 559 |
| hexyl-v0170 | exact-token-hash | 568 | 727 | 0.814570 | 0.507565 | 0.625424 | 0.337751 | 0.146341 | 369 / 84 / 358 |
| hexyl-v0170 | B2-token-cfg | 568 | 727 | 0.296296 | 0.011004 | 0.021220 | 0.102787 | 0.073171 | 8 / 19 / 719 |
| hexyl-v0170 | C3-token-cfg-relation | 568 | 727 | 0.320000 | 0.011004 | 0.021277 | 0.102787 | 0.073171 | 8 / 17 / 719 |
| hexyl-v0170 | B2-body-score | 568 | 727 | 0.320000 | 0.011004 | 0.021277 | 0.102787 | 0.073171 | 8 / 17 / 719 |
| hexyl-v0170 | C3-rescue | 568 | 727 | 0.320000 | 0.011004 | 0.021277 | 0.102787 | 0.073171 | 8 / 17 / 719 |
| hyperfine-v1200 | V0-relation | 753 | 686 | 0.208672 | 0.112245 | 0.145972 | 0.280526 | 0.129630 | 77 / 292 / 609 |
| hyperfine-v1200 | exact-token-hash | 753 | 686 | 0.804795 | 0.342566 | 0.480573 | 0.241959 | 0.111111 | 235 / 57 / 451 |
| hyperfine-v1200 | B2-token-cfg | 753 | 686 | 0.695652 | 0.046647 | 0.087432 | 0.060908 | 0.018519 | 32 / 14 / 654 |
| hyperfine-v1200 | C3-token-cfg-relation | 753 | 686 | 0.684211 | 0.037901 | 0.071823 | 0.039009 | 0.000000 | 26 / 12 / 660 |
| hyperfine-v1200 | B2-body-score | 753 | 686 | 0.657143 | 0.033528 | 0.063800 | 0.039383 | 0.000000 | 23 / 12 / 663 |
| hyperfine-v1200 | C3-rescue | 753 | 686 | 0.684211 | 0.037901 | 0.071823 | 0.039009 | 0.000000 | 26 / 12 / 660 |
| tokei-v1500 | V0-relation | 2,216 | 1,701 | 0.106626 | 0.285714 | 0.155296 | 0.361787 | 0.176871 | 486 / 4,072 / 1,215 |
| tokei-v1500 | exact-token-hash | 2,216 | 1,701 | 0.123571 | 0.196943 | 0.151859 | 0.278979 | 0.170068 | 335 / 2,376 / 1,366 |
| tokei-v1500 | B2-token-cfg | 2,216 | 1,701 | 0.523529 | 0.052322 | 0.095136 | 0.133531 | 0.102041 | 89 / 81 / 1,612 |
| tokei-v1500 | C3-token-cfg-relation | 2,216 | 1,701 | 0.629630 | 0.049971 | 0.092593 | 0.112929 | 0.088435 | 85 / 50 / 1,616 |
| tokei-v1500 | B2-body-score | 2,216 | 1,701 | 0.577465 | 0.048207 | 0.088985 | 0.132718 | 0.102041 | 82 / 60 / 1,619 |
| tokei-v1500 | C3-rescue | 2,216 | 1,701 | 0.629630 | 0.049971 | 0.092593 | 0.112929 | 0.088435 | 85 / 50 / 1,616 |

이 세 case만으로 p-value, 유의성 주장, Rust 프로그램 일반화 주장을 만들지
않는다. Exact arm의 높은 F1은 source-independent identity의 증거가 아니다.
Hexyl에서 exact arm이 얻은 TP 369개는 모두 `clap_builder` 298개와 `anyhow`
71개의 dependency origin에서 나왔다.

## Candidate selection and logical cost

F6 strict arm은 모두 10,000 detailed comparisons와 500,000,000 logical
alignment cells ceiling을 사용했다. B2와 C3의 initial candidate cost는 달랐고,
on-demand comparison은 별도로 기록했다. V0와 exact arm은 F6 alignment를
실행하지 않는다.

| case | B2 total comparisons / cells | C3 total comparisons / cells | body-score total comparisons / cells | Rescue additional comparisons / cells |
| --- | ---: | ---: | ---: | ---: |
| hexyl-v0170 | 1,545 / 156,185,877 | 497 / 60,682,116 | 497 / 60,689,557 | 353 / 915,387 |
| hyperfine-v1200 | 1,627 / 235,955,935 | 373 / 48,627,844 | 373 / 48,539,320 | 321 / 669,314 |
| tokei-v1500 | 4,661 / 235,983,667 | 2,148 / 40,692,981 | 2,150 / 40,652,013 | 612 / 3,852,680 |

| case | B2 candidate pairs | C3/body-score pairs | body-score and C3 overlap | forced pairs / strata | nominal cost deviation |
| --- | ---: | ---: | ---: | ---: | ---: |
| hexyl-v0170 | 2,110 | 656 | 484 / 73.78% | 26 / 12 | 0.0123% |
| hyperfine-v1200 | 2,313 | 535 | 362 / 67.66% | 35 / 8 | 0.1815% |
| tokei-v1500 | 6,424 | 2,676 | 2,252 / 84.16% | 293 / 11 | 0.1021% |

Body-score는 각 C3 cost stratum의 quota를 B2 pool에서 선택한 뒤 body score의
min, mean, pair ID 순서만 사용했다. 그러므로 이 arm은 C3 quota를 상속한 control로
읽어야 한다. Rescue는 C3 strict partition 뒤 existing `f7-rescue-v1`을
사용했으며 세 case의 rescued family count는 모두 0이다.

## Positive first-outcome stages

다음 표는 F6 strict 또는 strict input에서 1차로 관찰한  positive pair의 손실
위치다. 각 행의 합은 해당 case의 positive pair 수와 일치한다. C3-rescue는
strict C3의 stage를 그대로 유지하므로 별도 행을 반복하지 않았다.

| case | arm | recovered | observation ineligible | structure failed | slot policy failed | not retrieved or requested |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| hexyl-v0170 | B2-token-cfg | 8 | 53 | 133 | 345 | 188 |
| hexyl-v0170 | C3-token-cfg-relation | 8 | 53 | 93 | 160 | 413 |
| hexyl-v0170 | B2-body-score | 8 | 53 | 84 | 169 | 413 |
| hyperfine-v1200 | B2-token-cfg | 32 | 79 | 184 | 182 | 209 |
| hyperfine-v1200 | C3-token-cfg-relation | 26 | 79 | 113 | 27 | 441 |
| hyperfine-v1200 | B2-body-score | 23 | 79 | 106 | 31 | 447 |
| tokei-v1500 | B2-token-cfg | 89 | 471 | 319 | 211 | 611 |
| tokei-v1500 | C3-token-cfg-relation | 85 | 471 | 212 | 155 | 778 |
| tokei-v1500 | B2-body-score | 82 | 471 | 200 | 162 | 786 |

## Secondary scopes

Project-owned scope는 기존 `gt_extractor.belongs_to_subject` namespace 규칙을
사용했다. Previously-unobserved scope는 13개 exposure GT 파일에서 만든
normalized-origin label set에 없는 origin을 고른다. 두 scope 모두 target address
에 known origin이 하나만 있는 경우만 포함하고, prediction cluster를 자른 뒤
regroup하지 않았다.

아래 TP 열은 arm 순서 `[V0, exact, B2, C3, body-score, Rescue]`에 따른다.

| case | project-owned target / positive / TP | previously-unobserved target / positive / TP |
| --- | --- | --- |
| hexyl-v0170 | 37 / 1 / 0, 0, 0, 0, 0, 0 | 49 / 2 / 0, 0, 0, 0, 0, 0 |
| hyperfine-v1200 | 49 / 3 / 0, 0, 0, 0, 0, 0 | 270 / 168 / 31, 22, 19, 17, 11, 17 |
| tokei-v1500 | 102 / 10 / 1, 0, 0, 0, 0, 0 | 458 / 219 / 71, 36, 7, 7, 7, 7 |

`previously-unobserved`는 `not present in this inventoried normalized-origin-label
set`이라는 운영적 구분이다. source definition이 실제로 미관측이라는 증거가
아니다. Project-owned mask와 exposure mask의 target 구성도 source-independent
표본을 보장하지 않는다.

## Observation provenance

| case | body functions | fixture nodes | raw-graph functions | transfers | GT origins | linkage multimember origins |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| hexyl-v0170 | 568 | 1,465 | 2,063 | 15,443 | 387 | 47 |
| hyperfine-v1200 | 753 | 1,748 | 2,442 | 16,367 | 548 | 63 |
| tokei-v1500 | 2,216 | 4,423 | 5,905 | 41,807 | 1,581 | 227 |

세 source는 각각 `sharkdp/hexyl` `v0.17.0` commit
`8eb6d4771ce1ec7af65d06bd335457783b77d557`, `sharkdp/hyperfine` `v1.20.0`
commit `975fe108c4ee7bd2600d10758207b44ca3dae738`, `XAMPPRocky/tokei`
`v15.0.0` commit `c14f744716272fadeb27a74443cdffa0af35f82f`에 고정했다. Build는
Cargo/rustc `1.93.1`, LLVM `21.1.8`, Linux
`x86_64-unknown-linux-gnu`, O3S/plain, locked Cargo input을 사용했다.

Target boundary는 non-stripped Rust symbol extent oracle에서 만들었다. Raw source
GT는 boundary와 후속 scoring에 사용했지만, clustering process에는 body, fixture,
named candidate input만 전달했고 origin label은 전달하지 않았다.

Angr observation에는 unsupported operation과 unconstrained register 관련 경고가
저장되어 있다. Hexyl에는 `Unsupported Unop Iop_GetMSBs8x16`, hyperfine에는
`Iop_CmpF64`와 `Iop_GetMSBs8x16`, tokei에는 `Iop_Ctz64`,
`Iop_GetMSBs8x16`, `amd64g_dirtyhelper_IN`, `Iop_64x4toV256` 등이 기록되었다.
따라서 이 자료는 bounded body/graph observation의 기록이며 full callgraph
coverage를 주장하지 않는다.

## CallKin-Real hexyl condition

CallKin-Real은 controlled run과 별도인 stripped-only discovery/inference 조건이다.
입력은 stripped hexyl fixture 하나였고 `--no-flirt`,
`--component-budgeted-v1`, `top_k=16`을 사용했다. Controlled GT, boundary,
linkage, body, candidates, cache는 analysis input이 아니었다.

| Real score scope | V0 relation-only | V1 strict | V1 strict + rescue | V1 relaxed provisional |
| --- | ---: | ---: | ---: | ---: |
| GT-overlap primary, 509 scored members | F1 0.2828 | F1 0.0190 | F1 0.0190 | F1 0.0190 |
| Full 568-ID posthoc supplementary | F1 0.2821 | F1 0.0189 | F1 0.0189 | F1 0.0189 |

GT-overlap primary의 TP/FP/FN은 V0 `165/278/559`, strict/rescue/relaxed
`7/7/717`이다. Full 568-ID supplementary에서 V0는 `165/278/562`, strict/rescue/
relaxed는 `7/7/720`이다. Full scope는 발견되지 않은 GT ID를 unresolved로 세는
posthoc 표이고, boundary oracle은 Real discovery/inference에 들어가지 않았다.

Real은 7,056 functions를 발견했다. 5,514개는 grouping member, 906개는
context-only node, 636개는 abstention이다. Body record는 6,151개이고 그중
5,515개가 complete, 636개가 incomplete였다. GT 568개 중 567개를 발견했고
complete body coverage는 0.8961이었다.

F5 component은 3,594개였고 3,567개를 선택, 27개를 618 member와 함께 deferred
상태로 남겼다. Strict F6는 2,882 comparisons와 2,512,526 cells로 106 family,
346 member를 accepted했다. F7은 1,807 comparisons와 1,077,296 cells를 사용했고
19개 component를 모두 거부했다. FLIRT를 끄므로 direct label과 propagation은
없다.

Run manifest의 전체 analyzer pipeline duration은 870.901초다. Lower-level
discovery, body, graph, stage-writing 기록의 duration은 558.688초다. 이 두
값은 서로 다른 측정 범위이므로 하나의 duration으로 더하거나 바꾸어 쓰지
않는다. Real 결과는 controlled method의 causal comparison이 아니라 별도 조건의
기술 통계다.

## Source audit

Hexyl audit는 기존 normalized `hexyl::run::{{closure}}` positive pair가
`src/main.rs:342`의 seek `map_err` closure와 `src/main.rs:353`의
`parse_byte_count` closure를 하나의 label로 합친 것을 확인했다. 두 body와 raw
symbol은 다르며, versioned source-site sensitivity에서는 이 pair를 나눠
project-owned positive가 P0이 된다. Frozen primary GT, linkage, prediction,
score는 바꾸지 않았다.

Old fd audit는 `FUN_003b0160`이 `regex.rs:3613` Builder closure의 retained
symbol membership를 가지는 동시에 `regex.rs:1916` Clone closure와 한 address를
공유할 수 있음을 확인했다. Separate ambiguity overlay는 그 address를 만지는
2,213 previously scored pair를 neutral로 만들었다. 구성은 2 positive와 2,211
negative였고, 나머지 8쌍은 이미 ambiguous-neutral이었다. Old method rank
direction은 바뀌지 않았다.

이 두 audit는 normalized group membership와 unique source-origin identity를
분리한다. Mangled symbol, body bytes, vtable, source-site evidence는 operational
proxy이며 compiler DefId 또는 semantic MonoItem identity의 증명이 아니다.
최종 bounded project-positive audit는 세 group을 검토했으며, 그 결과를 현재
primary에 소급하지 않는다. Hyperfine의 `Exporter::serialize`와 Tokei의
`Printer<W>::print_results`는 각각 하나의 generic source definition에서 나온
source-consistent group으로 판정되었다. Tokei의
`SyntaxCounter::parse_context::{{closure}}`는 script `from_mime` closure와
style/template `from_str` closure를 합친 cross-expression false pair였다.
후자의 body는 두 source site에서 재사용되어 정확한 line assignment가
ambiguous하므로 corrected GT/linkage는 쓰지 않았고, Tokei P10은 original
primary로 남겼다. 이 audit는 three named groups만 다루며 other generated groups는
검토 대상이 아니다.

## Reproduction and verification limits

Controlled three-case path는 source build -> boundary observation -> six
predictions -> prediction hash validation -> score까지 현재 로컬 artifact로
완료되어 있다. 첫 observation 시도는 `build_manifest` import error로 GT 생성
전에 끝났고, startup `sys.path` fix 뒤에 관측을 진행했다. Evaluator-only
arm-schema validation fix는 GT scoring 전에 적용했으며 prediction bytes는
바뀌지 않았다.

Hexyl build preflight는 source path를 유지한 same-path rebuild에서 canonical
GT와 fixture byte를 모두 재현했다. Source checkout을 다른 위치로 옮기고
relative source argument를 사용한 rebuild에서는 hash가 달라졌고 embedded
source path 변화가 관찰되었다. Source 위치와 argument spelling을 함께 바꾼
bounded check이므로 portable clean external full replay를 증명하지 않는다.

현재 score artifact hash는 다음과 같다.

| case | scores.json SHA-256 | summary.csv SHA-256 |
| --- | --- | --- |
| hexyl-v0170 | `bc046a81267cf5763922ca72785a30a2d1d23c745133e09610454778667078ad` | `3ead5b1a5cf86575d92b297ae755008a8ad6f81dbd7ca3f6980b6ef97339ae53` |
| hyperfine-v1200 | `1f882c41daf22170a042882e3b4287dce9c311a9a34cc66e3e58480f289d4522` | `ab5e3d694bba75982c986c2e10c941b69a1a50db6de534b7ac63b8541c102126` |
| tokei-v1500 | `257d8b48da728490b3aac83e799eb20644a609b9694ebbfc76dd2d2d56eec1b0` | `781f1e782b21a5e89d5d13921e62be7b78d7c5ddadae88bc1c0d37929e76b651` |

Local validation checked all 18 prediction hashes, 54 metric views, confusion
matrix conservation, stage sums, all Real manifest artifacts and postrun inventory,
and the hexyl source-site sensitivity. This is local artifact verification and is
not external human reproduction. The final artifact bundle is retained at
`4482a5cb5cb9084b7e12fe6722b118164d4f25efbcf9e3c473b43ab6be50eb59`.
No external human reproduction, portable clean full replay, or external published
method baseline comparison is claimed.

## Artifact links

- [Study README](README.md)
- [Frozen protocol](protocol.md)
- [Frozen config](config.json)
- [Hash manifest](hash-manifest.json)
- [Exposed origin labels](exposed-origins.json)
- [Hexyl score JSON](scores/hexyl-v0170/scores.json)
- [Hyperfine score JSON](scores/hyperfine-v1200/scores.json)
- [Tokei score JSON](scores/tokei-v1500/scores.json)
- [CallKin-Real report](real/hexyl-v0170/real-run-report.md)
- [CallKin-Real supplementary scope](real/hexyl-v0170/real-run-supplementary.json)
- [CallKin-Real evaluation](real/hexyl-v0170/evaluation.json)
- [Verification bundle ZIP](verification-bundle.zip)
- [Build reproducibility check](build-repro-check.md)
- [Hexyl source audit](audit/hexyl-source-audit.md)
- [Hexyl source-site sensitivity](audit/hexyl-source-site-sensitivity.md)
- [Hyperfine and Tokei project-source audit](audit/project-source-audit.md)
- [Old fd ambiguity sensitivity](audit/sensitivity-audit.md)
