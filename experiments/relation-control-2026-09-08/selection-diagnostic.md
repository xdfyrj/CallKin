# Selection diagnostic

## 범위와 자료

이 문서는 이미 노출된 세 사례 `fd`, `zoxide`, `ripgrep-main`에서 `C3-k16`과 `B2-body-score`의 차이를 사후에 기술한다. 방향은 `C3 - B2`다. 21개 예측은 그대로 두고, scoring agent가 확정한 최종 평가만 읽었다.

- 최종 per-arm 평가: `runs/<case>/<arm>/evaluation.json`
- 예측: `runs/<case>/<arm>/prediction.json`
- 전체 요약: `results-summary.csv`, `primary-deltas.json`
- scorer alias 수정 기록: `archive/scoring-attempt1-macro-alias/fix-note.txt`; 최종 evaluator SHA-256 `e418d9e22553b4c0d486f3ea86a54ab50e711aa37e071906154b4102949e8506`

`fd`와 `zoxide`는 frozen source-audit corrected GT/linkage를, `ripgrep-main`은 corrected pair가 없어 frozen original linkage를 label proxy로 쓴다. 아래 origin label은 이 proxy의 문자열이며 새로운 source 판정이 아니다. 모든 수치는 descriptive post-hoc 결과다. 인과 효과, 새 일반화, 또는 다음 protocol의 verdict를 주장하지 않는다.

## 전체 비교

| case | candidate positive recall, C3 / B2 | TP / FP / FN, C3 / B2 | pairwise F1, C3 / B2 | macro_R, C3 / B2 |
| --- | --- | --- | --- | --- |
| `zoxide` | 290/1239 `.234060` / 315/1239 `.254237` | 18/15/1221 / 18/15/1221 | `.028302` / `.028302` | `.084890` / `.084890` |
| `fd` | 845/3179 `.265807` / 831/3179 `.261403` | 87/56/3092 / 74/64/3105 | `.052378` / `.044619` | `.061283` / `.068209` |
| `ripgrep-main` | 922/3857 `.239046` / 961/3857 `.249157` | 428/425/3429 / 440/403/3417 | `.181741` / `.187234` | `.134914` / `.147182` |

### Candidate와 first outcome

`NR`은 `not_retrieved_or_requested`, `OI`는 `observation_ineligible`, `R`은 `recovered`, `SF`는 `structure_failed`, `SP`는 `slot_policy_failed`, `CL`은 `complete_link_not_retained`다. Stage 합계는 각 사례의 positive-pair 수와 같다.

| case | C3 first outcome | B2 first outcome |
| --- | --- | --- |
| `zoxide` | `NR 801, OI 186, R 18, SF 158, SP 76` | `NR 791, OI 186, R 18, SF 155, SP 89` |
| `fd` | `NR 2182, OI 229, R 87, SF 358, SP 323` | `NR 2192, OI 229, R 74, SF 307, SP 377` |
| `ripgrep-main` | `NR 1360, OI 1658, R 428, SF 267, SP 143, CL 1` | `NR 1338, OI 1658, R 440, SF 276, SP 144, CL 1` |

Zoxide의 B2는 positive candidate를 25개 더 포함했지만 recovered는 늘지 않았다. Fd에서는 C3가 candidate positive 14개와 recovered 13개를 더 가졌다. C3의 first outcome은 B2보다 `R`이 13개 많고 `SP`가 54개 적지만 `SF`는 51개 많다. Ripgrep-main에서는 B2가 candidate positive 39개와 recovered 12개를 더 가졌다. 이 stage 이동은 각 frozen selection에서 관찰된 분해이며, 어느 stage가 원인이라고 단정하지 않는다.

## TP 차이를 만든 origin 그룹

`per_origin.recovered_pairs`의 차이를 절댓값 순으로 확인했다. `positive`는 해당 origin의 frozen positive pair 수이고 `members`는 target member 수다.

| case | C3 - B2 recovered | origin label | C3 / B2 recovered of positive | members |
| --- | ---: | --- | --- | ---: |
| `fd` | +16 | `aho_corasick::automaton::Automaton::try_find_overlapping` | 26/91 / 10/91 | 14 |
| `fd` | -3 | `regex_automata::meta::regex::Builder::build_many_from_hir::{{closure}}` | 0/3 / 3/3 | 3 |
| `ripgrep-main` | -8 | `grep_searcher::searcher::glue::MultiLine<M,S>::sink_context` | 7/15 / 15/15 | 6 |
| `ripgrep-main` | +7 | `aho_corasick::automaton::Automaton::try_find_overlapping` | 7/28 / 0/28 | 8 |
| `ripgrep-main` | -4 | `grep_searcher::searcher::core::Core<M,S>::after_context_by_line` | 3/15 / 7/15 | 6 |
| `ripgrep-main` | -4 | `grep_searcher::searcher::core::Core<M,S>::match_by_line` | 3/15 / 7/15 | 6 |
| `ripgrep-main` | -4 | `grep_searcher::searcher::core::Core<M,S>::match_by_line_slow` | 3/15 / 7/15 | 6 |

Fd의 pairwise F1과 macro_R가 반대 방향인 이유는 집계 단위가 다르기 때문이다. frozen scorer `experiments/followup-2026-09-08/score_followup.py:60-81`은 TP/FP/FN을 전체 pair에서 합산하고, `macro_origin_recall`은 origin별 recall의 단순 평균을 낸다. 따라서 14-member `aho_corasick` origin의 91 pair에서 C3가 16개를 더 회수한 효과는 pairwise 합계에 크게 반영된다. 반면 3-member `regex_automata` origin은 C3가 3개를 모두 잃었다. 그 결과 전체 TP는 87 대 74, FP는 56 대 64로 C3 F1이 높지만, origin 하나의 recall이 1에서 0으로 바뀌어 equal-weight macro_R는 B2가 높다. 이는 큰 origin weighting에 대한 설명이지 어느 지표가 유일하게 옳다는 뜻은 아니다.

Fd의 `regex_automata::meta::regex::Builder::build_many_from_hir::{{closure}}` 3-member 그룹은 추가 source-site audit의 우선 대상이다. `fd`의 frozen `Cargo.lock`은 `regex-automata` 0.4.14를 가리키고 `src/meta/regex.rs:3600-3617`에는 map borrow와 `create_cache`라는 두 closure site가 보이지만, 세 member가 여러 site에서 섞였다는 뜻은 아니며 한 closure의 monomorph일 수도 있으므로 현재는 frozen label 지표 설명으로만 남긴다.

## Zoxide의 동일 F1 검증

동일한 F1이 동일 partition을 뜻하지 않는다. `zoxide`에서 C3는 accepted cluster 26개, 63 member이고 B2는 25개, 60 member였다. accepted member-set을 비교하면 다음 차이가 있다.

- C3-only: `anyhow::__private::format_err` 3-member cluster. 세 pair는 frozen primary label상 `duplicate-neutral`이라 TP가 아니다.
- C3-only: `anyhow::error::impl=anyhow::Error::msg`와 `anyhow::kind::Adhoc::new`의 mixed pair 1개. 이는 negative라 FP 1개다.
- B2-only: `<clap_lex::ShortFlags as core::iter::traits::iterator::Iterator>::next`와 `clap_lex::ShortFlags::next_flag`의 mixed pair 1개. 역시 negative라 FP 1개다.

따라서 accepted partition은 다르지만 C3-only와 B2-only에서 primary FP가 각각 1개이고, duplicate-neutral pair는 점수에서 제외되어 두 arm의 TP/FP/FN/F1가 같아졌다. 이 확인은 `runs/zoxide/C3-k16/prediction.json`, `runs/zoxide/B2-body-score/prediction.json`과 current evaluation의 frozen label proxy를 함께 사용했다.

## Ripgrep-main body-score 승리의 범위

현재 frozen `ripgrep-main`, `plain/O3S`, `rust-nonstd` universe에서 B2-body-score의 F1은 `.187234`로 C3-k16의 `.181741`보다 높고, macro_R도 `.147182` 대 `.134914`로 높다. B2는 candidate positive recall도 `.249157` 대 `.239046`, TP도 440 대 428이었다. 이 결과는 이 한 노출 사례와 이 두 frozen selection arm에서 body-score control이 더 높은 pairwise 점수를 냈다는 뜻이다. body evidence 또는 B2 selection의 일반적 우월성으로 확장하지 않는다.

이 문서는 scorer, F4/core, config, labels, predictions를 변경하지 않았다. 다음 판단은 root가 frozen study의 전체 자료와 protocol 범위 안에서 한다.
