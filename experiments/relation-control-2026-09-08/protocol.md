# CallKin 관계 합의 선택 대조 연구 규약

상태: FROZEN DESIGN - OUTCOMES NOT RUN
작성일: 2026-09-08
승인: Root 확인 완료, outcome 실행 전
적용 design checklist: checked

이 문서는 실행 전 설계다. Root가 확인하고 protocol.md와 config.json의 hash를 고정하기 전에는 새 F4 또는 F6 결과를 만들지 않는다. 이 연구는 기존 결과를 본 개발 프로그램에 대한 선택 대조이며 새 원본 검증이나 일반화 실험이 아니다.

## 1. 비교 질문

같은 B2-k16 후보 풀에서 C3-k16의 F6 적격성 및 LCS 비용 stratum별 candidate quota를 유지할 때, 관계 합의를 포함한 C3-k16과 B2-body-score control의 pairwise F1이 다른가. Pairwise F1이 primary endpoint이고 threshold는 정하지 않는다. Precision, recall, macro_R와 exact_group_rate는 secondary descriptive metrics로 함께 보고한다.

C3의 F1이 높으면 이 quota-matched thinning 설계에서 관계 합의 선택에 따른 선택 특이 효과와 양립한다. F1과 secondary metric의 방향이 충돌하면 전체적인 우위로 선언하지 않고 충돌을 그대로 보고한다. 이 결과만으로 relation이 geometry와 독립적인 semantic information을 제공한다고 증명하지 않는다. B2-body-score의 F1이 높아도 quota가 C3에서 상속되므로 deployable body-only rule을 확정하지 않는다. 이 연구는 p-value, confidence interval 또는 유의성 검정을 사용하지 않는다.

## 2. 고정 대상과 기존 artifact

모든 case는 이미 결과를 본 plain O3S 개발 프로그램이다.

| case | build | profile | mode | source status |
| --- | --- | --- | --- | --- |
| zoxide | O3S | plain | out-in | previously exposed development data |
| fd | O3S | plain | out-in | previously exposed development data |
| ripgrep-main | O3S | plain | out-in | previously exposed development data |

기존 study 디렉터리 ../followup-2026-09-08의 다음 artifact를 byte identity와 SHA-256으로 고정한다.

- cache/<case>/body2-k16.candidates.json
- cache/<case>/combined3-k16.candidates.json
- inputs.json이 가리키는 body evidence와 fixture
- inputs.json이 가리키는 original ground truth와 linkage
- fd와 zoxide의 audit-corrections/* 파일
- 기존 protocol.md, README.md, config.json, inputs.json

새 disassembly, CFG 추출, source checkout, candidate 재검색은 하지 않는다. 기존 body evidence와 candidate artifact가 가리키는 provenance와 target universe가 서로 같은지 먼저 확인한다. C3 pair set은 B2 pair set의 부분집합이어야 하며, 두 artifact의 target ID set과 common input provenance는 같아야 한다. pair set 자체는 처리군과 풀의 목적상 다르다. core base commit은 7277f7e7d1d2fa5ee781b0f0c0d6626618f3a1bf로 고정한다.

## 3. Arm

처리군은 기존 combined3-k16.candidates.json을 그대로 쓰며 이름은 C3-k16이다. B2는 기존 body2-k16.candidates.json이다.

대조군은 B2에서만 만든다.

| arm | selection rule | use |
| --- | --- | --- |
| B2-body-score | 각 stratum에서 body score 내림차순 quota | primary comparison |
| random-0 | seed relation-control-2026-09-08/0 | descriptive variability |
| random-1 | seed relation-control-2026-09-08/1 | descriptive variability |
| random-2 | seed relation-control-2026-09-08/2 | descriptive variability |
| random-3 | seed relation-control-2026-09-08/3 | descriptive variability |
| random-4 | seed relation-control-2026-09-08/4 | descriptive variability |

각 control은 case별 C3 stratum quota를 그대로 쓴다. arm 내부에서는 replacement를 하지 않는다. B2에서 뽑으므로 C3와 다른 control 사이의 pair overlap은 허용하고 count와 fraction을 보고한다. overlap을 줄이기 위한 사후 제거는 하지 않는다.

## 4. Stratum과 selection

### 4.1 Endpoint eligibility

endpoint failure reason은 다음 세 token만 쓴다.

- missing: endpoint body가 없거나 B2 canonical target ID set에 없다.
- incomplete: body가 있으나 complete_decode=false다.
- opaque: opaque_indirect_jumps > 0이다.

pair의 ineligible reason은 두 endpoint에서 관찰한 모든 reason의 union이다. 중복을 제거하고 deterministic sorted tuple로 기록한다. 한 reason만 남기는 priority rule을 쓰지 않는다. 예를 들어 incomplete와 opaque가 있으면 tuple은 ["incomplete","opaque"]다.

reason이 없으면 F6 eligible이다. F6 policy는 opaque endpoint에서 abstain하므로 opaque는 eligible로 처리하지 않는다.

### 4.2 LCS cost bin

pair p=(a,b)의 nominal cost c는 양의 정수 instruction cell 수다.

    c = len(instructions_a) * len(instructions_b)

ineligible pair의 stratum cost는 0이다. eligible pair에서 c=0이면 cost0 별도 bin을 쓴다. positive c에는 다음 정수식을 사용한다.

    e = c.bit_length() - 1
    sub = ((c - 2**e) * 16) // 2**e

구현의 stratum 표현은 다음과 같다.

- eligible positive cost: ("complete/noopaque", (e, sub))
- eligible cost zero: ("complete/noopaque", "cost0")
- ineligible: ("abstain", sorted union of endpoint reasons)

stratum_label은 이 값을 sort_keys=true, separators=(",", ":")인 canonical JSON으로 직렬화한 문자열이다. 부동소수점 log, 반올림 또는 topology 값으로 bin을 바꾸지 않는다.

### 4.3 Exact quota

case와 stratum s에 대해 다음을 계산한다.

    q_s = number of C3 pairs in s
    n_s = number of B2 pairs in s

각 control은 B2의 s에서 정확히 q_s pair를 선택한다. n_s < q_s이면 replacement, 인접 bin 합치기 또는 quota 완화를 하지 않고 selection failure다.

각 control에 대해 다음을 검증한다.

    selected_count(s) == q_s
    eligible_count(s) == C3 eligible_count(s)
    ineligible_reason_count(s, reason) == C3 ineligible_reason_count(s, reason)

따라서 전체 candidate count, eligible count, ineligible reason count가 정확히 일치한다. 이 quota와 eligibility 및 cost matching은 C3의 non-label selection statistics를 control에 상속한다. 이는 control에 유리할 수 있으며 해석에서 공개한다. body score 분포 자체를 matching하는 설계가 아니다.

### 4.4 Random control order

각 B2 pair를 canonical endpoint order left < right로 쓴다. 다음 UTF-8 byte string의 SHA-256 digest를 계산한다.

    seed + NUL + case + NUL + stratum_label + NUL + pair.left + NUL + pair.right

digest ascending, pair.left ascending, pair.right ascending 순으로 정렬하고 앞에서 q_s개를 선택한다. OS entropy, Python random state 또는 실행 시각을 쓰지 않는다. digest, seed, case, stratum_label과 pair ID를 selection manifest에 기록한다.

### 4.5 Body-score order

B2 record의 token과 cfg view score만 읽는다. relation field, relation score, GT, linkage 또는 source audit는 읽지 않는다.

    body_score_min = min(token_score, cfg_score)
    body_score_mean = (token_score + cfg_score) / 2

각 stratum에서 다음 순서로 정렬한다.

1. body_score_min descending
2. body_score_mean descending
3. pair.left ascending
4. pair.right ascending

score는 반올림하지 않는다. token 또는 cfg score가 없으면 selection failure로 기록하며 relation score로 대체하지 않는다. score distribution matching이나 score threshold 조정은 하지 않는다.

### 4.6 Selection freeze와 진단

모든 control artifact와 selection manifest를 작성하고 hash한 뒤에만 F4 feature cache 또는 기존 F4/F6 prediction cache를 연다. selection 단계에서 GT, linkage, old decisions, old clusters를 열지 않는다. metadata에 다음을 true 또는 false로 저장한다.

- selection_frozen_before_f4_cache: true
- gt_used_for_selection: false
- relation_flags_used_for_selection: false

positive cost stratum의 control nominal cell sum과 C3 nominal cell sum의 상대 차이는 같은 16분할 bin에서 약 1/16, 즉 6.25% 이내가 기대된다. cost0와 ineligible stratum의 nominal cost는 0이어야 한다. stratum별 실제 deviation을 보고하고 이를 맞추기 위해 다시 뽑지 않는다.

다음은 matching 기준이 아니라 진단이다.

- n_s == q_s인 forced stratum 수
- forced pair 수와 forced pair fraction
- control별 C3 overlap count와 fraction
- selected candidate graph의 degree summary
- selected candidate graph의 connected component count와 size summary

degree, node topology, CFG topology, relation flag, final/prior color, in/out signature를 selection key나 matching key로 쓰지 않는다.

## 5. F6 실행

모든 case와 arm에 기존 F6를 그대로 적용한다.

| policy | value |
| --- | --- |
| structure_match_threshold | 0.95 |
| slot_match_threshold | 1.0 |
| structure_reject_threshold | null |
| require_informative_slot | true |
| abstain_on_opaque_indirect | true |
| max_comparison_count | 10000 |
| max_alignment_cell_budget | 500000000 |
| Rescue | off |

Align, Decide, tri-state classification, complete-link와 positive/neutral policy는 변경하지 않는다.

Candidate queue 전체를 먼저 price한다. candidate queue가 comparison 또는 alignment cell budget을 넘으면 arm 전체를 budget-refused로 기록하고 prefix 품질을 내지 않는다. queue가 예산 안에 들어간 뒤 complete-link on-demand cross-pair가 남은 예산을 넘으면 기존 동작대로 해당 merge를 comparison_budget blocked merge로 기록하고 다음 edge를 계속 처리한다. 이 on-demand shortage만으로 arm 전체를 폐기하지 않는다.

각 arm의 budget은 독립적이다. deterministic body-only F4 feature cache를 physical work에 공유할 수 있으나 cache hit로 logical cost를 줄이지 않는다. candidate와 on-demand 비교 수 및 alignment cells, total logical cost, physical cache cost, cache hit 수와 timing을 분리해 기록한다. cache 공유를 근거로 wall-time 승리를 주장하지 않는다.

각 arm은 Python 3.12.3, Linux RLIMIT_AS 12 GiB, process wall time 1800초 제한을 쓴다. max RSS를 별도 기록한다. address-space 또는 wall-time 중단은 resource-incomplete이며 품질 0점이 아니다.

## 6. Label plan

selection과 inference가 prediction artifact와 selection hash를 쓰기 전에는 ground truth와 linkage를 열지 않는다. prediction이 고정된 뒤 evaluator에서 기존 linkage label_pair의 positive, negative, duplicate-neutral, unresolved-neutral, ambiguous-neutral 규칙을 적용한다.

fd와 zoxide는 source-audit correction을 primary로 한다.

- audit-corrections/fd.gt.v1.json + audit-corrections/fd.linkage.v1.json
- audit-corrections/zoxide.gt.v1.json + audit-corrections/zoxide.linkage.v1.json

같은 case의 original ground truth와 linkage는 secondary sensitivity로 같은 prediction을 다시 채점한다. ripgrep-main은 보정 audit pair가 없으므로 original ground truth와 linkage만 primary로 쓴다. ripgrep에 source correction sensitivity가 있다고 쓰지 않는다. label universe 또는 provenance mismatch이면 점수를 만들지 않고 join failure를 기록한다.

## 7. Metrics

결과가 없는 arm은 0으로 치환하지 않는다. budget-refused 또는 resource-incomplete의 quality fields는 NA다.

### 7.1 Candidate와 selection metrics

각 case와 arm에 다음을 기록한다.

- target_count
- candidate_pair_count
- candidate_comparisons
- candidate_alignment_cells
- eligible_pair_count
- ineligible_pair_count
- ineligible_count_by_reason
- per-stratum quota, pool, selected count, forced flag
- nominal_alignment_cells_by_stratum
- nominal_cost_deviation_by_stratum
- forced_selection_strata_count
- forced_selection_pair_count
- forced_selection_pair_fraction
- c3_overlap_count
- c3_overlap_fraction
- candidate_graph_summary

GT를 읽은 뒤에만 candidate_positive_pairs와 candidate_positive_recall을 붙인다. 이 두 값은 selection key가 아니다.

### 7.2 F6 quality metrics

기존 scorer 출력 계약을 그대로 쓴다.

    TP, FP, FN, TN
    precision = TP / (TP + FP)
    recall = TP / (TP + FN)
    f1 = 2 * TP / (2 * TP + FP + FN)
    macro_origin_recall = mean(origin별 positive pair recall)

표에서는 macro_origin_recall을 macro_R로도 표시한다. 함께 저장할 quality fields는 다음과 같다.

- target_count
- TP, FP, FN, TN
- precision, recall, f1
- macro_origin_recall 및 macro_R
- exact_group_rate
- positive_pairs, scored_pairs, neutral_pairs
- per_origin
- positive_first_outcome
- on_demand_positive_compared
- comparison_cost

positive_first_outcome의 recovered, observation_ineligible, comparison_budget, not_retrieved_or_requested, complete_link_not_retained, structure_failed, slot_policy_failed 합은 primary label의 positive pair 수와 같아야 한다.

### 7.3 Actual cost metrics

prediction의 comparison_cost에는 기존 F6 raw field를 그대로 보존한다.

- candidate_detailed_comparison_count
- on_demand_comparison_count
- candidate_alignment_cells
- on_demand_alignment_cells
- total_detailed_comparisons
- total_alignment_cells
- abstain_comparison_count
- budget_blocked_merge_count
- budget_limited
- remaining_comparisons
- remaining_alignment_cells
- cache_hit_count

별도 metadata에는 physical_cache_comparisons, physical_cache_alignment_cells, wall_seconds, max_rss와 status를 기록한다. nominal cost와 actual on-demand cost는 다를 수 있으며 total_detailed_comparisons와 total_alignment_cells를 arm의 logical cost로 보고한다.

### 7.4 Source-corrected sensitivity

fd와 zoxide의 각 arm은 같은 prediction을 corrected primary와 original secondary에 채점한다. source-corrected-sensitivity.json에 다음을 둔다.

- primary와 secondary의 TP, FP, FN, TN
- primary와 secondary의 precision, recall, f1
- primary와 secondary의 macro_R
- primary와 secondary의 exact_group_rate
- primary_minus_secondary delta
- label join 및 provenance status

이는 audit correction에 대한 sensitivity이며 selection이나 prediction을 바꾸지 않는다.

### 7.5 Primary 비교와 random5

주 비교는 각 case의 C3-k16 대 B2-body-score다. case별로 precision, recall, f1, macro_R, exact_group_rate, candidate_positive_recall 및 actual cost 차이를 기록한다.

B2 random-0부터 4까지는 각 metric의 mean, min, max와 seed별 값을 기술 통계로만 보고한다. p-value, confidence interval, significance claim, Rust generalization claim을 만들지 않는다. raw pair count를 pooled하여 한 case가 결과를 지배하게 하지 않는다.

## 8. Expected outputs

다음은 결과 숫자가 아니라 현재 relation-control runner가 검증할 실행 계약이다. selector helper가 이 경로와 다르면 실행 전에 helper를 계약에 맞춘다.

- selection/<case>.json
  - case별 C3 quota, B2 pool count, random/body-score selection stats
  - canonical stratum encoding, eligibility reason counts, nominal cost deviation
  - forced selection, C3 overlap, selection hash와 source hash
- snapshot.json
  - reference input hash, config/protocol hash, selection hash, control artifact hash
- candidates/<case>/random-0.candidates.json through random-4.candidates.json
  - B2 canonical candidate schema와 selected pair list
- candidates/<case>/body-score.candidates.json
  - B2 canonical candidate schema와 selected pair list
- runs/<case>/<arm>/prediction.json, replay.prediction.json, metadata.json
  - fresh/replay F6 parity와 raw cost record
- run-summary.json
  - case와 arm별 실행 상태 및 metadata hash
- 각 arm의 evaluation record
  - 기존 F6 prediction schema와 scorer fields
  - raw comparison_cost, status, logical/physical cost와 timing

선택 stats에는 selected_count, selected_strata, candidate_comparisons,
candidate_alignment_cells, c3_overlap_count,
forced_selection_strata_count, forced_selection_pair_count와 stratum별
quota, pool, forced를 보존한다. F6 prediction의 comparison_cost에는
candidate_detailed_comparison_count, on_demand_comparison_count,
candidate_alignment_cells, on_demand_alignment_cells,
total_detailed_comparisons, total_alignment_cells,
abstain_comparison_count, budget_blocked_merge_count, budget_limited,
remaining_comparisons, remaining_alignment_cells, cache_hit_count를
보존한다. Evaluation은 7.2의 기존 scorer field와 primary label identity를
보존한다. 별도 summary를 만들면 raw pair count를 pooled하지 않고 case별
C3 대 body-score와 random5 mean/min/max를 표시한다.

## 9. Risks

1. 세 case는 이미 노출된 개발 데이터이므로 새 원본 일반화가 아니다.
2. C3의 non-label quota와 eligibility 및 cost allocation을 control에 상속하므로 control이 유리할 수 있다.
3. body score는 선택 순위일 뿐 score distribution matching이 아니다.
4. degree와 topology를 match하지 않으므로 C3의 graph topology와 merge-order 변화가 estimand에 포함된다.
5. sparse stratum은 forced selection이 될 수 있으므로 forced fraction을 보고한다.
6. B2 sampling은 C3 overlap을 허용하므로 overlap을 보고하고 제거하지 않는다.
7. nominal cost와 on-demand actual cost가 다를 수 있으므로 두 값을 분리한다.
8. old F4 cache를 물리적으로 공유해도 arm별 logical cost와 budget은 독립이다.
9. corrected label이 없는 ripgrep은 original만 쓰며 보정 효과를 추정하지 않는다.
10. budget refusal과 resource interruption은 미완료이지 0점이 아니다.
11. floating point score는 반올림하지 않고 정해진 tie order를 쓴다.
12. selection hash와 모든 control artifact를 F4 cache open 전에 고정한다.

## 10. Freeze gate

Root는 실행 전에 다음을 확인한다.

- [ ] full core commit과 old artifact hash
- [ ] endpoint reason union과 deterministic serialization
- [ ] cost e, sub 정수식과 cost0 bin
- [ ] SHA-256 seed string과 hash input
- [ ] body-score min, mean, ID tie order
- [ ] exact C3 quota와 B2 pool rule
- [ ] 6.25% nominal cost QA와 actual on-demand reporting
- [ ] no degree/topology matching
- [ ] corrected label primary와 original secondary
- [ ] random5 descriptive-only analysis
- [ ] old F6 policy, Rescue off, per-arm resource limits
- [ ] selection hash before F4 cache open
- [ ] config.json protocol_sha256 update

이 문서는 설계 승인 상태이며 outcome은 아직 실행하지 않았다. 이 문서에는 결과 주장이 없다.
