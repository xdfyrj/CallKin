# 오프라인 retrieval 교집합 비교 경로

> 이 문서는 Understand-Anything 런타임 플러그인이 없는 환경에서 작성한 **manual scoped fallback**이다. 아래 13개 파일과 그 직접 의존 관계만 추적했으며, 저장소 전체 분석을 뜻하지 않는다. 자동 hook, 서버, dashboard는 만들거나 실행하지 않았다.

## 결론과 불변식

한 번 만든 `token+cfg+relation`, `top_k=32` multiview 후보 artifact를 재사용해 `k in {8,16,32}`의 두 조건을 오프라인에서 만들 수 있다.

- `C2(k) = token_k & cfg_k`
- `C3(k) = token_k & cfg_k & relation_k`
- 따라서 모든 k에서 `C3(k) subset-of C2(k)`다. relation view를 추가해 candidate pair 수나 candidate positive 수가 늘 수는 없다. 최종 family TP가 달라진다면 후보 pruning 뒤 complete-link merge 경로 또는 예산 사용이 달라졌기 때문이다.

`views[name].rank`는 각 endpoint의 방향별 top-k 순위 중 더 작은 값으로 저장된다. 각 view의 정렬은 score 내림차순, function ID 오름차순으로 고정되므로 같은 k32 artifact에서 `rank <= k`로 자른 결과는 그 view를 k로 다시 실행했을 때의 무방향 pair 선택과 일치한다 (`v1_candidates.generate_multiview_candidate_pairs`, `_symmetric_top_k`, `_grouped_symmetric_top_k`). 입력 body, fixture, profile version이 같다는 전제다.

기존 `analysis.v1_consensus_candidates.build_consensus_artifact`는 `_top_k` reason의 **개수**만 센다. 3-view source에 `minimum_views=2`를 적용하면 `token&cfg`가 아니라 세 가지 2-of-3 조합의 합집합이다. 이 비교에서는 필요한 view 이름과 rank cutoff를 직접 검사해야 한다. 파생 artifact는 top-level/config/pair schema를 그대로 두고 `pairs`와 열린 `provenance`만 바꾸면 `v1_candidates.validate_candidate_artifact`를 통과하며 F6 코드는 변경할 필요가 없다.

```text
body evidence JSON -- load_body_evidence -+- token profile/rank -+
                                         ├- CFG profile/rank ---+- k32 union artifact
fixture JSON -- load_case -- run_cg_wl --+- relation rank ------+
                                                               |
                                      named-view + rank filter |
                            +----------------------------------+---------------+
                            |                                                  |
                       C2(8/16/32)                                       C3(8/16/32)
                            |                                                  |
                            +-------- unchanged v1_engine F6 ------------------+
                                                  |
                                   family artifact + cost/status metrics
                                                  |
                               v1_pair_eval (+ optional linkage overlay)
```

## 실행 경로

1. `body_evidence.normalize_instruction`은 주소와 call target을 local skeleton에서 지우면서 operand shape, 상수, data slot을 보존하고, `body_evidence.build_cfg`는 address-free intraprocedural CFG를 만든다. 저장된 body artifact는 `body_similarity.load_body_evidence`가 `FunctionBody`로 읽는다.
2. `loader.load_case`가 fixture schema와 provenance를 검증해 `Case`를 만들고, `engine.run_cg_wl`이 call graph의 고정점 partition과 round trace를 만든다.
3. `v1_candidates.build_multiview_candidate_artifact_from_files`는 body/fixture join을 검증한 뒤 CG-WL 결과를 `relation_context_from_cgwl`로 바꾸고 `generate_multiview_candidate_pairs`를 호출한다. token, CFG, relation은 서로의 점수로 재정렬되지 않고 각각 독립 top-k를 만든다.
4. k32 source에서 아래 조건으로 6개 파생 queue를 만든다. source artifact의 pair record는 수정하지 않고 선택된 record만 유지하는 방식이 가장 안전하다.

   ```python
   def selected(pair, required_views, k):
       return all(
           pair["views"][name] is not None
           and pair["views"][name]["rank"] <= k
           for name in required_views
       )
   # required_views=("token", "cfg") 또는 ("token", "cfg", "relation")
   ```

   `reasons`만 보면 k32에서 그 view가 골랐다는 사실만 알 수 있고 k8/k16 경계를 알 수 없으므로 반드시 `views[*].rank`를 사용한다. 파생 provenance에는 최소한 `kind`, `required_views`, `rank_cutoff`, `source_candidate_sha256`, `source_pair_count`, `derived_pair_count`를 기록한다.
5. 각 queue를 같은 body artifact와 같은 `PairPolicyConfig`로 `v1_engine.build_family_artifact`에 넣는다. 이 단계가 unchanged F6 비교다. F6는 schema를 검증하고 실제 body hash 및 `stripped_sha256`, `candidate_selection_sha256`, `raw_graph_sha256`를 대조한다.
6. F6는 전체 candidate queue가 comparison/count budget에 들어오는지 먼저 계산한다. 통과하면 모든 candidate body pair를 비교하고, `match`만 margin 내림차순으로 처리하면서 cluster 사이 전체 cross-product가 모두 `match`일 때만 complete-link merge한다. 필요한 비후보 pair는 on-demand로 비교한다.
7. `analysis.v1_pair_eval.evaluate_family_artifact`가 strict accepted cluster를 pair로 펼쳐 GT와 평가한다. linkage audit가 있으면 `linkage_overlay.score_labeled_pairs`가 duplicate/folded/ambiguous/unresolved pair를 neutral로 제외한 primary metric과 source-origin metric을 추가한다. F7 rescue는 별도 후처리이며 unchanged F6 비교의 기본 결과와 섞지 않아야 한다.

## 검증과 예산

| 경계 | 실제 검사 | 비교 시 의미 |
|---|---|---|
| body ↔ fixture | `v1_candidates._validate_body_fixture_join`: case/build/profile/scope, stripped hash, raw-graph hash, candidate-selection hash | 서로 다른 추출 run의 retrieval 결합을 거부한다. |
| derived candidate ↔ body | `v1_engine.build_family_artifact`: body artifact SHA-256와 세 provenance hash | 파생 과정에서 원본 provenance를 보존해야 한다. |
| candidate schema | `v1_candidates.validate_candidate_artifact` | closed top-level/config/pair schema다. 파생 설명은 `provenance`에 둔다. |
| F6 queue | `PairEvidenceCache.demand/within_budget`, `build_family_artifact` | 전체 candidate queue를 선결제한다. 전체 한도를 넘으면 실행 전체가 예외로 끝난다. |
| F6 merge | cluster cross-product를 merge 전에 선결제 | partial merge 없이 해당 merge만 `comparison_budget`으로 막힌다. |
| F7 rescue | `family_rescue.check_inputs_agree`, `reserve_cost`, `RescueBudget` | strict family와 rescue queue의 8개 provenance 필드와 target universe를 맞추고 component 단위로 예약한다. |
| 평가 | `v1_pair_eval.evaluate_family_files`가 입력 artifact hash 기록, `_validate_metadata`가 case/build/profile 및 존재하는 stripped hash 확인 | GT의 `scope`는 검사하지 않으며 stripped hash가 한쪽에 없으면 mismatch 검사가 생략된다. |

`analysis.v1_consensus_candidates.cost_summary`의 alignment cell은 두 instruction 수의 곱을 합산한 사전 추정치다. opaque/incomplete pair의 무비용 abstain, F6 cache hit, complete-link on-demand 비교는 반영하지 않으므로 F6 artifact의 `metrics`와 함께 봐야 한다.

## 구체적 위험

- **전역 queue 거부:** F6는 candidate queue 전체가 한도에 들어오지 않으면 즉시 거부한다. k32 union을 F6에 먼저 넣은 뒤 내부 교집합을 기대할 수 없다. C2/C3 queue를 먼저 파생하고 각각 예산 적합성을 확인해야 한다.
- **subset 불변식의 오해:** `C3(k) subset-of C2(k)`이므로 relation 추가 뒤 candidate positive가 증가했다면 filter 정의나 rank 처리 오류다. 최종 TP 증가는 가능하지만 이는 더 작은 queue가 false bridge를 제거해 complete-link 경로를 바꾸거나 예산 차단을 피한 결과여야 한다.
- **비교/merge 순서:** candidate artifact는 pair ID 순으로 저장·비교되지만 merge 시도는 `match margin`, `structure_score`, pair ID 순이다. queue가 달라지면 초기 match edge뿐 아니라 현재 cluster, on-demand cross-pair, 남은 예산도 달라진다. 결과 차이는 retrieval precision만의 차이가 아니다.
- **relation metadata와 classifier 입력의 차이:** relation view와 `same_final_color`, `same_prior_color`, `same_out_signature`, `same_in_signature`는 후보 선택과 진단 기록에는 쓰이지만 `v1_engine.classify_pair`는 이 네 필드를 읽지 않는다. `call_shape_similarity`도 계산·기록되지만 match 조건의 informative slot 목록에는 없다. C3는 F6 점수를 바꾸지 않고 F6에 도달하는 pair 집합을 바꾼다.
- **consensus helper 의미:** 3-view artifact의 `minimum_views=2`는 named token+CFG 교집합이 아니다. helper 자체는 source candidate schema나 body hash를 검증하지 않는다. 파생 단계에서 source SHA-256와 schema를 확인해야 한다.
- **F7 queue 의미:** `family_rescue.build_components`는 모든 2-view candidate crossing으로 fragment component를 연결하고 `same_prior_color` pair만 bridge 증거로 센다. C2/C3 strict F6 비교 뒤 F7까지 적용하면 relation 역할이 다시 달라지므로 별도 분석 축으로 취급해야 한다.

## 기존 metric의 해석 한계

- family precision/recall은 accepted cluster를 모든 pair로 펼친 micro metric이다. 큰 origin/family가 조합 수에 따라 제곱 비중으로 지배한다.
- `correct_member_coverage`는 GT origin의 부분집합인 여러 strict fragment도 모두 올바른 member로 센다. fragmentation은 `exact_family_recovered_count`와 origin별 coverage를 함께 봐야 드러난다.
- `decision_confusion`은 실제로 평가된 candidate와 on-demand pair만 포함한다. queue별 표본과 on-demand 경로가 달라 C2와 C3 사이 classifier 성능을 같은 모집단처럼 직접 비교할 수 없다.
- 기본 pair recall은 모든 labeled positive pair를 분모로 삼아 retrieval miss와 F6 reject/unknown/merge block을 한 값에 섞는다. 현재 모듈에는 named-view별 candidate recall@k, F6 conditional precision, merge 성공률을 분리한 metric이 없다.
- linkage primary metric은 관측 불가능 pair를 neutral로 제외한다. 조건별 `neutral_fraction`과 `scored_pair_count`를 함께 보고 denominator가 같은지 확인해야 한다.
- prediction이 없으면 평가 precision은 `None`이지만 development policy selection은 match 또는 reject가 없을 때 precision을 `1.0`으로 둔다. 매우 보수적인 queue/config가 precision gate를 통과할 수 있다.
- `accepted_family_count`와 `accepted_cluster_member_count`는 순도나 완전성을 보장하지 않는다. pairwise P/R, exact recovery, origin별 correct coverage가 필요하다.

권장 비교 표의 최소 열은 `required_views`, `k`, derived pair/positive count, preflight cells, F6 candidate/on-demand comparisons와 cells, budget blocked merges, abstain/unknown 수, pair precision/recall/F1, exact families, correct member coverage, linkage scored/neutral counts다. 모든 행은 동일한 k32 source SHA-256, body SHA-256, fixture/projection provenance, F6 policy hash를 공유해야 한다.

## 함수 기준 학습 순서

1. 입력 정규화: `body_evidence.normalize_instruction` (169), `body_evidence.build_cfg` (306), `body_similarity.load_body_evidence` (101), `loader.load_case` (42)
2. relation context: `engine.run_cg_wl` (96), `v1_candidates.relation_context_from_cgwl` (535)
3. 독립 retrieval: `v1_retrieval_views.build_token_profiles` (119), `token_similarity` (162), `build_cfg_profiles` (180), `cfg_similarity` (251), `build_relation_profiles` (267), `relation_similarity` (341)
4. rank와 artifact: `v1_candidates.generate_multiview_candidate_pairs` (361), `build_multiview_candidate_artifact_from_files` (918), `validate_candidate_artifact` (688)
5. offline 파생: `analysis.v1_consensus_candidates.build_consensus_artifact` (25)의 제한과 `cost_summary` (63)
6. unchanged F6: `v1_engine.pair_features_from_bodies` (172), `classify_pair` (240), `PairEvidenceCache` (280), `build_family_artifact` (446)
7. 선택적 rescue: `slot_overlay.collect_slot_observations` (132), `family_template.build_family_template` (435), `family_rescue.check_inputs_agree` (113), `rescue_families` (338)
8. 평가: `linkage_overlay.score_labeled_pairs` (198), `analysis.v1_pair_eval.evaluate_family_artifact` (35), `select_development_policy` (232)
