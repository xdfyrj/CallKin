# 채점 파이프라인

## 1. 목적

CallKin의 `scores.py`는 CG-WL predicted partition과 compiler-symbol ground-truth partition을 비교한다.

```text
fixtures/plain/family_graph_03.O3S.fixture.json
-> engine.py
-> predicted clusters

ground_truth/plain/family_graph_03.O3S.gt.json
-> true origins

predicted clusters + true origins
-> scores.py
-> TP / FP / FN / TN
-> PR / RE / F1 / ARI
```

Ground truth는 이 단계에서 처음 grouping 결과와 만난다. `engine.py` 실행 중에는 전달되지 않는다.

## 2. 가장 단순한 실행

```bash
python3 scores.py billing-client --track direct-in
python3 scores.py billing-client --track angr
python3 scores.py billing-client --track angr --anchor-policy role
python3 scores.py family_graph_03 --candidate-scope subject
```

일반 CLI 기본값:

```text
case    = 사용자가 입력한 stem
build   = O3S
profile = plain
candidate scope = rust-nonstd
anchor policy = address
mode    = full
fixture = fixtures/rust-nonstd/plain/<case>.O3S.fixture.json
GT      = ground_truth/rust-nonstd/plain/<case>.O3S.gt.json
```

아래 출력 예시는 `--candidate-scope subject`로 실행한 동결
`family_graph_03` baseline이다.

핵심 출력:

```text
case : family_graph_03 / O3S / plain
mode: full
candidates: 13
candidate pairs: 78
rounds: 2
...
share: k_obs=3 clusters=2 pairs=1/3 collisions=-
TP=4 FP=1 FN=6 TN=67
PR=0.80 RE=0.40 F1=0.53 ARI=0.49
```

라운드별 scored partition도 함께 보려면 `--trace`를 사용한다.

```bash
python3 scores.py family_graph_03 --trace --candidate-scope subject
```

이 경우 `round 0(seed)`부터 마지막 `fixpoint` 확인 라운드까지 CLI에 추가로 출력된다.

`direct`가 기본 track이고 `rust-nonstd`가 기본 candidate scope다. Frozen
family-graph 결과는 `--candidate-scope subject`를 명시한다. Broad
`direct-in` fixture는 다음 경로에서 읽는다.

```text
fixtures/direct-in/rust-nonstd/plain/billing-client.O3S.fixture.json
```

`angr` fixture는 다음 경로에서 읽는다.

```text
fixtures/angr/rust-nonstd/plain/billing-client.O3S.fixture.json
```

Role policy fixture는 address fixture와 분리된다.

```text
fixtures/angr/role/rust-nonstd/plain/billing-client.O3S.fixture.json
```

Schema v5 fixture를 채점하면 CLI와 결과 JSON에 track, candidate scope, raw/projection hash,
candidate selection hash가 포함된다. Ground truth는 build에 속하고 track에는 속하지 않으므로 기존
scope별 `ground_truth/<scope>/<profile>/...` 파일을 사용한다.

## 3. 전체 함수 호출 순서

```text
main()
  -> CLI path/mode 결정
  -> score_case()
       -> load_case(fixture)
       -> load_ground_truth(GT)
       -> _check_join()
       -> run_cg_wl()
       -> 모든 scored pair 분류
       -> _pairwise_score()
       -> _adjusted_rand_index()
       -> _make_predicted_clusters()
       -> _make_origin_scores()
       -> ScoreReport
  -> format_report()
  -> optional write_reports_json()
```

`--all-modes`이면 같은 fixture/GT에 `score_case()`를 네 mode로 반복한다.

## 4. Ground truth loading

GT schema version은 5이며, cross-origin shared address를 보존하는 broad GT는 schema
version 6을 사용한다.

```json
{
  "case": "family_graph_03",
  "build": "O3S",
  "profile": "plain",
  "schema_version": 5,
  "provenance": {
    "build_id": "...",
    "source_sha256": "...",
    "non_stripped_sha256": "...",
    "stripped_sha256": "..."
  },
  "origins": [
    {
      "origin": "share",
      "members": [
        "FUN_001146b0",
        "FUN_00114a30",
        "FUN_00114d90"
      ]
    }
  ],
  "symbols": {
    "FUN_001146b0": ["family_graph_03::share"]
  }
}
```

`load_ground_truth()`는 JSON을 다음 dataclass로 바꾼다.

```text
GroundTruth
  -> OriginGroup(origin, members)
  -> symbols[member_id]
```

Loader는 다음을 검사한다.

- required/unknown field
- schema version
- manifest build provenance 형식
- 중복 origin 이름
- 빈 origin
- 한 member가 둘 이상의 origin에 포함되는지
- `symbols` key 집합과 member 전체 집합이 같은지
- schema v6 shared-address member와 원래 origin 목록의 형식

`GroundTruth.origin_of()`는 다음 lookup을 만든다.

```python
{
    "FUN_001146b0": "share",
    "FUN_00114a30": "share",
    "FUN_00114d90": "share",
}
```

## 5. Scored universe join

`_check_join()`은 점수 계산 전에 두 조건을 확인한다.

### Case/build/profile identity

```text
fixture.case  == GT.case
fixture.build == GT.build
fixture.profile == GT.profile
```

예를 들어 `plain` fixture와 `min` GT를 섞거나 O3S fixture와 O3KS GT를 섞으면 중단한다.

```text
case/build/profile mismatch: fixture=family_graph_03/O3S/plain
vs ground_truth=family_graph_03/O3S/min
```

Case/build/profile이 같아도 `build_id` 또는 source/non-stripped/stripped SHA-256이
다르면 서로 다른 build generation으로 보고 중단한다.

### Member universe

```text
fixture의 scored=true node ID 집합
==
GT의 모든 origin member ID 집합
```

이 검사가 필요한 이유는 pair 수가 candidate 수에 따라 달라지기 때문이다.

```text
13 candidates -> 13 * 12 / 2 = 78 pairs
12 candidates -> 12 * 11 / 2 = 66 pairs
```

서로 다른 universe를 비교하면 같은 metric이라고 말할 수 없다.

## 6. Pairwise 평가의 기본 생각

함수 하나를 맞혔는지 세지 않는다. 서로 다른 함수 두 개를 하나의 pair로 보고 다음 두 질문을 한다.

```text
Prediction: 두 함수가 같은 predicted cluster인가?
Truth     : 두 함수가 같은 origin인가?
```

두 답의 조합은 네 가지다.

| Prediction | Truth | Count |
|---|---|---|
| same cluster | same origin | TP |
| same cluster | different origin | FP |
| different cluster | same origin | FN |
| different cluster | different origin | TN |

### TP 예시

```text
A = share instance 1
B = share instance 2
prediction: 같은 C1
truth: 둘 다 share
=> TP
```

### FP 예시

```text
A = decoy_a
B = decoy_b
prediction: 같은 C4
truth: 서로 다른 origin
=> FP
```

### FN 예시

```text
A = share instance 1, predicted C1
B = share instance 3, predicted C2
truth: 둘 다 share
=> FN
```

### TN 예시

```text
A = share instance
B = drive_x instance
prediction: 다른 cluster
truth: 다른 origin
=> TN
```

## 7. fg03 O3S의 실제 pair count

Candidate는 13개다.

```text
all pairs = C(13, 2)
          = 13 * 12 / 2
          = 78
```

Ground truth의 same-origin pair는 다음과 같다.

```text
share   : C(3,2) = 3
leaf_p  : C(2,2) = 1
drive_x : C(3,2) = 3
drive_y : C(3,2) = 3
decoy_a : C(1,2) = 0
decoy_b : C(1,2) = 0
--------------------------------
total true same-origin pairs = 10
```

CG-WL이 복원한 same-origin pair:

```text
share   : 1/3
leaf_p  : 1/1
drive_x : 1/3
drive_y : 1/3
----------------
TP = 4
FN = 6
```

`decoy_a`와 `decoy_b`가 같은 cluster에 들어가므로:

```text
FP = 1
```

나머지 pair:

```text
TN = 78 - TP - FP - FN
   = 78 - 4 - 1 - 6
   = 67
```

최종 count:

```text
TP=4 FP=1 FN=6 TN=67
```

## 8. Precision, Recall, F1

연구 초기의 다른 PRN 용어와 구분하기 위해 출력에서는 Precision을 `PR`, Recall을 `RE`로 표시한다.

### Precision (`PR`)

```text
PR = TP / (TP + FP)
```

Fg03 O3S:

```text
PR = 4 / (4 + 1)
   = 4 / 5
   = 0.80
```

의미:

> 같은 family라고 묶은 pair 중 실제 같은 origin인 비율

### Recall (`RE`)

```text
RE = TP / (TP + FN)
```

Fg03 O3S:

```text
RE = 4 / (4 + 6)
   = 4 / 10
   = 0.40
```

의미:

> 실제 같은 origin pair 중 같은 cluster로 복원한 비율

### F1

```text
F1 = 2 * PR * RE / (PR + RE)
```

Fg03 O3S:

```text
F1 = 2 * 0.80 * 0.40 / (0.80 + 0.40)
   = 0.64 / 1.20
   = 0.533...
   -> 출력 0.53
```

## 9. ARI

ARI는 predicted partition과 true partition의 전체 일치를 chance-adjusted 방식으로 본다.

코드가 사용하는 값:

```text
index        = TP
same_cluster = TP + FP
same_origin  = TP + FN
total        = TP + FP + FN + TN
```

기대값과 최대값:

```text
expected = same_cluster * same_origin / total
maximum  = (same_cluster + same_origin) / 2
```

최종 공식:

```text
ARI = (index - expected) / (maximum - expected)
```

Fg03 O3S 값을 넣는다.

```text
index        = 4
same_cluster = 4 + 1 = 5
same_origin  = 4 + 6 = 10
total        = 78

expected = 5 * 10 / 78 = 0.641025...
maximum  = (5 + 10) / 2 = 7.5

ARI = (4 - 0.641025...) / (7.5 - 0.641025...)
    = 0.4897...
    -> 출력 0.49
```

## 10. 분모가 0인 경우

Predicted same pair가 하나도 없으면 `TP + FP == 0`이다. 코드는 이 경우 PR을 `1.0`으로 둔다.

True same-origin pair가 하나도 없으면 `TP + FN == 0`이다. 코드는 이 경우 RE를 `1.0`으로 둔다.

Node pair 자체가 없거나 partition denominator가 퇴화하면 ARI를 `1.0`으로 둔다.

이는 계산 예외를 피하기 위한 명시적 convention이다. Singleton-only case를 실제 성능 1.0으로 해석해서는 안 되며 raw TP/FP/FN/TN과 candidate count를 함께 봐야 한다.

## 11. Predicted cluster report

`_make_predicted_clusters()`는 engine cluster에 scoring-side 정보를 붙인다.

예시:

```text
C1:
  FUN_001146b0 | share | origin=share
  FUN_00114a30 | share | origin=share
```

각 member는 다음 정보를 가진다.

```text
id      = FUN_001146b0
symbols = [share]
origin  = share
```

Cluster 안에 서로 다른 origin이 있으면 `origins` 목록에 모두 표시된다.

```text
C4 origins = [decoy_a, decoy_b]
```

이는 관찰 가능한 collision을 보여주지만 원인을 자동 진단하지 않는다.

## 12. Origin별 결과

`_make_origin_scores()`는 origin 하나당 다음 값을 계산한다.

```text
origin
k_obs
predicted_cluster_count
recovered_pairs
total_pairs
colliding_origins
```

Fg03 O3S `share`:

```json
{
  "origin": "share",
  "k_obs": 3,
  "predicted_cluster_count": 2,
  "recovered_pairs": 1,
  "total_pairs": 3,
  "colliding_origins": []
}
```

의미:

```text
최종 binary에서 share instance 3개 관찰
그 3개가 predicted cluster 2개로 분할
가능한 같은-origin pair 3개 중 1개 복원
다른 origin과 합쳐진 cluster는 없음
```

Fg03 O3S `decoy_a`:

```json
{
  "origin": "decoy_a",
  "k_obs": 1,
  "predicted_cluster_count": 1,
  "recovered_pairs": 0,
  "total_pairs": 0,
  "colliding_origins": ["decoy_b"]
}
```

Singleton이므로 within-origin pair는 없지만 `decoy_b`와 같은 predicted cluster에 있다는 사실은 기록된다.

## 13. `ScoreReport`

한 case/mode 결과는 다음 정보를 하나의 객체에 담는다.

```text
case, build, profile, mode
candidate_count, pair_count, rounds
clusters
origins
pairwise score
trace (`--trace`를 요청한 경우)
```

이 객체 하나에서 CLI text와 JSON을 모두 만든다. Scoring을 다시 실행하는 별도 report generator는 없다.

## 14. JSON output

전체 pipeline 진단까지 저장하려면 `run_case.py`를 사용한다.

```bash
python3 run_case.py billing-client --track angr --all-modes \
  --json-output results/billing-client.angr.json
```

이 경로의 top-level schema는 version 5다. `run_summary`는 mode와 무관하므로 한 번만
저장하고, `results` 배열에 full/out/in/out-in 결과를 둔다.

```json
{
  "schema_version": 5,
  "run_summary": {
    "ground_truth": {
      "candidate_count": 320,
      "origin_count": 219,
      "generic_family_count": 42,
      "same_family_pair_count": 400
    },
    "extraction": {
      "indirect_call_summary": {
        "all_sources": {
          "total": 2117,
          "resolved_internal": 151,
          "resolved_import": 1521,
          "unresolved": 445,
          "target_resolution_rate": 0.7898,
          "internal_resolution_rate": 0.2534,
          "by_operand": {},
          "rejected": {}
        },
        "candidate_sources": {
          "total": 1005,
          "resolved_internal": 147,
          "resolved_import": 620,
          "unresolved": 238,
          "target_resolution_rate": 0.7632,
          "internal_resolution_rate": 0.3818,
          "by_operand": {},
          "rejected": {}
        }
      }
    },
    "candidate_impact": {},
    "candidate_observability": {},
    "execution": {},
    "artifact_summary": {},
    "tool_versions": {}
  },
  "results": [
    {"mode": "full"},
    {"mode": "out"},
    {"mode": "in"},
    {"mode": "out-in"}
  ]
}
```

`all_sources`는 전체 raw graph의 간접 callsite를, `candidate_sources`는 candidate가
source인 callsite만 센다. `resolved_import`는 angr가 이름 있는 외부 함수를 찾았지만
CallKin graph 정책상 filtered 처리한 성공이다. `internal_resolution_rate`는
`resolved_internal / (total - resolved_import)`이므로 import를 실패 분모에서 제외한다.
`candidate_impact`는 `resolved_internal` callsite 중 candidate의 OUT/IN에 실제로 추가된
수를 센다. `candidate_observability`는 projected fixture 기준 root 도달성,
zero-OUT, zero-IN, 완전 고립, unresolved indirect call 보유 candidate를 센다.
`ground_truth.same_family_pair_count`는 모든 mode에서 `TP + FN`과 같아야 하며,
다르면 JSON 생성을 중단한다. `execution.warnings`는 같은 component/message를 묶어
count만 저장한다. 시간과 경고는 raw graph SHA에 넣지 않아 evidence hash를 안정적으로
유지한다.

이미 생성된 fixture/GT의 점수만 저장하려면 `scores.py`를 사용한다.

```bash
python3 scores.py family_graph_03 \
  --profile plain \
  --candidate-scope subject \
  --json-output results/plain/family_graph_03.O3S.json
```

네 canonical build를 저장한다.

```bash
python3 scores.py --baseline --profile plain \
  --json-output results/plain/v0_baseline.json
```

이 경우에는 extraction 실행 정보가 없으므로 기존 score-only schema를 유지한다.

```json
{
  "schema_version": 3,
  "results": [
    {
      "case": "family_graph_03",
      "build": "O3S",
      "profile": "plain",
      "mode": "full",
      "provenance": {
        "build_id": "...",
        "source_sha256": "...",
        "non_stripped_sha256": "...",
        "stripped_sha256": "..."
      },
      "candidate_count": 13,
      "pair_count": 78,
      "rounds": 2,
      "pairwise": {
        "TP": 4,
        "FP": 1,
        "FN": 6,
        "TN": 67,
        "precision": 0.8,
        "recall": 0.4,
        "F1": 0.5333333333333333,
        "ARI": 0.48971962616822434
      },
      "clusters": [],
      "origins": []
    }
  ]
}
```

실제 JSON에는 float의 계산값을 저장하고 CLI만 소수점 둘째 자리로 표시한다.

`--trace`와 `--json-output`을 함께 사용하면 각 결과에 `trace` 배열도 저장된다. `--trace`를 생략하면 기존 JSON schema와 baseline 파일에는 `trace` field가 추가되지 않는다.

Plain/min의 candidate universe 차이는 별도 JSON으로 비교한다.

```bash
python3 compare_profiles.py billing-client --build O3S
```

기본 출력은
`results/profile_comparison/rust-nonstd/billing-client.O3S.json`이며, origin,
`k_obs >= 2` family, instance의 common/plain-only/min-only 수를 기록한다.
Instance 비교는 `(origin, 정렬된 symbol alias 목록)`의 멀티셋으로 수행하므로,
legacy demangling에서 여러 주소가 같은 이름으로 보이더라도 instance 개수가
하나로 축약되지 않는다. 다만 이 값은 concrete type identity를 복구하는 source-level
census가 아니라 최종 binary에서 관찰된 symbol instance 비교다. 두 GT의 source
SHA-256이 다르면 비교를 거부한다.

## 15. Mode와 baseline 실행

한 mode:

```bash
python3 scores.py family_graph_03 --mode out --candidate-scope subject
```

네 mode:

```bash
python3 scores.py family_graph_03 --all-modes --candidate-scope subject
```

선택한 profile의 canonical 네 build full mode:

```bash
python3 scores.py --baseline --profile min
```

`min` profile canonical 네 build의 네 mode:

```bash
python3 scores.py --baseline --profile min --all-modes \
  --json-output results/min/v0_all_modes.json
```

`scores.py --baseline`은 이미 존재하는 fixture/GT를 채점한다. Source compile이나 manifest 검증을 직접 실행하지 않는다. Source부터 재생성하고 manifest를 검증하려면 다음을 사용한다.

```bash
python3 run_baseline.py
```

## 16. Exact regression

`tests/test_scores.py`는 두 profile의 8개 canonical artifact set에 대해 다음을 고정한다.

- source, non-stripped, stripped hash
- origin별 instance 수
- candidate 수와 전체 pair 수
- refinement rounds
- exact cluster membership
- TP/FP/FN/TN
- PR/RE/F1/ARI
- origin별 split/collision 결과
- 저장된 `results/plain/v0_baseline.json`, `results/min/v0_baseline.json` 전체

실행:

```bash
python3 tests/test_scores.py
```

출력 일부:

```text
plain/family_graph_03/O3S: n=13 TP=4 FP=1 FN=6 TN=67 PR=0.80 RE=0.40 F1=0.53 ARI=0.49 PASS
plain baseline score JSON: PASS
min baseline score JSON: PASS
ALL PASS
```

## 17. Scorer가 하지 않는 일

- Collision이나 fragmentation의 compiler 원인을 자동 판정하지 않는다.
- Source-level instance census를 만들지 않는다.
- Grouping 결과를 고치거나 재그룹하지 않는다.
- GT를 engine 입력으로 전달하지 않는다.
- 다른 compiler artifact에 canonical V0 hash를 강제하지 않는다.

Scorer는 관찰된 partition을 비교하고 객관적인 count와 metric을 출력하는 역할만 한다.

## 18. 코드 읽기 순서

1. `score_case()`
2. `GroundTruth`와 `OriginGroup`
3. `load_ground_truth()`와 `_validate_ground_truth()`
4. `_check_join()`
5. Pair loop (`combinations(scored_ids, 2)`)
6. `_pairwise_score()`
7. `_adjusted_rand_index()`
8. `_make_predicted_clusters()`
9. `_make_origin_scores()`
10. `ScoreReport` 관련 dataclass
11. `format_report()`
12. `score_report_to_dict()`와 `write_reports_json()`
13. `score_all_modes()`와 `score_v0_baseline()`
