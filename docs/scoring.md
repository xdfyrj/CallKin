# 채점과 결과 해석

[scores.py](../scores.py)는 predicted CG-WL partition과 ground-truth origin partition을 결합한다. Engine은 GT를 모르며, symbol/origin annotation은 이 단계에서만 붙는다.

채점 결과는 두 층으로 읽어야 한다.

```text
conditional grouping quality:
  실제로 graph evidence가 있어 grouping한 candidate끼리 얼마나 맞았는가?

coverage/effective recovery:
  전체 target 중 CallKin이 얼마나 판단했고, abstain을 포함하면 family pair를 얼마나 복원했는가?
```

둘 중 하나만 보고 도구 성능을 해석하면 안 된다.

## 실행

한 fixture/GT를 stem으로 채점:

```bash
python3 scores.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in
```

네 mode:

```bash
python3 scores.py billing-client \
  --profile plain \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --all-modes \
  --json-output results/billing-client/plain/angr.role.all-modes.json
```

Fixture/GT path를 직접 줄 수도 있다.

```bash
python3 scores.py \
  fixtures/angr/role/rust-nonstd/plain/billing-client.O3S.fixture.json \
  ground_truth/rust-nonstd/plain/billing-client.O3S.gt.json \
  --mode out-in
```

Micro-corpus frozen baseline:

```bash
python3 scores.py --baseline --profile plain
python3 scores.py --baseline --profile plain --all-modes
```

Round partition 포함:

```bash
python3 scores.py billing-client \
  --profile plain \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in \
  --trace
```

일반 pipeline에서는 [run_case.py](../run_case.py)가 extraction runtime까지 포함한 `run_summary`를 함께 넣는다.

## 채점 전에 하는 strict join

`score_case()`는 점수 계산 전에 fixture와 GT가 같은 실험인지 확인한다.

### Identity

```text
case
build
profile
```

### Build provenance

```text
build_id
source_sha256
non_stripped_sha256
stripped_sha256
```

### Target universe

Schema v6:

```text
GT member IDs
=
fixture scored node IDs
union
fixture abstention IDs
```

Legacy schema:

```text
GT member IDs
=
fixture scored node IDs
```

이 식이 맞지 않으면 점수를 내지 않는다. 한 target이 projection에서 조용히 사라지거나 다른 candidate scope의 GT를 섞는 일을 막는다.

## Predicted cluster에 symbol을 붙이는 과정

Engine 결과:

```text
C1 = [FUN_A, FUN_B]
```

Scorer가 GT의 display-only symbol과 origin을 join한다.

```text
C1:
  FUN_A | decode::<Invoice>  | origin=billing_client::decode
  FUN_B | decode::<Customer> | origin=billing_client::decode
```

Concrete instance type을 사람이 확인할 수 있도록 full demangled symbol을 유지한다. Case namespace prefix와 trailing Rust hash만 display에서 줄인다. 이 symbol은 clustering 계산에는 사용되지 않는다.

한 address에 alias symbol이 여러 개면 `|`로 모두 표시한다.

## Pairwise universe

Grouped candidate가 `n`개면 conditional pair 수는:

```text
C(n, 2) = n(n-1)/2
```

각 unordered pair `(a,b)`에 두 질문을 한다.

```text
pred_same = CG-WL cluster가 같은가?
true_same = GT origin이 같은가?
```

| pred_same | true_same | Count |
|---:|---:|---|
| true | true | TP |
| true | false | FP |
| false | true | FN |
| false | false | TN |

예:

```text
GT:
origin X = {A, B}
origin Y = {C}

Prediction:
C1 = {A, C}
C2 = {B}
```

Pairs:

```text
A-B: true same, predicted different -> FN
A-C: true different, predicted same -> FP
B-C: true different, predicted different -> TN
```

결과:

```text
TP=0 FP=1 FN=1 TN=1
```

## PR, RE, F1

### Precision, `PR`

```text
PR = TP / (TP + FP)
```

질문:

> 같은 family라고 예측한 pair 중 실제 같은 origin은 얼마인가?

`TP+FP=0`이면 positive prediction이 없으므로 `N/A`다.

### Recall, `RE`

```text
RE = TP / (TP + FN)
```

질문:

> 조건부 grouped universe 안의 실제 same-origin pair 중 얼마를 같은 cluster로 복원했는가?

`TP+FN=0`이면 grouped universe에 same-origin pair가 없으므로 `N/A`다.

이 RE는 abstain target과 source에서 사라진 instance를 포함하지 않는다.

### F1

Pair가 하나도 없으면:

```text
TP+FP+FN+TN = 0
F1 = N/A
```

그 외에는 다음 count 식과 같다.

```text
F1 = 2TP / (2TP + FP + FN)
```

예:

```text
TP=0, FP=0, FN=3, TN=7
PR=N/A, RE=0, F1=0
```

Missed true pairs가 있는데 precision이 정의되지 않는다는 이유로 F1까지 `N/A`로 숨기지 않는다.

또 다른 예:

```text
TP=0, FP=2, FN=3, TN=5
PR=0, RE=0, F1=0
```

분모 0을 일괄적으로 1.0으로 두지 않는다.

## Adjusted Rand Index

Pairwise count 형태의 Hubert-Arabie ARI를 사용한다.

```text
index        = TP
same_cluster = TP + FP
same_origin  = TP + FN
total        = TP + FP + FN + TN

expected = same_cluster * same_origin / total
maximum  = 0.5 * (same_cluster + same_origin)

ARI = (index - expected) / (maximum - expected)
```

Grouped pair가 하나도 없으면 `ARI=N/A`다. `maximum == expected`인 degenerate but non-empty partition에서는 구현이 `1.0`을 반환한다.

ARI는 chance correction을 제공하지만 abstained target이 conditional universe에서 빠지는 문제를 해결하지 않는다. Coverage를 함께 본다.

## Abstain이 conditional score에 미치는 영향

GT family:

```text
F = {A, B, C}
```

Projection:

```text
A, B = grouped candidate
C    = abstain
```

전체 same-family pair:

```text
A-B
A-C
B-C
total = 3
```

Conditional pairwise scorer는 A-B만 본다. A-B를 복원하면 conditional RE는 1.0이다. 하지만 전체 family pair 중 실제 복원한 것은 1/3이다.

CallKin은 abstain을 FN으로 강제하지 않는다. Abstain은 “different cluster” 예측이 아니라 판단 보류이기 때문이다. 대신 별도 coverage/effective metrics로 책임을 드러낸다.

## Coverage metrics

Notation:

- `T`: 전체 target 수 = grouped + abstained
- `G`: grouped candidate 수
- `P_T = C(T,2)`: 전체 target pair
- `P_G = C(G,2)`: 실제 decision pair
- `S_T`: GT 전체 same-family pair
- `S_G`: grouped target 사이 GT same-family pair = TP + FN

### Target coverage

```text
target coverage = G / T
```

전체 target 중 color와 predicted cluster를 받은 함수 비율이다.

### Pair decision coverage

```text
pair decision coverage = P_G / P_T
```

Target coverage보다 더 빠르게 감소한다.

예:

```text
T=10, G=8
target coverage = 0.8
pair decision coverage = C(8,2)/C(10,2) = 28/45 = 0.6222
```

### Same-family pair coverage

```text
same-family pair coverage = S_G / S_T
                          = (TP + FN) / S_T
```

전체 family truth pair 중 conditional scorer가 평가할 수 있었던 비율이다. 이름이 `true_positive_pair_count`가 아닌 `same_family_pair_count`인 이유는 복원 여부와 무관한 GT denominator이기 때문이다.

### Effective family-pair recall

```text
effective family-pair recall = TP / S_T
```

전체 observed target family pair 중 실제 복원한 비율이다.

관계:

```text
effective recall
=
same-family pair coverage
x
conditional RE
```

두 항이 정의되는 일반 case에서 성립한다.

### Undefined coverage

- `T=0`: target coverage `N/A`
- `C(T,2)=0`: pair decision coverage `N/A`
- `S_T=0`: same-family pair coverage와 effective recall `N/A`

All-singleton GT에서 family recall을 1.0으로 만들지 않는다. 평가할 same-family pair가 없다는 뜻이다.

## Origin별 결과

각 GT origin마다 다음을 계산한다.

| Field | 의미 |
|---|---|
| `k_obs` | GT에서 관찰된 전체 instance 수 |
| `scored_instance_count` | grouped candidate 수 |
| `abstained_instance_count` | abstain 수 |
| `predicted_cluster_count` | grouped member가 차지한 cluster 수 |
| `recovered_pairs` | 같은 cluster에 남은 same-origin grouped pair |
| `total_pairs` | grouped member 사이 same-origin pair |
| `total_target_pairs` | abstain 포함 전체 same-origin pair |
| `scored_pair_coverage` | `total_pairs / total_target_pairs` |
| `effective_recall` | `recovered_pairs / total_target_pairs` |
| `colliding_origins` | 같은 predicted cluster에 들어온 다른 origin |

예:

```json
{
  "origin": "share",
  "k_obs": 3,
  "scored_instance_count": 2,
  "abstained_instance_count": 1,
  "predicted_cluster_count": 1,
  "recovered_pairs": 1,
  "total_pairs": 1,
  "total_target_pairs": 3,
  "scored_pair_coverage": 0.3333,
  "effective_recall": 0.3333,
  "colliding_origins": []
}
```

`predicted_cluster_count=0`은 모든 member가 abstain일 수 있음을 뜻한다. “완전히 하나로 복원”을 뜻하지 않는다.

## Family status summary

[analysis/summary.py](../analysis/summary.py)는 generic family, 즉 `total_target_pairs>0`인 origin을 evidence와 recovery로 나누어 센다.

### Evidence status

- `full`: abstain 없이 grouped pair가 있음
- `partial`: 일부 abstain이 있지만 grouped pair가 있음
- `insufficient`: grouped same-family pair가 하나도 없음

### Recovery status

- `complete`: conditional same-family pair를 모두 복원
- `partial`: 일부 복원
- `missed`: 하나도 복원하지 못함
- `N/A`: evidence insufficient

### Collision

다른 origin과 같은 predicted cluster를 공유하는지 별도 boolean/count로 본다. Evidence/recovery status와 collision을 한 문자열에 섞지 않는다.

## Ground-truth summary

[run_summary.py](../run_summary.py)는 mode-independent GT facts를 한 번 저장한다.

```json
{
  "target_count": 320,
  "origin_count": 219,
  "generic_family_count": 42,
  "singleton_origin_count": 177,
  "family_member_count": 143,
  "same_family_pair_count": 400,
  "family_size": {
    "min": 2,
    "median": 3,
    "max": 12
  },
  "cross_origin_alias_address_count": 6
}
```

여기서 `generic_family_count`는 source syntax를 다시 분석한 count가 아니다. 관찰된 member가 2개 이상인 origin 수다.

자동 invariant:

```text
scored_same_family_pair_count
=
TP + FN
```

각 mode에서 이 식이 맞지 않으면 run summary 생성을 중단한다.

## Extraction diagnostics

Result `run_summary.extraction`은 두 종류의 indirect evidence를 whole-binary와 candidate-source로 나누어 기록한다.

### Exact static indirect

주로 `elf-relocation`:

- total
- resolved internal
- filtered import
- unmapped
- resolver별 count

### Angr unresolved indirect

- total
- resolved internal
- resolved import
- unresolved
- target resolution rate
- internal resolution rate
- operand별 memory/register
- rejection reason별 count

Import를 정확히 식별하고 policy로 제외한 것을 angr 실패로 세지 않는다.

## Candidate impact

Angr가 전체 binary에서 많은 indirect call을 해결해도 target grouping에 영향이 없을 수 있다.

기록 항목:

- accepted internal callsites/unique edges
- candidate outgoing/incoming edge 추가 수
- 새 OUT/IN evidence를 얻은 candidate 수
- unchanged candidate 수

이 값이 `direct-in -> angr` score 변화의 실제 원인을 설명한다.

## Candidate observability

기록 항목:

- target/grouped/abstained count
- root에서 reachable/unreachable target
- zero OUT
- zero IN
- fully isolated
- unresolved indirect call이 있는 target
- reachability edge policy
- anchor traversal policy

Reachability는 target selection이 아니라 진단이다. `unreachable_from_root`라는 이유만으로 GT/candidate에서 제거하지 않는다.

## Execution과 artifact summary

Execution:

- completed / completed_with_warnings
- direct extraction, angr, projection, scoring, total seconds
- peak RSS
- normalized warning component/message/count

Artifact:

- binary와 `.text` size
- known/candidate/fixture node count
- abstention count
- boundary oracle supplied/discovered/missing/size mismatch

Tool versions:

- Python
- radare2
- r2pipe
- Capstone
- pyelftools
- angr
- cle
- pyvex

Build compiler version은 manifest에 있으므로 result에 중복하지 않는다.

## CLI text output

CLI는 다음 순서로 핵심 사실을 출력한다.

```text
case/build/profile
track/scope/mode
target/grouped/pair/round count
predicted clusters with ID/symbol/origin
abstentions with reason
origin recovery rows
TP FP FN TN
PR RE F1 ARI
coverage metrics
optional trace
```

Symbol과 origin annotation은 설명을 위한 scorer output이다. Engine output 자체가 이 정보를 사용했다는 뜻이 아니다.

## Result JSON

Schema v6 top-level:

```json
{
  "schema_version": 6,
  "run_summary": {
    "ground_truth": {},
    "extraction": {},
    "candidate_impact": {},
    "candidate_observability": {},
    "execution": {},
    "artifact_summary": {},
    "tool_versions": {}
  },
  "results": [
    {
      "mode": "full"
    },
    {
      "mode": "out"
    },
    {
      "mode": "in"
    },
    {
      "mode": "out-in"
    }
  ]
}
```

Mode-independent summary를 네 번 복제하지 않는다. 각 result에는 partition, origin row, pairwise, coverage, provenance/analysis가 들어간다.

Schema v6 fixture에서 abstain이 0개여도 v6 output shape를 유지한다.

```json
{
  "target_count": 10,
  "grouped_candidate_count": 10,
  "abstained_candidate_count": 0,
  "abstentions": [],
  "coverage": {
    "target_coverage": 1.0
  }
}
```

데이터 값에 따라 schema가 바뀌면 안 된다.

## 결과 요약 CLI

한 파일:

```bash
python3 analysis/summary.py \
  results/billing-client/plain/angr.role.out-in.json
```

한 case:

```bash
python3 analysis/summary.py results/billing-client
```

전체:

```bash
python3 analysis/summary.py results
```

출력 table:

- Ground truth
- Scores
- Coverage
- Family status
- Graph and execution
- Exact static indirect transfers
- Angr unresolved indirect transfers

이 도구는 새 진단을 추측하지 않는다. Result JSON의 핵심 값을 사람이 profile/track/policy/mode별로 비교하기 쉽게 펼친다.

## Plain/min 비교

Candidate 수가 profile 사이에서 다르면 같은 denominator의 F1 비교가 아니다.

```bash
python3 compare_profiles.py billing-client \
  --build O3S \
  --candidate-scope rust-nonstd \
  --json-output results/billing-client/profile-comparison.json
```

비교:

- common/plain-only/min-only origin
- common/plain-only/min-only observed generic family
- demangled instance symbol multiset

먼저 target survival/universe 차이를 본 뒤 동일한 extraction track과 mode score를 비교한다.

## 구현 읽는 순서

1. `load_ground_truth()`, `_validate_ground_truth()`
2. `_check_join()`
3. `score_case()`
4. TP/FP/FN/TN loop
5. `_pairwise_score()`, `_adjusted_rand_index()`
6. `_make_predicted_clusters()`
7. `_make_origin_scores()`
8. `format_report()`
9. `score_report_to_dict()`, `reports_to_dict()`
10. [run_summary.py](../run_summary.py)의 `build_run_summary()`
11. [analysis/summary.py](../analysis/summary.py)의 `print_case()`

## Regression

[tests/test_scores.py](../tests/test_scores.py)는 frozen micro-corpus에 대해 다음을 exact하게 검사한다.

- source/binary hash
- origin별 observed instance 수
- target/candidate 수
- rounds
- TP/FP/FN/TN
- pair 수
- PR/RE/F1/ARI
- exact cluster membership
- origin별 split/collision
- stored baseline JSON

[tests/test_run_summary.py](../tests/test_run_summary.py)는 다음을 검사한다.

- indirect classification
- candidate impact
- observability/reachability
- GT denominator
- abstain coverage
- profile comparison
- execution warning/runtime shape

반드시 포함할 edge cases:

- 모든 target abstain
- 한 family 일부 abstain
- grouped pair 0
- `TP=0, FP=0, FN>0`
- `TP=0, FP>0, FN>0`
- all singleton origin
- cross-profile/scope/provenance join rejection

전체:

```bash
python3 tests/run_all.py
```

## 해석 시 금지할 주장

다음 해석은 수치만으로 할 수 없다.

- High conditional F1이 source-level survival까지 높다는 주장
- Abstain이 dead code라는 주장
- Angr accepted yield가 indirect-call accuracy라는 주장
- `min` F1 변화가 compiler robustness만의 효과라는 주장
- Controlled collision count를 real-world frequency로 일반화
- `rust-nonstd`를 정확한 user/dependency ownership truth로 간주
- ARI 하나로 extraction coverage 문제를 해결했다는 주장

결과를 설명할 최소 묶음은 다음이다.

```text
target/origin/k_obs
grouped/abstain coverage
call evidence recovery
predicted cluster
TP/FP/FN/TN
PR/RE/F1/ARI
effective family-pair recall
profile universe comparison
```
