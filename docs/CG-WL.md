# Call-Graph Weisfeiler-Lehman

## 1. 목적

CallKin의 `engine.py`는 fixture JSON의 call graph만 보고 scored user 함수를 cluster로 묶는다.

```text
fixtures/plain/family_graph_01.O3S.fixture.json
-> loader.py
-> engine.py
-> predicted clusters
```

Engine은 다음 파일을 읽지 않는다.

```text
ground_truth/*.gt.json
gt_bin/*.gt.bin
users/*.users.json
symbol 이름
source code
```

따라서 `process`, `share`, concrete type 같은 정답 정보는 color refinement에 들어가지 않는다.

## 2. Color의 의미

여기서 color는 화면에 보이는 빨강이나 파랑이 아니다. **같은 관계 특징을 가진 node에 붙이는 class label**이다.

예를 들어 초기 특징이 같은 세 함수는 같은 문자열 color를 받는다.

```text
FUN_00113e40 -> USER:self=1:distinct_out=0
FUN_00113f20 -> USER:self=1:distinct_out=0
FUN_00113fa0 -> USER:self=1:distinct_out=0
```

세 함수는 같은 color이므로 같은 class에 있다. 다음 refinement에서 이웃 color pattern이 달라지면 서로 다른 새 color를 받을 수 있다.

## 3. 입력 data model

Fixture는 `loader.py`를 거쳐 다음 구조가 된다.

```python
Case(
    case="family_graph_01",
    build="O3S",
    profile="plain",
    schema_version=4,
    nodes=[...],
)
```

한 node 예시:

```python
Node(
    id="FUN_00114480",
    type="user",
    scored=True,
    calls=[
        Call(target="FUN_00113f20", count=5),
    ],
)
```

`type="user"` node는 grouping 대상이다. `type="anchor"` node는 주변 context를 제공하지만 최종 scored cluster에는 포함되지 않는다.

## 4. `run_cg_wl()` 전체 흐름

```text
run_cg_wl(case, mode)
  -> validate_cg_wl_mode()
  -> build_relation_graph_view()
  -> make_initial_cg_wl_colors()
  -> refine_cg_wl_once() 반복
  -> same_partition()으로 fixpoint 확인
  -> make_scored_clusters()
  -> make_cluster_id_by_node()
  -> CGWLResult
```

반복 최대 횟수는 전체 node 수다. 그 안에 fixpoint에 도달하지 않으면 오류로 중단한다.

## 5. Relation graph 만들기

`build_relation_graph_view()`는 fixture edge를 CG-WL 계산에 편한 다섯 정보로 나눈다.

```text
node_ids
self_call_count
outgoing non-self edges
incoming non-self edges
distinct_out_callee_count
distinct_in_caller_count
```

### 5.1 Self edge 분리

다음 fixture edge가 있다고 하자.

```json
{
  "id": "FUN_00113e40",
  "calls": [
    {"target": "FUN_00113e40", "count": 1}
  ]
}
```

Graph view에서는 다음이 된다.

```text
self_call_count[FUN_00113e40] = 1
outgoing[FUN_00113e40]        = []
incoming[FUN_00113e40]        = []
```

Self edge는 별도 seed 특징으로 올리고 OUT/IN neighbor multiset에는 넣지 않는다.

### 5.2 Non-self edge

다음 edge:

```text
FUN_00114480 -> FUN_00113f20 x5
```

Graph view:

```python
outgoing["FUN_00114480"] = [("FUN_00113f20", 5)]
incoming["FUN_00113f20"] = [("FUN_00114480", 5)]
```

### 5.3 Distinct count

함수 A가 B를 5곳에서, C를 2곳에서 호출한다고 하자.

```text
A -> B x5
A -> C x2
```

값은 다음과 같다.

```text
distinct_out_callee_count[A] = 2
```

`5 + 2 = 7`이 아니다. 서로 다른 non-self callee가 B와 C 두 개이기 때문이다.

## 6. Anchor initial color

Schema v4에서는 각 anchor가 자기 ID가 들어간 초기 color를 받는다.

```text
FUN_00113e00 -> ANCHOR:FUN_00113e00
FUN_00152600 -> ANCHOR:FUN_00152600
```

Schema v5에서는 fixture의 `color_class`가 초기 color의 기준이다.

```text
color_class=ADDR:FUN_001487a0
-> ANCHOR:ADDR:FUN_001487a0
```

기본 `anchor_policy=address`는 anchor마다 서로 다른 class를 주므로 schema v4와
같은 individualized 의미를 유지한다. 공식 `anchor_policy=role`은 주소를 버리고
`ROLE:root`, `ROLE:incoming`, `ROLE:outgoing`, `ROLE:both`, `ROLE:context` 중 하나를 사용한다.
따라서 서로 다른 주소의 anchor도 같은 방향 역할이면 동일한 `color_class`를 공유한다.
Refinement에서는 anchor도 user와 같은 방식으로 OUT/IN relation signature를 계산한다.
따라서 같은 초기 role을 가진 anchor도 뒤쪽 call graph가 다르면 갈라지고, 그 차이가
다음 round에서 candidate로 전파된다.

따라서 두 user 함수가 서로 다른 library anchor를 호출하면 그 차이가 relation signature에 남는다.

Anchor는 final cluster와 채점에서 제외되지만 color refinement에는 끝까지 참여한다.

## 7. 초기 seed color

### `full`, `out`, `out-in`

초기 user color는 다음 두 값이다.

```text
(self_call_count, distinct_out_callee_count)
```

예시:

```text
self call 1회, non-self callee 0개
-> USER:self=1:distinct_out=0

self call 0회, non-self callee 1개
-> USER:self=0:distinct_out=1
```

### `in`

`in` mode만 다음 seed를 쓴다.

```text
(self_call_count, distinct_in_caller_count)
```

예시:

```text
self call 0회, 서로 다른 caller 2개
-> USER:self=0:distinct_in=2
```

Call count의 총합은 seed에 사용하지 않는다.

## 8. Neighbor color multiset

Refinement는 raw neighbor ID를 직접 비교하지 않는다. **이웃의 이전 round color별로 static callsite count를 합산**한다.

다음 상황을 가정한다.

```text
callee B의 이전 color = C:4
callee C의 이전 color = C:4

A -> B x2
A -> C x3
```

A의 OUT color multiset은 다음이다.

```python
(("C:4", 5),)
```

계산:

```text
color C:4로 향하는 count = 2 + 3 = 5
```

다음처럼 edge별 tuple을 그대로 두지 않는다.

```python
# 사용하지 않는 표현
(("C:4", 2), ("C:4", 3))
```

다른 color가 섞이면 entry가 나뉜다.

```text
A -> B(color C:4) x2
A -> D(color C:7) x3
```

결과:

```python
(("C:4", 2), ("C:7", 3))
```

Tuple을 정렬하므로 dictionary나 edge 순서와 무관하게 같은 multiset은 같은 값이 된다.

## 9. Refinement signature

각 user의 새 color는 이전 color와 선택된 방향의 neighbor color multiset으로 결정된다.

### `full`

```python
(
    previous_color,
    out_multiset,
    in_multiset,
)
```

구체적인 예:

```python
(
    "USER:self=0:distinct_out=1",
    (("C:2", 5),),
    (("ANCHOR:FUN_00113e00", 2),),
)
```

### `out`

```python
(
    previous_color,
    out_multiset,
)
```

Caller 차이는 무시한다.

### `in`

```python
(
    previous_color,
    in_multiset,
)
```

Callee 차이는 무시한다.

### `out-in`

Non-leaf user는 OUT만 쓴다.

```python
(previous_color, out_multiset)
```

`distinct_out_callee_count == 0`인 leaf user만 IN도 함께 쓴다.

```python
(previous_color, out_multiset, in_multiset)
```

예시:

```text
process가 callee를 호출함
-> OUT만 사용

leaf 함수가 non-self callee 없음
-> OUT이 비어 있으므로 IN도 사용
```

## 10. Signature를 color로 바꾸기

`_canonicalize_signatures()`는 현재 round의 unique signature를 정렬하고 번호를 붙인다.

```text
첫 번째 unique signature -> C:0
두 번째 unique signature -> C:1
세 번째 unique signature -> C:2
```

두 node의 signature가 완전히 같으면 같은 새 color를 받는다. 하나라도 다르면 다른 color를 받는다.

이전 color가 signature에 항상 포함되므로 이미 갈라진 class가 이후 round에 다시 합쳐지지 않는다.

## 11. Fixpoint와 rounds

한 번 정련한 뒤 `same_partition()`이 이전 color partition과 새 color partition을 비교한다.

Color 문자열 자체가 바뀌어도 node 묶음이 같으면 같은 partition이다.

예시:

```text
이전: {A, B}, {C}
새 값: A=C:0, B=C:0, C=C:1
```

Label 문자열은 달라졌지만 묶음은 여전히 다음과 같다.

```text
{A, B}, {C}
```

따라서 fixpoint다.

`rounds`는 마지막으로 “변화가 없음”을 확인한 refinement도 포함한다.

Fg01 결과:

```text
rounds = 1
```

이는 seed partition에 한 번 refinement를 적용했고 partition 변화가 없음을 확인했다는 뜻이다.

### Round trace

기본 실행은 최종 partition과 `rounds`만 반환한다. `--trace`를 지정하면 `round 0` seed부터 마지막 fixpoint 확인까지 scored partition을 모두 기록하고 출력한다.

```bash
python3 engine.py family_graph_02 --build O3S --profile plain --trace --candidate-scope subject
```

출력 형태:

```text
trace:
  round 0 (seed):
    C1 = ['FUN_...', 'FUN_...']
  round 1 (changed):
    C1 = ['FUN_...']
    C2 = ['FUN_...']
  round 2 (fixpoint):
    C1 = ['FUN_...']
    C2 = ['FUN_...']
```

마지막 `fixpoint` partition은 직전 partition과 동일하다. 이 라운드는 새로운 분할이 아니라 변화가 없음을 확인한 refinement다. Trace의 cluster 이름은 각 라운드 안에서만 사용하는 표시이며, 라운드 사이의 `C1`이 같은 color라는 뜻은 아니다.

## 12. Final cluster

Fixpoint color별로 `scored=true` node만 모은다.

Fg01 `full` mode 결과:

```python
[
    ["FUN_00113e40", "FUN_00113f20", "FUN_00113fa0"],
    ["FUN_00114480", "FUN_00114660", "FUN_001148a0"],
]
```

Root anchor `FUN_00113e00`은 refinement에는 참여했지만 final cluster에는 없다.

Cluster와 member는 ID 기준으로 정렬해 출력 순서를 안정화한다.

`CGWLResult`는 다음을 반환한다.

```text
mode
cluster_id_by_node
clusters
rounds
trace (`--trace`를 요청한 경우)
```

예를 들어 첫 cluster의 member map은 다음과 같다.

```python
{
    "FUN_00113e40": 0,
    "FUN_00113f20": 0,
    "FUN_00113fa0": 0,
}
```

## 13. Mode 비교

| Mode | Seed | Refinement에서 사용 |
|---|---|---|
| `full` | self + distinct OUT | previous + OUT + IN |
| `out` | self + distinct OUT | previous + OUT |
| `in` | self + distinct IN | previous + IN |
| `out-in` | self + distinct OUT | non-leaf는 OUT, leaf는 OUT + IN |

기본 mode는 `full`이다.

```bash
python3 engine.py family_graph_03 --candidate-scope subject
python3 engine.py family_graph_03 --mode out --candidate-scope subject
python3 engine.py family_graph_03 --mode in --candidate-scope subject
python3 engine.py family_graph_03 --mode out-in --candidate-scope subject
```

출력 예시:

```text
full
2
[['FUN_001146b0', 'FUN_00114a30'], ['FUN_00114d90'], ...]
```

모든 mode를 GT와 함께 비교하려면 scorer를 사용한다.

```bash
python3 scores.py family_graph_03 --all-modes --candidate-scope subject
```

## 14. Engine이 하지 않는 일

- Symbol이나 origin을 읽지 않는다.
- Generic 여부를 판정하지 않는다.
- Type을 복원하지 않는다.
- 함수 body byte, instruction, CFG를 비교하지 않는다.
- Indirect call을 새로 복구하지 않는다.
- 비슷한 signature를 soft matching하지 않는다.
- GT를 보고 round나 mode를 선택하지 않는다.

Engine의 결과는 fixture에 관찰된 exact relation equivalence partition이다.

## 15. 코드 읽기 순서

1. `run_cg_wl()`
2. `RelationGraphView`와 `CGWLResult`
3. `build_relation_graph_view()`
4. `make_initial_cg_wl_colors()`
5. `refine_cg_wl_once()`
6. `_neighbor_color_multiset()`
7. `make_relation_signature()`
8. `_canonicalize_signatures()`
9. `same_partition()`과 `canonical_partition()`
10. `make_scored_clusters()`
11. `make_cluster_id_by_node()`
