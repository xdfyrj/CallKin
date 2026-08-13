# Call-Graph Weisfeiler-Lehman

이 문서는 [engine.py](../engine.py)가 fixture를 어떻게 partition으로 바꾸는지 정의한다. Extraction 정확도나 GT normalization은 다루지 않는다.

## 실행

Fixture path 직접 실행:

```bash
python3 engine.py \
  fixtures/angr/role/rust-nonstd/plain/billing-client.O3S.fixture.json \
  --mode out-in
```

Stem과 분석 좌표로 path 해석:

```bash
python3 engine.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in
```

Round partition까지 출력:

```bash
python3 engine.py billing-client \
  --profile plain \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in \
  --trace
```

## 입력 graph

Fixture node는 두 종류다.

```text
user/candidate:
  grouping과 채점 대상

anchor:
  call context 제공
  refinement에는 참여
  최종 predicted cluster에는 미포함
```

Abstain target은 fixture `nodes`에 없으므로 engine이 보지 않는다. Engine은 abstain을 singleton으로 만들지도, color를 주지도 않는다.

Edge는 방향과 static callsite count를 가진다.

```json
{
  "id": "A",
  "calls": [
    {"target": "B", "count": 2},
    {"target": "L", "count": 1}
  ]
}
```

그래프 의미:

```text
A --2--> B
A --1--> L
```

Dynamic runtime frequency가 아니다. Binary 안에 관찰된 static callsite 개수다.

## 그래프 view 만들기

`build_relation_graph_view()`는 fixture를 네 구조로 바꾼다.

### Self-call

```text
A -> A count=3
```

별도 scalar로 들어간다.

```text
self_call_count[A] = 3
```

Self-edge는 OUT/IN neighbor multiset에서 제거한다. 그렇지 않으면 같은 self relation이 scalar와 neighbor relation에 중복 반영된다.

### Non-self OUT

```text
outgoing[A] = [(B, 2), (L, 1)]
```

### Non-self IN

위 edge를 뒤집어 만든다.

```text
incoming[B] = [(A, 2)]
incoming[L] = [(A, 1)]
```

Fixture가 incoming list를 별도로 저장하지 않아도 된다.

### Distinct degree

```text
distinct_out_callee_count[A] = 2
distinct_in_caller_count[B]  = 1
```

호출 횟수 합이 아니라 서로 다른 neighbor 수다.

```text
A -> B count=5
distinct_out[A] = 1
```

## Seed color

### Anchor

```text
ANCHOR:<color_class>
```

Address policy example:

```text
ANCHOR:ADDR:FUN_00123450
```

Role policy example:

```text
ANCHOR:ROLE:incoming
```

Anchor도 이후 refinement를 수행한다. 다만 초기 anchor color와 user color가 다르고 이전 color가 매 signature에 포함되므로 anchor와 user partition이 나중에 합쳐지지 않는다.

### User in `full`, `out`, `out-in`

```text
USER:self=<self_call_count>:distinct_out=<distinct callees>
```

예:

```text
A self-call 1회
A가 B와 L을 호출
-> USER:self=1:distinct_out=2
```

### User in `in`

```text
USER:self=<self_call_count>:distinct_in=<distinct callers>
```

`full` mode도 seed에서는 distinct OUT을 쓴다. IN은 첫 refinement부터 들어온다. 이 seed 정의를 바꾸면 모든 baseline partition과 round count를 다시 검토해야 한다.

## Weighted neighbor-color multiset

한 round 전 color가 다음과 같다고 하자.

```text
color(B) = C:7
color(C) = C:7
color(L) = ANCHOR:ROLE:outgoing
```

그리고 A의 edge가:

```text
A -> B count=2
A -> C count=1
A -> L count=4
```

OUT multiset:

```text
(
  ("ANCHOR:ROLE:outgoing", 4),
  ("C:7", 3)
)
```

핵심은 neighbor ID가 아니라 **이전 color별 call count 합**이다.

```python
count_by_color[prev_color[neighbor]] += edge_count
```

따라서 다음 두 구조는 이 multiset에서 같다.

```text
color X neighbor 하나를 2회 호출
color X neighbor 둘을 각각 1회 호출
```

둘 다:

```text
(X, 2)
```

이는 구현 실수가 아니라 현재 feature definition이다. Seed의 distinct degree는 round 0에서 neighbor cardinality 일부를 보존하지만 refinement multiset 자체는 color별 weight 합을 사용한다.

## 네 mode의 정확한 signature

Notation:

- `c_t(v)`: round t의 v color
- `OUT_t(v)`: outgoing neighbor color/count multiset
- `IN_t(v)`: incoming neighbor color/count multiset

### `full`

```text
signature(v) = (
  c_t(v),
  OUT_t(v),
  IN_t(v)
)
```

Caller와 callee relation을 동등하게 사용한다.

### `out`

```text
signature(v) = (
  c_t(v),
  OUT_t(v)
)
```

함수가 무엇을 호출하는지만 propagation에 쓴다.

### `in`

```text
signature(v) = (
  c_t(v),
  IN_t(v)
)
```

함수를 누가 호출하는지만 쓴다. Seed도 distinct IN을 쓴다.

### `out-in`

OUT이 있는 함수:

```text
signature(v) = (
  c_t(v),
  OUT_t(v)
)
```

OUT이 0인 leaf:

```text
signature(v) = (
  c_t(v),
  OUT_t(v),
  IN_t(v)
)
```

즉 “OUT 우선, leaf에서만 IN 보조”다. 이름은 OUT 후 IN을 순차 적용한다는 뜻이 아니다.

## 한 round 예제

초기:

```text
A, A' : USER:self=0:distinct_out=1
B, B' : USER:self=0:distinct_out=0
L     : ANCHOR:ROLE:outgoing
```

Edges:

```text
A  -> B count=1
A' -> B' count=1
B  -> L count=1
B' -> L count=2
```

Round 1에서 B/B'의 OUT multiset이 다르다.

```text
B : {(anchor-color, 1)}
B': {(anchor-color, 2)}
```

따라서 B와 B'가 갈라진다.

Round 2에서 A/A'는 각각 다른 이전 color의 B/B'를 보므로 갈라진다.

```text
callee-side split
-> caller-side propagation
```

이것이 color refinement가 여러 hop relation 차이를 전파하는 방식이다.

## Canonical color

각 node의 tuple signature를 모은 뒤 unique signature를 정렬한다.

```text
sorted(set(signatures))
```

정렬 위치에 따라:

```text
C:0
C:1
C:2
...
```

를 부여한다. Hash digest를 사용하지 않으므로 hash collision에 의존하지 않는다. Color 문자열 자체는 의미가 없다. 같은 round에서 같은 signature인가만 중요하다.

## Fixpoint

`run_cg_wl()`은 최대 node 수만큼 반복한다. 1-WL refinement는 partition을 더 세분화할 뿐 기존 class를 합치지 않으므로 finite graph에서 안정화된다.

Convergence는 color 문자열 equality가 아니라 partition equality로 확인한다.

```text
round t colors:   A=X, B=X, C=Y
round t+1 colors: A=P, B=P, C=Q

문자열은 다르지만 partition {{A,B},{C}}는 같음
-> fixpoint
```

`rounds`는 **변화 없음까지 확인한 round**를 포함한다.

예:

```text
round 0 seed
round 1 changed
round 2 changed
round 3 fixpoint confirmation

result.rounds = 3
```

“유효하게 partition이 바뀐 횟수”는 이 예에서 2다. 보고서에서 round 정의를 섞지 않는다.

## Trace

`--trace`는 다음을 저장/출력한다.

- round 0 seed partition
- 각 refinement round의 scored partition
- `changed` 또는 `fixpoint` 상태

예:

```text
trace:
  round 0 (seed):
    C1 = ['A', 'A_prime']
    C2 = ['B', 'B_prime']
  round 1 (changed):
    C1 = ['A', 'A_prime']
    C2 = ['B']
    C3 = ['B_prime']
  round 2 (changed):
    C1 = ['A']
    C2 = ['A_prime']
    C3 = ['B']
    C4 = ['B_prime']
  round 3 (fixpoint):
    ...
```

Trace cluster 번호는 사람이 읽기 위한 round-local label이다. 서로 다른 round의 `C1`이 동일 semantic color라는 뜻이 아니다.

## 최종 predicted cluster

Fixpoint color별로 **`scored=true` node만** 모은다.

```text
anchors participate in refinement
anchors excluded from output clusters
```

Cluster 내부 member는 ID 순서로 정렬하고 cluster list는 첫 member 기준으로 정렬한다. CLI의 `C1`, `C2` 번호가 deterministic하게 보이도록 하기 위함이다.

## Engine이 사용하지 않는 정보

Loader가 fixture에 허용하지 않거나 engine이 읽지 않는 것:

- origin
- full symbol
- generic/concrete type
- GT family members
- source
- Rust namespace
- compiler profile flag 내용
- angr confidence를 별도 relation type으로 구분한 값

Fixture에 이미 projection된 node, anchor color, weighted edge만 사용한다.

Exact static edge와 angr inferred edge는 raw evidence에서는 구분되지만 fixture `calls`에서는 같은 count edge로 합쳐진다. 따라서 현재 CG-WL은 resolver confidence-aware가 아니다.

## Loader의 방어 역할

[loader.py](../loader.py)는 fixture를 strict하게 검증한다.

- schema v4/v5/v6만 허용
- unknown top-level/node/call field 거부
- node ID 중복 거부
- call target이 fixture node인지 확인
- call count가 양수 integer인지 확인
- anchor는 `scored=false`
- user는 anchor metadata를 가질 수 없음
- anchor는 valid `anchor_kind/color_class` 필수
- abstention은 node와 겹칠 수 없음
- abstention reason 고정
- build/analysis provenance strict parse

Fixture에 `origin` field를 실수로 추가하면 engine이 무시하는 것이 아니라 loader가 거부한다.

## Mode 해석

### 왜 OUT을 중심으로 보는가

같은 generic source implementation은 concrete type이 달라도 비슷한 callee structure를 만들 가능성이 있다. Compiler inlining 때문에 달라질 수 있지만 OUT은 implementation sharing의 직접적인 흔적이다.

### 왜 IN을 폐기하지 않는가

Leaf function은 OUT이 없다. OUT-only이면 self count와 seed degree가 같은 leaf를 구분할 relation이 없다. 또한 실제 usage context가 family signal을 줄 수 있다.

### 왜 full과 별도 mode를 모두 유지하는가

IN은 caller usage를 반영하므로 같은 implementation family라도 호출 위치 차이로 분리할 수 있다. 반대로 collision을 줄일 수도 있다. 어느 방향이 유리한지는 결과를 보고 하나만 고르면 안 되므로 네 mode를 명시적 ablation으로 유지한다.

## 구현 읽는 순서

1. [model.py](../model.py)의 `Call`, `Node`, `Case`
2. [loader.py](../loader.py)의 `load_case()`, schema validation
3. [engine.py](../engine.py)의 `RelationGraphView`
4. `build_relation_graph_view()`
5. `make_initial_cg_wl_colors()`
6. `_neighbor_color_multiset()`
7. `make_relation_signature()`
8. `refine_cg_wl_once()`
9. `same_partition()`
10. `run_cg_wl()`
11. `make_scored_clusters()`, trace formatter

## 변경 시 테스트해야 할 것

[tests/test_engine.py](../tests/test_engine.py)에서 최소한 다음을 고정한다.

- self edge 분리
- distinct degree와 weighted count 차이
- neighbor color별 count aggregation
- full/out/in/out-in signature
- out-in leaf fallback
- incoming graph reversal
- anchor initial color
- anchor propagation과 unscored output
- deterministic canonical partition
- fixpoint round count
- trace의 seed/changed/fixpoint
- invalid mode rejection

Engine signature를 바꾸면 [tests/test_scores.py](../tests/test_scores.py)의 exact cluster baseline도 함께 확인한다.

## 현재 모델링 한계

- Edge relation type은 하나다. Exact/inferred, call/tail-call을 WL에서 구분하지 않는다.
- Multiple-target may-call은 표현하지 않는다.
- Weight는 dynamic frequency가 아닌 static callsite count다.
- Neighbor identity가 아니라 color별 weight 합을 쓰므로 같은-color neighbor cardinality 일부를 잃는다.
- Node local body/CFG/constant/type feature는 없다.
- Color refinement는 서로 다른 graph structure가 1-WL-equivalent이면 구분할 수 없다.
- Abstain target은 engine 외부에서 판단 보류되므로 conditional cluster quality와 coverage를 함께 봐야 한다.
