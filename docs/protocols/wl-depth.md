# CallKin WL Depth Baseline Protocol

## 1. 질문

초기 seed만으로 만든 partition과 비교할 때, 1-WL refinement 1회, 2회, fixpoint가 CallKin의 grouping 결과를 실제로 얼마나 바꾸는가?

이 실험은 더 강한 graph algorithm을 찾지 않는다. 현재 CallKin에서 반복 refinement가 seed-only baseline보다 어떤 이득과 손실을 만드는지만 측정한다.

## 2. 사전 가설

- H1: 적어도 한 canonical artifact에서 round 1 이후 partition이 seed partition과 달라지고, FP 감소 또는 F1 증가가 나타난다. 이 경우 1-WL은 seed-only 규칙에 없는 정보를 추가한다고 해석한다.
- H2: round 2 이후 fixpoint까지의 변화는 round 0에서 round 2까지의 변화보다 작다. 이 경우 현재 corpus에서 깊은 반복보다 초기 1-2회 refinement가 결과를 주로 결정한다고 해석한다.
- 반대 결과도 그대로 보고한다. Seed와 fixpoint가 같거나 refinement가 모든 case에서 악화되면, 현재 1-WL 반복의 추가 효용은 입증되지 않은 것으로 판정한다.

## 3. 고정 corpus와 조건

### Controlled 8개

- `family_graph_01/O3S`: plain, min
- `family_graph_02/O3S`: plain, min
- `family_graph_03/O3S`: plain, min
- `family_graph_03/O3KS`: plain, min
- Mode: `full`
- Track/anchor/scope: 기존 frozen controlled artifact 그대로

### Real-world 7개

- `billing-client/O3S`: plain, min
- `zoxide/O3S`: plain, min
- `fd/O3S`: plain, min
- `ripgrep-main/O3S`: plain
- Mode: `out-in`
- Track: `angr`
- Anchor policy: `role`
- Candidate scope: `rust-nonstd`

새 binary extraction은 하지 않는다. 기존 fixture와 ground truth의 바이트를 그대로 사용하고 SHA-256을 결과 artifact에 기록한다.

## 4. 독립변수

| 이름 | 의미 |
| --- | --- |
| seed | Round 0. Candidate seed는 self-call count와 distinct OUT callee count이고 anchor는 기존 color class를 사용한다. |
| r1 | WL refinement 1회 뒤 partition |
| r2 | WL refinement 2회 뒤 partition. 이미 fixpoint이면 그 partition을 유지한다. |
| fixpoint | 전체 fixture partition이 더 이상 바뀌지 않을 때의 final partition |

Mode, call evidence, target, anchor, abstain, ground truth와 scorer는 네 조건에서 동일하다.

## 5. 지표

각 artifact와 depth마다 다음을 기록한다.

- TP, FP, FN, TN
- Precision, Recall, F1
- Predicted cluster 수와 singleton 수
- 둘 이상의 predicted cluster로 갈라진 multi-member origin 수
- 둘 이상의 origin을 포함한 predicted cluster 수
- Seed 대비 TP/FP/FN 변화
- Fixpoint round 수

Abstain과 target coverage는 depth가 아니라 fixture projection에서 이미 결정되므로 artifact별 공통값으로 한 번 기록한다.

## 6. 해석 규칙

- Refinement의 효용은 F1 하나로 판정하지 않는다. TP 회수와 FP 증가/감소를 함께 본다.
- FP 감소와 TP 감소가 동시에 생기면 precision-recall 교환으로 기록한다.
- Aggregate는 큰 family에 지배될 수 있으므로 각 case 결과를 본문에 우선 보고한다.
- Controlled와 real-world 결과를 하나의 평균으로 합쳐 성능 순위를 만들지 않는다.
- 이 실험은 현재 graph extraction, seed, mode와 corpus에 대한 depth ablation이다. 더 깊은 WL 또는 higher-order WL의 보편적 무용성을 주장하지 않는다.

## 7. No-tuning 규칙

결과를 본 뒤 다음을 바꾸지 않는다.

- corpus 포함/제외
- `full`과 `out-in` mode
- target/anchor/abstain 정의
- round 선택
- ground truth normalization
- primary metric 또는 해석 기준

실행 실패나 provenance mismatch가 생기면 점수를 보지 않고 원인을 고친 뒤 동일 protocol로 처음부터 다시 실행한다.

## 8. 비용 상한

기존 JSON artifact를 읽고 deterministic WL partition과 pair score만 재계산한다. 새 disassembly, angr CFG, body alignment는 실행하지 않는다. 예상 wall-clock은 수 분 이내이며, 10분을 넘으면 중단하고 어느 case와 단계가 비용을 만들었는지 기록한다.

## 9. 결과 상태

이 문서가 Git에 커밋되기 전에는 결과를 생성하지 않는다.
