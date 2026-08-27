# CallKin

CallKin은 Rust monomorphized function family를 stripped binary의 call graph 관계로 다시 묶는 연구용 Python prototype이다.

이 저장소는 다음 과정을 재현한다.

```text
Rust source
-> non-stripped / stripped binary pair
-> compiler-symbol ground truth + candidate addresses/symbol extents
-> stripped raw call evidence
-> track별 projected call-graph fixture
-> Call-Graph Weisfeiler-Lehman grouping
-> PR / RE / F1 / ARI scoring
```

현재 구현은 통제된 `family_graph_01`, `family_graph_02`, `family_graph_03`
baseline과 `subjects/` 아래 Cargo project 입력을 지원한다. 일반 Rust binary에서
generic 함수를 자동 탐지하거나 type을 복원하는 도구는 아니다.

## Quick Start

Python dependency를 설치한다.

```bash
python3 -m pip install -r requirements.txt
```

저장된 fixture와 ground truth로 한 case를 채점한다.

```bash
python3 scores.py family_graph_03 --candidate-scope subject
python3 scores.py family_graph_03 --profile min --candidate-scope subject
python3 scores.py family_graph_03 --build O3KS --profile min --candidate-scope subject
```

각 profile의 네 canonical build를 채점하고 profile별 JSON으로 기록한다.

```bash
python3 scores.py --baseline --profile plain --json-output results/micro-corpus/plain/baseline.json
python3 scores.py --baseline --profile min --json-output results/micro-corpus/min/baseline.json
```

Rust source부터 두 profile의 8개 canonical artifact set을 전부 다시 생성하고 검증한다.

```bash
python3 run_baseline.py
```

각 profile의 `baseline.json`과 `all_modes.json`도
`results/micro-corpus/<profile>/`에 함께 갱신된다.

이 명령에는 `rustc`, GNU `strip`, GNU `nm`, `radare2`, Python `r2pipe`, `capstone`,
`pyelftools`가 필요하다. 현재 canonical target은 `x86_64-unknown-linux-gnu`이다.

전체 테스트를 실행한다.

```bash
python3 tests/run_all.py
```

F1–F4 body feasibility 진단을 별도로 실행할 수 있다. 이 단계는 V0 grouping을
바꾸지 않고, exact body decode·정규화·CFG·pair evidence만 측정한다.

```bash
python3 body_extractor.py ripgrep-main --build O3S --profile plain \
  --candidate-scope rust-nonstd \
  --raw-graph /path/to/ripgrep-main.O3S.raw.json
python3 analysis/v1_feasibility.py ripgrep-main --build O3S --profile plain \
  --candidate-scope rust-nonstd \
  --body-evidence body_evidence/plain/ripgrep-main.O3S.body.json \
  --ground-truth ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json
```

F4.5는 V0가 만든 한 collision cluster 안에서 body evidence가 오군집을
분리할 수 있는지만 진단한다. 먼저 V0 member list를 이름 없는 hash ID로
고정하고, 그 artifact를 입력으로 세 조건을 비교한다. 기본값은 함수 325개인
cluster와 52,650개 pair이며, GT는 pair label과 채점에만 사용한다.

```bash
# 1) V0 partition을 먼저 고정
python3 analysis/f45_collision.py ripgrep-main --build O3S --profile plain \
  --fixture /path/to/ripgrep-main.O3S.fixture.json \
  --track angr --candidate-scope rust-nonstd --anchor-policy role \
  --mode out-in --partition-only \
  --partition-output results/ripgrep-main/plain/v0.partition.json

# 2) hash ID를 지정해 전 pair 진단
python3 analysis/f45_collision.py ripgrep-main --build O3S --profile plain \
  --partition-input results/ripgrep-main/plain/v0.partition.json \
  --partition-output results/ripgrep-main/plain/v0.partition.json \
  --track angr --candidate-scope rust-nonstd --anchor-policy role \
  --mode out-in \
  --cluster-id cluster_<member-list-sha256> \
  --body-evidence /path/to/ripgrep-main.O3S.body.json \
  --ground-truth /path/to/ripgrep-main.O3S.gt.json \
  --output results/ripgrep-main/plain/f4_5.collision.json
```

`--cluster-size 325`을 사용하면 hash를 직접 입력하지 않아도 되지만, 같은 크기의
cluster가 둘 이상이면 `--cluster-id`를 요구한다. 결과 JSON에는 structure-only
(instruction/block/CFG), slot-only (constant/call/data reference), combined의
TP/FP/FN/TN, Precision/Recall/F1,
percentile·histogram 분포와 false-positive/false-negative 예시가 함께 저장된다.
partition의 `raw_graph_sha256`와 `candidate_selection_sha256`는 body-evidence
provenance와 반드시 일치해야 하며, 선택한 cluster에 속한 GT origin만
`origin_count`로 집계된다. 불일치 자료는 채점 전에 거부한다.

F5는 F4 정밀 비교 전에 비교할 pair 수를 줄인다. 완전하게 decode된 body의
body top-k와 V0 final/prior color 안의 relation top-k를 합치며, 같은 mnemonic
hash 전체 조합은 만들지 않는다. cheap profile이 같은 함수는 profile group
단위로 score한 뒤 top-k ID만 펼쳐 함수별 전체 `nC2` 계산을 피한다. OUT/IN
signature은 결과에 annotation으로만 기록하고 판정에는 사용하지 않는다. 이
단계는 GT를 읽지 않는다.

Gate B가 실패하면 먼저 F5.1 miss audit를 실행한다. 이 도구는 고정된 `k=64`
candidate와 GT를 비교해 family별 누락 member/pair, body 차이, exact mnemonic
hash, V0 final/prior color, candidate retrieval source를 기록한다. 기존
`member_without_candidate_count`는 아무 candidate edge도 없는 함수 수이고,
핵심 지표는 multi-member family 내부에서 같은-origin edge가 없는 함수 수,
`same_origin_member_coverage`, `connected_family_rate`다. exact mnemonic hash도
found/missed pair로 나누어 기록한다. 또한 전체 body universe에서 exact mnemonic
bucket의 최대 크기, 그 bucket이 만드는 전체 pair 수, GT가 다른 origin인 pair
수를 별도로 기록해 descriptor collision을 직접 측정한다. body 차이는 평균뿐
아니라 median, p75, p90도 저장한다. GT는 이 평가기에만 전달된다.

```bash
python3 analysis/v1_retrieval_miss.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.k64.candidates.json \
  ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json \
  --body-evidence body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json \
  --fixture /path/to/ripgrep-main.O3S.fixture.json \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.retrieval-miss.json
```

```bash
python3 v1_candidates.py ripgrep-main --build O3S --profile plain \
  --body-evidence body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json \
  --fixture /path/to/ripgrep-main.O3S.fixture.json \
  --mode out-in --track angr --candidate-scope rust-nonstd \
  --anchor-policy role --top-k 16 \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidates.json
python3 analysis/v1_candidate_eval.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidates.json \
  ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json
```

Gate B는 하나의 `k`만 보고 임의로 고정하지 않는다. `k=8,16,32,64`로 만든
artifact를 한 번에 넘기면 평가기가 각 결과를 비교하고 Gate B를 통과하는 가장
작은 `k`를 선택한다. 모두 실패하면 retrieval feature를 다시 설계해야 한다.
Sweep는 stripped binary뿐 아니라 body/fixture/graph/projection의 SHA-256,
track·anchor policy·relation mode와 target universe까지 동일한지 먼저 검사한다.
Threshold 선택도 엔진이 나중에 만든 `on-demand` pair를 제외하고, 처음 F5가
생성한 `source=candidate` pair만 사용한다.

```bash
for k in 8 16 32 64; do
  python3 v1_candidates.py ripgrep-main --build O3S --profile plain \
    --body-evidence body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json \
    --fixture /path/to/ripgrep-main.O3S.fixture.json \
    --mode out-in --track angr --candidate-scope rust-nonstd \
    --anchor-policy role --top-k "$k" \
    --output "results/ripgrep-main/plain/ripgrep-main.O3S.v1.k${k}.candidates.json"
done
```

```bash
python3 analysis/v1_candidate_eval.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.k8.candidates.json \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.k16.candidates.json \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.k32.candidates.json \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.k64.candidates.json \
  ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidate-sweep.json
```

F6는 후보 pair를 `match/reject/unknown/abstain`으로 분류하고, 모든 교차
pair가 `match`인 경우에만 family를 합친다. 불투명한 간접 jump가 있는 pair는
CFG가 완전하지 않으므로 기본 정책에서 `abstain`한다. 기본 정책은
`configs/v1.json`에 고정되어 있으며, GT는 엔진에 전달하지 않는다.

```bash
python3 v1_engine.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.candidates.json \
  --body-evidence body_evidence/rust-nonstd/plain/ripgrep-main.O3S.body.json \
  --config configs/v1.json \
  --output results/ripgrep-main/plain/ripgrep-main.O3S.v1.families.json
python3 analysis/v1_pair_eval.py \
  results/ripgrep-main/plain/ripgrep-main.O3S.v1.families.json \
  ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json
```

Threshold를 정식으로 고정할 때는 development family/GT를 여러 개 함께
넣고 선택 artifact를 저장한다. 아래 결과는 test case를 보지 않고
`configs/v1.selected.json`에 선택 근거와 case 목록을 남긴다. 선택 표본은
`candidate-only`로 고정되므로, complete-link 과정의 정책 의존적인 on-demand
비교가 threshold를 바꾸지 않는다.

```bash
python3 analysis/v1_pair_eval.py \
  results/fg01/v1.families.json ground_truth/fg01.gt.json \
  --development-pair results/fg02/v1.families.json ground_truth/fg02.gt.json \
  --development-pair results/ripgrep-main/plain/ripgrep-main.O3S.v1.families.json \
                    ground_truth/rust-nonstd/plain/ripgrep-main.O3S.gt.json \
  --development-config-output configs/v1.selected.json
```

## One-Case Commands

단일-file case를 non-stripped/stripped binary pair로 컴파일한다.

```bash
python3 compile.py family_graph_03 case
python3 compile.py family_graph_03 case --profile min
python3 compile.py family_graph_03 case --build O3KS --profile min
```

Cargo subject는 `subjects/<name>/Cargo.toml`과 `Cargo.lock`을 사용하되,
`[profile.release]`를 CallKin의 `plain`/`min` 설정으로 덮어쓴다.

```bash
python3 compile.py billing-client subject --profile plain --build O3S
python3 run_case.py billing-client --profile plain --build O3S --track direct-in
python3 run_case.py billing-client --profile plain --build O3S --track angr
python3 run_case.py billing-client --track angr --anchor-policy role
python3 run_case.py billing-client --track angr --all-modes \
  --json-output results/billing-client/plain/angr.address.all_modes.json
```

이미 컴파일된 한 build에서 GT, users, fixture를 생성하고 grouping과 scoring까지 수행한다.

```bash
python3 run_case.py family_graph_03 --candidate-scope subject
python3 run_case.py family_graph_03 --build O3KS --profile min --candidate-scope subject
python3 run_case.py family_graph_03 --all-modes --candidate-scope subject
python3 run_case.py family_graph_03 --trace --candidate-scope subject
```

기본 candidate scope는 `rust-nonstd`다. Non-stripped binary에서 demangle 가능한 Rust
text symbol 중 함수 소유 namespace가 `core`, `alloc`, `std`, `__rustc`인 함수와 source `main`을
제외하고, subject crate와 dependency crate 함수는 모두 scored candidate로 둔다.
기존 통제 corpus의 subject-owned 함수만 재현하려면 `--candidate-scope subject`를
명시한다. 두 scope 모두 candidate 주소를 compiler symbol에서 받는 oracle 조건이며,
stripped binary만으로 library 소유권을 분류하는 기능은 아니다.

기본 projection track은 `direct`다. `subject + direct + address`는 동결 baseline을
재생성하는 schema v4 compatibility 경로를 유지하며 `direct-immediate`와
`direct-tail`만 사용한다. Raw graph에 새 `elf-relocation` evidence가 있어도 이 경로는
무시한다. 그 외 새 projection은 schema v6으로 생성된다.
`direct-in`은
candidate가 직접 호출하는 외부 함수뿐 아니라 candidate를 직접 호출하는 외부
함수도 traversal seed로 포함한다. 두 track은 서로 다른 fixture 경로에 저장되어 기존
fixture를 덮어쓰지 않는다. `direct`와 `direct-in`은
`extractions/<profile>/`의 같은 raw graph를 공유하고, projector가 별도 candidate
selection과 track 정책을 결합한다. Base extractor는 ELF relocation으로 증명한
indirect call/tail-call도 exact edge로 만든다. Target 주소가 함수 경계 목록에 없으면
schema v6 projector가 이름과 body가 없는 opaque anchor로 연결하며, raw evidence는
`unmapped` 상태를 유지한다. `angr`는 여기에
angr CFG가 하나의 기존 함수 시작점으로 확정한 unresolved indirect call/tail-call을
추가하고, `direct-in`과 같은 incoming-caller
seed를 사용한다. 모든 track은 seed에서 시작한 resolved outgoing closure를 투영하며,
anchor도 선택된 다른 anchor로 향하는 edge를 유지한다. Angr evidence는 extraction 자체가 다르므로
`extractions/angr/<profile>/`에 별도로 저장된다.

Anchor policy 기본값은 `address`다. `--anchor-policy role`은 anchor 주소 대신
`root/incoming/outgoing/both/context` 역할을 color class로 사용한다. `context`는
candidate와 직접 맞닿지 않은 outgoing closure 내부 anchor다. Role fixture는
`fixtures/<track>/role/...`에 저장되어 address 결과를 덮어쓰지 않는다.

`run_case.py --json-output`은 mode별 점수 외에 `run_summary`를 한 번 저장한다.
여기에는 exact-static 간접 transfer 복구 수, angr 성공/거절 이유, candidate에 추가된
edge, root 도달성·고립
통계, GT family 난이도, 단계별 시간·경고·peak RSS, binary/boundary/tool 통계가
포함된다. Schema v6 결과에서는 `target`, `grouped`, `abstain` 수와 family별
target coverage, pair coverage, effective family-pair recall도 함께 저장한다.
Plain/min의 서로 다른 target universe는 별도로 비교한다.

```bash
python3 compare_profiles.py billing-client --build O3S
```

각 단계를 단독 실행할 수도 있다.

```bash
python3 gt_extractor.py family_graph_03 --candidate-scope subject
python3 binary_extractor.py family_graph_03 --candidate-scope subject
python3 binary_extractor.py family_graph_03 --track direct-in --candidate-scope subject
python3 binary_extractor.py billing-client --track angr
python3 graph_projector.py \
  extractions/plain/family_graph_03.O3S.raw.json \
  users/plain/family_graph_03.O3S.users.json \
  --track direct-in
python3 engine.py family_graph_03 --mode full --candidate-scope subject
python3 scores.py family_graph_03 --mode full --candidate-scope subject
python3 engine.py family_graph_03 --trace --candidate-scope subject
```

기본 build는 `O3S`, 기본 compiler profile은 `plain`이다. `O3KS`는 profile 설정에 `--cfg keep`을 추가한다.

| Profile | Compiler flags |
|---|---|
| `plain` | Cargo default-release 설정을 근사한 profile: O3, `lto=false`(thin local LTO 가능), CGU 16, panic unwind |
| `min` | aggressive minimized stress profile: O3, fat LTO, CGU 1, panic abort |

## Documentation

처음 읽을 문서는 [전체 구현 안내](docs/document.md)이다. 이후 필요한 단계의 문서로 이동한다.

| 문서 | 설명 |
|---|---|
| [전체 구현 안내](docs/document.md) | 연구 범위, 전체 data flow, artifact와 module의 관계 |
| [컴파일 파이프라인](docs/compilation.md) | `compile.py`, build profile, staging, manifest, failure safety |
| [바이너리 추출](docs/binary_extraction.md) | `binary_extractor.py`, radare2, root, call edge, user/anchor 경계 |
| [Ground truth 추출](docs/ground_truth.md) | `gt_extractor.py`, symbol normalization, origin과 users JSON |
| [CG-WL](docs/CG-WL.md) | `engine.py`, seed, refinement, mode, fixpoint |
| [채점](docs/scoring.md) | `scores.py`, pairwise count, PR/RE/F1/ARI, 결과 JSON |

## Canonical Artifacts

파일명은 `<case>.<build>` stem을 공유하고, 산출물 directory 아래에서 profile로 나뉜다.

```text
src/family_graph_03.rs
gt_bin/plain/family_graph_03.O3S.gt.bin
bin/plain/family_graph_03.O3S.fixture.bin
build_info/plain/family_graph_03.O3S.json
ground_truth/plain/family_graph_03.O3S.gt.json
users/plain/family_graph_03.O3S.users.json
boundaries/plain/family_graph_03.O3S.boundaries.json
fixtures/plain/family_graph_03.O3S.fixture.json
extractions/plain/family_graph_03.O3S.raw.json
fixtures/direct-in/plain/family_graph_03.O3S.fixture.json
extractions/angr/plain/family_graph_03.O3S.raw.json
fixtures/angr/plain/family_graph_03.O3S.fixture.json
fixtures/angr/role/plain/family_graph_03.O3S.fixture.json

# 기본 rust-nonstd scope의 scope별 산출물
ground_truth/rust-nonstd/plain/billing-client.O3S.gt.json
users/rust-nonstd/plain/billing-client.O3S.users.json
fixtures/direct-in/rust-nonstd/plain/billing-client.O3S.fixture.json
```

각 profile에서 다음 네 case/build 조합을 생성하므로 canonical artifact set은 총 8개다.

```text
family_graph_01 / O3S
family_graph_02 / O3S
family_graph_03 / O3S
family_graph_03 / O3KS
```

저장된 canonical 결과는 [plain baseline](results/micro-corpus/plain/baseline.json)과
[min baseline](results/micro-corpus/min/baseline.json)에 있다. 결과 경로는 원칙적으로
`results/<case>/<profile>/`이며, 여러 `family_graph_*` case를 합친 canonical
결과만 `results/micro-corpus/<profile>/`에 둔다.

## Scope

현재 포함하는 것:

- direct call과 다른 함수 시작점으로 향하는 tail-call-like jump
- x86-64 ELF relocation으로 증명한 exact indirect call/tail-call
- resolved/unresolved transfer evidence를 분리한 raw extraction graph
- projection과 독립된 raw graph 및 별도 candidate selection
- target을 알지만 제외한 import의 `filtered`, 함수에 매핑되지 않은 target의 `unmapped` evidence
- exact ELF relocation의 unmapped target을 보존하는 schema v6 opaque anchor
- 모든 Rust symbol extent와 startup C `main` extent를 담는 scope-independent boundary artifact
- 기본 `rust-nonstd` candidate scope와 호환용 `subject` scope
- candidate selection SHA-256을 포함한 projection provenance
- `direct`: root와 candidate에서 시작하는 direct-edge outgoing closure
- `direct-in`: direct external caller를 seed에 추가한 outgoing closure
- `angr`: direct-in closure에 singleton angr-resolved indirect call/tail-call 추가
- `address`와 `role` anchor color policy
- directed weighted call graph 기반 CG-WL
- `full`, `out`, `in`, `out-in` relation mode
- pairwise PR/RE/F1과 ARI
- F1 exact body decode, F2 local-only instruction normalization, F3 intraprocedural CFG,
  F4 pairwise body-evidence feasibility 진단 (Stage A 별도 경로)
- F4.5 V0 collision cluster member-list artifact와 body-evidence collision 진단
- F5 body/relation top-k candidate pair retrieval과 후보 coverage/reduction 평가
- F5.1 고정 candidate artifact의 retrieval miss 원인(member/body/WL/source) 진단
- F6 local body evidence의 tri-state family builder와 complete-link 병합

현재 포함하지 않는 것:

- generic function 자동 탐지
- 함수 경계 복원 연구
- multi-target 또는 미해결 indirect transfer의 exact edge 투영
- stripped-only std/library classifier를 candidate selection에 적용하는 기능. Direct-FLIRT
  label은 현재 audit-only이며 scope를 바꾸지 않는다.
- source-level mono-item census와 inlined/eliminated 원인 판정
- 학습된 weight/ML 모델과 type recovery
- body evidence를 V0 CG-WL에 자동으로 주입하는 production pipeline

Example source와 build recipe의 출처는 [rust-loss](https://github.com/xdfyrj/rust-loss) 저장소다.
