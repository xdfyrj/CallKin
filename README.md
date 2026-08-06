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
python3 scores.py --baseline --profile plain --json-output results/plain/v0_baseline.json
python3 scores.py --baseline --profile min --json-output results/min/v0_baseline.json
```

Rust source부터 두 profile의 8개 canonical artifact set을 전부 다시 생성하고 검증한다.

```bash
python3 run_baseline.py
```

이 명령에는 `rustc`, GNU `strip`, GNU `nm`, `radare2`, Python `r2pipe`와 `capstone`이 필요하다. 현재 canonical target은 `x86_64-unknown-linux-gnu`이다.

전체 테스트를 실행한다.

```bash
python3 tests/run_all.py
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
  --json-output results/billing-client.angr.json
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

기본 projection track은 `direct`다. 기존 동결 baseline은 정확히
`subject/direct` 조합이며, 새 기본값인 `rust-nonstd/direct`는 별도
경로와 schema v5로 생성된다. `direct-in`은
candidate가 직접 호출하는 외부 함수뿐 아니라 candidate를 직접 호출하는 외부
함수도 one-hop anchor로 포함한다. 두 track은 서로 다른 fixture 경로에 저장되어 기존
fixture를 덮어쓰지 않는다. `direct`와 `direct-in`은
`extractions/<profile>/`의 같은 raw graph를 공유하고, projector가 별도 candidate
selection과 track 정책을 결합한다. `angr`는 기존 direct edge에 더해 angr CFG가 하나의 기존
함수 시작점으로 확정한 indirect call을 사용하고, `direct-in`과 같은 one-hop
incoming/outgoing anchor 문맥을 투영한다. Angr evidence는 extraction 자체가 다르므로
`extractions/angr/<profile>/`에 별도로 저장된다.

Anchor policy 기본값은 `address`다. `--anchor-policy role`은 anchor 주소 대신
`root/incoming/outgoing/both` 역할을 color class로 사용한다. Role fixture는
`fixtures/<track>/role/...`에 저장되어 address 결과를 덮어쓰지 않는다.

`run_case.py --json-output`은 mode별 점수 외에 `run_summary`를 한 번 저장한다.
여기에는 angr 간접호출 성공/거절 이유, candidate에 추가된 edge, root 도달성·고립
통계, GT family 난이도, 단계별 시간·경고·peak RSS, binary/boundary/tool 통계가
포함된다. Plain/min의 서로 다른 candidate universe는 별도로 비교한다.

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

저장된 결과는 [plain baseline](results/plain/v0_baseline.json)과 [min baseline](results/min/v0_baseline.json)에 있다.

## Scope

현재 포함하는 것:

- direct call과 다른 함수 시작점으로 향하는 tail-call-like jump
- resolved/unresolved transfer evidence를 분리한 raw extraction graph
- projection과 독립된 raw graph 및 별도 candidate selection
- target을 알지만 제외한 import의 `filtered`, 함수에 매핑되지 않은 direct target의 `unmapped` evidence
- 모든 Rust symbol extent와 startup C `main` extent를 담는 scope-independent boundary artifact
- 기본 `rust-nonstd` candidate scope와 호환용 `subject` scope
- candidate selection SHA-256을 포함한 projection provenance
- `direct`: user 함수가 직접 호출하는 library/runtime anchor
- `direct-in`: user 함수의 direct callee와 direct external caller anchor
- `angr`: direct edge와 singleton angr-resolved indirect edge, 양방향 one-hop anchor
- `address`와 `role` anchor color policy
- directed weighted call graph 기반 CG-WL
- `full`, `out`, `in`, `out-in` relation mode
- pairwise PR/RE/F1과 ARI

현재 포함하지 않는 것:

- generic function 자동 탐지
- 함수 경계 복원 연구
- multi-target 또는 미해결 indirect call의 exact edge 투영
- stripped-only std/library classifier. 현재 scope는 non-stripped symbol owner oracle이다.
- source-level mono-item census와 inlined/eliminated 원인 판정
- type recovery 또는 body/CFG similarity

Example source와 build recipe의 출처는 [rust-loss](https://github.com/xdfyrj/rust-loss) 저장소다.
