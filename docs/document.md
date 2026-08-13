# CallKin 구현 안내

이 문서는 CallKin 저장소의 기술 문서 입구다. README가 설치와 첫 실행을 안내한다면, 이 문서는 다음 질문에 답한다.

- CallKin은 무엇을 입력받아 무엇을 계산하는가?
- non-stripped binary와 stripped binary는 왜 둘 다 필요한가?
- compiler symbol, radare2, Capstone, angr 정보는 어느 단계에서 쓰이는가?
- candidate, anchor, abstain은 어떻게 다르며 점수에는 어떻게 반영되는가?
- build profile, candidate scope, extraction track, anchor policy, CG-WL mode는 서로 무엇이 다른가?
- 구현을 바꿀 때 어느 계약과 테스트를 함께 확인해야 하는가?

세부 형식과 함수는 각 단계 문서에서 다룬다. 공통 경로와 JSON 계약은 [Artifact와 provenance](artifacts.md)에 모아 두었다.

## 한 문장 정의

CallKin은 **Rust 함수들의 직접 및 복구된 간접 호출 관계를 방향성과 호출 횟수가 있는 그래프로 만들고, Call-Graph Weisfeiler-Lehman color refinement로 구조적으로 비슷한 함수들을 묶은 뒤, symbol에서 만든 source-origin 정답과 비교하는 연구 자동화기**다.

CallKin이 직접 복구하려는 것은 source code나 concrete type이 아니다. 현재 핵심 질문은 다음과 같다.

> 함수 이름과 type 정보를 grouping 입력으로 쓰지 않을 때, call-graph relation만으로 같은 monomorphized source-origin의 out-of-line instance를 얼마나 다시 묶을 수 있는가?

## 시스템을 세 층으로 보기

전체 코드를 한 덩어리로 보면 non-stripped 정보가 분석 입력으로 새는지 판단하기 어렵다. CallKin은 세 층으로 나누어 읽는 것이 정확하다.

### 1. Build plane

하나의 source를 한 번 컴파일해 동일한 linked ELF에서 binary pair를 만든다.

```text
Rust source 또는 Cargo subject
        |
        | rustc / cargo build
        v
non-stripped ELF
        |
        | byte copy + strip --strip-all
        v
stripped ELF
```

이 단계는 [compile.py](../compile.py)가 담당한다. 두 ELF와 source, compiler, command, hash의 관계는 build manifest가 증명한다.

### 2. Evidence plane

같은 build에서 서로 다른 목적의 정보를 꺼낸다.

```text
non-stripped ELF                         stripped ELF
       |                                     |
       | nm -n -S -C                         | radare2 + Capstone
       v                                     | ELF relocation
candidate selection                          | optional angr CFGFast
ground truth                                 v
function boundaries                    raw call evidence
       |                                     |
       +----------------+--------------------+
                        |
                        v
                 projected fixture
```

중요한 경계는 다음과 같다.

- `ground_truth/*.gt.json`의 origin과 full symbol은 **채점 전용**이다.
- `users/*.users.json`은 candidate 주소와 크기만 전달한다. origin grouping은 전달하지 않는다.
- `boundaries/*.boundaries.json`은 전체 Rust 함수 시작점과 크기를 제공한다. 현재 실험은 이 symbol-boundary oracle을 사용한다.
- `extractions/*.raw.json`은 binary에서 확인한 transfer evidence다. candidate scope나 projection track과 독립적이다.
- `fixtures/*.fixture.json`은 raw evidence에 특정 정책을 적용해 CG-WL이 읽을 그래프로 만든 결과다.

### 3. Experiment plane

Fixture에 대해 CG-WL을 실행하고 GT와 비교한다.

```text
fixture
   |
   | seed colors
   | repeated directed weighted refinement
   v
predicted clusters
   |
   | strict fixture/GT join
   v
TP, FP, FN, TN
PR, RE, F1, ARI
coverage and abstention statistics
```

[engine.py](../engine.py)는 GT를 읽지 않는다. [scores.py](../scores.py)만 predicted partition과 GT origin partition을 결합한다.

## 전체 실행 흐름

Cargo subject `billing-client`를 `plain` profile로 분석하는 예를 따라가 보자.

### 1. 컴파일

```bash
python3 compile.py billing-client subject --profile plain --build O3S
```

주요 산출물은 다음과 같다.

```text
gt_bin/plain/billing-client.O3S.gt.bin
bin/plain/billing-client.O3S.fixture.bin
build_info/plain/billing-client.O3S.json
```

Cargo subject에서는 `Cargo.toml`, `Cargo.lock`, package, dependency, feature, target 정보는 Cargo가 처리한다. CallKin은 release profile 설정만 `plain` 또는 `min`으로 강제한다.

### 2. 추출, grouping, 채점

현실적인 주 분석 조합의 예는 다음과 같다.

```bash
python3 run_case.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in \
  --json-output results/billing-client/plain/angr.role.out-in.json
```

이 명령 한 번이 수행하는 순서는 고정되어 있다.

```text
1. build manifest 검증
2. nm symbol에서 GT, users, boundaries 생성
3. stripped ELF에서 raw call evidence 생성
4. 필요하면 angr로 unresolved indirect transfer 보완
5. raw evidence + users + projection 정책으로 fixture 생성
6. CG-WL 실행
7. fixture와 GT join 검증
8. 점수와 진단 요약 출력 및 JSON 저장
```

한 단계만 조사할 때는 각 Python entry point를 직접 실행할 수 있다. 일반 실행은 `run_case.py`가 경로와 join을 함께 검증하므로 더 안전하다.

## 실험을 결정하는 여섯 축

비슷해 보이는 옵션들이 실제로는 서로 다른 층을 바꾼다.

| 축 | 값 | 기본값 | 바꾸는 것 |
|---|---|---|---|
| build profile | `plain`, `min` | `plain` | compiler optimization과 panic/LTO 조건 |
| build | `O3S`, `O3KS` | `O3S` | source의 `cfg(keep)` 활성화 여부 |
| candidate scope | `subject`, `rust-nonstd` | `rust-nonstd` | 어떤 함수가 grouping target인가 |
| extraction track | `direct`, `direct-in`, `angr` | `direct` | 어떤 call evidence와 incoming context를 fixture에 투영하는가 |
| anchor policy | `address`, `role` | `address` | anchor의 초기 identity를 주소로 볼지 역할로 볼지 |
| CG-WL mode | `full`, `out`, `in`, `out-in` | `full` | refinement signature에서 OUT/IN을 어떻게 쓰는가 |

### Build profile

`plain`은 Cargo default-release 설정을 근사한 direct-rustc/Cargo controlled profile이다.

```text
O3, codegen-units=16, lto=false, panic=unwind
```

`min`은 aggressive size/optimization stress profile이다.

```text
O3, codegen-units=1, lto=true, panic=abort
```

`min`을 일반적인 “악성코드 build”라고 동일시하지 않는다. 이 profile은 LTO와 abort 조건에서 call relation과 out-of-line survival이 어떻게 달라지는지 보기 위한 통제 조건이다.

### Build label

- `O3S`: profile flag만 적용한다.
- `O3KS`: profile flag에 `--cfg keep`을 추가한다.

`S`는 최종 fixture binary가 stripped임을 나타내는 이름이다. strip은 compile flag가 아니라 동일 linked ELF의 복사본에 수행된다.

### Candidate scope

- `subject`: manifest에 기록된 subject namespace만 target으로 삼는다.
- `rust-nonstd`: demangled Rust 함수 중 `core`, `alloc`, `std`, `__rustc`와 source main을 제외한 함수를 target으로 삼는다.

기본값은 `rust-nonstd`다. `rust-nonstd`는 main에서 reachable한 함수만 고르는 옵션이 아니다. 최종 non-stripped ELF에서 symbol로 관찰되고 scope 규칙에 맞는 함수 집합이다.

### Extraction track

- `direct`: 정적으로 확정된 edge를 사용하되 외부 incoming caller를 별도로 시작 문맥으로 추가하지 않는다.
- `direct-in`: `direct` evidence에 candidate를 직접 호출하는 외부 caller를 incoming anchor로 추가한다.
- `angr`: `direct-in` projection에 angr가 단일 내부 target으로 복구한 indirect call/tail-call edge를 더한다.

`direct`와 `direct-in`의 raw direct evidence는 같다. 차이는 projection이다. `angr`만 별도의 augmented raw graph를 만든다.

### Anchor policy

- `address`: anchor마다 `ADDR:FUN_...` 고유 색을 준다.
- `role`: root, incoming, outgoing, both, context 역할별 색을 준다.

주소 정책은 문맥을 구체적으로 보존하지만 같은 의미의 서로 다른 library 함수 주소 때문에 family를 과분할 수 있다. 역할 정책은 주소 변동에 덜 민감하지만 서로 다른 library 함수를 같은 역할로 압축한다.

### CG-WL mode

- `full`: OUT과 IN을 모두 사용한다.
- `out`: OUT만 사용한다.
- `in`: IN만 사용한다.
- `out-in`: OUT을 우선하고 OUT이 없는 leaf에서만 IN을 추가한다.

기본값은 `full`이다. 각 mode의 정확한 signature는 [CG-WL](CG-WL.md)에 정의한다.

## 함수의 세 graph role

Candidate scope로 선택된 target이 모두 자동으로 WL node가 되는 것은 아니다.

| 역할 | 의미 | CG-WL 참여 | 채점 방식 |
|---|---|---:|---|
| candidate | 현재 track의 projected graph에서 non-self IN 또는 OUT 관계가 있는 target | 예 | 조건부 partition 채점 |
| anchor | target은 아니지만 candidate의 call context를 제공하는 함수 또는 opaque address | 예 | 채점하지 않음 |
| abstain | target이지만 resolved non-self relation이 하나도 없는 함수 | 아니오 | coverage와 effective recall에 반영 |

Self-call만 있는 target도 abstain이다. Self-call은 함수 내부 특징은 주지만 다른 함수와 비교할 relation evidence는 주지 않기 때문이다.

예를 들어 target family가 `{A, B, C}`이고 `C`가 abstain이면:

```text
조건부 grouping은 A-B만 채점한다.
전체 same-family pair는 A-B, A-C, B-C 세 개다.
```

따라서 CallKin은 conditional F1과 함께 target coverage, pair decision coverage, same-family pair coverage, effective family-pair recall을 출력한다. Abstain을 임의 singleton cluster로 만들어 “다른 family”라고 판정하지 않는다.

## Oracle과 leakage 경계

현재 자동화는 완전한 stripped-only end-to-end function recovery 실험이 아니다.

### 분석에서 허용하는 oracle

non-stripped binary에서 다음을 가져온다.

- candidate 함수 시작 주소
- candidate 함수 크기
- 전체 demangle 가능한 Rust 함수의 시작 주소와 크기
- startup root를 검증하는 namespace 정보

이 정보는 stripped binary의 같은 linked address와 join된다. `CFGFast(function_starts=...)`에도 boundary oracle의 함수 시작점이 전달된다.

### Grouping에 금지된 정보

다음은 engine 입력에 들어가지 않는다.

- origin 이름
- concrete generic type
- full demangled candidate symbol
- GT family membership
- source-level mono-item census

`users.json`이 숫자 주소 목록만 갖는 이유가 이것이다. Candidate oracle은 제공하지만 정답 partition은 제공하지 않는다.

### 현재 GT가 뜻하는 것

GT는 다음이다.

> 최종 non-stripped binary에서 text symbol로 관찰된 함수들의 normalized source-origin partition.

따라서 source에서 예정되었지만 완전히 inlined/eliminated된 instance는 GT에 없다. CallKin의 현재 RE는 **out-of-line으로 관찰된 target 안에서의 conditional recovery**이며 source-level survival recall이 아니다.

## Artifact가 분리된 이유

하나의 JSON에 모든 정보를 넣으면 다음 오염을 막기 어렵다.

```text
origin truth가 fixture에 들어감
projection 정책이 raw evidence를 덮어씀
서로 다른 build의 GT와 fixture가 우연히 join됨
angr 결과가 direct baseline을 덮어씀
```

그래서 CallKin은 다음 계약을 사용한다.

| Artifact | 질문 |
|---|---|
| build manifest | 이 source와 두 binary가 같은 build에서 왔는가? |
| GT | 정답 origin partition은 무엇인가? |
| users | 이 scope에서 target 주소는 무엇인가? |
| boundaries | 분석기에 제공한 전체 function boundary oracle은 무엇인가? |
| raw graph | binary에서 어떤 transfer를 보았고 무엇을 못 풀었는가? |
| fixture | 어떤 evidence와 projection 정책이 WL graph가 되었는가? |
| result | 그 graph가 어떤 partition과 점수를 만들었는가? |

각 artifact의 path grammar와 schema는 [Artifact와 provenance](artifacts.md)를 참고한다.

## 핵심 모듈 지도

| 모듈 | 책임 | 읽지 않는 정보 |
|---|---|---|
| [build_profiles.py](../build_profiles.py) | target, profile, build flag 정의 | binary/GT |
| [compile.py](../compile.py) | source/Cargo를 ELF pair와 manifest로 변환 | call graph |
| [build_manifest.py](../build_manifest.py) | hash와 build identity 검증 | origin |
| [gt_extractor.py](../gt_extractor.py) | symbol에서 GT/users/boundaries 생성 | stripped call graph |
| [binary_extractor.py](../binary_extractor.py) | root, boundaries, static transfer evidence 추출 | origin grouping |
| [load_elf_relocation_targets()](../binary_extractor.py) | ELF relocation slot과 target 해석 | GT |
| [angr_adapter.py](../angr_adapter.py) | unresolved indirect transfer의 보수적 target 보완 | origin |
| [graph_evidence.py](../graph_evidence.py) | raw evidence schema와 검증 | projection target |
| [graph_projector.py](../graph_projector.py) | raw + users + policy를 fixture로 투영 | origin |
| [loader.py](../loader.py) | fixture schema strict load | GT |
| [engine.py](../engine.py) | directed weighted CG-WL | symbols/origins |
| [scores.py](../scores.py) | GT join, cluster 설명, metrics | machine-code extraction |
| [run_summary.py](../run_summary.py) | extraction, coverage, runtime 요약 | grouping 변경 |
| [run_case.py](../run_case.py) | 한 case의 전체 분석 orchestration | compilation |
| [run_baseline.py](../run_baseline.py) | micro-corpus compile부터 regression까지 실행 | 새 corpus 선택 |
| [all_rust_catalog.py](../all_rust_catalog.py) | FLIRT 평가용 all-Rust symbol catalog 생성 | grouping target 선택 |
| [oxidizer_probe.py](../oxidizer_probe.py) | 별도 Oxidizer 환경에서 evidence 단계별 FLIRT label 수집 | CallKin fixture |
| [oxidizer_adapter.py](../oxidizer_adapter.py) | Probe 검증, 주소 정규화, raw boundary join, cache | GT origin |
| [flirt_audit.py](../flirt_audit.py) | Direct-FLIRT label을 all-Rust catalog와 비교 | CG-WL 결과 |

## 반드시 유지할 불변식

구현을 바꿀 때 아래 조건이 깨지면 결과를 신뢰할 수 없다.

1. Non-stripped와 stripped binary는 한 번 생성된 동일 linked ELF에서 파생되어야 한다.
2. Manifest의 source/binary hash가 현재 파일과 일치해야 분석을 시작할 수 있다.
3. Raw graph는 candidate scope와 projection track을 포함하지 않는다. 단, direct와 angr evidence backend는 별도 raw artifact다.
4. Fixture에는 origin, GT members, concrete type 정답이 들어가면 안 된다.
5. Schema v6에서 `GT members = grouped candidates ∪ abstentions`가 정확히 성립해야 한다.
6. Anchor는 `scored=false`이고 candidate만 predicted cluster와 conditional pairwise score에 들어간다.
7. Abstain은 WL color를 받지 않으며 coverage에서 사라지지 않는다.
8. ELF relocation edge는 target이 정확한 known function start일 때만 내부 function edge가 된다. 정확한 주소지만 boundary가 없으면 opaque anchor로 남긴다.
9. Angr edge는 callsite의 전체 target 집합이 정확히 하나일 때만 채택한다. 채택 전 target filtering으로 singleton을 만들면 안 된다.
10. Controlled `subject + direct + address` baseline은 schema v4 compatibility semantics를 유지한다.
11. Engine은 GT를 import하거나 읽지 않는다.
12. 같은 case/build/profile이라도 provenance가 다르면 join을 거부한다.

## 현재 구현의 의도적인 한계

다음은 버그가 아니라 현재 실험 범위다.

- Candidate와 function boundary는 non-stripped symbol oracle에 의존한다.
- Indirect call은 완전 복구하지 않는다. Exact relocation과 conservative angr singleton만 graph edge가 된다.
- Multiple-target may-call relation은 일반 edge로 넣지 않는다.
- Source-level mono-item census, inlined/eliminated/folded lifecycle truth는 생성하지 않는다.
- `rust-nonstd` ownership은 namespace-based 규칙이다. 완전한 crate provenance classifier가 아니다.
- Oxidizer는 현재 direct-FLIRT label을 측정하는 [audit-only 단계](flirt_audit.md)다. FLIRT label이 candidate/anchor나 CG-WL seed를 바꾸지 않는다.
- `plain`과 `min` 점수 차이는 candidate survival과 graph recovery 차이를 함께 포함할 수 있다. F1만 단독 비교해서 compiler 효과로 해석하면 안 된다.

## 문서 읽는 순서

### 전체 파이프라인을 처음 읽을 때

1. 이 문서
2. [Artifact와 provenance](artifacts.md)
3. [컴파일](compilation.md)
4. [Ground truth](ground_truth.md)
5. [바이너리 추출](binary_extraction.md)
6. [CG-WL](CG-WL.md)
7. [채점과 결과](scoring.md)
8. [Oxidizer direct-FLIRT audit](flirt_audit.md)

### FLIRT 결과를 조사할 때

1. [Oxidizer direct-FLIRT audit](flirt_audit.md)
2. `labels/oxidizer/...labels.json`
3. `ground_truth/all-rust/...catalog.json`
4. `results/...flirt_audit.json`
5. Raw join, catalog join, standard classification, exact identity를 순서대로 구분한다.

### Extraction 오류를 조사할 때

1. [바이너리 추출](binary_extraction.md)
2. [Artifact와 provenance](artifacts.md)의 raw/fixture schema
3. `extractions/...raw.json`
4. `fixtures/...fixture.json`
5. `results/...json`의 `run_summary`

### 점수가 이상할 때

1. [채점과 결과](scoring.md)
2. result의 target/grouped/abstain coverage
3. origin별 recovered pair와 collision
4. fixture의 node/call relation
5. raw graph의 rejected/unresolved transfer

### Compiler profile 차이를 볼 때

1. [컴파일](compilation.md)
2. 두 profile의 build manifest
3. `compare_profiles.py`
4. candidate 수와 same-family pair denominator
5. 동일 track/mode의 result

## 변경 작업의 기본 절차

문서와 코드가 다시 어긋나지 않게 변경은 다음 순서로 한다.

```text
1. 변경할 층을 정한다: build / truth / evidence / projection / engine / scoring
2. 해당 artifact schema 또는 policy가 바뀌는지 확인한다.
3. 가장 작은 unit test를 먼저 추가한다.
4. 구현한다.
5. tests/run_all.py를 실행한다.
6. 저장 artifact 의미가 바뀌면 extractor/schema version을 올린다.
7. 영향받은 case만 재생성한다.
8. 저장 result와 다시 채점한 result가 일치하는지 확인한다.
9. 이 문서 세트의 해당 계약을 갱신한다.
```

전체 회귀 명령은 다음이다.

```bash
python3 tests/run_all.py
```

Micro-corpus를 source부터 다시 만드는 명령은 다음이다.

```bash
python3 run_baseline.py
```

실제 Cargo subject 결과는 compiler와 extractor 비용이 크므로, 변경 영향이 없는 경우 무조건 전체 재생성하지 않는다. 어떤 변경이 어느 artifact부터 재생성을 요구하는지는 [Artifact와 provenance](artifacts.md)의 변경 영향표를 따른다.
