# CallKin 전체 구현 안내

## 1. 프로젝트가 답하려는 질문

Rust generic 함수는 하나의 source definition에서 여러 monomorphized instance로 컴파일된다. 최종 stripped binary에는 source의 generic 이름과 concrete type 정보가 남지 않을 수 있다.

CallKin은 다음의 제한된 질문을 다룬다.

> 분석 대상 Rust 함수 집합이 주어졌을 때, stripped binary에서 관찰되는 caller/callee 관계만으로 같은 source origin에서 나온 monomorphized 함수들을 다시 묶을 수 있는가?

예를 들어 source에 다음 함수가 있다고 하자.

```rust
fn process<T>(value: T) { /* ... */ }
```

컴파일 후 세 instance가 다음 주소에 생존할 수 있다.

```text
FUN_00114480  process instance 1
FUN_00114660  process instance 2
FUN_001148a0  process instance 3
```

`engine.py`는 `process`라는 이름을 받지 않는다. 각 함수가 누구를 몇 번 호출하고 누구에게 호출되는지만 보고 세 주소를 같은 cluster로 묶으려 한다.

이 연구의 대상은 **relation-only grouping**이다. generic 탐지, type 복원, source 복원, 함수 경계 복원 자체는 대상이 아니다.

## 2. 전체 data flow

```text
                         source side
                             |
                             v
       src/<case>.rs             subjects/<subject>/Cargo.toml
            |                               |
          rustc                         cargo build
            +---------------+---------------+
                            |
                        compile.py
                             |
             +---------------+---------------+
             |                               |
             v                               v
  non-stripped binary                stripped binary
  gt_bin/<profile>/*.gt.bin          bin/<profile>/*.fixture.bin
             |                               |
       gt_extractor.py                binary_extractor.py
             |                               |
       +-----+-------------+                 v
       |          |        |      extractions/*/*.raw.json
       |          |        |                 |
       |          |   boundaries/            |
       |          |   *.boundaries.json -----+
       |          |                  graph_projector.py
       |           |                         |
       |           |                 fixtures/*.fixture.json
       v           v                         |
ground_truth/    users/                  engine.py
*.gt.json        *.users.json                |
       |           |                         v
       |           +------ candidate ----> predicted clusters
       |                                      |
       +---------------- scores.py <----------+
                             |
                             v
                    PR / RE / F1 / ARI
```

한 build에는 source와 두 binary가 같은 실행에서 나왔음을 기록하는 manifest도 있다.

```text
build_info/plain/family_graph_01.O3S.json
```

`run_case.py`는 JSON을 추출하기 전에 이 manifest의 source hash와 두 binary hash를 검사한다.

## 3. 가장 중요한 분리

### 3.1 Grouping side

Grouping side는 stripped binary에서 만든 fixture만 사용한다.

```text
fixtures/plain/family_graph_01.O3S.fixture.json
```

fixture의 한 user node는 다음처럼 생겼다.

```json
{
  "id": "FUN_00114480",
  "type": "user",
  "scored": true,
  "calls": [
    {
      "target": "FUN_00113f20",
      "count": 5
    }
  ]
}
```

이 입력은 다음 사실만 말한다.

```text
FUN_00114480이 FUN_00113f20을 정적으로 5곳에서 호출한다.
```

`process`, generic type, origin 같은 정답 정보는 fixture에 없다.

### 3.2 Ground-truth side

Ground-truth side는 non-stripped binary의 compiler symbol을 사용한다.

```json
{
  "origin": "process",
  "members": [
    "FUN_00114480",
    "FUN_00114660",
    "FUN_001148a0"
  ]
}
```

이 정보는 `engine.py`에 전달되지 않는다. `scores.py`가 engine 실행이 끝난 뒤에만 읽는다.

### 3.3 Candidate address bridge

`users/<scope>/<profile>/*.users.json`에는 candidate raw address와 그 함수의 symbol
extent가 들어간다. Extent에는 source `main`도 포함된다.

```json
{
  "namespaces": ["family_graph_01"],
  "addresses": [
    "0x13e40",
    "0x13f20",
    "0x13fa0",
    "0x14480",
    "0x14660",
    "0x148a0"
  ],
  "function_bounds": [
    {"address": "0x13e40", "size": 212},
    {"address": "0x14040", "size": 1075}
  ]
}
```

이 파일은 `0x14480`이 `process`인지, 다른 주소와 같은 origin인지 말하지 않는다.
따라서 projector가 scored candidate를 정하는 데 사용하지만 grouping 정답 partition은
전달하지 않는다. Candidate selection의 canonical SHA-256은 schema v5 fixture의
analysis provenance에 기록된다.

기본 `rust-nonstd` scope는 demangled Rust text symbol 중 소유 namespace가 `core`,
`alloc`, `std`, `__rustc`인 함수와 source `main`만 제외한다. Subject와 dependency crate 함수는
모두 candidate다. `subject` scope는 manifest의 subject namespace만 candidate로 두는
기존 통제 평가다. 둘 다 non-stripped symbol을 사용하는 oracle이며, stripped-only
library classifier가 아니다.

함수 경계는 candidate selection에서 분리되어
`boundaries/<profile>/*.boundaries.json`에 저장된다. 이 파일은 scope와 무관하게
demangle 가능한 모든 Rust text symbol extent와 startup root 탐지용 C `main` extent를
담는다. 따라서 같은 raw graph를
`subject`와 `rust-nonstd` selection에 각각 투영할 수 있다.

## 4. Artifact의 의미

모든 canonical 파일은 `<case>.<build>` stem을 공유하며 산출물 directory 아래의 `<profile>/`로 분리된다.

| Artifact | 예시 | 역할 |
|---|---|---|
| Rust input | `src/family_graph_01.rs`, `subjects/billing-client/` | case 또는 Cargo subject |
| Non-stripped binary | `gt_bin/plain/family_graph_01.O3S.gt.bin` | symbol, GT, users 주소의 근거 |
| Stripped binary | `bin/plain/family_graph_01.O3S.fixture.bin` | 실제 relation 추출 대상 |
| Build manifest | `build_info/plain/family_graph_01.O3S.json` | source/tool/binary hash 결속 |
| Ground truth | `ground_truth/rust-nonstd/plain/*.gt.json`, `ground_truth/plain/*.gt.json` | scope별 origin partition과 symbol |
| Candidate selection | `users/rust-nonstd/plain/*.users.json`, `users/plain/*.users.json` | scope별 candidate raw address 집합 |
| Function boundaries | `boundaries/plain/*.boundaries.json` | scope-independent Rust/startup symbol extents |
| Raw graph | `extractions/plain/*.raw.json`, `extractions/angr/plain/*.raw.json` | candidate/projection 독립 transfer evidence; angr backend만 별도 |
| Fixture | `fixtures/rust-nonstd/plain/*.fixture.json`, `fixtures/direct-in/rust-nonstd/plain/*.fixture.json`, `fixtures/angr/rust-nonstd/plain/*.fixture.json`, role은 track 아래 `role/`, 호환용 `fixtures/plain/*.fixture.json` | scope, track, anchor 정책으로 투영한 node와 weighted edge |
| Score result | `results/micro-corpus/plain/baseline.json`, `results/billing-client/plain/*.json` | case/profile별 cluster, origin별 결과, metric |

`plain`은 Cargo 기본 release 설정을 근사한 CallKin profile로 O3/`lto=false`(thin local LTO 가능)/16 codegen units/panic unwind를 사용한다. `min`은 aggressive minimized stress profile로 O3/fat LTO/1 codegen unit/panic abort를 사용한다. Case는 direct rustc flag로, Cargo subject는 release-profile overlay로 같은 조건을 적용한다. `O3S`는 추가 source cfg가 없으며 `O3KS`는 `--cfg keep`을 추가한다. 어느 조합이든 non-stripped binary를 한 번 만든 뒤 복사본에 `strip --strip-all`을 적용한다.

## 5. Module 책임

### `compile.py`

`case` 입력은 direct rustc로, `subject` 입력은 Cargo metadata/build로 컴파일해 non-stripped/stripped binary pair와 manifest를 만든다.

상세: [컴파일 파이프라인](compilation.md)

### `gt_extractor.py`

Non-stripped binary에서 `nm -n -S -C` 결과를 읽고 같은 normalized symbol path를 같은 origin으로 묶는다. 동시에 scope별 candidate selection과 모든 Rust symbol 및 C `main`의 공용 boundary artifact를 만든다. 이름이나 origin partition은 binary extractor에 전달하지 않는다.

상세: [Ground truth 추출](ground_truth.md)

### `binary_extractor.py`

Radare2와 Capstone으로 stripped function과 transfer evidence를 추출한다. 확정된
direct edge, 정책상 제외한 import, 함수에 매핑되지 않은 direct target, target을 정하지
못한 indirect callsite를 raw graph에 각각
resolved/filtered/unmapped/unresolved로 구분해 남긴다.

### `candidate_selection.py`, `graph_evidence.py`, `graph_projector.py`

`candidate_selection.py`는 users JSON을 검증하고 candidate 집합과 SHA-256을 만든다.
`function_boundaries.py`는 scope-independent Rust/startup function extent를 검증한다.
`graph_evidence.py`는 candidate와 projection track을 포함하지 않는 raw graph schema v5와 hash
검증을 담당한다. `graph_projector.py`는 raw evidence, candidate selection, track
정책을 결합해 CG-WL fixture로 바꾼다.
`direct`는 root와 candidate에서 시작한 resolved outgoing closure를 투영한다.
`direct-in`은 candidate의 direct external caller를 seed에 추가한 뒤 동일한 outgoing
closure를 계산한다. `angr`는 여기에 singleton으로 확정한 indirect edge를 추가한다.
Anchor는 채점 대상이 아닐 뿐 traversal wall이 아니며, 선택된 anchor 사이의 edge도
fixture에 보존된다.
`angr_adapter.py`는 CFGFast 결과를 raw callsite와 join하고, 기존 함수 시작점 하나로
확정된 unresolved call만 `resolver=angr-cfg`, `confidence=inferred`로 승격한다.
Singleton 판정은 unknown target을 제거하기 전에 수행한다. Raw에서는 direct exact와
angr inferred evidence를 구분하고, 거절된 callsite도 이유와 target 후보를 보존하지만
현재 fixture는 동일 source-target call count로 합산한다.
Projector의 공식 anchor policy는 주소별 초기 color인 `address`와 방향 역할별 초기
color인 `role`이다. Role은 `root/incoming/outgoing/both/context`를 구분한다.
Anchor도 매 round 정련되지만 final cluster와 채점에서는 제외된다. Role fixture는
각 track 아래 `role/` 경로에 별도로 저장한다.

상세: [바이너리 추출](binary_extraction.md)

### `model.py`와 `loader.py`

Fixture JSON을 검증하고 다음 세 dataclass로 바꾼다.

```text
Case
  -> Node
       -> Call(target, count)
```

Loader는 unknown field, 중복 node, 존재하지 않는 call target, 0 이하 count, `anchor + scored=true` 같은 잘못된 입력을 거부한다.

### `engine.py`

Fixture만 보고 directed weighted call graph를 만들고 CG-WL color refinement를 fixpoint까지 반복한다.

상세: [CG-WL](CG-WL.md)

### `scores.py`

Predicted partition과 GT origin partition을 같은 scored universe 위에서 비교한다. TP/FP/FN/TN, PR/RE/F1/ARI, origin별 분할과 충돌을 출력한다.

상세: [채점](scoring.md)

### `run_case.py`

이미 컴파일된 한 case/build를 분석하는 orchestration layer다.

```text
manifest 검증
-> GT/users 생성
-> raw graph 생성
-> track별 fixture projection
-> GT와 scored universe join 검사
-> CG-WL
-> scoring
```

### `run_baseline.py`

두 profile의 네 canonical case/build 조합에 대해 `compile.py`와 `run_case.py`를 실행한 뒤 profile별 baseline JSON과 exact regression을 생성한다.

```text
plain, min 각각:
  family_graph_01 / O3S
  family_graph_02 / O3S
  family_graph_03 / O3S
  family_graph_03 / O3KS
```

## 6. 한 case가 실제로 처리되는 과정

다음 명령을 예로 든다.

```bash
python3 compile.py family_graph_01 case
python3 run_case.py family_graph_01 --candidate-scope subject
```

### 6.1 Compile

첫 명령은 기본 build `O3S`를 사용한다.

```text
input : src/family_graph_01.rs
output: gt_bin/plain/family_graph_01.O3S.gt.bin
output: bin/plain/family_graph_01.O3S.fixture.bin
output: build_info/plain/family_graph_01.O3S.json
```

### 6.2 Manifest verification

`run_case.py`는 manifest에서 다음 세 hash를 다시 계산해 확인한다.

```text
source SHA-256
non-stripped binary SHA-256
stripped binary SHA-256
```

Case, build, profile, target도 각각 `family_graph_01`, `O3S`, `plain`, `x86_64-unknown-linux-gnu`인지 검사한다. Manifest의 compiler/strip flags가 코드에 정의된 canonical profile과 정확히 같은지도 확인한다.

이후 manifest의 `build_id`와 세 hash는 GT, users, fixture, score result에
`provenance`로 전달된다. 같은 case/build/profile이라도 provenance가 다르면
scoring join은 실패한다.

### 6.3 GT and fixture extraction

Non-stripped side에서 관찰되는 origin은 두 개다.

```text
shared_recursive: 3 members
process          : 3 members
```

Stripped side fixture에는 다음 node가 생긴다.

```text
6 user/scored nodes
1 root anchor
```

### 6.4 Grouping and scoring

`full` mode CG-WL 결과는 두 cluster다.

```text
C1 = shared_recursive instances 3개
C2 = process instances 3개
```

Scored node 6개의 전체 pair 수는 다음과 같다.

```text
6 * 5 / 2 = 15 pairs
```

저장된 결과는 다음과 같다.

```text
TP=6 FP=0 FN=0 TN=9
PR=1.00 RE=1.00 F1=1.00 ARI=1.00
```

## 7. 구현이 강제하는 불변조건

다음 조건이 깨지면 pipeline은 점수를 내지 않고 중단한다.

1. Manifest의 case/build/profile/target이 요청과 같아야 한다.
2. 현재 source와 binary hash가 manifest 기록과 같아야 한다.
3. Non-stripped와 stripped binary는 같은 manifest pair에 속해야 한다.
4. GT member ID 집합과 fixture의 `scored=true` ID 집합이 정확히 같아야 한다.
5. Fixture call target은 fixture 안에 존재해야 하고 count는 양수여야 한다.
6. 한 GT member는 둘 이상의 origin에 속할 수 없다.
7. `subject` scope에서 서로 다른 origin symbol이 한 주소를 공유하면 GT 생성은 실패한다. `rust-nonstd` scope에서는 주소 하나를 중복 node로 만들 수 없으므로 `shared-address@FUN_*` singleton과 원래 origin 목록을 보존한다.
8. Engine은 fixture 외의 GT/symbol 파일을 읽지 않는다.

## 8. 현재 범위와 한계

### Candidate 조건

현재 점수는 compiler symbol에서 얻은 candidate 주소와 Rust 함수 symbol extent가
제공된 조건의 결과다. 기본 scope는 `core/alloc/std/__rustc` 소유 함수를 제외한 모든
관찰 가능한 Rust 함수이고, 호환 scope는 subject namespace만 사용한다. Stripped
binary만으로 함수 소유권이나 경계를 복구하는 성능을 측정하지 않는다.

### Function과 edge 복구

Canonical source 함수와 source `main`의 경계는 non-stripped symbol extent를
oracle로 사용한다. 해당 stripped byte 범위는 radare2 `p8j`로 읽고 Capstone으로
x86-64 instruction을 디코딩한다. One-hop library anchor의 함수 시작점과 범위는
radare2 분석에 의존한다. 두 경로 모두 direct immediate call과 다른 함수의 정확한
시작점으로 향하는 unconditional jump를 exact edge로 센다. `angr` track에서는 여기에
angr CFG가 기존 함수 시작점 하나로 해결한 indirect call을 inferred edge로 추가한다.
Multi-target과 미해결 indirect call은 edge로 만들지 않는다.

### Ground truth의 의미

GT는 최종 non-stripped binary에 text symbol로 남은 함수의 origin partition이다. Source에서 예정된 모든 mono-item, 완전히 inline된 instance, eliminated instance의 원인을 알려주는 survival ground truth가 아니다.

### Grouping feature

Engine은 call relation만 사용한다. 함수 body, CFG, ABI, argument type, register class를 사용하지 않는다. 같은 relation signature를 가진 다른 origin은 분리할 수 없고, type-dependent inlining으로 relation이 달라진 같은 origin은 갈라질 수 있다.

### Corpus 범위

현재 네 build는 알고리즘의 동작과 한계를 고정하는 controlled micro-corpus다. 일반 Rust ecosystem의 평균 성능을 뜻하지 않는다.

## 9. 권장 문서 순서

전체 구현을 처음 읽는다면 다음 순서가 가장 짧다.

1. 이 문서
2. [컴파일 파이프라인](compilation.md)
3. [Ground truth 추출](ground_truth.md)
4. [바이너리 추출](binary_extraction.md)
5. [CG-WL](CG-WL.md)
6. [채점](scoring.md)

특정 Python 파일만 이해하려면 해당 단계 문서의 마지막 `코드 읽기 순서`를 따른다.
