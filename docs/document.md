# CallKin 전체 구현 안내

## 1. 프로젝트가 답하려는 질문

Rust generic 함수는 하나의 source definition에서 여러 monomorphized instance로 컴파일된다. 최종 stripped binary에는 source의 generic 이름과 concrete type 정보가 남지 않을 수 있다.

CallKin은 다음의 제한된 질문을 다룬다.

> 분석 대상 user 함수 집합이 주어졌을 때, stripped binary에서 관찰되는 caller/callee 관계만으로 같은 source origin에서 나온 monomorphized 함수들을 다시 묶을 수 있는가?

예를 들어 source에 다음 함수가 있다고 하자.

```rust
fn process<T>(value: T) { /* ... */ }
```

컴파일 후 세 instance가 다음 주소에 생존할 수 있다.

```text
FUN_00114240  process instance 1
FUN_00114420  process instance 2
FUN_00114660  process instance 3
```

`engine.py`는 `process`라는 이름을 받지 않는다. 각 함수가 누구를 몇 번 호출하고 누구에게 호출되는지만 보고 세 주소를 같은 cluster로 묶으려 한다.

이 연구의 대상은 **relation-only grouping**이다. generic 탐지, type 복원, source 복원, 함수 경계 복원 자체는 대상이 아니다.

## 2. 전체 data flow

```text
                         source side
                             |
                             v
                    src/family_graph_01.rs
                             |
                         compile.py
                             |
             +---------------+---------------+
             |                               |
             v                               v
  non-stripped binary                stripped binary
  gt_bin/*.gt.bin                    bin/*.fixture.bin
             |                               |
       gt_extractor.py                binary_extractor.py
             |                               |
       +-----+-----+                         v
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
build_info/family_graph_01.O3S.json
```

`run_case.py`는 JSON을 추출하기 전에 이 manifest의 source hash와 두 binary hash를 검사한다.

## 3. 가장 중요한 분리

### 3.1 Grouping side

Grouping side는 stripped binary에서 만든 fixture만 사용한다.

```text
fixtures/family_graph_01.O3S.fixture.json
```

fixture의 한 user node는 다음처럼 생겼다.

```json
{
  "id": "FUN_00114240",
  "type": "user",
  "scored": true,
  "calls": [
    {
      "target": "FUN_00113ce0",
      "count": 5
    }
  ]
}
```

이 입력은 다음 사실만 말한다.

```text
FUN_00114240이 FUN_00113ce0을 정적으로 5곳에서 호출한다.
```

`process`, generic type, origin 같은 정답 정보는 fixture에 없다.

### 3.2 Ground-truth side

Ground-truth side는 non-stripped binary의 compiler symbol을 사용한다.

```json
{
  "origin": "process",
  "members": [
    "FUN_00114240",
    "FUN_00114420",
    "FUN_00114660"
  ]
}
```

이 정보는 `engine.py`에 전달되지 않는다. `scores.py`가 engine 실행이 끝난 뒤에만 읽는다.

### 3.3 Candidate address bridge

`users/*.users.json`에는 user 함수의 raw address만 들어간다.

```json
{
  "prefix": "family_graph_01::",
  "addresses": [
    "0x13e20",
    "0x13f00",
    "0x13f80",
    "0x14460",
    "0x14640",
    "0x14880"
  ]
}
```

이 파일은 `0x14460`이 `process`인지, 다른 주소와 같은 origin인지 말하지 않는다. 따라서 binary extractor가 user/library 경계를 정하는 데 사용하지만 grouping 정답 partition은 전달하지 않는다.

단, 이것은 일반적인 user/library classifier가 아니다. 통제 corpus의 non-stripped symbol namespace를 이용해 candidate 집합을 제공하는 연구 조건이다.

## 4. Artifact의 의미

모든 canonical 파일은 `<case>.<build>` stem을 공유한다.

| Artifact | 예시 | 역할 |
|---|---|---|
| Rust source | `src/family_graph_01.rs` | corpus 원본 |
| Non-stripped binary | `gt_bin/family_graph_01.O3S.gt.bin` | symbol, GT, users 주소의 근거 |
| Stripped binary | `bin/family_graph_01.O3S.fixture.bin` | 실제 relation 추출 대상 |
| Build manifest | `build_info/family_graph_01.O3S.json` | source/tool/binary hash 결속 |
| Ground truth | `ground_truth/family_graph_01.O3S.gt.json` | origin partition과 symbol |
| User addresses | `users/family_graph_01.O3S.users.json` | candidate raw address 집합 |
| Fixture | `fixtures/family_graph_01.O3S.fixture.json` | node와 weighted call edge |
| Score result | `results/v0_baseline.json` | cluster, origin별 결과, metric |

`O3S`의 non-stripped binary는 O3 profile로 컴파일한 binary다. 같은 파일을 복사하고 `strip --strip-all`한 결과가 O3S fixture binary다. `O3KS`는 `--cfg keep`이 추가된 O3K profile에 같은 절차를 적용한다.

## 5. Module 책임

### `compile.py`

한 Rust source를 컴파일해 non-stripped/stripped binary pair와 manifest를 만든다. 실제 컴파일 파이프라인은 이 파일에 있다.

상세: [컴파일 파이프라인](compilation.md)

### `gt_extractor.py`

Non-stripped binary에서 `nm -n -C` 결과를 읽고 같은 normalized symbol path를 같은 origin으로 묶는다. 동시에 user raw address 집합을 만든다.

상세: [Ground truth 추출](ground_truth.md)

### `binary_extractor.py`

Radare2가 복구한 stripped function과 direct call을 fixture로 변환한다. user 함수와 직접 인접한 library/runtime 함수까지만 anchor로 emit한다.

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
-> fixture 생성
-> GT와 scored universe join 검사
-> CG-WL
-> scoring
```

### `run_baseline.py`

네 canonical build 각각에 대해 `compile.py`와 `run_case.py`를 실행한 뒤 baseline JSON과 exact regression을 생성한다.

```text
family_graph_01 / O3S
family_graph_02 / O3S
family_graph_03 / O3S
family_graph_03 / O3KS
```

## 6. 한 case가 실제로 처리되는 과정

다음 명령을 예로 든다.

```bash
python3 compile.py family_graph_01
python3 run_case.py family_graph_01
```

### 6.1 Compile

첫 명령은 기본 build `O3S`를 사용한다.

```text
input : src/family_graph_01.rs
output: gt_bin/family_graph_01.O3S.gt.bin
output: bin/family_graph_01.O3S.fixture.bin
output: build_info/family_graph_01.O3S.json
```

### 6.2 Manifest verification

`run_case.py`는 manifest에서 다음 세 hash를 다시 계산해 확인한다.

```text
source SHA-256
non-stripped binary SHA-256
stripped binary SHA-256
```

Case, build, target도 각각 `family_graph_01`, `O3S`, `x86_64-unknown-linux-gnu`인지 검사한다.

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

1. Manifest의 case/build/target이 요청과 같아야 한다.
2. 현재 source와 binary hash가 manifest 기록과 같아야 한다.
3. Non-stripped와 stripped binary는 같은 manifest pair에 속해야 한다.
4. GT member ID 집합과 fixture의 `scored=true` ID 집합이 정확히 같아야 한다.
5. Fixture call target은 fixture 안에 존재해야 하고 count는 양수여야 한다.
6. 한 GT member는 둘 이상의 origin에 속할 수 없다.
7. 서로 다른 origin symbol이 한 주소를 공유하면 GT 생성은 실패한다.
8. Engine은 fixture 외의 GT/symbol 파일을 읽지 않는다.

## 8. 현재 범위와 한계

### Candidate 조건

현재 점수는 compiler symbol에서 얻은 user 주소 집합이 제공된 조건의 결과다. Stripped binary만으로 user 함수를 자동 분류하는 성능을 측정하지 않는다.

### Function과 edge 복구

함수 경계와 instruction 분석은 radare2에 의존한다. Direct immediate call과 다른 함수 시작점으로 향하는 jump만 edge로 센다. Indirect call은 복구하지 않는다.

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
