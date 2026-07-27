# 바이너리 추출 파이프라인

## 1. 목적과 입력 경계

CallKin의 `binary_extractor.py`는 stripped binary를 radare2로 분석해 CG-WL 입력인 fixture JSON을 만든다.

```text
bin/plain/family_graph_01.O3S.fixture.bin
+ users/plain/family_graph_01.O3S.users.json
-> binary_extractor.py
-> fixtures/plain/family_graph_01.O3S.fixture.json
```

이 단계가 추출하는 것은 함수 body feature가 아니라 다음 Axis 1 정보다.

```text
node ID
user 또는 anchor
scored 여부
directed call target
static callsite count
```

`count=5`는 프로그램을 실행했을 때 다섯 번 호출됐다는 뜻이 아니다. Disassembly 안에서 같은 target으로 향하는 direct callsite 또는 tail-call-like jump가 다섯 개 관찰됐다는 뜻이다.

## 2. 정상 실행

Canonical 파일명을 사용하는 가장 짧은 명령은 다음과 같다.

```bash
python3 binary_extractor.py family_graph_01
```

기본값이 해석된 결과는 다음과 같다.

```text
binary = bin/plain/family_graph_01.O3S.fixture.bin
users  = users/plain/family_graph_01.O3S.users.json
case   = family_graph_01
build  = O3S
profile = plain
output = fixtures/plain/family_graph_01.O3S.fixture.json
```

실행 결과 예시:

```text
wrote fixtures/plain/family_graph_01.O3S.fixture.json
nodes=7
```

이 case의 7개 node는 다음과 같다.

```text
6 user/scored nodes
1 root anchor: FUN_00114040
```

## 3. 전체 함수 호출 순서

```text
main()
  -> build_arg_parser()
  -> apply_cli_defaults()
  -> extract_fixture()
       -> BinaryExtractor(...)
       -> analyze()
            -> radare2 aaa
            -> aflj
       -> load_users()
       -> resolve_root()
       -> build_call_graph()
            -> direct_calls() for every discovered function
       -> select_user_context()
       -> make_fixture_json()
  -> write_fixture()
```

`BinaryExtractor.close()`는 성공과 실패에 관계없이 `finally`에서 r2pipe session을 닫는다.

## 4. Radare2 session

`open_r2()`는 먼저 system에서 `radare2` 실행 파일을 찾는다. 그다음 Python package `r2pipe`를 import하고 binary를 연다.

```text
Python binary_extractor.py
-> r2pipe
-> radare2 process
-> JSON analysis result
```

Radare2가 없으면 다음처럼 실패한다.

```text
error: radare2 executable was not found. Install radare2 before running binary_extractor.py.
```

`r2pipe`만 없으면 다음 설치 방법을 포함해 오류를 낸다.

```text
python3 -m pip install -r requirements.txt
```

## 5. 함수 목록 복구

`analyze()`는 radare2에 다음 명령을 보낸다.

```text
aaa
```

이 명령은 radare2의 자동 분석을 실행한다. 이후 `_refresh_functions()`가 다음 명령으로 함수 목록을 JSON으로 받는다.

```text
aflj
```

각 함수는 내부에서 다음 값으로 저장된다.

```python
R2Function(
    addr=0x13e40,
    name="fcn.00013e20",
    size=224,
    kind="fcn",
)
```

여기서 중요한 경계는 다음과 같다.

> 이 extractor는 함수 경계를 직접 연구하거나 복구하지 않는다. Radare2가 함수로 복구한 결과를 사용한다.

`--include-imports`를 주지 않으면 radare2 import stub으로 판단한 함수는 목록과 edge에서 제외한다.

## 6. 함수 ID

Fixture는 raw address 대신 다음 형식의 ID를 사용한다.

```text
FUN_<8자리 hexadecimal>
```

기본 `id_bias`는 `0x100000`이다.

실제 예시:

```text
raw address = 0x13e40
id bias     = 0x100000
sum         = 0x113e40
fixture ID  = FUN_00113e40
```

이 bias는 현재 Ghidra-style hand fixture와 ID를 맞추기 위한 표현 규칙이다. Call graph 의미나 실제 binary address를 바꾸지 않는다.

Raw radare2 address 형식을 원하면 다음처럼 실행할 수 있다.

```bash
python3 binary_extractor.py family_graph_01 --id-bias 0
```

그 경우 같은 함수 ID는 다음이 된다.

```text
FUN_00013e40
```

## 7. Root 탐지

`resolve_root()`는 다음 순서로 root를 찾는다.

1. 사용자가 `--root`로 지정한 함수
2. Rust/glibc startup pattern에서 복구한 user main
3. 이름이 `main` 또는 `sym.main`인 함수
4. 마지막 fallback인 `entry0`

Canonical 실행에서는 startup wrapper를 따라 Rust user main을 찾는다.

### 7.1 `entry0`에서 libc wrapper 찾기

`_libc_start_main_wrapper_addr()`는 `entry0`의 `pdfj` 결과를 읽는다. 예를 들어 다음 형태를 찾는다.

```text
lea rdi, [0x14020]
...
call __libc_start_main
```

`rdi`에 적재된 `0x14020`을 glibc에 전달된 main wrapper 주소로 해석한다.

### 7.2 Wrapper에서 Rust user main 찾기

`_rust_main_from_start_wrapper()`는 wrapper 앞부분을 `pdj 64`로 읽는다. 다음과 같은 흐름을 찾는다.

```text
lea rax, [rust_user_main]
mov [rsp], rax
call std::rt::lang_start_internal
```

여기서 `rax`에 적재된 immediate address를 실제 Rust user main으로 사용한다.

이것은 일반 indirect dispatch recovery가 아니다. Rust startup에서 main function pointer constant를 회수하는 제한된 heuristic이다. 실패하면 `--list-functions`로 목록을 본 뒤 `--root`를 지정한다.

```bash
python3 binary_extractor.py family_graph_01 --list-functions
python3 binary_extractor.py family_graph_01 --root FUN_00113e00
```

## 8. Call edge 추출

`build_call_graph()`는 함수 종류에 따라 두 경계 source를 사용한다.

Canonical users mode에서 source namespace 함수와 source `main`은 users JSON의
symbol extent를 사용한다. Stripped binary bytes를 다음 radare2 명령으로 읽고,
Capstone x86-64 decoder로 `[start, start + size)` 전체를 선형 디코딩한다.

```text
p8j <symbol size> @ <function address>
```

따라서 radare2가 main을 실제보다 짧은 함수로 복구해도 뒤쪽 callsite를 버리지
않는다. 예를 들어 symbol size가 1465 bytes인데 radare2 size가 951 bytes이면
fixture의 `extraction.boundary_mismatches`에 차이를 기록하고 1465 bytes 전체를
디코딩한다.

Users가 직접 호출하는 one-hop library anchor는 symbol extent가 없으므로 기존처럼
radare2 `pdfj @ <function address>`를 사용한다. Anchor는 terminal이므로 그 내부
edge는 fixture에 기록하지 않는다.

### 8.1 Direct call

Instruction에 radare2의 direct `jump` target이 있고 operation이 call이면 target을 포함하는 함수를 찾는다.

예시:

```text
현재 함수: 0x14480
instruction: call 0x13f20
target function start: 0x13f20
```

Bias를 적용한 fixture edge는 다음과 같다.

```json
{
  "target": "FUN_00113f20",
  "count": 1
}
```

같은 함수 body에 `call 0x13f20`이 다섯 곳 있으면 `Counter`가 합산한다.

```json
{
  "target": "FUN_00113f20",
  "count": 5
}
```

### 8.2 Tail-call-like jump

O3는 다음 형태를:

```text
call target
ret
```

다음처럼 바꿀 수 있다.

```text
jmp target
```

Extractor는 jump target이 **다른 함수의 정확한 시작 주소**일 때만 call edge로 센다.

```text
current function start = 0x14480
jump target            = 0x13f20
known function start   = 0x13f20
=> tail-call edge로 포함
```

함수 내부 basic block으로 향하는 일반 branch는 target이 다른 함수 시작점이 아니므로 제외한다.

### 8.3 포함하지 않는 call

`call rax`처럼 immediate target이 없는 indirect call은 `_direct_code_target()`이 주소를 얻을 수 없으므로 제외한다.

```text
call rax
=> target unknown
=> fixture edge 없음
```

GOT/PLT 형태도 radare2 결과에 직접 code target이 없으면 포함되지 않는다. 이는 호출이 실행되지 않는다는 뜻이 아니라 현재 extractor가 direct target으로 복구하지 않았다는 뜻이다.

## 9. User address 입력

정상 pipeline은 `gt_extractor.py`가 만든 users JSON을 읽는다.

```json
{
  "case": "family_graph_01",
  "build": "O3S",
  "profile": "plain",
  "schema_version": 4,
  "provenance": {
    "build_id": "...",
    "source_sha256": "...",
    "non_stripped_sha256": "...",
    "stripped_sha256": "..."
  },
  "source": "gt_bin/plain/family_graph_01.O3S.gt.bin",
  "prefix": "family_graph_01::",
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

`load_users()`는 candidate 주소를 integer set으로, symbol extent를 address-to-size
map으로 바꾼다. `function_bounds`에는 source `main`도 포함된다.

```python
{
    0x13e40,
    0x13f20,
    0x13fa0,
    0x14480,
    0x14660,
    0x148a0,
}
```

Candidate 주소마다 stripped binary에서 radare2가 정확한 함수 시작점을 복구했는지 검사한다. 예를 들어 `0x14480`이 symbol side에는 있지만 `aflj` 함수 시작점에는 없으면 다음 유형의 오류로 중단한다.

```text
user address(es) are not radare2 function starts in stripped binary: 0x14480
```

Root reachability는 candidate 필터로 사용하지 않는다. 대신 namespace 함수의
relation은 symbol extent로 추출하며 radare2 size가 다르면 mismatch를 fixture에
남긴다.

## 10. 어떤 node를 fixture에 넣는가

정상 users mode의 emitted node 집합은 다음과 같다.

```text
root anchor
+ users JSON에 적힌 모든 user 함수
+ 각 user 함수가 직접 호출하는 함수
```

중요하게도 user가 직접 호출한 library/runtime 함수에서 더 깊이 내려가지 않는다.

구체적인 예를 가정한다.

```text
root R -> user U
user U -> library L1
library L1 -> library L2
```

Emitted node:

```text
R, U, L1
```

Emitted되지 않는 node:

```text
L2
```

Fixture edge는 다음처럼 제한된다.

```text
R  -> U   유지
U  -> L1  유지
L1 -> L2  제거
```

Node type과 scoring은 다음과 같다.

| Node | type | scored | outgoing edge 처리 |
|---|---|---:|---|
| users JSON의 함수 | `user` | `true` | selected node로 향하는 edge 유지 |
| root | `anchor` | `false` | listed user로 향하는 edge만 유지 |
| user의 직접 library callee | `anchor` | `false` | terminal, outgoing edge 없음 |

따라서 anchor는 user의 call-graph 문맥을 보존하지만 점수 계산 대상은 아니다.

정상 users mode에서는 users JSON의 주소 집합을 authoritative candidate set으로 사용한다. Root reachability를 candidate 필터로 다시 적용하지 않는다. 이는 radare2가 큰 함수의 경계를 일찍 끊더라도 symbol에서 확인된 user 함수를 누락시키지 않기 위해서다.

`select_user_context()`는 root, 모든 listed user, 각 listed user가 직접 호출하는 함수만 선택한다. 따라서 library anchor의 callee로 더 내려가지 않는다.

`select_reachable()`은 users JSON 없이 직접 실행하는 fallback mode에서만 root-reachable closure 전체를 선택한다. 이것은 canonical 연구 pipeline이 아니다.

## 11. Fixture JSON

`make_fixture_json()`의 출력 schema version은 4다.

실제 fg01 일부:

```json
{
  "case": "family_graph_01",
  "build": "O3S",
  "profile": "plain",
  "schema_version": 4,
  "provenance": {
    "build_id": "...",
    "source_sha256": "...",
    "non_stripped_sha256": "...",
    "stripped_sha256": "..."
  },
  "extraction": {
    "boundary_mode": "symbol-extent",
    "boundary_mismatches": []
  },
  "nodes": [
    {
      "id": "FUN_00113e40",
      "type": "user",
      "scored": true,
      "calls": [
        {
          "target": "FUN_00113e40",
          "count": 1
        }
      ]
    },
    {
      "id": "FUN_00114040",
      "type": "anchor",
      "scored": false,
      "calls": [
        {
          "target": "FUN_00113e40",
          "count": 2
        }
      ]
    }
  ]
}
```

Self-call도 일반 call edge 형태로 JSON에 기록한다. `engine.py`가 fixture를 읽은 뒤 self edge를 `self_call_count`로 분리한다.

`loader.py`는 다음 오류를 거부한다.

- unknown field
- 중복 node ID
- `anchor`인데 `scored=true`
- fixture에 없는 target
- count가 0 이하
- 같은 source에서 같은 target edge가 중복됨

## 12. CLI argument

| Argument | 기능 | 예시 |
|---|---|---|
| `binary` | binary path 또는 stem | `family_graph_01` |
| positional `output` | fixture 출력 경로 | `fixtures/custom.fixture.json` |
| `--case` | JSON case override | `--case custom_case` |
| `--build` | build label | `--build O3KS` |
| `--profile` | compiler profile과 artifact directory | `--profile min` |
| `--root` | root name/ID/address | `--root FUN_00114040` |
| `--users` | users JSON 경로 | `--users users/min/custom.users.json` |
| `--manifest` | build manifest override | `--manifest build_info/min/custom.json` |
| `--score-root` | root도 user/scored로 처리 | canonical pipeline에서는 사용하지 않음 |
| `--include-imports` | import stub 포함 | debugging option |
| `--id-bias` | FUN ID address bias | `--id-bias 0` |
| `--list-functions` | 함수 목록만 출력 | root 문제 진단 |

## 13. 한계의 정확한 의미

- Source namespace 함수 경계는 non-stripped symbol extent를 oracle로 사용한다.
- One-hop library anchor의 시작점과 범위 복구는 radare2 분석에 의존한다.
- Immediate direct target이 없는 call은 복구하지 않는다.
- Root 자동 탐지는 현재 Rust/glibc startup 형태에 맞춘 heuristic이다.
- Users JSON은 compiler symbol namespace에서 얻은 controlled candidate와 boundary 조건이다.
- Library/runtime 함수의 종류를 분류하지 않는다. User의 direct callee이면 동일하게 anchor다.
- Anchor 내부를 계속 탐색하지 않으므로 library subgraph topology는 feature에 들어가지 않는다.
- Fixture의 call count는 dynamic execution frequency가 아니다.

## 14. 코드 읽기 순서

1. `main()`
2. `apply_cli_defaults()`
3. `extract_fixture()`
4. `BinaryExtractor.analyze()`와 `_refresh_functions()`
5. `resolve_root()`와 startup helper
6. `build_call_graph()`와 `direct_calls()`
7. `_direct_calls_from_symbol_extent()`와 `_direct_call_target()`
8. `select_reachable()`
9. `select_user_context()`
10. `make_fixture_json()`
11. `write_fixture()`
