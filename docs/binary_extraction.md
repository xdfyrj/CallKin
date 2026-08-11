# 바이너리 추출 파이프라인

## 1. 목적과 입력 경계

CallKin의 `binary_extractor.py`는 stripped binary를 radare2와 Capstone으로 분석해
raw transfer evidence를 만든다. `graph_projector.py`가 이 evidence를 track 정책에
따라 CG-WL fixture로 투영한다. Raw graph에는 projection track과 candidate 주소가
들어가지 않는다. Base extraction은 direct transfer와 ELF relocation으로 exact하게
증명된 indirect transfer를 저장한다. `angr` track은 같은 evidence에서 출발해 angr
CFG가 단일 target으로 해결한 unresolved call/tail-call을 보강한 별도 raw graph를 사용한다.

```text
bin/plain/family_graph_01.O3S.fixture.bin
+ boundaries/plain/family_graph_01.O3S.boundaries.json
-> binary_extractor.py
-> extractions/plain/family_graph_01.O3S.raw.json
+ users/plain/family_graph_01.O3S.users.json
-> graph_projector.py
-> fixtures/plain/family_graph_01.O3S.fixture.json
```

이 단계가 추출하는 것은 함수 body feature가 아니라 다음 Axis 1 정보다.

```text
node ID
candidate, anchor, 또는 abstain
directed call target
static callsite count
```

`count=5`는 프로그램을 실행했을 때 다섯 번 호출됐다는 뜻이 아니다. Disassembly 안에서 같은 target으로 향하는 direct callsite 또는 tail-call-like jump가 다섯 개 관찰됐다는 뜻이다.

## 2. 정상 실행

Canonical 파일명을 사용하는 가장 짧은 명령은 다음과 같다.

```bash
# 기본 rust-nonstd scope
python3 binary_extractor.py billing-client --track direct-in
python3 binary_extractor.py billing-client --track angr
python3 binary_extractor.py billing-client --track angr --anchor-policy role

# frozen subject-only baseline
python3 binary_extractor.py family_graph_01 --candidate-scope subject
```

기본값이 해석된 결과는 다음과 같다.

```text
binary = bin/plain/family_graph_01.O3S.fixture.bin
users  = users/plain/family_graph_01.O3S.users.json
boundaries = boundaries/plain/family_graph_01.O3S.boundaries.json
case   = family_graph_01
build  = O3S
profile = plain
output = fixtures/plain/family_graph_01.O3S.fixture.json
raw    = extractions/plain/family_graph_01.O3S.raw.json
```

실행 결과 예시:

```text
wrote fixtures/plain/family_graph_01.O3S.fixture.json
raw graph: extractions/plain/family_graph_01.O3S.raw.json
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
  -> extract_artifacts()
       -> BinaryExtractor(...)
       -> analyze()
            -> radare2 aaa
            -> aflj
       -> load_candidate_selection()
       -> load_function_boundaries()
       -> resolve_root()
       -> transfer_evidence() for every discovered function
       -> build_raw_graph()
       -> [angr track] augment_raw_graph_with_angr()
       -> graph_projector.py(raw + candidate selection + track)
  -> write_raw_graph()
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

`r2pipe`가 없으면 다음 설치 방법을 포함해 오류를 낸다.

```text
python3 -m pip install -r requirements.txt
```

Canonical symbol-extent 추출에서 `capstone`이 없을 때도 같은 명령을 안내하며
중단한다. `requirements.txt`는 `r2pipe`, `capstone`, `pyelftools`, pinned `angr`를 설치한다.
Angr는 `--track angr`에서만 import하고 실행하므로 direct track의 실행 비용에는
영향을 주지 않는다.

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
python3 binary_extractor.py family_graph_01 --id-bias 0 --candidate-scope subject
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

`_rust_main_from_start_wrapper()`는 boundary JSON에 C `main`의 symbol size가 있으면
stripped binary에서 해당 byte 범위 전체를 `p8j`로 읽고 Capstone으로 선형
디코딩한다. 따라서 radare2의 `pdfj`가 C `main` 앞부분만 반환해도 뒤쪽 startup
코드를 검사한다. Symbol extent가 없는 비표준 입력에서만 기존 `pdfj`/`pdj 64`
경로를 fallback으로 사용한다.

Non-LTO startup에서는 다음 흐름을 찾는다.

```text
lea rax, [rust_user_main]
mov qword ptr [rsp], rax
call std::rt::lang_start_internal
```

여기서 `rax`에 적재된 immediate address를 실제 Rust user main으로 사용한다.
Capstone이 실제 plain `billing-client`의 `48 89 04 24`를 어떤 문자열로 출력하는지에
의존하지 않는다. Instruction operand에서 destination이 offset 없는 `[rsp]` memory이고
source가 `rax` register인지 검사해 startup argument store로 인식한다. 문자열 비교는
symbol extent가 없는 radare2 fallback에만 남는다. Plain에서는 C `main=0x3cb60`의
`0x27` bytes 전체를 디코딩해 `reconcile::main=0x38800`을 root로 선택한다.

Fat LTO로 `lang_start_internal`이 C `main` 안에 인라인된 경우에는 다음 흐름도
찾는다.

```text
lea rdi, [rust_user_main]
call __rust_begin_short_backtrace

__rust_begin_short_backtrace:
call rdi
```

예를 들어 min `billing-client`에서는 C `main=0x37c40`, symbol size `0x54a`의
전체 범위를 디코딩하여 `main+0x450`의 `lea rdi, [0x35440]`을 찾고,
`0x35440`의 `reconcile::main`을 root로 선택한다.

이것은 일반 indirect dispatch recovery가 아니다. Rust startup에서 main function pointer constant를 회수하는 제한된 heuristic이다. 실패하면 `--list-functions`로 목록을 본 뒤 `--root`를 지정한다.

```bash
python3 binary_extractor.py family_graph_01 --list-functions
python3 binary_extractor.py family_graph_01 --root FUN_00113e00
```

## 8. Call edge 추출

`build_call_graph()`는 함수 종류에 따라 두 경계 source를 사용한다.

Canonical extraction은 candidate scope와 독립된 boundaries JSON의 Rust symbol
extent를 사용한다. Stripped binary bytes를 다음 radare2 명령으로 읽고,
Capstone x86-64 decoder로 `[start, start + size)` 전체를 선형 디코딩한다.

```text
p8j <symbol size> @ <function address>
```

따라서 radare2가 main을 실제보다 짧은 함수로 복구해도 뒤쪽 callsite를 버리지
않는다. 예를 들어 symbol size가 1465 bytes인데 radare2 size가 951 bytes이면
fixture의 `extraction.boundary_mismatches`에 차이를 기록하고 1465 bytes 전체를
디코딩한다.

Boundary artifact에 없는 C/import 함수는 기존처럼 radare2
`pdfj @ <function address>`를 사용한다. 해당 함수가 projection의 outgoing closure에
포함되면 그 내부의 복구된 edge도 fixture에 기록한다.

Radare2 함수는 entry 주소부터 연속된 byte range 하나가 아닐 수 있다. 실제
billing-client의 한 함수는 nominal entry가 `0x411b0`이지만 앞쪽의 `0x3105c`
basic block도 같은 함수에 속한다. 따라서 radare2 `pdfj`가 그 함수에 귀속한
operation은 `entry <= callsite < entry+size`라는 선형 조건으로 다시 자르지 않는다.
반대로 symbol-oracle extent는 정확한 연속 범위이므로 Capstone이 그 범위를 엄격히
검사한다.

### 8.1 Direct call

Symbol-extent 경로에서는 Capstone instruction의 단일 immediate operand를 direct
target으로 사용한다. Radare2 경로에서는 operation이 call이고 JSON에 direct
`jump` target이 있을 때 그 주소를 사용한다. 어느 경로든 target 주소를 포함하는
알려진 함수를 찾아 같은 edge 규칙으로 합산한다.

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

### 8.3 Exact static indirect resolution

Immediate operand가 아니어도 ELF가 target을 정확히 증명하는 경우가 있다. CallKin은
x86-64 ELF relocation table을 `pyelftools`로 읽고 다음 형태를 exact edge로 복구한다.

```text
0x406b0: jmp qword ptr [rip + 0x6e2f2]
           │
           └─ pointer slot = 0xae9a8

ELF relocation: 0xae9a8 -> 0x56410
known function: 0x56410

=> kind=tail-call
=> status=resolved
=> target=0x56410
=> resolver=elf-relocation
=> confidence=exact
```

이 방식은 relocation이 가리키는 값이 raw function table의 정확한 함수 시작점일 때만
raw evidence를 `resolved`로 기록한다. 주소는 알지만 함수 시작점에 매핑되지 않으면
`unmapped`, import라서 정책상 제외하면 `filtered`로 기록한다.

Schema v6 projection은 `confidence=exact`인 `elf-relocation`의 `unmapped` target을
버리지 않는다. 해당 주소를 이름과 함수 body가 없는 `anchor/scored=false` node로 만들고
증명된 edge를 이 opaque anchor로 연결한다. 이는 target 주소가 함수 시작이라고 symbol로
주장하는 것이 아니라, call instruction과 relocation이 증명한 목적지 주소를 문맥으로
보존하는 것이다. 일반 `direct-immediate`의 `unmapped` target에는 이 규칙을 적용하지
않는다.

### 8.4 Target을 확정하지 못한 call과 tail-call

`call rax`처럼 immediate target이 없는 indirect call은 fixture edge로 만들지 않는다.
대신 raw graph에 `status=unresolved`로 기록한다.

```text
call rax
=> raw evidence: operand_kind=register, status=unresolved
=> projected fixture edge 없음
```

함수의 마지막 의미 있는 instruction인 `jmp rax` 또는 `jmp [memory]`도 일반 branch로
버리지 않고 `kind=tail-call`로 기록한다. 함수 중간의 indirect jump는 switch나 basic
block branch일 수 있으므로 이 규칙으로 call evidence에 넣지 않는다.

```text
jmp rax  # terminal instruction
=> raw evidence: kind=tail-call, operand_kind=register, status=unresolved
=> angr 분석 대상
```

GOT/PLT 형태도 relocation이나 다른 resolver로 target을 확정하지 못하면 동일하게
unresolved다.
이는 호출이 실행되지 않는다는 뜻이 아니라 현재 extractor가 target을 복구하지
못했다는 뜻이다.

### 8.5 Angr singleton indirect resolution

`--track angr`는 base raw graph의 unresolved `call`과 terminal `tail-call` callsite를 angr
`CFGFast(resolve_indirect_jumps=True)` 결과와 주소로 join한다. Resolver가 성공해
일반 `Ijk_Call` call edge 또는 `Ijk_Boring` tail edge가 된 결과와,
`cfg.indirect_jumps`에 남은 결과를 모두 수집한다. 다음 조건을 순서대로 모두 만족할
때만 fixture edge 후보로 승격한다.

`CFGFast(function_starts=...)`에는 boundaries JSON의 함수 시작점을 angr load base에
맞게 rebasing하여 전달한다. 이 boundaries JSON은 non-stripped binary의 demangle 가능한
전체 Rust text symbol과 startup C `main`에서 얻는다. 따라서 angr target recovery는 stripped binary의
instruction을 분석하지만, 함수 시작점은 symbol-boundary oracle을 사용하는 조건이며
stripped-only function discovery가 아니다.

```text
같은 callsite를 가리킴
+ filtering 전 angr target 집합의 크기가 정확히 1
+ 그 유일한 target이 raw graph에 이미 존재하는 함수 시작점
```

예를 들어 `call rax`의 callsite가 `0x39048`이고 angr가 target `0x35470` 하나만
찾으면 raw transfer는 다음처럼 바뀐다.

```text
status=resolved
target=0x35470
resolver=angr-cfg
confidence=inferred
```

target이 두 개 이상이면 가능한 target 집합을 `angr_targets`에 보존하되 기존
`unresolved` 상태를 유지한다. 이 집합은 `may-call` evidence이지 exact edge가 아니므로
현재 CG-WL fixture에는 투영하지 않는다. 알려진 함수 시작점이 아닌 singleton도
`unknown_target`으로 남긴다. Raw schema v5는 각 간접 transfer에 `angr_status`, `angr_targets`,
`angr_target_names`를 추가해 `resolved_internal`, `resolved_import`,
`unresolvable_target`, `multiple_targets`, `unknown_target`, `ambiguous_source`,
`no_angr_result`를 구분한다. 이름 있는 외부 import는 복원 성공이지만 현재 graph
정책에서 제외되므로 `status=filtered`, `filter_reason=import`로 기록한다.
`indirect_call_summary`는 angr에 전달된 unresolved transfer의 판정을 operand 종류별로
합산한다. `elf-relocation`으로 먼저 해결된 exact indirect transfer는
angr 시도 분모에 들어가지 않고 개별 transfer의 resolver로 확인한다. Base raw graph에서는
분석 전 상태를 `not_run`으로 기록한다. 이미 `direct-immediate`, `direct-tail`,
`elf-relocation`으로 확정된 edge는 angr 결과가 달라도 덮어쓰지 않는다.

Raw graph에서는 direct edge의 `confidence=exact`와 angr edge의
`confidence=inferred`를 구분한다. 현재 projected fixture의 `calls`는 resolver별
evidence를 보존하지 않고 같은 `(source, target)`의 static callsite count로 합산한다.

### 8.6 확정했지만 제외한 import

`include_imports=false`일 때 import stub의 주소를 정확히 알아도 fixture edge에서는
제외한다. 이 경우는 unresolved가 아니라 다음처럼 기록한다.

```text
status=filtered
target=0x52760
resolver=direct-immediate
confidence=exact
filter_reason=import
```

따라서 `unresolved`는 target을 정하지 못한 callsite만 의미한다.

Angr가 이름 있는 import를 복원한 경우도 같은 정책을 사용하되
`resolver=angr-cfg`, `confidence=inferred`, `angr_status=resolved_import`로 기록한다.
따라서 import는 간접호출 복원 실패 수에 포함되지 않는다.

### 8.7 주소는 알지만 함수에 매핑하지 못한 call

Immediate operand에서 숫자 target은 정확히 디코딩했지만 raw function table의 어느
함수에도 연결하지 못한 경우는 `unresolved`와 구분한다.

```text
status=unmapped
target=0x5b072054
resolver=direct-immediate
confidence=exact
```

이는 target 주소를 모른다는 뜻이 아니다. 주소는 알지만 현재 function/boundary
evidence로 함수 node에 매핑할 수 없다는 뜻이다. 일반 direct target은 fixture edge로
투영하지 않는다. 단, exact ELF relocation target은 Schema v6에서 body와 이름이 없는
opaque anchor로 투영한다. Raw의 `status=unmapped`는 그대로 유지되므로 함수 경계를
복구했다는 잘못된 주장을 하지 않는다.

## 9. Candidate와 boundary 입력

정상 pipeline은 `gt_extractor.py`가 만든 users JSON을 읽는다.

```json
{
  "case": "family_graph_01",
  "build": "O3S",
  "profile": "plain",
  "schema_version": 5,
  "provenance": {
    "build_id": "...",
    "source_sha256": "...",
    "non_stripped_sha256": "...",
    "stripped_sha256": "..."
  },
  "source": "gt_bin/plain/family_graph_01.O3S.gt.bin",
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

`candidate_selection.py`는 candidate 주소를 integer set으로, symbol extent를
address-to-size map으로 바꾼다. `function_bounds`에는 source `main`도 포함된다.

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

공용 `boundaries/*.boundaries.json`은 demangle 가능한 모든 Rust text symbol extent와
startup root 탐지에 필요한 C `main` extent를 담으며 candidate 주소나 scope를 담지
않는다. Candidate 주소가 radare2 함수 시작점에
없더라도 이 검증된 boundary에 있으면 symbol-bound 함수로 보충한다. 이 함수의 byte 범위는
Capstone으로 직접 디코딩하고, fixture의 `boundary_mismatches`에는
`radare2_size=0`으로 기록한다. Symbol에도 없는 주소는 users 생성 단계에서
들어올 수 없으며, provenance가 다른 users 파일은 별도로 거부한다.

Root reachability는 candidate 필터로 사용하지 않는다. 대신 namespace 함수의
relation은 symbol extent로 추출하며 radare2 size가 다르면 mismatch를 fixture에
남긴다.

Raw schema v5는 각 함수가 radare2에서도 발견됐는지
`discovered_by_radare2`로 기록하고 boundary JSON의 SHA-256을
`analysis.boundary_input_sha256`에 기록한다. Projection track과 candidate 주소는 raw에
없다.

Raw graph의 구조 schema는 v5로 유지하며, 추출 의미의 변경은 별도
`analysis.extractor_version`으로 구분한다. 예를 들어 구조가 같은 raw graph라도
`call-evidence-v5`와 `call-evidence-v6`은 서로 다른 extraction semantics를 뜻한다.

Candidate 주소는 raw graph에 복사하지 않는다. Projector가 users JSON을 별도
입력으로 읽고 candidate 집합을 선택하며, 그 JSON의 canonical SHA-256을 schema v5
fixture의 `analysis.candidate_selection_sha256`에 기록한다. 따라서 하나의 raw
evidence를 다른 candidate scope와 projection 정책에 재사용할 수 있다.

Boundary 파일이 없을 때 users의 candidate extent로 대신 raw를 만드는 fallback은
허용하지 않는다. 그렇게 하면 같은 binary의 raw evidence가 candidate scope에 따라
달라지기 때문이다. Standalone 실행은 `gt_extractor.py`로 users와 boundaries를 먼저
생성해야 한다.

## 10. Track과 fixture node 선택

Schema v6 projection은 candidate selection이 정한 target 함수를 세 역할로 나눈다.

| 역할 | 조건 | CG-WL node | pairwise scoring |
|---|---|---:|---:|
| candidate | resolved non-self IN 또는 OUT edge가 하나 이상 있음 | 포함 | 포함 |
| anchor | target은 아니지만 candidate의 문맥을 제공함 | 포함 | 제외 |
| abstain | target이지만 resolved non-self IN과 OUT이 모두 0 | 제외 | 제외, 별도 기록 |

Self-call만 있는 target도 다른 함수와의 relation evidence가 없으므로 `abstain`이다.
`abstain`에는 node나 CG-WL color를 만들지 않는다. fixture top-level의
`abstentions`에 이유만 기록한다.

```json
{
  "id": "FUN_0011d920",
  "status": "abstain",
  "reason": "no_resolved_nonself_in_or_out_edge"
}
```

동결된 `subject/direct` baseline만 schema v4 compatibility projection을 유지한다.
이는 이전 family-graph score regression을 그대로 보존하기 위한 예외다. 새 context
projection(`direct-in`, `angr`, 또는 `rust-nonstd` scope)은 schema v6을 사용한다.

### 10.1 `direct`

정상 users mode의 emitted node 집합은 다음과 같다.

```text
closure_out(root + users JSON에 적힌 모든 user 함수)
```

User가 호출한 library/runtime 함수도 wall로 사용하지 않고 resolved outgoing edge를
계속 따라간다.

구체적인 예를 가정한다.

```text
root R -> user U
user U -> library L1
library L1 -> library L2
```

Emitted node:

```text
R, U, L1, L2
```

Fixture edge는 다음처럼 제한된다.

```text
R  -> U   유지
U  -> L1  유지
L1 -> L2  유지
```

Node type과 scoring은 다음과 같다.

| Node | type | scored | outgoing edge 처리 |
|---|---|---:|---|
| relation이 있는 target | `user` | `true` | selected node로 향하는 edge 유지 |
| root | `anchor` | `false` | selected node로 향하는 edge 유지 |
| closure의 non-candidate 함수 | `anchor` | `false` | selected node로 향하는 edge 유지 |

관계가 없는 target은 node가 아니라 top-level `abstentions`에 기록된다.

따라서 anchor는 user의 call-graph 문맥을 보존하지만 점수 계산 대상은 아니다.

정상 users mode에서는 users JSON의 주소 집합을 authoritative target set으로 사용한다.
다만 현재 track이 실제로 emit하는 graph에서 non-self IN/OUT relation이 하나도 없는
target은 `user/scored` node로 만들지 않고 abstain으로 분리한다. Root reachability를
candidate 필터로 다시 적용하지 않는 것과, fixture relation이 없는 target에 color를
주지 않는 것은 별개의 규칙이다.

`subject + direct + address` fixture는 `project_fixture()`가
`project_direct_fixture()`로 위임하는 schema v4 compatibility 경로를 유지한다. 그 외
projection은 provisional emitted graph를 먼저 만들고 active target과 abstain을
판정한다.
동결된 schema v4 경로의 edge policy는 `direct-immediate`와 `direct-tail`뿐이다.
같은 raw graph에 `elf-relocation` evidence가 있어도 이 compatibility fixture에는
투영하지 않는다. Schema v6 `direct`, `direct-in`, `angr`만 새 exact resolver를 사용한다.
공용 boundary가 새로 복구한 non-candidate 함수 때문에 동결 결과가 바뀌지 않도록,
구형 호환 projection의 외부 anchor는 radare2도 발견한 함수로 제한한다.

### 10.2 `direct-in`

다음 집합을 사용한다.

```text
U = candidate 함수
I = U를 직접 호출하는 외부 함수
S = closure_out(U + I + root)
```

Anchor 역할은 다음과 같다.

| `anchor_kind` | 의미 | 보존하는 edge |
|---|---|---|
| `root` | Rust user main | selected 방향 |
| `incoming` | 외부 함수가 candidate 호출 | selected 방향 |
| `outgoing` | candidate가 외부 함수 호출 | selected 방향 |
| `both` | 두 관계가 모두 존재 | selected 방향 |
| `context` | candidate와 직접 맞닿지 않은 closure 내부 함수 | selected 방향 |

예를 들어 `X -> A`, `X -> B`이면 X를 두 번 복제하지 않는다.

```text
          +-> A
X(anchor)-+
          +-> B
```

`X -> library Y`도 Y가 resolved graph에 있으면 유지하며, Y의 outgoing relation도
고정점까지 따라간다. Incoming caller의 caller를 역방향으로 재귀 탐색하지는 않는다.

### 10.3 `angr`

`angr`는 node 선택은 `direct-in`과 같고, 허용하는 edge evidence만 넓힌다.

```text
direct-immediate
+ direct-tail
+ elf-relocation
+ angr-cfg singleton indirect call
```

Candidate가 angr로 복구된 간접 call을 통해 외부 함수를 호출하면 그 함수는
outgoing anchor가 되고, 외부 함수가 candidate를 간접 호출한 것이 단일 target으로
복구되면 incoming anchor가 된다. 두 경우 모두 해당 anchor의 resolved outgoing
closure를 계속 투영한다.

Direct raw graph는 `extractions/<profile>/`에, angr 보강 raw graph는
`extractions/angr/<profile>/`에 저장한다. 이 둘은 projection만 다른 것이 아니라
추출 evidence가 실제로 다르기 때문에 별도 파일이다.

### 10.4 Oxidizer direct-FLIRT audit

Oxidizer는 현재 CallKin graph extractor나 CG-WL engine 안에 import하지 않는다.
CallKin의 `angr==9.2.165`와 Oxidizer checkout의 angr fork는 dependency pin이 다르기
때문이다. `oxidizer_adapter.py`가 Oxidizer checkout에서 별도 subprocess를 한 번
실행하고 JSON만 받는다.

```bash
python3 all_rust_catalog.py billing-client --profile plain --build O3S
python3 oxidizer_adapter.py billing-client --profile plain --build O3S
python3 flirt_audit.py billing-client --profile plain --build O3S
```

기본 Oxidizer checkout은 `/mnt/c/users/sumyr/playground/oxidizer`이다. 다른 위치에서는
`oxidizer_adapter.py --oxidizer-dir <path>`를 사용한다.
`oxidizer_adapter.py`는 address join을 위해 canonical direct raw graph도 읽으므로, 먼저
같은 build에 대해 `run_case.py` 또는 `binary_extractor.py --track direct`를 실행해야 한다.

첫 명령은 non-stripped binary를 **채점 전용**으로 읽어
`ground_truth/all-rust/<profile>/<case>.<build>.catalog.json`을 만든다. 이 catalog는
candidate selection이나 fixture를 바꾸지 않는다. Source root `main`을 제외한 모든
observable Rust symbol을 origin별로 정리하므로 `drop_in_place<T>` 같은 standard-library
family도 audit할 수 있다.

둘째 명령은 stripped binary만 Oxidizer에 전달한다. Probe는 direct FLIRT, wrapper
propagation, cleanup heuristic을 순서대로 실행하지만 세 결과를 섞지 않는다. 최종
`labels/oxidizer/<profile>/...labels.json`의 `matches`에는 direct-FLIRT match만 들어간다.
`propagated_wrappers`와 `cleanup_heuristics`는 보존만 하며 현재 seed, candidate, anchor에
사용하지 않는다. 같은 stripped binary의 기존 label JSON이 provenance와 일치하면 adapter는
그 evidence를 재사용한다. Oxidizer를 의도적으로 다시 실행하려면 `--force`를 준다.

Oxidizer address는 ELF linked virtual address로 정규화한 뒤 raw graph의 known function
start와 join한다. 이 join에는 현재 symbol-boundary oracle가 쓰인다. 따라서 이 단계는
"stripped-only library label + oracle function boundary" 조건이다. Join하지 못한 label은
버리지 않고 `unmatched_addresses`에 남긴다. Label JSON의 `tool`에는 Oxidizer commit,
`uv.lock` hash, angr/cle/pyvex/archinfo version, applied signature DB hash와 probe config
hash를 기록한다. `execution`에는 timeout과 cache 사용 여부를 기록한다. 현재 memory
limit은 적용하지 않으므로 `memory_limit_mb=null`로 명시한다.

셋째 명령은 평가 측에서만 catalog와 labels를 대조한다. 결과는 두 질문을 분리한다.
`std_classification`은 예측과 실제 owner가 모두 `core`/`alloc`/`std`인지를 P/R로 보고,
`exact_identity`는 그 owner와 canonical origin까지 모두 맞는 direct-FLIRT label 비율을
따로 기록한다. 따라서 `std::A`를 `std::B`로 부른 결과는 전자에서는 표준 라이브러리
분류 성공이지만 후자에서는 identity 오류다.

known/unknown mixed family와 cross-boundary pair는 향후 seed 정책과 동일하게
`direct-flirt`이면서 예측 owner가 `core`/`alloc`/`std`인 instance만 known으로 센다.
`__rustc`와 wrapper/cleanup label은 이 audit의 seed가 아니다. 아직 Context/Transfer
CG-WL view나 `flirt` candidate scope를 만들지 않는다. 이 audit는 direct-FLIRT label의
양과 address join 품질을 확인하는 gate다.

### 10.5 Anchor policy: `address`와 `role`

`address`는 기본값이며 anchor마다 주소 기반 고유 color class를 준다.

```text
ADDR:FUN_0013105c
ADDR:FUN_00148976
```

`role`은 주소를 무시하고 fixture에서의 방향 역할만 사용한다.

```text
ROLE:root
ROLE:incoming
ROLE:outgoing
ROLE:both
ROLE:context
```

예를 들어 서로 다른 외부 함수 X와 Y가 각각 candidate A와 B를 호출하면 address
정책에서는 X와 Y가 다른 color지만 role 정책에서는 둘 다 `ROLE:incoming`이다.
Role 결과는 address 결과를 덮어쓰지 않고 다음처럼 별도 경로에 저장된다.

```text
fixtures/direct-in/role/rust-nonstd/plain/billing-client.O3S.fixture.json
fixtures/angr/role/rust-nonstd/plain/billing-client.O3S.fixture.json
```

## 11. Fixture JSON

Frozen `subject/direct` 출력만 schema version 4를 유지한다. 새 기본
`rust-nonstd/direct`, 모든 `direct-in`, `angr` 출력은 analysis provenance와 anchor
metadata, abstention 목록이 추가된 schema version 6을 사용한다.

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

Schema v5 anchor 예시는 다음과 같다.

```json
{
  "id": "FUN_001487a0",
  "type": "anchor",
  "scored": false,
  "anchor_kind": "incoming",
  "color_class": "ADDR:FUN_001487a0",
  "observability": {
    "resolved_out_calls": 1,
    "unresolved_indirect_out_callsites": 0,
    "address_taken_references": null,
    "resolved_in_callers": 0
  },
  "calls": [
    {"target": "FUN_001562e0", "count": 1}
  ]
}
```

`address_taken_references=null`은 아직 address-taken 분석을 수행하지 않았다는 뜻이다.
0이라고 단정하지 않는다. Fixture의 `analysis`는 raw graph SHA-256과 projection
config SHA-256, candidate selection SHA-256을 기록한다.

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
| `--track` | `direct`, `direct-in`, `angr` | `--track angr` |
| `--anchor-policy` | `address`(기본) 또는 `role` | `--anchor-policy role` |
| `--candidate-scope` | `rust-nonstd`(기본) 또는 `subject` | `--candidate-scope subject` |
| `--raw-output` | raw evidence 출력 override | `--raw-output /tmp/case.raw.json` |
| `--root` | root name/ID/address | `--root FUN_00114040` |
| `--users` | users JSON 경로 | `--users users/min/custom.users.json` |
| `--boundaries` | scope-independent boundary JSON | `--boundaries boundaries/min/custom.json` |
| `--manifest` | build manifest override | `--manifest build_info/min/custom.json` |
| `--score-root` | root도 user/scored로 처리 | canonical pipeline에서는 사용하지 않음 |
| `--include-imports` | import stub 포함 | debugging option |
| `--id-bias` | FUN ID address bias | `--id-bias 0` |
| `--list-functions` | 함수 목록만 출력 | root 문제 진단 |

## 13. 한계의 정확한 의미

- Rust 함수 경계는 non-stripped symbol extent를 oracle로 사용한다.
- Symbol boundary가 없는 closure anchor의 시작점과 범위 복구는 radare2 분석에 의존한다.
- x86-64 ELF relocation으로 증명된 indirect call/tail-call은 `confidence=exact` edge로
  사용한다. 알려진 함수 시작점과 일치하면 일반 함수 node, 일치하지 않으면 Schema v6의
  주소 기반 opaque anchor로 연결한다.
- `angr`는 single-target으로 복구되고 기존 함수 시작점과 일치한 unresolved
  call/tail-call만 `confidence=inferred` edge로 사용한다.
- Angr multi-target은 가능한 target 집합으로 raw evidence에 남지만 exact edge로
  투영하지 않는다. 미해결 transfer도 가짜 edge를 만들지 않는다.
- Runtime 입력, heap object, 동적으로 선택된 vtable 또는 외부 plugin에 따라 target이
  달라지는 호출은 순수 정적분석으로 단일 target을 보장할 수 없다. 해당 target 함수에
  다른 resolved non-self IN/OUT도 없으면 `abstain`으로 남는다.
- Raw graph는 exact/inferred resolver를 구분하지만 fixture `calls`는 같은 target의
  edge evidence를 합산한다.
- 확정했지만 정책상 제외한 import는 unresolved가 아니라 filtered로 기록한다.
- 숫자 target은 알지만 함수에 매핑하지 못한 direct call은 unmapped로 기록하고 edge로
  투영하지 않는다. Exact ELF relocation의 unmapped target만 opaque anchor 예외다.
- `direct-in`은 복구된 direct caller만 추가하며 완전한 incoming graph를 주장하지 않는다.
- Root 자동 탐지는 현재 Rust/glibc startup 형태에 맞춘 heuristic이다.
- Users JSON은 compiler symbol owner에서 얻은 candidate oracle이다. 기본은
  `core/alloc/std/__rustc`를 제외한 Rust 함수, 호환 mode는 subject namespace 함수다.
- 제외된 `core/alloc/std/__rustc` 함수는 삭제되는 것이 아니다. Candidate와 직접
  또는 간접적으로 연결된 outgoing closure에 있으면 `anchor/scored=false` node로 투영된다.
- 이 범위 판정은 stripped-only library classifier가 아니다.
- Anchor는 traversal wall이 아니므로 복구된 library subgraph topology도 feature에 들어간다.
- Fixture의 call count는 dynamic execution frequency가 아니다.

## 14. 코드 읽기 순서

1. `main()`
2. `apply_cli_defaults()`
3. `extract_artifacts()`
4. `BinaryExtractor.analyze()`와 `_refresh_functions()`
5. `resolve_root()`와 startup helper
6. `transfer_evidence()`와 symbol/radare2 evidence helper
7. `build_raw_graph()`와 `graph_evidence.py`
8. `angr_adapter.py` (`angr` track만)
9. `graph_projector.py`
10. `candidate_selection.py`, `function_boundaries.py`, `project_fixture()`
11. `write_raw_graph()`과 `write_fixture()`

`tests/test_angr_integration.py`는 Linux에서 작은 실제 x86-64 ELF를 임시로 빌드해
angr CFG가 memory-indirect call target을 복구하는지 검사한다. `cc` 또는 angr가 없는
환경에서는 명시적으로 skip하며, cardinality와 merge 정책은
`tests/test_angr_adapter.py`가 별도로 고정한다.
