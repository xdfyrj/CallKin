# 바이너리 추출과 graph projection

CallKin의 바이너리 단계는 하나가 아니라 두 단계다.

```text
stripped ELF
    |
    | binary_extractor.py
    v
raw call evidence
    |
    | graph_projector.py + candidate selection + policy
    v
CG-WL fixture
```

이 분리는 중요하다.

- Raw evidence는 “binary에서 무엇을 보았는가?”를 기록한다.
- Fixture는 “그 evidence 중 무엇을 어떤 context로 grouping에 쓸 것인가?”를 기록한다.

Candidate scope, incoming anchor, anchor color를 바꾼다고 machine instruction을 다시 해석할 이유가 없다.

## 실행 예

전체 pipeline:

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

Extraction만 직접 실행:

```bash
python3 binary_extractor.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role
```

필요한 선행 artifact:

```text
build manifest
stripped binary
users candidate selection
scope-independent boundaries
```

[run_case.py](../run_case.py)는 이를 자동으로 생성 및 연결한다.

## 전체 구현 흐름

```text
1. manifest와 input hash 검증
2. radare2 availability 확인
3. stripped ELF open
4. aaa 분석 후 function list 수집
5. symbol boundary oracle join
6. Rust root main 탐지
7. 각 function extent에서 transfer evidence 생성
8. direct raw graph 저장
9. track=angr이면 unresolved indirect transfer 분석
10. raw graph + users + projection config join
11. candidate / anchor / abstain 분류
12. fixture 저장
```

Core implementation:

- [binary_extractor.py](../binary_extractor.py): r2/Capstone/root/static transfer
- [graph_evidence.py](../graph_evidence.py): raw schema와 validation
- [angr_adapter.py](../angr_adapter.py): conservative indirect resolution
- [graph_projector.py](../graph_projector.py): raw-to-fixture policy
- [candidate_selection.py](../candidate_selection.py): users JSON validation
- [function_boundaries.py](../function_boundaries.py): boundary JSON validation

ELF relocation parser는 현재 별도 module이 아니라 `binary_extractor.py`의 `load_elf_relocation_targets()`에 있다.

## Radare2의 역할

### Preflight

`ensure_radare2_available()`는 `r2` executable을 확인한다. [r2pipe](https://github.com/radareorg/radare2-r2pipe) Python package만 설치되어 있고 radare2 program이 없으면 안전하게 실패한다.

### Open

`open_r2()`는 stripped binary를 `r2pipe.open()`으로 연다. 실패 시 missing executable, launch error, package error를 사용자에게 설명 가능한 exception으로 바꾼다.

### Analysis

`BinaryExtractor.analyze()`:

```text
aaa
aflj
```

`aflj` 결과는 `R2Function(addr, name, size, kind)`로 바꾼다. Import stub은 기본적으로 active function list에서 제외하지만 `all_functions`에는 남겨 filtered evidence를 구분한다.

Radare2 결과를 절대적인 함수 truth로 보지 않는다. Symbol boundary와 비교해 다음을 기록한다.

- radare2가 같은 시작점을 찾았는가
- r2 size와 symbol size가 다른가
- symbol에만 있는 시작점을 분석기에 추가했는가

## Function boundary oracle

Non-stripped symbol에서 만든 `boundaries/*.boundaries.json`이 전체 Rust function address/size를 제공한다.

Extractor는 같은 linked address를 stripped ELF에 적용한다.

```text
non-stripped:
Rust function @ 0x406b0, size 0x10

stripped:
same bytes @ 0x406b0
```

### 왜 시작점뿐 아니라 size도 쓰는가

Radare2가 LTO로 커진 함수의 끝을 너무 일찍 자를 수 있다.

```text
실제 symbol extent: 0xf540 .. 0xfaf9
r2 recovered extent: 0xf540 .. 0xf8f7
```

R2 `pdfj`만 믿으면 뒤쪽 callsite가 사라진다. CallKin은 symbol size만큼 raw bytes를 읽어 Capstone으로 선형 decode한다.

```text
p8j <symbol-size> @ <function-start>
-> Capstone x86-64 decode
-> first byte부터 exact end까지 gap 없는지 검사
```

Decode가 중간에서 끊기거나 byte count가 다르면 조용히 부분 graph를 만들지 않고 실패한다.

### Boundary source 표시

Raw function마다 다음을 남긴다.

```text
boundary_source = symbol-oracle | radare2
discovered_by_radare2 = true | false
```

따라서 결과가 function-boundary oracle에 얼마나 의존하는지 `run_summary.artifact_summary.boundary_oracle`에서 확인할 수 있다.

## Root 탐지

Root는 candidate scope filter의 시작점이 아니다. Fixture context에 포함되는 `scored=false` root anchor다.

자동 탐지 순서:

```text
1. entry0에서 __libc_start_main에 전달되는 C main wrapper 찾기
2. startup wrapper 안에서 실제 Rust <root_namespace>::main pointer 찾기
3. 실패하면 main / sym.main
4. 마지막 fallback은 entry0
```

### 일반 Rust startup

개념적 구조:

```text
entry0
  -> __libc_start_main(C main)
       -> std::rt::lang_start_internal(...)
            -> Rust crate::main
```

`_libc_start_main_wrapper_addr()`는 entry code에서 `rdi`에 놓인 C main wrapper 주소와 `__libc_start_main` call을 연결한다.

`_rust_main_from_start_wrapper()`는 wrapper에서 Rust main pointer가 `rdi` argument로 전달되는 pattern을 찾는다.

### LTO로 lang_start_internal이 inline된 경우

`min` profile에서는 startup이 다음처럼 변할 수 있다.

```text
entry0
  -> C main
       + inline lang_start_internal code
       + lea rax/rdi, [Rust main]
       + pointer를 stack argument로 저장
       + __rust_begin_short_backtrace
             -> call rdi
```

Radare2 `pdfj`가 C main 앞부분만 반환하면 실제 main pointer load를 놓친다. 그래서 root detector는 boundary oracle의 C main 전체 size를 받아 `_startup_ops_from_symbol_extent()`로 bytes 전체를 Capstone decode한다.

Stack store는 opcode 문자열 하나를 비교하지 않는다. Capstone operand 의미로 검사한다.

```text
destination = memory [rsp]
source      = rax
```

따라서 spacing이나 disassembly text 변형에 덜 민감하다.

Root가 의심스러우면:

```bash
python3 binary_extractor.py billing-client --profile min --list-functions
python3 binary_extractor.py billing-client --profile min --root 0x35440
```

수동 `--root`는 name, `FUN_` ID, raw/biased address를 받을 수 있다.

## Transfer evidence model

Raw graph는 edge aggregate만 저장하지 않고 callsite별 evidence를 저장한다.

### Kind

- `call`
- `tail-call`

Tail-call은 optimized `call f; ret`가 `jmp f`로 바뀐 경우를 포함한다.

### Operand kind

- `immediate`: `call 0x40100`
- `memory`: `call [rip + offset]`, `jmp [rax + 0x18]`
- `register`: `call rax`, `jmp rdi`
- `unknown`

### Status

- `resolved`: graph target으로 사용할 수 있다.
- `unresolved`: transfer는 확실하지만 target을 모른다.
- `unmapped`: target address는 정확하지만 known function start가 아니다.
- `filtered`: target은 해결했지만 import policy로 graph에서 제외한다.

### Resolver

- `direct-immediate`
- `direct-tail`
- `elf-relocation`
- `angr-cfg`

### Confidence

- `exact`: instruction/relocation으로 target이 확정됨
- `inferred`: angr CFG가 단일 target으로 복구
- `unknown`: target 미복구

이 구분 덕분에 “edge가 없다”와 “indirect transfer는 있지만 해결하지 못했다”를 같은 0으로 취급하지 않는다.

## Direct immediate call

Capstone operand가 immediate면 code target을 얻는다.

```asm
call 0x40100
```

일반 call은 radare2 function extent가 target 내부 address를 가리키는 경우 containing function으로 해석할 수 있다. Tail jump는 ordinary intra-function branch를 피하기 위해 다른 함수의 **정확한 시작점**일 때만 direct tail-call로 인정한다.

```asm
jmp 0x40100
```

Callsite가 같은 source-target에 여러 번 나타나면 raw에는 각 callsite가 남고 fixture에서는 count를 합친다.

```text
A -> B at callsites 0x10, 0x20
fixture: A calls B count=2
```

## Indirect tail-call

이전 구현은 target을 모르는 `jmp rax`와 `jmp [memory]`를 버렸다. 현재는 함수의 terminal transfer이면 raw evidence로 보존한다.

```asm
jmp rax
```

```json
{
  "kind": "tail-call",
  "operand_kind": "register",
  "status": "unresolved"
}
```

Symbol-extent Capstone path에서는 현재 jump instruction의 end가 symbol extent의 exact end일 때 terminal로 본다. Radare2 path는 뒤에 `nop` 또는 `int3` padding만 있어도 terminal로 본다.

이 차이는 알려진 낮은 우선순위 한계다. Symbol-extent path의 tail jump 뒤에 padding이 symbol size에 포함되면 놓칠 수 있다.

## ELF relocation resolution

### 해결하는 형태

대표 형태:

```asm
jmp qword ptr [rip + displacement]
call qword ptr [rip + displacement]
```

x86-64 RIP-relative slot:

```text
slot = instruction.address
     + instruction.size
     + displacement
```

[pyelftools](https://github.com/eliben/pyelftools)로 relocation section을 읽어 `slot -> linked target` map을 만든다.

지원 relocation:

- `R_X86_64_RELATIVE`
- `R_X86_64_64`
- `R_X86_64_GLOB_DAT`
- `R_X86_64_JUMP_SLOT`

Defined symbol 또는 relative addend로 target이 정적으로 결정될 때만 map에 넣는다.

### Exact-start rule

Relocation target은 일반 call의 containing-function heuristic을 사용하지 않는다.

```text
known function: 0x2000 .. 0x2020
relocation target: 0x2001
```

결과:

```text
status = unmapped
target = 0x2001
```

금지되는 결과:

```text
resolved to function 0x2000
```

Radare2가 잘못 복구한 거대한 extent가 무관한 target address를 포함할 수 있기 때문이다. `elf-relocation`은 known function의 **정확한 시작 주소**와 같을 때만 internal resolved edge다.

### Opaque anchor

Relocation target address가 정확하지만 boundary list에 없을 수 있다.

예:

```text
candidate -> allocator C function address
target name/body boundary unavailable
```

Schema v6 projector는 이 주소를 다른 함수에 억지로 매핑하지 않고 opaque anchor로 만든다.

```text
candidate --exact relocation--> opaque anchor 0x...
```

Opaque anchor:

- target address identity는 보존한다.
- 함수 이름/origin을 요구하지 않는다.
- `scored=false`다.
- body를 분석한 known function이라고 주장하지 않는다.

Frozen schema v4 compatibility projection은 historical semantics를 위해 opaque relocation을 무시한다.

### 일반 RIP-relative load는 call이 아니다

```asm
mov rax, qword ptr [rip + slot]
```

Relocation slot을 참조해도 call/jump instruction이 아니므로 transfer evidence가 아니다. Instruction kind를 확인한 뒤 relocation resolver를 적용한다.

## Import 처리

기본값은 import를 graph에서 제외하되 evidence를 보존하는 것이다.

```text
angr/r2 resolves free
-> status=filtered
-> filter_reason=import
-> target/name diagnostics retained
-> fixture edge omitted
```

“angr가 못 찾음”과 “찾았지만 CallKin policy로 제외”를 구분한다.

`--include-imports`는 radare2 import stub을 direct graph에 포함하는 실험용 option이다. Canonical real-world 결과의 import policy를 바꿀 때는 raw/result interpretation과 tests를 함께 고정해야 한다.

## Angr track

### 입력 대상

Angr는 raw transfer 중 다음만 받는다.

```text
status=unresolved
kind=call or tail-call
operand_kind=memory or register
```

이미 exact direct/relocation으로 해결된 transfer는 다시 추측하지 않는다.

### Function boundary oracle 전달

`analyze_indirect_calls_detailed()`은 stripped ELF를 angr project로 열지만, raw graph의 known function starts를 load bias만큼 rebasing해 전달한다.

```python
CFGFast(
    normalize=True,
    resolve_indirect_jumps=True,
    function_starts=oracle_starts,
    force_complete_scan=False,
)
```

따라서 현재 angr 결과는 stripped-only discovery가 아니라 **symbol-boundary oracle 조건의 target recovery**다.

### 주소 정규화

```text
angr mapped address
- load bias
= linked virtual address
= CallKin raw address
```

Load bias를 빼지 않고 join하면 PIE mapping address와 linked address가 섞인다.

### Singleton-before-filter rule

Angr가 한 callsite에 반환한 전체 target set을 먼저 보존한다.

```text
{known internal A, unknown B}
```

Unknown B를 먼저 버리고 `{A}`를 singleton으로 만들면 false exactness다. 현재 순서:

```text
1. complete target set 수집
2. cardinality 확인
3. 정확히 하나일 때만 target category 확인
4. known internal이면 inferred edge 채택
```

### Angr status

- `resolved_internal`: singleton known function start, graph edge 채택
- `resolved_import`: 이름 있는 import, filtered
- `unresolvable_target`: angr의 synthetic unresolvable target
- `multiple_targets`: 둘 이상, 보수적으로 edge 미채택
- `unknown_target`: singleton이지만 known/import mapping 실패
- `ambiguous_source`: callsite를 raw source 하나에 연결할 수 없음
- `no_angr_result`: CFG result 없음

`resolved_internal`의 confidence는 `inferred`다. 이것은 indirect-call ground truth로 검증한 accuracy가 아니라 CallKin이 보수적으로 채택한 internal-edge recovery yield다.

### Warning과 runtime

Angr/CLE/Python warning은 normalized message와 count로 집계한다. Result JSON에는 다음이 남는다.

- angr duration
- warning component/message/count
- angr version
- total/candidate indirect-call breakdown
- internal/import/rejected counts

Console warning만 보고 결과 신뢰성을 판단하지 않아도 된다.

### 정적 분석의 남는 한계

다음은 CFGFast가 해결하지 못할 수 있다.

```asm
mov rax, [rsi + 8]
mov rax, [rax + 0x18]
jmp rax
```

Runtime vtable, heap state, input-dependent function pointer는 정적 singleton target이 없거나 analysis가 값의 출처를 추적하지 못할 수 있다. 현재 multiple-target may-call을 exact edge로 바꾸지 않는다. 복구하지 못한 evidence는 raw에 남고 target은 경우에 따라 abstain된다.

## Raw graph는 candidate와 독립적이다

Raw graph에 들어가면 안 되는 것:

- candidate address list
- origin
- candidate scope
- anchor policy
- direct/direct-in projection 차이

Raw graph에 들어가는 것:

- build provenance
- boundary input hash
- root
- function universe
- callsite evidence
- extractor/backend version
- boundary mismatch
- indirect summary

그래서 다음 세 fixture는 하나의 direct raw graph를 재사용할 수 있다.

```text
direct + subject + address
direct-in + rust-nonstd + address
direct-in + rust-nonstd + role
```

`angr`만 augmented raw graph를 사용한다.

## Projection track

[graph_projector.py](../graph_projector.py)의 `projection_config_for()`가 canonical policy를 정한다.

### `direct`

Schema v6에서 사용하는 resolver:

```text
direct-immediate
direct-tail
elf-relocation
```

외부 함수가 candidate를 호출한다는 이유만으로 그 caller를 initial incoming anchor로 추가하지 않는다.

```text
external X -> candidate A
```

X가 root/candidate outgoing closure에 없다면 edge는 fixture에 나타나지 않는다. 그 결과 A에 다른 non-self relation이 없다면 A는 abstain이다.

### `direct-in`

Exact resolver는 `direct`와 같다. 추가로 candidate를 직접 호출하는 외부 source를 incoming anchor seed로 포함한다.

```text
X(anchor) -> A(candidate)
X(anchor) -> B(candidate)
```

X node는 하나이고 두 edge를 모두 보존한다. Candidate별로 anchor를 복제하지 않는다.

### `angr`

`direct-in` context에 `angr-cfg` inferred edge를 추가한다.

```text
direct exact evidence
+ external incoming anchors
+ accepted singleton indirect internal edges
```

Track 이름은 backend 이름과 완전히 같은 뜻이 아니다. `angr` fixture도 direct/relocation exact evidence를 기본으로 포함한다.

## Anchor traversal

현재 anchor는 더 이상 “한 단계에서 멈추는 벽”이 아니다.

Projector는 다음 seed의 complete resolved outgoing closure를 선택한다.

```text
active candidates
root
track이 허용한 incoming anchors
```

따라서:

```text
candidate -> library A -> library B -> library C
```

resolved edge와 function이 raw graph에 있으면 A/B/C가 모두 context anchor로 들어갈 수 있다. Incoming anchor의 candidate 외 outgoing relation도 selected closure 안에서 보존된다.

이 정책의 영향:

- library context propagation을 잃지 않는다.
- fixture 크기와 WL context 범위가 커질 수 있다.
- “candidate가 직접 호출하는 library까지만”이라는 이전 문서/가정은 현재 구현과 맞지 않는다.

정책을 다시 terminal anchor로 바꾸려면 `ProjectionConfig.anchor_traversal`, selection closure, fixture provenance, tests, result를 함께 바꿔야 한다.

## Candidate, anchor, abstain

Candidate selection JSON의 target 전체를 먼저 가져오지만, 실제 graph role은 **현재 track이 방출할 provisional graph**에서 결정한다.

### Candidate

다른 함수와 resolved non-self OUT 또는 IN relation이 하나 이상 있다.

```text
A -> B
or
X -> A
```

Fixture node:

```json
{
  "type": "user",
  "scored": true
}
```

### Anchor

Target은 아니지만 selected graph context를 제공한다.

종류:

- `root`
- `incoming`
- `outgoing`
- `both`
- `context`

Opaque relocation target도 anchor다.

### Abstain

Target이지만 projected graph에서 resolved non-self IN/OUT이 모두 0이다.

```json
{
  "id": "FUN_...",
  "status": "abstain",
  "reason": "no_resolved_nonself_in_or_out_edge"
}
```

- Fixture `nodes`에 들어가지 않는다.
- WL color를 받지 않는다.
- Predicted cluster에 들어가지 않는다.
- GT universe에서는 사라지지 않는다.
- Coverage와 effective recall에 반영된다.

Self-call만 있는 함수도 abstain이다. 비교할 다른 함수 relation이 없기 때문이다.

중요한 순서:

```text
wrong:
raw 전체에서 relation 확인 -> track edge 제거 -> 고립 candidate 잔존

current:
track provisional graph 생성 -> 실제 남는 relation 확인
-> candidate/abstain 분류 -> final fixture
```

그래서 external incoming relation만 있는 함수는 다음처럼 달라진다.

```text
direct    -> abstain
direct-in -> candidate
```

## Anchor color policy

### `address`

```text
ADDR:FUN_00123450
ADDR:FUN_00167890
```

각 anchor를 다른 identity로 고정한다.

### `role`

```text
ROLE:root
ROLE:incoming
ROLE:outgoing
ROLE:both
ROLE:context
```

주소를 역할로 압축한다. 두 policy 모두 anchor는 refinement로 user color가 되지 않는다. 초기 anchor color가 고정된 identity seed이고, user signature가 그 color를 관측한다.

Opaque anchor는 현재 address/role policy에 따라 color class를 받는다. Semantic FLIRT anchor policy는 아직 구현되지 않았다.

## Fixture edge count

Raw는 callsite record다. Projector는 allowed resolver/status만 골라 `graph[src][dst] += 1`한다.

예:

```text
raw:
A callsite 0x10 -> B
A callsite 0x20 -> B
A callsite 0x30 -> C

fixture:
A.calls = [
  {target: B, count: 2},
  {target: C, count: 1}
]
```

Unresolved, multiple-target, filtered transfer는 fixture count에 들어가지 않는다.

## Frozen controlled baseline

다음 조합은 [project_direct_fixture()](../graph_projector.py)의 schema v4 compatibility path다.

```text
candidate scope = subject
track           = direct
anchor policy   = address
```

이 경로는 기존 micro-corpus 결과를 동결하기 위해:

- direct immediate/tail resolver만 사용
- relocation과 opaque anchor를 제외
- radare2가 독립 발견한 context만 허용
- legacy node shape 유지

Real-world schema v6 구현을 고치면서 이 branch를 함께 바꾸면 이전 baseline의 실험 조건이 바뀐다.

## CLI option

```text
python3 binary_extractor.py BINARY_OR_STEM [OUTPUT] [options]
```

| 옵션 | 의미 |
|---|---|
| `--case/build/profile` | artifact identity |
| `--track` | `direct`, `direct-in`, `angr` |
| `--anchor-policy` | `address`, `role` |
| `--candidate-scope` | users/fixture scope |
| `--raw-output` | raw output override |
| `--users` | candidate selection input |
| `--boundaries` | scope-independent boundary input |
| `--manifest` | verified build input |
| `--root` | auto root override |
| `--score-root` | root를 user/scored로 만드는 debug option |
| `--include-imports` | r2 import stubs 포함 실험 |
| `--id-bias` | raw address to `FUN_` ID bias |
| `--list-functions` | r2 function 목록만 출력 |

일반 사용자는 path override보다 `run_case.py`를 사용한다.

## Debugging playbook

### Candidate가 abstain일 때

1. Fixture `abstentions`에서 ID와 reason을 확인한다.
2. Users JSON에서 raw address와 size를 찾는다.
3. Raw `transfers`에서 `source=address`인 OUT evidence를 찾는다.
4. 다른 transfer의 `target=address`인 IN evidence를 찾는다.
5. `unresolved`, `multiple_targets`, `filtered`, `unmapped`를 분리한다.
6. 현재 track의 edge policy가 resolver를 허용하는지 본다.
7. Direct와 direct-in의 incoming context 차이를 확인한다.

“abstain = dead code”라고 바로 결론 내리지 않는다. 가능한 원인:

- 실제 residual/dead out-of-line function
- external caller가 direct track projection에서 제외
- unresolved vtable/function pointer
- boundary/root recovery 누락
- import/unknown target policy

### Root가 틀릴 때

1. Raw `root`를 확인한다.
2. Non-stripped `<root_namespace>::main` address와 비교한다.
3. Boundary JSON에 C main과 Rust main extent가 있는지 본다.
4. `min` LTO startup full extent를 확인한다.
5. `--root`로 수동 실행해 graph 차이를 비교한다.
6. Root detector test에 같은 instruction bytes를 추가한다.

### Edge가 잘못된 함수로 갈 때

1. Resolver를 확인한다.
2. `elf-relocation`이면 raw target이 exact known start인지 확인한다.
3. Relocation slot과 ELF target을 독립 대조한다.
4. Containing function heuristic이 relocation에 사용되지 않았는지 본다.
5. Raw callsite instruction이 실제 call/tail-call인지 본다.

### Angr yield가 낮을 때

전체 `resolved_internal / total` 하나만 보지 않는다.

- imports are resolved but filtered
- unresolvable target
- multiple targets
- unknown target
- ambiguous source
- no result

그리고 whole-binary와 candidate-source 통계를 분리한다. LTO profile은 외부 libc indirect calls를 많이 노출해 단순 rate denominator를 바꿀 수 있다.

## 구현을 읽는 순서

Static extraction:

1. `BinaryExtractor.__init__()`, `analyze()`
2. `resolve_root()`과 startup helper
3. `add_symbol_bound_functions()`, `boundary_mismatches()`
4. `transfer_evidence()`
5. `_symbol_extent_transfer_evidence()`
6. `load_elf_relocation_targets()`
7. `build_raw_graph()`
8. `extract_artifacts()`

Angr:

1. `analyze_indirect_calls_detailed()`
2. address/load-bias normalization
3. complete target-set collection
4. `merge_angr_resolutions()`
5. `make_indirect_call_summary()`

Projection:

1. `ProjectionConfig`, `projection_config_for()`
2. `resolved_graph()`
3. `project_context_fixture()`
4. active candidate/abstain calculation
5. outgoing closure와 anchor kinds
6. `project_direct_fixture()` compatibility branch
7. `project_fixture()` dispatch

## 변경 시 최소 테스트

- Root pattern 변경: real instruction-byte regression
- Boundary 변경: missing start와 size mismatch
- Direct call 변경: call vs branch, count aggregation
- Tail call 변경: terminal/non-terminal positive and negative
- Relocation 변경: exact start, start+1 negative, ordinary mov negative, opaque target
- Angr 변경: singleton, known+unknown multi-target, import, unresolvable, actual small ELF
- Projection 변경: direct/direct-in difference, shared incoming anchor, anchor closure, abstain/self-only
- Schema 변경: strict loader와 stale artifact rejection

주 테스트:

- [test_binary_extractor.py](../tests/test_binary_extractor.py)
- [test_graph_projector.py](../tests/test_graph_projector.py)
- [test_angr_adapter.py](../tests/test_angr_adapter.py)
- [test_angr_integration.py](../tests/test_angr_integration.py)

## 현재 한계

- x86-64 ELF relocation만 지원한다.
- Function boundary와 candidate는 non-stripped symbol oracle을 쓴다.
- CFGFast singleton은 inferred evidence이며 indirect-call ground-truth accuracy가 아니다.
- Multiple-target may-call을 CG-WL relation으로 표현하지 않는다.
- Runtime-dependent vtable target은 unresolved로 남을 수 있다.
- Symbol-extent terminal jump 뒤 padding 처리가 r2 path와 완전히 같지 않다.
- Address-taken reference는 model field가 있지만 현재 일반적으로 `null`이다.
- Oxidizer direct-FLIRT는 audit-only이고 fixture projection에 사용하지 않는다.
