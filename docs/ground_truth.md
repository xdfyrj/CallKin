# Ground truth 추출 파이프라인

## 1. 목적

CallKin의 `gt_extractor.py`는 non-stripped Rust binary의 symbol table에서 세 파일을 만든다.

```text
gt_bin/plain/family_graph_01.O3S.gt.bin
-> ground_truth/plain/family_graph_01.O3S.gt.json
-> users/plain/family_graph_01.O3S.users.json
-> boundaries/plain/family_graph_01.O3S.boundaries.json
```

세 출력의 역할은 다르다.

### Ground truth JSON

어떤 최종 함수 주소들이 같은 source origin에서 나왔는지 기록한다.

```text
shared_recursive
  -> FUN_00113e40
  -> FUN_00113f20
  -> FUN_00113fa0
```

이 파일은 scoring에서만 사용한다.

### Users JSON

선택한 candidate scope에 속한 함수의 raw address만 기록한다.

```text
0x13e40
0x13f20
0x13fa0
...
```

이 파일은 stripped binary extractor가 candidate 함수를 선택할 때 사용한다. Origin이나 group 관계는 담지 않는다.

### All-Rust audit catalog

`all_rust_catalog.py`는 기존 GT/users JSON을 대체하지 않는 평가 전용 artifact를 만든다.

```bash
python3 all_rust_catalog.py billing-client --profile plain --build O3S
```

출력은 다음 경로다.

```text
ground_truth/all-rust/plain/billing-client.O3S.catalog.json
```

이 catalog에는 source root `main`을 제외한 모든 observable Rust symbol이 들어간다.
따라서 기존 `rust-nonstd` scope에서 제외되는 `core::ptr::drop_in_place<T>`도 origin family로
기록된다. 단, 이 파일은 Oxidizer direct-FLIRT audit과 미래 transfer 평가에서만 사용한다.
현재 `users` selection, fixture, CG-WL 입력, 기본 PR/RE/F1/ARI 점수에는 들어가지 않는다.

## 2. 가장 단순한 실행

```bash
# 기본: core/alloc/std/__rustc를 제외한 모든 관찰 가능한 Rust 함수
python3 gt_extractor.py billing-client

# frozen micro-corpus의 subject-owned 함수만 재현
python3 gt_extractor.py family_graph_01 --candidate-scope subject
```

위 `family_graph_01 --candidate-scope subject` 명령은 다음처럼 해석된다.

```text
binary = gt_bin/plain/family_graph_01.O3S.gt.bin
case   = family_graph_01
build  = O3S
profile = plain
candidate scope = subject
GT     = ground_truth/plain/family_graph_01.O3S.gt.json
users  = users/plain/family_graph_01.O3S.users.json
boundaries = boundaries/plain/family_graph_01.O3S.boundaries.json
nm     = nm
```

출력 예시:

```text
wrote ground_truth/plain/family_graph_01.O3S.gt.json
origins=2
wrote users/plain/family_graph_01.O3S.users.json
users=6
wrote boundaries/plain/family_graph_01.O3S.boundaries.json
function boundaries=<all Rust text symbols + C main startup wrapper>
```

## 3. 전체 함수 호출 순서

```text
main()
  -> build_arg_parser()
  -> apply_cli_defaults()
  -> run_nm()
  -> parse_nm_lines()
  -> user_addresses()
       -> origin_from_symbol()
  -> rust_function_bounds()
  -> make_ground_truth()
       -> origin_from_symbol()
       -> function_id()
  -> optional validate_against_fixture()
  -> write_json(GT)
  -> make_users_json()
  -> write_json(users)
  -> make_function_boundaries_json()
  -> write_json(boundaries)
```

## 4. Symbol 읽기

`run_nm()`은 다음 command를 실행한다.

```bash
nm -n -S -C gt_bin/plain/family_graph_01.O3S.gt.bin
```

Option 의미:

```text
-n : symbol을 address 순서로 정렬
-S : 함수 symbol size를 함께 출력
-C : Rust/C++ mangled symbol을 demangle
```

출력 한 줄의 예시는 다음과 같은 형태다.

```text
0000000000013e40 00000000000000d4 t family_graph_01::shared_recursive
```

`parse_nm_lines()`는 이를 다음 객체로 바꾼다.

```python
Symbol(
    addr=0x13e40,
    size=0xd4,
    kind="t",
    name="family_graph_01::shared_recursive",
)
```

Text symbol kind `t`와 `T`만 사용한다. Data symbol, undefined symbol, 주소를 파싱할 수 없는 줄은 제외한다.

## 5. Candidate scope

### 5.1 기본 `rust-nonstd`

기본 정책은 demangle 가능한 Rust text symbol의 **함수 소유 namespace**를 판정한다.
소유자가 `core`, `alloc`, `std`, `__rustc`이면 제외하고, 그 밖의 subject/dependency crate 함수는
candidate로 포함한다. Source `main`은 CG-WL root anchor이므로 scored candidate에서
제외한다.

```text
serde_json::de::parse                       -> candidate
billing_client::client::decode              -> candidate
core::ptr::drop_in_place<billing_client::T> -> 제외(core 소유)
std::rt::lang_start_internal                -> 제외(std 소유)
__rustc::rust_begin_unwind                  -> 제외(__rustc 소유)
reconcile::main                             -> 제외(root)
```

Trait impl은 맨 앞 문자열만 보지 않는다. 구현 header에서 non-standard crate를 찾아
소유자를 정한다.

```text
<billing_client::Invoice as core::fmt::Display>::fmt
-> billing_client 소유 -> candidate

<alloc::vec::Vec<T> as billing_client::LocalTrait>::method
-> billing_client 소유 trait impl -> candidate

<&T as core::fmt::Debug>::fmt
-> core 소유 -> 제외
```

이 분류는 non-stripped symbol oracle이다. Stripped binary만 보고 standard library를
식별한 결과가 아니다. `std_detect`처럼 owner가 정확히
`core/alloc/std/__rustc`가 아닌 Rust namespace는 candidate가 될 수 있다.

### 5.2 호환 `subject`

단일-file case manifest에는 namespace 하나가 기록된다.

```text
family_graph_01::
```

다음 symbol은 포함된다.

```text
family_graph_01::shared_recursive
family_graph_01::process
```

다음 symbol은 포함되지 않는다.

```text
core::panicking::panic_bounds_check
std::rt::lang_start_internal
miniz_oxide::inflate::core::transfer
```

Cargo subject manifest에는 선택한 package의 library와 binary target namespace가
함께 기록된다.

```text
billing_client
reconcile
```

일반 symbol은 `billing_client::` 또는 `reconcile::`로 시작하는지 검사한다.
Trait impl symbol은 `<billing_client::` 또는 `<reconcile::`로 시작하는지도 검사한다.
외부 `serde::`, `std::`, `sha2::` 함수는 candidate가 아니라 direct library anchor다.
이 정책은 `--candidate-scope subject`로 선택하며 frozen family-graph baseline이
사용한다.

## 6. Symbol을 origin으로 정규화

`origin_from_symbol()`은 다음 순서로 origin을 만든다.

1. Symbol이 선택한 candidate scope에 속하는지 확인한다.
2. `subject`의 단일 namespace case에서는 prefix를 제거한다. 여러 namespace 또는 `rust-nonstd`에서는 crate path를 보존한다.
3. 끝의 Rust hash `::h<16 hex>`를 제거한다.
4. `::<impl ...>`이면 구현 대상 type을 먼저 보존한다.
5. 나머지 표시된 generic argument `::<...>`를 제거한다.
6. `main`은 제외한다.

### 예시 1: 일반 symbol

```text
input symbol = family_graph_01::process
prefix       = family_graph_01::
origin       = process
```

### 예시 2: hash가 있는 symbol

```text
input symbol = family_graph_01::process::h0123456789abcdef
after prefix = process::h0123456789abcdef
after hash   = process
origin       = process
```

### 예시 3: v0 demangle이 type argument를 보여주는 경우

```text
input symbol = family_graph_03::share::<core::option::Option<i32>>
after prefix = share::<core::option::Option<i32>>
after generic argument removal = share
origin = share
```

`strip_rust_generic_args()`는 `<...>`의 중첩 깊이를 세기 때문에 내부에 `Option<i32>` 같은 nested generic이 있어도 바깥 `::<...>` 전체를 제거한다.

현재 canonical legacy-mangled binary에서는 여러 instance가 이미 같은 demangled path로 보일 수 있다.

```text
family_graph_03::share @ 0x14720
family_graph_03::share @ 0x148e0
family_graph_03::share @ 0x14a30
```

세 주소의 normalized origin은 모두 `share`다.

## 7. Address를 member ID로 변환

Ground truth member ID는 fixture와 같은 규칙을 써야 한다.

기본 `id_bias`는 `0x100000`이다.

```text
raw symbol address = 0x13e40
id bias            = 0x100000
result             = 0x113e40
member ID          = FUN_00113e40
```

이 변환 덕분에 다음 두 파일이 같은 ID로 join된다.

```text
GT member       = FUN_00113e40
fixture user ID = FUN_00113e40
```

Bias는 주소의 의미를 바꾸지 않고 ID 문자열 표현만 바꾼다.

## 8. Origin grouping

`make_ground_truth()`는 normalized origin마다 member를 모은다.

실제 fg01 입력을 단순화하면 다음과 같다.

```text
0x13e40 family_graph_01::shared_recursive
0x13f20 family_graph_01::shared_recursive
0x13fa0 family_graph_01::shared_recursive
0x14480 family_graph_01::process
0x14660 family_graph_01::process
0x148a0 family_graph_01::process
```

결과 partition:

```text
shared_recursive = {
  FUN_00113e40,
  FUN_00113f20,
  FUN_00113fa0
}

process = {
  FUN_00114480,
  FUN_00114660,
  FUN_001148a0
}
```

Origin은 첫 member address 순서로 정렬되고, 각 origin의 member도 address 순서로 정렬된다. 따라서 같은 binary에서 반복 생성하면 JSON 순서가 안정적이다.

## 9. 동일 주소 symbol 처리

한 주소에 symbol이 여러 개 있을 수 있다.

### Same-origin alias

다음 두 symbol이 같은 주소와 같은 normalized origin을 가진다고 하자.

```text
0x13e40 family_graph_01::shared_recursive
0x13e40 family_graph_01::shared_recursive::h0123456789abcdef
```

Member는 한 번만 기록한다.

```text
FUN_00113e40
```

두 원래 symbol 문자열은 `symbols` 목록에 보존하고 GT `note`에 duplicate 처리를 기록한다.

### Cross-origin shared address

다음처럼 서로 다른 origin이 같은 주소를 소유하면:

```text
0x13e40 family_graph_01::alpha
0x13e40 family_graph_01::beta
```

`subject` scope는 어느 origin을 임의로 선택하지 않고 실패한다.

```text
cross-origin address alias at FUN_00113e40
```

`rust-nonstd`처럼 큰 universe에서는 실제 binary에 이런 alias가 존재할 수 있다.
기계 함수 하나를 두 GT group에 중복 배치할 수 없으므로 다음 singleton으로 둔다.

```text
shared-address@FUN_001557f0
```

GT schema v6의 `cross_origin_aliases`에는 해당 주소에서 관찰한 원래 origin을 모두
보존한다. 이것은 ICF나 compiler merging 원인을 확정한다는 뜻이 아니라, partition이
정의되지 않는 shared-address 관찰을 임의의 한 origin으로 귀속하지 않는 처리다.

## 10. Ground truth JSON schema

일반 GT schema version은 5다. Cross-origin shared address가 있으면 schema version
6과 `cross_origin_aliases`를 사용한다.

실제 fg01 구조:

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
  "origins": [
    {
      "origin": "shared_recursive",
      "members": [
        "FUN_00113e40",
        "FUN_00113f20",
        "FUN_00113fa0"
      ]
    }
  ],
  "symbols": {
    "FUN_00113e40": [
      "family_graph_01::shared_recursive"
    ]
  }
}
```

필드 의미:

| Field | 의미 |
|---|---|
| `case`, `build`, `profile` | fixture와 join할 identity |
| `schema_version` | GT schema version |
| `provenance` | manifest build ID와 source/non-stripped/stripped SHA-256 |
| `origins` | true partition |
| `symbols` | member별 원래 demangled symbol 목록 |
| optional `note` | same-origin duplicate/alias 기록 |
| optional `cross_origin_aliases` | shared-address member와 관찰된 원래 origin 목록 |

`symbols`의 key 집합은 모든 origin member 집합과 정확히 같아야 한다. 이 조건은 `scores.py` loader가 다시 검증한다.

## 11. Candidate selection과 boundary schema

### 11.1 `subject` users JSON

Schema version은 5다. Version 4 users JSON도 읽을 수 있다.

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

`addresses`는 scored candidate 시작 주소이며 중복을 제거해 오름차순으로 기록한다.
이 schema v5 예시에서 `function_bounds`는 같은 subject namespace에 속한 함수의
`(시작 주소, byte size)`다.
Candidate 외에 source `main`도 포함하며, stripped binary의 callsite를 radare2 함수
경계와 독립적으로 디코딩할 때 사용한다.

Users JSON에는 다음 정보가 없다.

```text
origin 이름
어떤 주소끼리 같은 family인지
generic type
symbol 문자열
origin label
```

따라서 binary extractor에 candidate 집합은 전달하지만 true partition은 전달하지 않는다.

### 11.2 `rust-nonstd` users JSON

Schema version 6은 선택 정책을 명시한다.

```json
{
  "schema_version": 6,
  "scope": "rust-nonstd",
  "root_namespace": "reconcile",
  "namespaces": [],
  "excluded_namespaces": ["core", "alloc", "std", "__rustc"],
  "addresses": ["0x2c840", "0x2ce00"],
  "function_bounds": [
    {"address": "0x2c840", "size": 64}
  ]
}
```

`candidate_selection.py`는 JSON 전체를 canonical form으로 hash하고, projector가 그
SHA-256을 fixture `analysis.candidate_selection_sha256`에 기록한다.

### 11.3 Scope-independent function boundaries

`boundaries/<profile>/*.boundaries.json`은 candidate를 고르지 않는다. Demangle 가능한
모든 Rust text symbol과 startup root 탐지용 C `main`의 `(address, size)`만 담고
별도 SHA-256으로 검증된다.

```text
같은 boundaries + stripped binary -> extraction backend별 raw graph 하나
raw + subject users              -> subject fixture
raw + rust-nonstd users          -> rust-nonstd fixture
```

따라서 candidate scope를 바꿀 때 disassembly evidence를 중복 생성할 필요가 없다.

## 12. Fixture universe 검증

`validate_against_fixture()`는 다음 두 집합을 비교한다.

```text
GT의 모든 origin member ID
==
fixture의 scored=true node ID
```

Fg01의 경우 양쪽 모두 다음 여섯 ID여야 한다.

```text
FUN_00113e40
FUN_00113f20
FUN_00113fa0
FUN_00114480
FUN_00114660
FUN_001148a0
```

하나라도 다르면 scoring universe가 달라지므로 중단한다.

Standalone CLI에서는 `--fixture`를 줄 때 이 검사를 수행한다.

```bash
python3 gt_extractor.py family_graph_01 \
  --candidate-scope subject \
  --fixture fixtures/plain/family_graph_01.O3S.fixture.json
```

`run_case.py`는 GT와 fixture를 모두 생성한 뒤 같은 검사를 항상 실행한다.

## 13. CLI argument

| Argument | 기능 | 예시 |
|---|---|---|
| `binary` | non-stripped binary path 또는 stem | `family_graph_01` |
| positional `output` | GT JSON 출력 경로 | `ground_truth/custom.gt.json` |
| `--case` | JSON case override | `--case custom_case` |
| `--build` | build label | `--build O3KS` |
| `--profile` | compiler profile과 artifact directory | `--profile min` |
| `--candidate-scope` | `rust-nonstd`(기본) 또는 `subject` | `--candidate-scope subject` |
| `--namespace` | manifest namespace override, 여러 번 지정 가능 | `--namespace billing_client` |
| `--fixture` | scored universe 검사용 fixture | `fixtures/custom.fixture.json` |
| `--users` | users JSON 출력 경로 | `users/custom.users.json` |
| `--boundaries` | 공용 Rust/startup symbol boundary 출력 | `boundaries/custom.json` |
| `--manifest` | build manifest override | `build_info/min/custom.json` |
| `--id-bias` | FUN ID address bias | `--id-bias 0` |
| `--nm-tool` | nm-compatible executable | `nm`, `/usr/bin/nm` |

명시적 실행 예시:

```bash
python3 gt_extractor.py \
  gt_bin/min/family_graph_03.O3KS.gt.bin \
  ground_truth/min/family_graph_03.O3KS.gt.json \
  --case family_graph_03 \
  --build O3KS \
  --profile min \
  --candidate-scope subject \
  --namespace family_graph_03 \
  --users users/min/family_graph_03.O3KS.users.json \
  --nm-tool nm
```

## 14. Ground truth가 말하는 것과 말하지 않는 것

이 GT의 정확한 의미는 다음과 같다.

> 최종 non-stripped binary에서 text symbol로 관찰된 함수들의 normalized source-origin partition

알 수 있는 것:

- 최종 binary에 symbol로 남은 함수 주소
- 같은 normalized source path를 가진 주소 집합
- 각 주소의 demangled symbol

알 수 없는 것:

- Source에서 예정된 전체 mono-item 수
- 완전히 inline되어 out-of-line symbol이 사라진 instance
- eliminated instance와 제거 이유
- emitted/inlined/folded lifecycle
- concrete type별 완전한 instance census
- cross-origin 동일 주소의 compiler/linker 원인

따라서 `k_obs`는 자동으로 알 수 있지만 source-level `k_ref`는 이 extractor만으로 만들 수 없다.

## 15. 코드 읽기 순서

1. `main()`
2. `apply_cli_defaults()`
3. `run_nm()`
4. `parse_nm_lines()`
5. `origin_from_symbol()`
6. `strip_rust_generic_args()`
7. `make_ground_truth()`
8. `user_addresses()`
9. `make_users_json()`
10. `rust_function_bounds()`과 `make_function_boundaries_json()`
11. `validate_against_fixture()`
12. `write_json()`
