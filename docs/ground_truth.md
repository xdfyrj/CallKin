# Ground truth와 candidate selection

CallKin은 non-stripped binary를 한 번 읽어 서로 목적이 다른 세 artifact를 만든다.

```text
non-stripped ELF
       |
       | nm -n -S -C
       v
demangled sized text symbols
       |
       +--> ground truth: origin partition + full symbols
       +--> users: target addresses + target bounds
       +--> boundaries: scope-independent Rust function bounds
```

세 파일을 분리하는 이유는 정답 누수를 막기 위해서다. Engine 쪽으로 넘어가는 것은 주소와 함수 경계이지 origin 이름이나 concrete type이 아니다.

## 실행

일반적으로 [run_case.py](../run_case.py)가 이 단계를 호출한다.

```bash
python3 run_case.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track angr \
  --anchor-policy role \
  --mode out-in
```

GT 단계만 실행하려면:

```bash
python3 gt_extractor.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd
```

Subject-only 예:

```bash
python3 gt_extractor.py family_graph_01 \
  --profile plain \
  --candidate-scope subject
```

Canonical path는 [Artifact와 provenance](artifacts.md)에 정의되어 있다.

## 이 GT가 정답으로 삼는 것

현재 GT의 정확한 정의는 다음이다.

> 최종 non-stripped ELF의 `t/T` text symbol로 관찰된 함수들을 normalized source-origin별로 나눈 partition.

예:

```text
billing_client::decode::<Invoice>  @ 0x40100
billing_client::decode::<Customer> @ 0x40200
```

Normalization 후:

```text
origin: billing_client::decode
members: [FUN_00140100, FUN_00140200]
```

주소는 예시다. 실제 ID는 linked address에 기본 `0x100000` bias를 더해 Ghidra-style `FUN_...` 문자열로 만든다.

## 이 GT가 정답으로 삼지 않는 것

현재 GT는 source-level mono-item census가 아니다. 다음을 알지 못한다.

- source에서 예정된 전체 concrete type instance
- compile 중 생성되었으나 완전히 inlined된 instance
- dead-code elimination으로 사라진 instance
- 어떤 pass에서 제거되었는지
- 동일 주소가 compiler merging인지 linker ICF인지
- source-level `k_ref`

따라서 origin member 수 `k_obs`는 “최종 symbol에서 보인 out-of-line instance 수”다.

```text
source에서 5개 instantiate
최종 symbol에서 3개 생존
GT k_obs = 3
```

사라진 두 instance는 현재 GT universe에 들어오지 않는다. 이 때문에 CallKin의 기본 RE는 source-level survival recall이 아니라 observed-target conditional recall이다.

## Symbol 입력

### `run_nm()`

실제 command:

```text
nm -n -S -C <non-stripped-binary>
```

Flag 의미:

- `-n`: address 순서
- `-S`: symbol size 포함
- `-C`: Rust symbol demangle

### `parse_nm_lines()`

다음 형태를 읽는다.

```text
0000000000040100 0000000000000080 t billing_client::decode::<Invoice>
```

결과:

```text
addr = 0x40100
size = 0x80
kind = t
name = billing_client::decode::<Invoice>
```

`t`와 `T`만 text function으로 취급한다. Undefined/import/data symbols는 GT member가 아니다. Size가 필요한 boundary artifact에서는 `size > 0`을 강제한다.

## Candidate scope

Scope는 “어떤 origin을 정답 partition과 target selection에 넣는가”를 결정한다.

### `subject`

Manifest의 `candidate_namespaces`에 직접 소유된 함수만 선택한다.

Cargo example:

```text
namespaces = [billing_client, reconcile]
```

포함:

```text
billing_client::client::decode
reconcile::run
<billing_client::Paginator<T> as Iterator>::next
<reconcile::ProxyTransport as billing_client::Transport>::execute
```

제외:

```text
serde_json::from_slice
core::ptr::drop_in_place<billing_client::Invoice>
std::rt::lang_start_internal
```

판정은 문자열 안에 subject type이 등장하는지만 보는 것이 아니다. 이름이 `namespace::` 또는 `<namespace::`로 시작해야 한다.

그 결과 다음처럼 외부 type에 subject trait을 구현한 특수 형태는 `subject` scope에서 누락될 수 있다.

```text
<alloc::vec::Vec<T> as billing_client::LocalTrait>::method
```

이 한계가 문제가 되는 corpus에서는 ownership parser를 확장해야 하며, type 문자열이 나타난다는 이유만으로 외부 generic specialization을 포함하면 안 된다.

### `rust-nonstd`

기본 scope다. Rust symbol owner를 추정해 다음 owner를 제외한다.

```text
core
alloc
std
__rustc
```

Source root main도 제외한다.

```text
reconcile::main -> target 아님
```

그 외 관찰 가능한 Rust owner는 subject와 dependency를 구분하지 않고 target으로 둔다.

```text
billing_client::...
reconcile::...
serde::...
serde_json::...
third_party_crate::...
```

이 scope는 “main에서 reachable한 non-std 함수”가 아니다. Symbol로 관찰된 전체 rust-nonstd 함수 집합이다. Reachability는 결과 진단으로 계산할 수 있지만 target selection filter로 쓰지 않는다.

### Trait impl owner

일반 path는 첫 crate component를 owner로 본다.

```text
serde_json::de::from_slice -> serde_json
```

Trait impl은 outer `<... as ...>` header의 crate roots를 보고 `core/alloc/std/__rustc`가 아닌 첫 root를 우선한다.

```text
<alloc::vec::Vec<T> as billing_client::LocalTrait>::method
                                     ^
owner = billing_client
```

Owner를 관찰할 수 없는 C symbol, PLT/import stub, anonymous address는 target이 아니다. 필요하면 graph projection에서 anchor가 된다.

## Root main은 왜 target에서 제외하는가

Root main은 graph의 관측 시작 문맥이다. 일반 family target과 같은 방식으로 채점하면 main의 단일 특성이 score와 seed universe를 바꾼다.

- GT origin에는 넣지 않는다.
- users candidate address에는 넣지 않는다.
- boundaries에는 root 탐지를 위해 포함할 수 있다.
- fixture에서는 기본적으로 `anchor_kind=root`, `scored=false`다.

Binary extractor의 `--score-root`는 디버깅용 override다.

## Origin normalization

[gt_extractor.py](../gt_extractor.py)의 핵심은 `origin_from_symbol()`과 `normalize_rust_origin()`이다.

### 1. Rust hash suffix 제거

```text
billing_client::decode::h0123456789abcdef
-> billing_client::decode
```

### 2. Derived impl identity 보존

Rust demangler는 derive/impl path를 `::<impl ...>` 형태로 보여 줄 수 있다. 이를 일반 generic argument처럼 통째로 지우면 서로 다른 type의 generated impl이 같은 origin으로 합쳐진다.

잘못된 결과:

```text
Invoice Deserialize impl
Customer Deserialize impl
-> 같은 "deserialize" origin
```

현재 `preserve_derived_impl_identity()`는 generic 제거 전에 impl target을 marker로 바꾼다.

```text
::<impl Trait for billing_client::Invoice>
-> ::impl_for=billing_client::Invoice
```

Inherent impl은 `::impl=<type>`으로 보존한다. 그 뒤 generic instance argument를 제거해도 implementation target identity는 남는다.

### 3. Displayed generic argument 제거

V0 demangled instance:

```text
billing_client::decode::<Invoice>
billing_client::decode::<Customer>
```

둘 다:

```text
billing_client::decode
```

`strip_rust_generic_args()`는 `::<...>`의 nested angle depth를 따라가며 제거한다. 정규식 한 번으로 처리하지 않는 이유는 nested generic type 때문이다.

```text
foo::<Vec<Result<A, B>>>
```

### 4. Namespace 표현

Subject namespace가 하나뿐인 legacy case는 namespace를 제거한 relative origin을 유지할 수 있다.

```text
family_graph_01::process::<i32>
-> process
```

Cargo처럼 namespace가 여러 개면 collision을 피하려 full path를 유지한다.

```text
billing_client::run
reconcile::run
```

## Address alias와 folding

하나의 address에 symbol이 여러 개 붙을 수 있다.

### Same-origin duplicate

```text
same address
same normalized origin
different symbol spelling
```

Member는 한 번만 보존하고 symbol spelling은 list에 남긴다.

### Cross-origin shared address

`rust-nonstd` scope에서는 서로 다른 origin이 같은 address를 공유하면 조용히 하나를 선택하지 않는다.

```text
origin A           same FUN address
origin B /
```

이 member의 GT origin을 다음처럼 명시적으로 바꾼다.

```text
shared-address@FUN_...
```

그리고 원래 origin 목록을 `cross_origin_aliases`에 보존한다. 이 상태는 grouping 전에 이미 binary에서 source identities가 address 하나로 합쳐진 관찰이다.

Frozen `subject` compatibility path는 cross-origin alias가 나타나면 기존 정책대로 실패할 수 있다. Controlled baseline의 의미를 조용히 바꾸지 않기 위해서다.

현재 artifact는 merging 원인을 compiler/linker로 확정하지 않는다. “shared address observed”만 기록한다.

## 세 output의 차이

### Ground truth JSON

포함:

- origin groups
- member ID
- full demangled symbol list
- cross-origin aliases
- build provenance

사용처:

- [scores.py](../scores.py)
- 사람이 cluster를 해석하는 symbol display

금지:

- engine seed
- graph projector candidate grouping
- raw transfer resolution

### Users JSON

포함:

- candidate raw address
- candidate symbol extent
- scope/namespace/excluded namespace
- build provenance

포함하지 않음:

- origin
- member group
- symbol 이름
- concrete type

사용처:

- candidate selection
- candidate boundary oracle
- projection candidate universe

### Boundaries JSON

포함:

- 전체 observable Rust text function address/size
- C `main` startup wrapper extent
- build provenance

Scope와 독립적이다. 사용처:

- candidate가 아닌 context function의 boundary
- full Capstone decoding
- root detection
- angr `function_starts`

GT와 users를 scope별로 다시 만들어도 boundary 규칙이 같다면 이 파일은 재사용할 수 있다.

## 엄격한 consistency checks

### GT 내부

- origin 이름은 중복될 수 없다.
- member는 두 origin에 동시에 나타날 수 없다.
- 모든 member에 symbol entry가 있어야 한다.
- 빈 origin은 허용하지 않는다.
- provenance hash 형식과 field set을 검사한다.

### Users 내부

[candidate_selection.py](../candidate_selection.py)가 검사한다.

- schema에 맞는 정확한 field set
- scope 값
- `rust-nonstd`의 excluded namespace가 정확히 네 개인지
- address 중복/형식
- 모든 candidate address에 function bound가 있는지
- case/build/profile/provenance

### Fixture와 join

`gt_extractor.py --fixture ...` 또는 scorer가 다음을 확인한다.

Schema v6:

```text
GT members
=
fixture scored node IDs
union
fixture abstention IDs
```

이 식이 맞지 않으면 일부 target이 graph projection 중 사라졌거나 다른 scope artifact를 섞은 것이다.

## All-Rust catalog와 Oxidizer audit

이 절은 GT 측 경계만 요약한다. 별도 Python 환경, direct/propagated/cleanup evidence, 주소 정규화, cache, audit metric의 전체 계약은 [Oxidizer direct-FLIRT audit](flirt_audit.md)을 참고한다.

`ground_truth/all-rust/...catalog.json`은 일반 grouping GT가 아니다. Direct-FLIRT label을 평가하기 위한 scoring-only catalog다.

포함 범위:

```text
all observable Rust-owned text functions
except source root main
```

즉 `core/alloc/std`도 포함한다. 목적은 다음을 측정하는 것이다.

- Oxidizer direct FLIRT가 실제 std function을 얼마나 식별했는가
- exact origin label이 얼마나 맞는가
- known/unknown member가 섞인 family와 `K x U` pair가 얼마나 있는가

[flirt_audit.py](../flirt_audit.py)는 다음 count를 분리한다.

- raw graph에 join된 match
- all-Rust catalog까지 join된 match
- catalog unmatched match
- standard-library classification
- exact identity
- mixed known/unknown family

현재 이것은 **audit-only**다.

```text
FLIRT label -> audit result
FLIRT label -X-> candidate/anchor 변경
FLIRT label -X-> CG-WL seed
```

Context view와 known-to-unknown transfer view는 아직 구현되지 않았다.

## CLI option

```text
python3 gt_extractor.py BINARY_OR_STEM [OUTPUT] [options]
```

| 옵션 | 의미 |
|---|---|
| `--case` | JSON identity override |
| `--build` | build label |
| `--profile` | canonical profile path |
| `--candidate-scope` | `subject` 또는 `rust-nonstd` |
| `--namespace` | subject namespace override, 반복 가능 |
| `--users` | candidate selection output override |
| `--boundaries` | boundary output override |
| `--fixture` | 생성 GT를 fixture universe와 즉시 검증 |
| `--manifest` | build manifest override/verification |
| `--id-bias` | raw address에서 `FUN_` ID로 바꿀 때 더할 값 |
| `--nm-tool` | nm-compatible executable |

Namespace는 일반 실행에서 manifest의 Cargo metadata 값을 사용한다. 사람이 file name에서 crate namespace를 추측하지 않는다.

## 구현을 읽는 순서

1. `run_nm()`, `parse_nm_lines()`
2. `rust_symbol_owner()`
3. `origin_from_symbol()`
4. `normalize_rust_origin()`
5. `preserve_derived_impl_identity()`, `strip_rust_generic_args()`
6. `make_ground_truth()`
7. `user_addresses()`, `user_function_bounds()`
8. `rust_function_bounds()`
9. `make_users_json()`, `make_function_boundaries_json()`
10. `validate_against_fixture()`
11. `main()`의 manifest/default/output orchestration

FLIRT를 조사할 때만 `make_all_rust_catalog()`과 [flirt_audit.py](../flirt_audit.py)를 추가로 읽는다.

## 변경 시 주의할 점

Origin normalizer를 바꾸면:

- GT family denominator가 달라진다.
- Candidate address 자체는 같아도 score와 origin summary가 바뀐다.
- Existing baseline GT/result를 재생성해야 한다.
- Derived impl과 nested generic 회귀를 추가해야 한다.

Candidate scope를 바꾸면:

- GT와 users를 함께 바꿔야 한다.
- Fixture와 result를 다시 만들어야 한다.
- Raw graph는 candidate-independent이므로 boundary/evidence 의미가 같으면 재사용 가능하다.
- Target count와 abstention count가 달라지는 것이 정상이다.

Boundary rule을 바꾸면:

- direct raw와 angr raw를 다시 만들어야 한다.
- Angr function start oracle도 바뀐다.
- 모든 fixture/result가 stale이다.

## 현재 한계

- Symbol이 없는 완전 inline/eliminated instance를 보지 못한다.
- Name normalization은 Rust demangler 출력 grammar에 의존한다.
- Owner 추정은 crate metadata가 아니라 demangled path 기반이다.
- Subject scope는 외부 type에 local trait을 구현한 일부 형태를 놓칠 수 있다.
- Shared address의 원인을 compiler merging/ICF로 자동 확정하지 않는다.
- Generic인지 concrete인지 별도 `kind` label을 만들지 않는다. 같은-origin partition과 member count가 필요한 정답이다.
