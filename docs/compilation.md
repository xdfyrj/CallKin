# 컴파일 파이프라인

이 문서는 [compile.py](../compile.py)를 중심으로 source가 어떻게 **서로 짝이 맞는 non-stripped/stripped ELF와 검증 가능한 manifest**가 되는지 설명한다.

CallKin의 compilation 범위는 여기까지다.

```text
source -> linked ELF -> stripped copy + manifest
```

GT 추출, call graph 추출, CG-WL, scoring은 compilation이 아니다.

## 가장 짧은 실행

단일 Rust 파일:

```bash
python3 compile.py family_graph_01 case --profile plain --build O3S
```

Cargo project:

```bash
python3 compile.py billing-client subject --profile min --build O3S
```

첫 positional argument는 이름 또는 path이고, 둘째 positional argument는 입력 종류다.

```text
family_graph_01 case
billing-client subject
```

`case`는 기본적으로 `src/<name>.rs`를 찾는다. `subject`는 `subjects/<name>/Cargo.toml`을 찾는다. 명시적인 file/directory path도 받을 수 있다.

## Compile의 입력과 출력

예를 들어 다음 명령을 실행한다.

```bash
python3 compile.py billing-client subject --profile plain --build O3S
```

입력:

```text
subjects/billing-client/Cargo.toml
subjects/billing-client/Cargo.lock
subjects/billing-client/src/**
subjects/billing-client/.cargo/**   if present
subjects/billing-client/build.rs    if present
selected rustc, cargo, strip
plain/O3S build policy
```

출력:

```text
gt_bin/plain/billing-client.O3S.gt.bin
bin/plain/billing-client.O3S.fixture.bin
build_info/plain/billing-client.O3S.json
```

두 binary를 독립적으로 compile하지 않는다.

```text
Cargo가 만든 executable 한 개
  +--> 그대로 보존                 non-stripped GT binary
  +--> byte copy + strip --strip-all stripped fixture binary
```

그래서 두 binary는 같은 linked machine code layout에서 출발하며, strip 전후의 linked address를 직접 join할 수 있다.

## Target와 build matrix

### Target

Target은 [build_profiles.py](../build_profiles.py)에 고정되어 있다.

```text
x86_64-unknown-linux-gnu
```

Rust compiler version은 고정하지 않는다. Compiler version 자체가 향후 실험 변수가 될 수 있기 때문이다. 대신 `rustc -vV`, compiler binary path, sysroot, flags와 command를 매 build manifest에 기록한다.

Target을 고정하고 compiler version을 기록한다는 두 정책을 혼동하지 않는다.

### Profile

공통 flag:

```text
-C opt-level=3
-C debuginfo=0
-C debug-assertions=off
-C overflow-checks=off
```

`plain`:

```text
-C codegen-units=16
-C lto=false
-C panic=unwind
```

`min`:

```text
-C codegen-units=1
-C lto=true
-C panic=abort
```

정확한 해석:

- `plain`은 Cargo default-release 설정을 근사한 controlled profile이다.
- Cargo의 `lto=false`는 가능한 경우 thin local LTO가 발생할 수 있으므로 “LTO 완전 off”라고 쓰지 않는다.
- `min`은 fat LTO, CGU 1, abort를 결합한 aggressive/minimized stress profile이다.
- `min`은 malware-motivated condition으로 사용할 수 있지만 malware-representative build라고 일반화하지 않는다.

### Build

`O3S`:

```text
추가 cfg 없음
```

`O3KS`:

```text
--cfg keep
```

Cargo subject에서는 `RUSTFLAGS=--cfg keep`으로 전달한다. `S`는 strip된 최종 fixture가 있다는 실험 이름이며 compiler option `strip`을 뜻하지 않는다.

### Edition

단일 file case는 edition 2024로 compile한다. Cargo subject는 `cargo metadata`가 반환한 package edition을 사용한다.

## CLI argument가 실제로 하는 일

```text
python3 compile.py SOURCE {case,subject} [options]
```

| 인자 | 의미 | 예 |
|---|---|---|
| `source` | name 또는 explicit path | `billing-client`, `subjects/billing-client` |
| `input_kind` | direct rustc인지 Cargo인지 선택 | `case`, `subject` |
| `--case` | output identity와 direct crate name override | 기본은 source 이름 |
| `--build` | `O3S` 또는 `O3KS` | 기본 `O3S` |
| `--profile` | `plain` 또는 `min` | 기본 `plain` |
| `--gt-binary` | non-stripped output override | 일반 실행에서는 생략 |
| `--fixture-binary` | stripped output override | 일반 실행에서는 생략 |
| `--manifest` | manifest output override | 일반 실행에서는 생략 |
| `--rustc-tool` | rustc-compatible executable | toolchain 비교용 |
| `--cargo-tool` | Cargo executable | subject에만 사용 |
| `--strip-tool` | GNU-compatible strip executable | 기본 `strip` |

Canonical path와 다른 output override는 임시 실험에만 쓴다. Downstream `run_case.py`는 manifest가 기록한 경로와 실제 입력 경로가 다르면 중단한다.

## `main()`부터 읽는 실행 흐름

[compile.py](../compile.py)의 하단부터 위로 올라가면 가장 쉽게 이해된다.

```text
main
  -> build_arg_parser
  -> parse_args
  -> apply_cli_defaults
  -> compile_case
       -> tool preflight
       -> source inspection/hash
       -> staging build
       -> strip copy
       -> source recheck
       -> binary hashes
       -> manifest
       -> publish binaries
       -> publish manifest last
```

### `build_arg_parser()`

CLI가 받을 수 있는 입력을 선언한다. 이 함수는 compile하지 않는다.

예를 들어:

```text
입력 argv:
["billing-client", "subject", "--profile", "min"]

parse 직후:
args.source = "billing-client"
args.input_kind = "subject"
args.profile = "min"
args.build = None
```

### `apply_cli_defaults()`

사용자가 짧게 쓴 name을 실제 path와 canonical output으로 확장한다.

예:

```text
입력:
source="billing-client"
input_kind="subject"
profile="plain"
build=None

변환:
source="subjects/billing-client"
case="billing-client"
build="O3S"
gt_binary="gt_bin/plain/billing-client.O3S.gt.bin"
fixture_binary="bin/plain/billing-client.O3S.fixture.bin"
manifest="build_info/plain/billing-client.O3S.json"
```

이 함수가 수행하는 검증:

- `case`: explicit file이 아니면 `src/<case>.rs`가 존재해야 한다.
- `subject`: directory와 그 안의 `Cargo.toml`이 존재해야 한다.
- profile/build를 canonical lowercase/uppercase로 정규화한다.

### `compile_case()`

실제 pipeline의 coordinator다. Compile 자체를 직접 구현하기보다 case/Cargo 분기와 안전한 publish 순서를 조립한다.

핵심 순서:

```text
1. profile/build 유효성 확인
2. rustc, strip, 필요하면 cargo가 PATH에 있는지 확인
3. source hash 계산
4. system temporary directory에 세 staging path 생성
5. non-stripped ELF 생성
6. 그 ELF를 복사하고 strip
7. compile 중 source가 바뀌지 않았는지 hash 재확인
8. 두 binary hash 계산
9. staging manifest 작성
10. non-stripped publish
11. stripped publish
12. manifest를 completion marker로 마지막 publish
```

## 단일 file branch

### `rustc_command()`

명령을 list로 조립한다.

개념적인 예:

```text
rustc src/family_graph_01.rs
  -C opt-level=3
  -C debuginfo=0
  -C debug-assertions=off
  -C overflow-checks=off
  -C codegen-units=16
  -C lto=false
  -C panic=unwind
  --crate-type bin
  --crate-name family_graph_01
  --edition 2024
  --target x86_64-unknown-linux-gnu
  --emit=link
  -o <staging>/non-stripped.bin
```

Shell string을 만들지 않고 argument list를 `subprocess.run()`에 전달한다. 공백이나 shell quoting에 의존하지 않는다.

### `compile_gt_binary()`

- output directory를 준비한다.
- 같은 directory에 temporary file을 만든다.
- rustc를 실행한다.
- 성공하면 `os.replace()`로 요청 path에 교체한다.
- 실패하면 temporary file을 지운다.

`compile_case()`가 system staging directory 안의 path를 넘기므로 여기서 만든 결과도 아직 canonical artifact가 아니다.

## Cargo subject branch

### `inspect_cargo_subject()`

`cargo metadata --no-deps --locked`를 실행하고 다음을 찾는다.

- 현재 directory의 정확한 package
- package edition
- binary target
- library target namespace
- `Cargo.lock`

현재 계약은 binary target이 정확히 하나여야 한다. 둘 이상이면 임의 선택하지 않고 실패한다.

Billing example:

```text
package             = billing-client
library namespace   = billing_client
binary target       = reconcile
candidate namespaces= [billing_client, reconcile]
root namespace      = reconcile
edition             = 2021
```

Hyphenated package `billing-client`와 Rust namespace `billing_client`를 같은 문자열로 추측하지 않고 metadata를 사용하는 이유다.

### Cargo input hash

[build_manifest.py](../build_manifest.py)의 `sha256_cargo_inputs()`는 build 결과 directory 전체를 hash하지 않는다. Build를 결정하는 입력만 path와 bytes 순서로 hash한다.

필수:

```text
Cargo.toml
Cargo.lock
```

포함:

```text
src/** files
.cargo/** files
build.rs
rust-toolchain
rust-toolchain.toml
```

제외되는 대표 항목:

```text
target/**
Git metadata
editor temporary files
unrelated subject files
```

### `cargo_profile_config()`

Staging directory에 temporary Cargo config를 만든다.

```toml
[profile.release]
opt-level = 3
debug = 0
debug-assertions = false
overflow-checks = false
codegen-units = 16
lto = false
panic = "unwind"
incremental = false
strip = "none"
```

`min`에서는 codegen-units, lto, panic만 해당 profile 값으로 달라진다.

Cargo.toml에서 유지하는 것:

- package/targets/edition
- dependencies와 features
- build script
- Cargo.lock resolution

CallKin이 release profile overlay로 강제하는 것:

- optimization/debug/assertion/overflow
- codegen units
- LTO
- panic strategy
- incremental off
- Cargo 자체 strip off

Cargo 자체 strip을 끄는 이유는 non-stripped executable 하나를 먼저 얻은 뒤 CallKin이 동일 executable의 copy를 직접 strip해야 하기 때문이다.

### `cargo_build_command()`

개념적인 command:

```text
cargo build
  --release
  --locked
  --manifest-path subjects/billing-client/Cargo.toml
  --package billing-client
  --bin reconcile
  --target x86_64-unknown-linux-gnu
  --target-dir <staging>/cargo-target
  --message-format=json-render-diagnostics
  --config <staging>/callkin-cargo-config.toml
```

Cargo stdout의 `compiler-artifact` JSON에서 selected binary target의 실제 `executable` path를 찾는다. 예상 directory를 문자열로 조립하지 않는다.

### `compile_cargo_binary()`

- temporary config와 target directory를 staging 아래에 둔다.
- `RUSTC`를 선택한 compiler로 설정한다.
- 기존 `CARGO_ENCODED_RUSTFLAGS`를 제거한다.
- `O3KS`에서만 `RUSTFLAGS=--cfg keep`을 설정한다.
- Cargo가 보고한 executable이 정확히 하나인지 확인한다.
- executable을 staging non-stripped path로 복사한다.
- command, environment, profile config를 manifest용으로 반환한다.

## Stripped pair 생성

`derive_fixture_binary()`는 다음만 한다.

```text
copy(non-stripped, temporary)
copy file mode
strip --strip-all temporary
atomic replace into staging stripped path
```

Strip이 실패하면 non-stripped staging file은 있어도 canonical output은 아직 교체되지 않는다. 두 binary를 별도로 compile하는 방식과 달리 compiler nondeterminism이나 address 차이를 pair 안에 만들지 않는다.

## Staging과 publish safety

`compile_case()`는 `TemporaryDirectory` 안에서 binary pair와 manifest를 모두 완성한다.

```text
/tmp/<case>.<profile>.<build>.../
  non-stripped.bin
  stripped.bin
  build.json
  cargo-target/             subject only
```

`_publish_file()`은 canonical destination과 같은 directory에 temporary copy를 만든 뒤 `os.replace()`한다. System `/tmp`에서 canonical path로 단순 rename하는 것이 아니다. Cross-filesystem rename 문제를 피하고 destination 단위 atomic replacement를 얻기 위한 두 단계다.

Publish 순서:

```text
non-stripped
stripped
manifest last
```

세 파일 전체를 하나의 filesystem transaction으로 교체할 수는 없다. 대신 manifest를 completion marker로 마지막에 배치하고, downstream에서 세 hash를 다시 검증한다. 중간 실패로 old/new file이 섞여도 manifest 검증이 이를 거부한다.

Staging `TemporaryDirectory`는 context를 벗어나면 제거된다. Destination 옆 temporary file도 `finally`에서 제거한다.

## Manifest가 기록하는 재현 정보

Build manifest에는 다음이 남는다.

- source kind/path/hash
- case/build/profile/target/edition/crate name
- random build ID
- rustc invoked/resolved path
- rustc sysroot와 compiler binary path
- `rustc -vV` 전체
- canonical flags와 실제 command
- strip invoked/resolved path, version, flags, command
- Cargo path/version/package/bin/namespaces
- Cargo manifest와 lockfile hash
- Cargo environment와 generated profile config
- 두 binary path/hash
- stripped copy의 source hash

Compiler version을 강제하지 않더라도 어느 compiler가 어떤 artifact를 만들었는지는 잃지 않는다.

## 실패는 어디에서 멈추는가

| 실패 | 결과 |
|---|---|
| rustc/cargo/strip 없음 | canonical file 교체 전 중단 |
| Cargo.lock 없음 | metadata/build 전 중단 |
| binary target 0개 또는 여러 개 | 임의 선택 없이 중단 |
| rustc/Cargo failure | stderr를 포함해 중단 |
| strip failure | publish 전 중단 |
| compile 도중 source 변경 | hash mismatch로 publish 전 중단 |
| Cargo executable 보고가 모호함 | 중단 |
| manifest 생성 실패 | publish 전 중단 |
| publish 중 일부 실패 | 다음 run의 manifest 검증이 혼합 상태 거부 |

## Downstream 검증

[run_case.py](../run_case.py)는 manifest를 먼저 읽고 다음을 검증한 뒤에만 nm/radare2를 실행한다.

```text
expected case/build/profile/target
current source hash
current non-stripped hash
current stripped hash
stripped_from relation
canonical compiler flags
Cargo input records
```

따라서 compile 후 source comment 하나만 바뀌어도 source hash가 달라져 분석을 거부한다. Source를 정리하고 commit한 뒤 compile해야 하는 이유다.

## 핵심 함수만 읽는 순서

Compilation을 이해하는 데 필요한 최소 순서:

1. [build_profiles.py](../build_profiles.py)의 `PROFILE_FLAGS`, `BUILD_FLAGS`, `compile_flags()`
2. [compile.py](../compile.py)의 `apply_cli_defaults()`
3. `compile_case()`
4. direct branch면 `rustc_command()`, `compile_gt_binary()`
5. Cargo branch면 `inspect_cargo_subject()`, `compile_cargo_binary()`
6. `derive_fixture_binary()`
7. `make_build_manifest()`, `_publish_file()`
8. [build_manifest.py](../build_manifest.py)의 `load_and_verify_manifest()`

Subprocess error formatting이나 작은 type validator는 문제가 생겼을 때만 읽어도 된다.

## 개발 시 체크리스트

Profile을 추가하거나 수정할 때:

1. [build_profiles.py](../build_profiles.py)의 direct flags와 Cargo config를 함께 수정한다.
2. Manifest verifier의 canonical flag 검사도 확인한다.
3. Profile path normalization을 [paths.py](../paths.py)에 반영한다.
4. [test_compile.py](../tests/test_compile.py)에 exact command/config test를 추가한다.
5. Binary부터 모든 downstream artifact를 다시 생성한다.

Cargo subject 지원을 넓힐 때:

1. Multi-binary selection 정책을 CLI에 명시한다.
2. Workspace/package 선택을 metadata로 검증한다.
3. Hash에 새 build input이 빠지지 않는지 확인한다.
4. Namespace와 root namespace를 manifest에 보존한다.
5. Direct case 회귀가 바뀌지 않는지 확인한다.

## 현재 한계

- Linux x86-64 ELF만 canonical target이다.
- Cargo subject는 binary target 하나만 지원한다.
- Features를 별도 CLI로 선택하지 않는다. Subject의 현재 Cargo invocation/default feature를 따른다.
- Compiler matrix용 version별 output namespace는 아직 없다. 같은 case/profile/build를 다른 compiler로 compile하면 canonical path를 덮어쓴다.
- Build manifest는 동일 input과 environment가 byte-identical output을 반드시 만든다고 증명하지 않는다. 실제 artifact identity와 실행 환경을 기록하고 검증한다.
