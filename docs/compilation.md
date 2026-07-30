# 컴파일 파이프라인

## 1. 범위

CallKin의 Rust source compilation pipeline은 `compile.py`에 구현되어 있다.

```text
case: src/<name>.rs -> rustc
subject: subjects/<name>/Cargo.toml -> cargo build
-> non-stripped binary 생성
-> binary 복사
-> 복사본에 strip --strip-all 적용
-> source/tool/binary 정보를 manifest에 기록
-> 완성된 세 파일을 최종 경로에 배치
```

`run_baseline.py`는 두 profile의 네 case/build 조합에 대해 `compile.py`를 총 8번 호출하는 상위 runner다. 컴파일 방법, profile flag, staging, strip, manifest 생성은 모두 `compile.py`가 결정한다.

## 2. 가장 단순한 실행

```bash
python3 compile.py family_graph_03 case
```

`--build`를 생략했으므로 기본값은 `O3S`다. 실제로 해석되는 값은 다음과 같다.

```text
source         = src/family_graph_03.rs
case           = family_graph_03
build          = O3S
profile        = plain
gt_binary      = gt_bin/plain/family_graph_03.O3S.gt.bin
fixture_binary = bin/plain/family_graph_03.O3S.fixture.bin
manifest       = build_info/plain/family_graph_03.O3S.json
rustc_tool     = rustc
strip_tool     = strip
```

크기 지향 `min` profile을 만들려면 다음과 같이 실행한다.

```bash
python3 compile.py family_graph_03 case --profile min
```

이때 핵심 값은 다음처럼 달라진다.

```text
profile = min
codegen-units = 1
lto = true
panic = abort
```

`--build O3KS`는 profile과 독립적이며 선택한 profile에 `--cfg keep`만 추가한다.

## 3. `main()`에서 시작하는 호출 순서

`compile.py`를 읽을 때는 파일 위에서 아래로 읽기보다 다음 호출 순서를 따라가는 편이 쉽다.

```text
main()
  -> build_arg_parser()
  -> parse_args()
  -> apply_cli_defaults()
  -> compile_case()
       -> compile_flags()
       -> _require_tool()
       -> case: compile_gt_binary() -> rustc_command()
       -> subject: inspect_cargo_subject() -> compile_cargo_binary()
       -> derive_fixture_binary()
            -> _run_tool()
       -> make_build_manifest()
       -> write_manifest()
       -> _publish_file() x 3
```

### `main()`

`main()`은 CLI 문자열을 해석하고 전체 작업의 성공/실패를 exit code로 바꾼다.

성공 예시 출력:

```text
wrote gt_bin/plain/family_graph_03.O3S.gt.bin
wrote bin/plain/family_graph_03.O3S.fixture.bin
wrote build_info/plain/family_graph_03.O3S.json
```

실패하면 예외를 다음 형식으로 출력하고 `1`을 반환한다.

```text
error: strip executable was not found. Install it before running compile.py.
```

## 4. CLI argument

| Argument | 의미 | `family_graph_03` 예시 |
|---|---|---|
| `source` | case 또는 subject 이름/경로 | `family_graph_03`, `billing-client` |
| `input_kind` | 입력 종류를 명시하는 위치 인자 | `case`, `subject` |
| `--case` | crate name과 manifest case를 명시적으로 덮어씀 | `--case family_graph_03` |
| `--build` | evaluation build | `O3S`, `O3KS` |
| `--profile` | compiler optimization profile | `plain`, `min` |
| `--gt-binary` | non-stripped 출력 경로 override | `gt_bin/custom.gt.bin` |
| `--fixture-binary` | stripped 출력 경로 override | `bin/custom.fixture.bin` |
| `--manifest` | manifest 출력 경로 override | `build_info/custom.json` |
| `--rustc-tool` | 실행할 rustc-compatible program | `rustc`, `/path/to/rustc` |
| `--cargo-tool` | subject에 사용할 Cargo program | `cargo`, `/path/to/cargo` |
| `--strip-tool` | 실행할 strip-compatible program | `strip`, `/usr/bin/strip` |

`--rustc-tool 1.93.1`처럼 version 문자열을 넘기는 것이 아니다. 실제 실행 파일의 이름이나 경로를 넘긴다.

모든 경로를 명시하는 예시는 다음과 같다.

```bash
python3 compile.py src/family_graph_03.rs case \
  --case family_graph_03 \
  --build O3KS \
  --profile min \
  --gt-binary gt_bin/min/family_graph_03.O3KS.gt.bin \
  --fixture-binary bin/min/family_graph_03.O3KS.fixture.bin \
  --manifest build_info/min/family_graph_03.O3KS.json \
  --rustc-tool rustc \
  --strip-tool strip
```

## 5. `apply_cli_defaults()`: 입력 종류를 실제 경로로 바꾸기

입력이 실제 파일인지 먼저 확인한다.

```bash
python3 compile.py family_graph_03 case
```

두 번째 위치 인자가 `case`이므로 다음 source를 찾는다.

```text
src/family_graph_03.rs
```

`paths.py`의 canonical naming 함수가 나머지 경로를 만든다.

```text
gt_binary_for("family_graph_03", "O3S", "plain")
-> gt_bin/plain/family_graph_03.O3S.gt.bin

fixture_binary_for("family_graph_03", "O3S", "plain")
-> bin/plain/family_graph_03.O3S.fixture.bin

build_manifest_for("family_graph_03", "O3S", "plain")
-> build_info/plain/family_graph_03.O3S.json
```

다음처럼 실제 source 경로를 전달해도 된다.

```bash
python3 compile.py src/family_graph_03.rs case --build O3KS
```

`subject` 입력은 같은 방식으로 `subjects/<name>/Cargo.toml`을 찾는다.

```bash
python3 compile.py billing-client subject --profile min --build O3S
```

Cargo metadata에서 package, edition, 하나뿐인 binary target과 library/bin crate
namespace를 가져온다. Binary target이 여러 개면 현재 구현은 임의 선택하지 않고
중단한다.

## 6. Profile과 build

Profile은 최적화·크기 전략이고 build는 source의 `keep` control 여부다. 두 축은 독립적이다.

| Profile | 핵심 설정 |
|---|---|
| `plain` | O3, codegen units 16, `lto=false`, panic unwind |
| `min` | O3, codegen unit 1, fat LTO, panic abort |

`plain`은 Cargo 기본 release codegen 설정을 근사한 CallKin profile이다.
`case`에서는 direct rustc flag로, `subject`에서는 임시 Cargo release-profile
overlay로 같은 조건을 적용한다. 특히 `lto=false`는 LTO를
완전히 끈다는 뜻이 아니며, rustc가 local crate의 codegen unit 사이에서 thin
local LTO를 수행할 수 있다.

`min`은 O3, fat LTO, CGU 1, panic abort를 결합해 binary 크기와 cross-unit
optimization 압력을 높인 stress profile이다. 특정 악성코드 build를 대표한다고
주장하지 않으며, 연구에서는 malware-motivated robustness condition으로만
해석한다.

`plain`의 전체 flag는 다음과 같다.

```text
-C opt-level=3
-C debuginfo=0
-C debug-assertions=off
-C overflow-checks=off
-C codegen-units=16
-C lto=false
-C panic=unwind
```

`min`은 공통 O3 설정 뒤에 다음 값을 사용한다.

```text
-C codegen-units=1
-C lto=true
-C panic=abort
```

Build `O3S`는 추가 source cfg가 없고, `O3KS`는 어느 profile에서든 다음을 추가한다.

```text
--cfg keep
```

고정된 compile setting은 다음과 같다.

```text
crate type = bin
edition    = 2024
target     = x86_64-unknown-linux-gnu
emit       = link
crate name = case
```

Crate name을 case와 같게 두는 이유는 non-stripped symbol prefix가 다음처럼 유지되어야 하기 때문이다.

```text
family_graph_03::share
```

## 7. 실제 rustc command 구성

다음 입력을 예로 든다.

```text
source  = src/family_graph_03.rs
case    = family_graph_03
profile = plain
build   = O3S
output  = /tmp/.../non-stripped.bin
```

`rustc_command()`가 만드는 명령은 의미상 다음과 같다.

```bash
rustc src/family_graph_03.rs \
  -C opt-level=3 \
  -C debuginfo=0 \
  -C debug-assertions=off \
  -C overflow-checks=off \
  -C codegen-units=16 \
  -C lto=false \
  -C panic=unwind \
  --crate-type bin \
  --crate-name family_graph_03 \
  --edition 2024 \
  --target x86_64-unknown-linux-gnu \
  --emit=link \
  -o /tmp/.../non-stripped.bin
```

`_run_tool()`은 command를 shell string으로 실행하지 않고 argument list로 `subprocess.run()`에 전달한다. Return code가 0이 아니면 stderr를 포함한 `RuntimeError`를 발생시킨다.

## 8. Non-stripped binary 생성

`compile_gt_binary()`는 최종 `gt_bin/` 경로에 바로 쓰지 않는다.

예를 들어 원하는 출력이 다음이라고 하자.

```text
gt_bin/plain/family_graph_03.O3S.gt.bin
```

함수는 같은 staging directory 안에 임시 파일을 만들고 rustc의 `-o`에 넘긴다.

```text
/tmp/family_graph_03.plain.O3S.xxxxx/non-stripped.bin
```

Rustc가 성공한 경우에만 임시 파일을 staging output으로 교체한다. 실패하면 임시 파일을 삭제한다.

이 binary는 symbol을 유지하며 `gt_extractor.py`가 읽는 쪽이다.

## 9. Stripped fixture binary 파생

`derive_fixture_binary()`는 non-stripped binary를 다시 컴파일하지 않는다.

```text
staged non-stripped binary
-> shutil.copyfile()
-> shutil.copymode()
-> strip --strip-all copied-file
-> staged stripped binary
```

실제 command 예시는 다음과 같다.

```bash
strip --strip-all /tmp/.../stripped.bin
```

따라서 두 binary는 서로 독립적인 compile 결과가 아니다. Stripped binary는 그 실행에서 생성한 non-stripped binary의 복사본에서 파생된다.

## 10. `compile_case()`: staging transaction

`compile_case()`는 세 최종 파일을 곧바로 덮어쓰지 않는다. 먼저 하나의 temporary directory에서 전부 준비한다.

```text
/tmp/family_graph_03.plain.O3S.xxxxx/
  non-stripped.bin
  stripped.bin
  build.json
```

순서는 다음과 같다.

1. `rustc`와 `strip`이 PATH에 있는지 검사한다.
2. Compile 시작 전 source SHA-256을 계산한다.
3. Staging directory에 non-stripped binary를 컴파일한다.
4. 그 binary를 복사하고 strip한다.
5. Source hash를 다시 계산해 compile 도중 source가 바뀌지 않았는지 검사한다.
6. 두 staged binary의 SHA-256을 계산한다.
7. Manifest를 staging에 작성한다.
8. Non-stripped binary를 최종 경로에 배치한다.
9. Stripped binary를 최종 경로에 배치한다.
10. Manifest를 가장 마지막에 최종 경로에 배치한다.

Manifest를 마지막에 쓰는 이유는 manifest를 **build completion marker**로 사용하기 위해서다.

```text
manifest가 새 build를 가리킨다
=> source와 두 binary가 모두 완성되었다
```

파일 교체에는 `os.replace()`를 사용한다. 각 파일은 완성된 임시 파일이 준비된 뒤 교체된다.

## 11. Build manifest

Manifest 생성은 `compile.py`의 책임이고, JSON 작성 및 이후 검증 helper는 `build_manifest.py`에 있다.

예시 핵심 구조:

```json
{
  "case": "family_graph_01",
  "build": "O3S",
  "profile": "plain",
  "target": "x86_64-unknown-linux-gnu",
  "edition": "2024",
  "source": {
    "kind": "case",
    "path": "src/family_graph_01.rs",
    "sha256": "09fb...a6c"
  },
  "artifacts": {
    "non_stripped": {
      "path": "gt_bin/plain/family_graph_01.O3S.gt.bin",
      "sha256": "2e71...a36"
    },
    "stripped": {
      "path": "bin/plain/family_graph_01.O3S.fixture.bin",
      "sha256": "a90a...248",
      "stripped_from_sha256": "2e71...a36"
    }
  }
}
```

추가로 다음을 기록한다.

- `rustc -vV` 전체 출력
- rustc invoked/resolved path와 sysroot
- compiler binary path
- 실제 compiler flags와 command
- strip path, version, flags, command
- 무작위 `build_id`

Rustc version을 강제로 하나로 제한하지 않는다. 사용한 version을 manifest에 손실 없이 기록한다. 다른 compiler version의 결과를 동시에 보관하려면 canonical V0 경로와 분리된 출력 경로를 사용해야 한다.

`load_and_verify_manifest()`는 hash와 identity뿐 아니라 `edition`, compiler flags,
strip flags가 코드에 정의된 canonical profile과 정확히 같은지도 검사한다.
검증된 `build_id`와 source/non-stripped/stripped SHA-256은 downstream JSON의
`provenance`로 전달된다.

### Canonical V0에서 기록된 환경

현재 checked-in manifest가 기록한 compiler 환경은 다음과 같다.

```text
rustc release : 1.93.1
commit        : 01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf
host          : x86_64-unknown-linux-gnu
target        : x86_64-unknown-linux-gnu
LLVM          : 21.1.8
GNU strip     : 2.42
```

`case`는 direct `rustc`, `subject`는 `cargo build --locked`를 사용한다. Cargo
subject manifest에는 package, selected binary, edition, Cargo.toml/Cargo.lock hash,
owned namespaces, Cargo command와 profile overlay도 기록한다. Cargo source digest는
`Cargo.toml`, `Cargo.lock`, `src/**`, 선택적 `build.rs`, `rust-toolchain*`,
`.cargo/**`만 포함하며 `target/`과 Git metadata는 포함하지 않는다.

## 12. Manifest 검증

`run_case.py`는 분석 전에 `build_manifest.load_and_verify_manifest()`를 호출한다.

다음 값이 맞아야 한다.

```text
manifest case   == 요청 case
manifest build  == 요청 build
manifest profile == 요청 profile
manifest target == x86_64-unknown-linux-gnu
```

그리고 현재 파일을 다시 hash한다.

```text
SHA-256(current source)          == manifest source.sha256
SHA-256(current non-stripped)    == manifest non_stripped.sha256
SHA-256(current stripped)        == manifest stripped.sha256
stripped.stripped_from_sha256    == non_stripped.sha256
```

Source와 binary hash를 서로 비교하는 것이 아니다. 각 파일의 현재 hash를 그 파일에 대해 기록된 hash와 비교한다.

## 13. 실패 시 동작

### Tool이 없음

Case의 `rustc`/`strip`, subject의 `cargo`/`rustc`/`strip` 중 필요한 tool이
없으면 binary를 건드리기 전에 중단한다.

```text
error: rustc executable was not found. Install it before running compile.py.
```

### Rustc 실패

Staging compile이 실패하고 기존 canonical binary는 유지된다.

### Strip 실패

새 non-stripped/stripped/manifest는 아직 최종 경로에 공개되지 않았으므로 기존 세트가 유지된다.

### Source가 compile 도중 변경됨

Compile 전후 source hash가 다르면 새 build를 폐기한다.

### 이후 파일 변조

`run_case.py`의 manifest 검증이 hash mismatch를 발견하고 분석을 거부한다.

## 14. 코드 읽기 순서

`compile.py`만 다음 순서로 읽으면 실제 compilation pipeline을 이해할 수 있다.

1. `main()`
2. `build_arg_parser()`
3. `apply_cli_defaults()`
4. `compile_case()`
5. `compile_flags()`와 `PROFILE_FLAGS`/`BUILD_FLAGS`
6. Case: `compile_gt_binary()`와 `rustc_command()`
7. Subject: `inspect_cargo_subject()`와 `compile_cargo_binary()`
8. `derive_fixture_binary()`
9. `make_build_manifest()`
10. `_publish_file()`

Manifest 검증까지 이해하려면 마지막에 `build_manifest.py`의 `load_and_verify_manifest()`를 읽는다.
