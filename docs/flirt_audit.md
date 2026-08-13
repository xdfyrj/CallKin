# Oxidizer direct-FLIRT audit

이 문서는 CallKin의 Oxidizer 연동이 현재 무엇을 하고, 무엇을 하지 않는지 설명한다.

가장 먼저 고정할 결론은 다음과 같다.

> 현재 FLIRT 파이프라인은 grouping 기능이 아니라 `audit-only` 기능이다.

Oxidizer가 복구한 이름은 아직 candidate scope, anchor role, CG-WL seed, predicted cluster를 바꾸지 않는다. 지금 구현은 stripped binary에서 얻은 direct-FLIRT label을 별도 artifact로 보존하고, non-stripped symbol에서 만든 평가 전용 all-Rust catalog와 비교한다.

이 분리는 의도적이다. FLIRT label 자체의 정확도와 coverage를 확인하기 전에 grouping 입력에 넣으면, 점수 변화가 label 품질 때문인지 call graph 때문인지 구분할 수 없다.

## 이 하위 파이프라인이 답하는 질문

현재 구현은 다음 질문에 답한다.

1. Oxidizer가 stripped ELF에서 direct FLIRT로 몇 개의 함수 이름을 복구했는가?
2. 그 주소 중 CallKin의 function-boundary oracle과 join되는 주소는 몇 개인가?
3. Join된 label이 실제로 `core`, `alloc`, `std` 함수를 식별했는가?
4. 표준 라이브러리라는 큰 분류뿐 아니라 정확한 normalized origin까지 맞혔는가?
5. 같은 all-Rust family 안에 direct-FLIRT로 알려진 instance와 알려지지 않은 instance가 함께 존재하는가?
6. 그런 known/unknown 경계를 가로지르는 same-family pair가 몇 개인가?

현재 구현이 답하지 않는 질문은 다음과 같다.

- FLIRT label을 사용하면 CallKin의 PR/RE/F1이 개선되는가?
- 알려진 `drop_in_place<String>`으로 미식별 `drop_in_place<UserType>`을 자동 명명할 수 있는가?
- FLIRT label을 anchor color로 넣는 것이 좋은가?
- Propagated wrapper나 cleanup heuristic을 신뢰해도 되는가?

이 질문들은 Context view와 Transfer view가 구현된 뒤의 실험 대상이다.

## 전체 구조

세 명령이 하나의 audit를 만든다.

```text
non-stripped ELF
      |
      | nm -n -S -C
      v
all-Rust catalog -------------------------------+
                                                  |
stripped ELF                                      |
      |                                           |
      | separate Oxidizer environment             |
      | CFGFast + rustc detection + FLIRT          |
      v                                           |
probe JSON                                        |
      |                                           |
      | address normalization + raw graph join    |
      v                                           |
Oxidizer label artifact -------------------------+
      |
      | scoring-only comparison
      v
FLIRT audit JSON
```

각 단계의 entry point는 다음과 같다.

| 단계 | Entry point | 주요 입력 | 주요 출력 |
|---|---|---|---|
| 평가 catalog | [all_rust_catalog.py](../all_rust_catalog.py) | non-stripped ELF, manifest | all-Rust catalog |
| FLIRT 실행 | [oxidizer_probe.py](../oxidizer_probe.py) | stripped ELF | 임시 probe JSON |
| 검증과 join | [oxidizer_adapter.py](../oxidizer_adapter.py) | manifest, raw graph, probe | label artifact |
| 정답 비교 | [flirt_audit.py](../flirt_audit.py) | catalog, labels | audit result |

`oxidizer_probe.py`는 사용자가 일반적으로 직접 실행하는 entry point가 아니다. `oxidizer_adapter.py`가 별도 Oxidizer 환경에서 subprocess로 호출하고 결과를 검증한다.

## 가장 짧은 실행

먼저 같은 case/profile/build의 compile과 direct raw graph가 존재해야 한다.

```bash
python3 compile.py billing-client subject --profile plain --build O3S

python3 run_case.py billing-client \
  --profile plain \
  --build O3S \
  --candidate-scope rust-nonstd \
  --track direct \
  --anchor-policy role \
  --mode out-in
```

그다음 audit artifact를 순서대로 만든다.

```bash
python3 all_rust_catalog.py billing-client \
  --profile plain \
  --build O3S

python3 oxidizer_adapter.py billing-client \
  --profile plain \
  --build O3S

python3 flirt_audit.py billing-client \
  --profile plain \
  --build O3S
```

기본 출력 경로는 다음과 같다.

```text
ground_truth/all-rust/plain/billing-client.O3S.catalog.json
labels/oxidizer/plain/billing-client.O3S.labels.json
results/billing-client/plain/billing-client.O3S.flirt_audit.json
```

기본 Oxidizer checkout은 다음 경로다.

```text
/mnt/c/users/sumyr/playground/oxidizer
```

다른 checkout을 쓸 때만 명시한다.

```bash
python3 oxidizer_adapter.py billing-client \
  --profile plain \
  --oxidizer-dir /path/to/oxidizer
```

## 왜 Python 환경을 분리하는가

CallKin과 Oxidizer는 서로 다른 angr 계열을 사용한다.

```text
CallKin process
  |
  | imports CallKin-pinned angr
  |
  +--> subprocess
         |
         | uv run --frozen
         v
      Oxidizer process
         imports Oxidizer's angr fork
```

같은 Python interpreter에 두 환경을 억지로 넣으면 다음 문제가 생긴다.

- CallKin의 간접호출 회귀 결과가 dependency 변경으로 달라질 수 있다.
- Oxidizer가 기대하는 angr API와 CallKin pin이 충돌할 수 있다.
- 어느 angr/cle/pyvex 결과인지 provenance가 불명확해진다.
- Oxidizer 분석 실패가 CallKin process의 import 상태를 오염시킬 수 있다.

[oxidizer_adapter.py](../oxidizer_adapter.py)의 `run_oxidizer_probe()`는 다음 형식으로 probe를 실행한다.

```text
uv run --frozen python <CallKin>/oxidizer_probe.py ...
```

실행 directory는 Oxidizer checkout이다. 따라서 그 repository의 `pyproject.toml`과 `uv.lock`이 적용된다. Adapter는 두 파일이 없거나 `uv` executable을 찾지 못하면 시작 전에 중단한다.

## 1단계: all-Rust catalog

일반 GT는 선택한 candidate scope만 포함한다. 예를 들어 `rust-nonstd`는 `core`, `alloc`, `std`, `__rustc`를 제외한다. 이 GT로는 FLIRT가 표준 라이브러리를 얼마나 맞혔는지 채점할 수 없다.

그래서 [all_rust_catalog.py](../all_rust_catalog.py)는 별도의 scoring-only catalog를 만든다.

### 포함 규칙

[gt_extractor.py](../gt_extractor.py)의 `is_all_rust_catalog_member()`는 다음을 포함한다.

```text
rust_symbol_owner(symbol) is not None
AND
symbol != <root_namespace>::main
```

따라서 다음 owner가 모두 들어갈 수 있다.

```text
core
alloc
std
__rustc
subject crate
dependency crate
```

Source-level Rust `main`은 call-graph root이므로 family catalog에서 제외한다.

### 입력과 검증

`all_rust_catalog.py`는 임의의 non-stripped binary를 조용히 읽지 않는다.

1. case/build/profile에 맞는 build manifest를 읽는다.
2. manifest의 source와 binary pair hash를 검증한다.
3. `--gt-binary` override가 manifest의 non-stripped path와 정확히 같은지 검사한다.
4. 실제 non-stripped SHA-256이 provenance와 같은지 검사한다.
5. `nm -n -S -C`로 text symbol을 읽는다.

즉 catalog는 특정 build provenance에 결속된다.

### Origin normalization

`normalize_all_rust_origin()`은 일반 GT의 frozen normalizer와 별도다.

- Rust hash suffix를 제거한다.
- derive-generated impl identity는 보존한다.
- 표시된 generic argument를 제거한다.
- `drop_in_place<T>`처럼 `::<T>`가 아닌 표기도 처리한다.

예:

```text
core::ptr::drop_in_place<alloc::string::String>
    ->
core::ptr::drop_in_place
```

이는 서로 다른 concrete type instance를 같은 평가 origin으로 묶기 위한 규칙이다.

### Cross-origin shared address

한 주소에 서로 다른 normalized origin symbol이 겹치면 하나를 임의 선택하지 않는다.

```json
{
  "origin": "shared-address@FUN_...",
  "members": ["FUN_..."]
}
```

원래 origin 목록은 `cross_origin_aliases`에 보존한다. 이렇게 해야 function merging이나 ICF 가능성을 숨긴 채 잘못된 exact identity 정답을 만들지 않는다.

### Catalog 핵심 구조

```json
{
  "schema_version": 1,
  "case": "billing-client",
  "build": "O3S",
  "profile": "plain",
  "scope": "all-rust",
  "root_namespace": "reconcile",
  "id_bias": 1048576,
  "provenance": {},
  "source": "gt_bin/plain/billing-client.O3S.gt.bin",
  "origins": [
    {
      "origin": "core::ptr::drop_in_place",
      "members": ["FUN_..."]
    }
  ],
  "symbols": {
    "FUN_...": ["core::ptr::drop_in_place<...>"]
  },
  "owners": {
    "FUN_...": "core"
  },
  "cross_origin_aliases": []
}
```

이 catalog는 candidate selection이 아니다. `users.json`, fixture, engine에 전달되지 않는다.

## 2단계: Oxidizer probe

[oxidizer_probe.py](../oxidizer_probe.py)는 Oxidizer 환경 안에서 실행된다. 입력은 stripped ELF 하나다.

### Project와 CFG

Probe는 다음 project를 만든다.

```python
angr.Project(
    binary,
    auto_load_libs=False,
    is_rust_binary=True,
)
```

그다음 `CFGFast(normalize=True)`를 실행한다.

이 지점은 CallKin의 `angr` extraction track과 다르다.

- CallKin extraction의 angr adapter는 unresolved indirect transfer를 보완한다.
- Oxidizer probe의 angr는 FLIRT와 Rust symbol recovery 기반을 준비한다.
- Oxidizer CFG 결과는 현재 CallKin raw graph로 병합되지 않는다.

### Rustc version과 signature

Probe는 `RustcVersionIdentification()`으로 rustc version과 signature directory를 선택한다. 선택된 version에 대해 최적화 수준 0, 1, 2, 3 signature 파일이 실제로 존재하면 차례로 적용한다.

```text
<detected-rustc>-O0.sig
<detected-rustc>-O1.sig
<detected-rustc>-O2.sig
<detected-rustc>-O3.sig
```

결과 artifact에는 다음 provenance가 기록된다.

- detected rustc version
- version match count
- signature directory와 사용한 signature path
- signature database SHA-256
- Oxidizer Git commit
- `uv.lock` SHA-256
- angr, cle, pyvex, archinfo version과 발견 가능한 Git commit
- probe config SHA-256

Detected version은 build manifest의 실제 rustc version과 같다고 가정하지 않는다. 이 값은 Oxidizer의 추정 결과다.

## 세 evidence 단계를 섞지 않는 이유

Oxidizer의 전체 Rust symbol recovery를 한 번 실행한 뒤 최종 이름만 저장하면, 이름이 어디에서 왔는지 알 수 없다. Probe는 세 시점의 snapshot을 따로 남긴다.

### `direct-flirt`

FLIRT signature를 직접 적용한 직후 `function.from_signature == "flirt"`인 함수다.

현재 audit에서 known seed로 인정할 수 있는 유일한 단계다.

### `propagated-wrapper`

`FlirtSigPropagation` 후 새로 FLIRT label을 받은 함수다. 단순 wrapper caller로 label이 전파될 수 있으므로 direct match와 동일한 신뢰도로 사용하지 않는다.

### `cleanup-heuristic`

`CleanupFunctionIdentification` 후 새로 label을 받은 함수다. 이름 없는 cleanup/nullstub 함수에 drop 관련 label이 붙을 수 있으므로 현재 seed나 anchor 판정에 사용하지 않는다.

Probe는 각 stage를 다음 배열로 분리한다.

```json
{
  "matches": [],
  "propagated_wrappers": [],
  "cleanup_heuristics": []
}
```

여기서 `matches`는 direct FLIRT만 뜻한다.

## 주소 공간 정규화

Oxidizer의 angr/CLE mapped address와 CallKin의 linked virtual address는 같은 숫자가 아닐 수 있다.

Probe는 다음 식으로 주소를 바꾼다.

```text
linked VA
= mapped VA
- main_object.mapped_base
+ main_object.linked_base
```

각 match에는 둘 다 남는다.

```json
{
  "address": "0xlinked",
  "mapped_address": "0xmapped",
  "name": "core::...",
  "canonical_origin": "core::...",
  "owner": "core",
  "evidence": "direct-flirt"
}
```

CallKin artifact join에는 `address`, 즉 linked VA만 사용한다. 이름 문자열로 join하지 않는다.

## 3단계: Adapter 검증과 raw graph join

[oxidizer_adapter.py](../oxidizer_adapter.py)는 두 환경 사이의 계약을 담당한다.

### 시작 전 검증

Adapter는 다음을 확인한다.

1. Manifest의 case/build/profile이 요청과 같다.
2. Manifest가 가리키는 source와 binary hash가 현재 파일과 같다.
3. `--binary`가 manifest의 stripped binary와 정확히 같다.
4. Raw graph의 build provenance가 manifest와 같다.
5. Raw graph의 stripped hash가 manifest와 같다.

이 검증이 끝나야 Oxidizer를 실행하거나 cache를 재사용한다.

### Probe output validation

Probe JSON은 field set까지 엄격하게 검사한다.

- schema version
- case/build/profile
- stripped SHA-256
- `analysis.input == "stripped-only"`
- 세 evidence 배열
- address와 mapped address 형식
- evidence stage 이름
- stage 내부 duplicate address

Probe가 일부 field를 빠뜨리거나 예상하지 않은 field를 추가해도 거부한다.

### Raw graph와 join

CallKin raw graph의 `functions[].address` 집합을 known function address로 사용한다.

```text
Oxidizer linked address in raw.functions
    -> joined label

Oxidizer linked address not in raw.functions
    -> unmatched_addresses
```

Join되지 않은 match를 조용히 버리지 않는 이유는 두 가지다.

- Oxidizer function discovery와 CallKin boundary oracle 차이를 측정할 수 있다.
- Raw graph boundary가 나중에 바뀌어도 같은 stripped-binary evidence를 다시 join할 수 있다.

Label artifact의 `matches`에는 raw graph와 join된 direct-FLIRT match만 들어간다. Propagation과 cleanup 결과는 각각 별도 배열에 남는다.

### CallKin normalization 재적용

Probe가 만든 name/origin/owner를 그대로 신뢰하지 않는다. Adapter는 full name을 입력으로 CallKin의 다음 함수를 다시 적용한다.

- `normalize_all_rust_origin()`
- `rust_symbol_owner()`

이렇게 catalog와 label이 같은 normalization 규칙으로 비교된다.

## Cache

Oxidizer 분석은 binary마다 한 번만 수행한다.

기존 label artifact가 있고 `--force`가 없으면 adapter는 다음 identity를 검사한다.

```text
case
build
profile
full BuildProvenance
```

모두 같으면 기존 artifact에서 probe evidence를 복원해 현재 raw graph에 다시 join한다. Joined와 unmatched evidence를 모두 저장했기 때문에 가능한 동작이다.

Identity가 다르면 stale cache를 덮어쓰지 않고 실패한다. 의도적으로 다시 실행하려면 `--force`를 사용한다.

```bash
python3 oxidizer_adapter.py billing-client \
  --profile plain \
  --build O3S \
  --force
```

### Label artifact 핵심 구조

```json
{
  "schema_version": 1,
  "case": "billing-client",
  "build": "O3S",
  "profile": "plain",
  "provenance": {},
  "stripped_sha256": "...",
  "raw_graph_sha256": "...",
  "analysis": {
    "input": "stripped-only",
    "address_space": "ELF linked virtual address",
    "boundary_oracle": "CallKin raw graph symbol-boundary oracle",
    "seed_policy": "direct-flirt-only"
  },
  "tool": {},
  "execution": {
    "timeout_seconds": 900,
    "memory_limit_mb": null,
    "cache_reused": false
  },
  "matches": [],
  "propagated_wrappers": [],
  "cleanup_heuristics": [],
  "unmatched_addresses": []
}
```

여기서 `analysis.input`은 FLIRT name recovery가 stripped binary를 입력으로 했다는 뜻이다. 전체 audit가 stripped-only라는 뜻은 아니다. Function address join에는 non-stripped symbol에서 유도된 CallKin raw boundary oracle을 사용하고, 정답 비교에는 all-Rust catalog를 사용한다.

## 4단계: FLIRT audit

[flirt_audit.py](../flirt_audit.py)는 label artifact와 all-Rust catalog를 결합한다. 이 단계만 정답 origin과 owner를 본다.

### Join 조건

다음 identity가 하나라도 다르면 중단한다.

```text
case
build
profile
full BuildProvenance
stripped SHA-256
```

주소를 member ID로 바꿀 때 catalog의 `id_bias`를 사용한다.

```text
FUN_<linked address + id_bias>
```

이 member가 catalog에 실제로 존재할 때만 catalog join으로 센다.

## Count 세 단계

비슷해 보이지만 다음 count는 서로 다르다.

### `raw_graph_joined_match_count`

```text
len(labels.matches)
```

Direct-FLIRT 주소가 CallKin raw graph의 known function과 join된 수다.

### `catalog_joined_match_count`

Raw graph에 join된 direct-FLIRT label 중 all-Rust catalog member까지 join된 수다.

Source root나 catalog membership 규칙 밖 함수는 raw graph에는 있어도 catalog에는 없을 수 있다.

### `catalog_unmatched_count`

```text
raw_graph_joined_match_count
- catalog_joined_match_count
```

### `unmatched_address_count`

Oxidizer가 label을 만들었지만 CallKin raw function address와 join되지 않은 direct-FLIRT 주소 수다.

이 네 수를 합치거나 같은 의미로 부르면 안 된다.

## Standard-library classification

현재 standard-library seed owner 집합은 정확히 다음 세 개다.

```text
core
alloc
std
```

`__rustc`는 일반 `rust-nonstd` candidate scope에서는 제외되는 namespace지만, FLIRT audit의 standard-library positive 정의에는 현재 포함되지 않는다.

각 all-Rust catalog member에 대해 다음을 비교한다.

```text
predicted standard
= direct-FLIRT match가 있고 predicted owner가 core/alloc/std

actual standard
= catalog owner가 core/alloc/std
```

그 결과로 TP, FP, FN, TN과 classification precision/recall을 계산한다.

이 지표는 “표준 라이브러리인지 맞혔는가?”만 본다. 실제 `std::A`를 `std::B`로 잘못 이름 붙여도 standard classification은 TP일 수 있다.

## Exact identity

정확한 함수 family label 평가는 별도다.

```text
correct identity
= predicted canonical_origin == catalog origin
AND
predicted owner == catalog owner
```

출력:

- matched member count
- correct/incorrect match count
- exact-identity precision
- 전체 catalog member 대비 correct identity coverage
- 각 incorrect label의 member, predicted/catalog origin, predicted/catalog owner

따라서 다음 두 문장은 서로 다르다.

```text
이 함수는 std라고 올바르게 분류했다.
이 함수의 정확한 normalized origin까지 올바르게 복구했다.
```

## Known/unknown mixed family

향후 Transfer view의 가능성을 측정하기 위해 같은 family 내부를 나눈다.

```text
known
= catalog member에 direct-FLIRT match가 있음
AND predicted owner in {core, alloc, std}

unknown
= 같은 family의 나머지 member
```

Known과 unknown이 모두 있는 family만 mixed family table에 들어간다.

Family 하나의 cross-boundary same-family pair 수는 다음과 같다.

```text
K = known direct-FLIRT instance count
U = unknown instance count

cross-boundary same-family pairs = K * U
```

예:

```text
drop_in_place family
known = 2
unknown = 3

known-unknown true pairs = 2 * 3 = 6
```

Hard anchor 방식으로 known member를 grouping 대상에서 제거하면 이 여섯 pair의 연결 가능성이 처음부터 사라진다. Audit는 그 잠재 손실의 크기를 보여 주지만, 아직 unknown에 label을 전파하지 않는다.

`drop_in_place` 문자열을 origin에 포함한 mixed family는 `drop_in_place_families`에 별도로 복사해 검토하기 쉽게 만든다.

## Audit result 핵심 구조

```json
{
  "schema_version": 2,
  "case": "billing-client",
  "build": "O3S",
  "profile": "plain",
  "provenance": {},
  "all_rust_catalog_sha256": "...",
  "oxidizer_labels_sha256": "...",
  "direct_flirt": {
    "raw_graph_joined_match_count": 0,
    "catalog_joined_match_count": 0,
    "catalog_unmatched_count": 0,
    "unmatched_address_count": 0,
    "std_classification": {},
    "exact_identity": {}
  },
  "mixed_families": {
    "family_count": 0,
    "cross_boundary_same_family_pair_count": 0,
    "families": []
  },
  "drop_in_place_families": []
}
```

Catalog와 labels의 canonical JSON SHA-256을 둘 다 저장하므로 audit가 정확히 어느 두 입력에서 나왔는지 확인할 수 있다.

## `audit-only`의 정확한 의미

현재 grouping pipeline과 FLIRT pipeline의 관계는 다음과 같다.

```text
raw call graph + candidate selection
              |
              v
           fixture
              |
              v
            CG-WL

Oxidizer labels + all-Rust catalog
              |
              v
          FLIRT audit
```

두 흐름은 build provenance와 function address를 공유하지만, 현재 graph 구성 단계에서는 만나지 않는다.

구체적으로 아직 하지 않는 동작:

- `--candidate-scope flirt`는 없다.
- direct-FLIRT match를 자동 anchor로 바꾸지 않는다.
- known label을 anchor `color_class`로 사용하지 않는다.
- direct-FLIRT 여부를 user seed color에 넣지 않는다.
- known member와 unknown member를 같은 structural cluster에서 찾아 label을 전파하지 않는다.
- propagated wrapper나 cleanup heuristic을 grouping에 사용하지 않는다.
- Oxidizer CFG edge를 CallKin raw graph에 넣지 않는다.

따라서 현재 CallKin candidate scope는 여전히 `subject`와 `rust-nonstd` 두 가지다.

## 향후 Context view와 Transfer view

아래는 현재 코드가 아니라 다음 단계의 설계 경계다.

### Context view

목표:

```text
direct-FLIRT로 알려진 std function을 안정된 context label로 사용
unknown candidate끼리 grouping
```

Known std 함수가 일반 candidate의 caller/callee 문맥을 구분하게 만들 수 있다. 하지만 known std instance와 unknown std instance를 같은 cluster로 묶는 목적에는 맞지 않는다.

### Transfer view

목표:

```text
known seed와 unknown function을 identity-neutral하게 구조 비교
```

해석 규칙의 예:

- cluster 안 direct seed origin이 하나면 unknown에 family 후보를 부여한다.
- seed origin이 둘 이상이면 ambiguous로 남긴다.
- seed가 없으면 이름 없는 structural family로 남긴다.

Context와 Transfer는 목표가 충돌하므로 하나의 seed policy로 합치지 않는 편이 안전하다.

구현 전에는 이 문서의 audit 지표를 먼저 보고 다음을 확인해야 한다.

- direct-FLIRT match가 충분한가?
- std classification FP가 허용 가능한가?
- exact identity 오분류가 특정 family에 집중되는가?
- mixed family와 cross-boundary pair가 실제로 존재하는가?
- raw/candidate boundary join 손실이 큰가?

## CLI option

### `all_rust_catalog.py`

| Option | 의미 |
|---|---|
| `stem` | case와 선택적 build suffix |
| `--build` | build label, 기본 `O3S` |
| `--profile` | `plain` 또는 `min` |
| `--manifest` | canonical manifest path override |
| `--gt-binary` | manifest와 같은 non-stripped binary만 허용 |
| `--output` | catalog 출력 path override |
| `--nm` | nm-compatible executable |

### `oxidizer_adapter.py`

| Option | 의미 |
|---|---|
| `stem` | case와 선택적 build suffix |
| `--build` | build label |
| `--profile` | `plain` 또는 `min` |
| `--manifest` | verified manifest override |
| `--binary` | manifest와 같은 stripped binary만 허용 |
| `--raw-graph` | label 주소를 join할 direct raw graph |
| `--output` | label artifact path override |
| `--force` | matching cache가 있어도 Oxidizer 재실행 |
| `--oxidizer-dir` | 별도 Oxidizer checkout |
| `--timeout` | subprocess timeout seconds, 기본 900 |

Adapter 기본 raw graph는 direct evidence 경로다. Angr-augmented raw를 사용하려면 `--raw-graph`로 명시해야 하지만, FLIRT audit의 기본 boundary join에는 direct raw면 충분하다.

### `flirt_audit.py`

| Option | 의미 |
|---|---|
| `stem` | case와 선택적 build suffix |
| `--build` | build label |
| `--profile` | `plain` 또는 `min` |
| `--catalog` | all-Rust catalog override |
| `--labels` | Oxidizer label artifact override |
| `--output` | audit result path override |

## 실패를 조사하는 순서

### Oxidizer가 실행되지 않을 때

1. `uv`가 PATH에 있는지 확인한다.
2. Oxidizer checkout에 `pyproject.toml`과 `uv.lock`이 있는지 확인한다.
3. `--oxidizer-dir`가 올바른지 확인한다.
4. Adapter가 출력한 subprocess stderr 마지막 부분을 확인한다.
5. Timeout이면 `--timeout`을 늘리기 전에 binary size와 이전 실행 시간을 확인한다.

### Cache가 다른 build라고 할 때

1. Label artifact의 `provenance`를 본다.
2. 현재 manifest의 `build_id`와 세 SHA-256을 비교한다.
3. Source나 binary가 재생성되었다면 기존 label은 stale이다.
4. 새 build에 대해 `--force`로 다시 실행한다.

다른 provenance의 cache를 JSON에서 수동 수정해 재사용하면 안 된다.

### `unmatched_addresses`가 많을 때

1. Probe의 `mapped_address`와 normalized linked `address`를 확인한다.
2. ELF linked/mapped base 계산이 맞는지 확인한다.
3. Raw graph `functions[].address`에 target이 있는지 확인한다.
4. Boundaries artifact가 같은 build인지 확인한다.
5. Oxidizer가 발견한 함수가 symbol-boundary oracle에는 없는 경우인지 구분한다.

이 수치는 FLIRT 오분류와 function discovery 차이를 섞지 않기 위해 별도로 유지한다.

### Raw join은 되는데 catalog join이 안 될 때

1. 함수가 source root `main`인지 확인한다.
2. `rust_symbol_owner()`가 owner를 찾을 수 없는 symbol인지 확인한다.
3. Catalog와 label의 `id_bias` 기반 member ID를 계산한다.
4. `catalog_unmatched_count`와 `unmatched_address_count`를 혼동하지 않는다.

### Std classification은 높은데 exact identity가 낮을 때

이는 “library ownership 판정은 맞지만 구체적인 family name이 틀린” 상태다.

다음 순서로 본다.

1. `exact_identity.incorrect_labels`
2. predicted/catalog canonical origin
3. predicted/catalog owner
4. generic argument normalization 차이
5. propagated/cleanup label이 direct 배열에 잘못 섞였는지

## 구현을 읽는 순서

전체 흐름을 이해하려면 다음 순서가 가장 짧다.

1. [all_rust_catalog.py](../all_rust_catalog.py)의 `main()`
2. [gt_extractor.py](../gt_extractor.py)의 `make_all_rust_catalog()`
3. [oxidizer_adapter.py](../oxidizer_adapter.py)의 `main()`
4. `run_oxidizer_probe()`
5. [oxidizer_probe.py](../oxidizer_probe.py)의 `run_probe()`
6. [oxidizer_adapter.py](../oxidizer_adapter.py)의 `build_label_artifact()`
7. [flirt_audit.py](../flirt_audit.py)의 `build_flirt_audit()`
8. [paths.py](../paths.py)의 세 artifact path 함수

Schema validation을 바꿀 때는 다음 함수도 함께 읽는다.

- `validate_all_rust_catalog()`
- `validate_probe_output()`
- `validate_label_artifact()`
- `all_rust_catalog_sha256()`

## 변경 시 최소 테스트

관련 테스트는 다음과 같다.

- [test_all_rust_catalog.py](../tests/test_all_rust_catalog.py)
- [test_oxidizer_adapter.py](../tests/test_oxidizer_adapter.py)
- [test_flirt_audit.py](../tests/test_flirt_audit.py)

수정 종류별 최소 검증:

| 변경 | 반드시 확인할 것 |
|---|---|
| origin normalization | all-Rust origin과 exact identity expected value |
| owner 판정 | std classification TP/FP/FN/TN |
| address normalization | mapped/linked join과 unmatched 보존 |
| evidence stage | direct/propagated/cleanup 비혼합 |
| cache | same provenance 재사용, different provenance 거부 |
| catalog schema | alias와 owner/member key 일치 |
| audit count | raw join, catalog join, 두 unmatched count 분리 |
| known seed 정의 | direct FLIRT + predicted std owner만 known |

전체 회귀는 다음으로 실행한다.

```bash
python3 tests/run_all.py
```

실제 Oxidizer checkout과 대형 binary를 쓰는 통합 실행은 unit test보다 오래 걸릴 수 있다. Unit test 통과와 실제 label 품질 검증은 같은 것이 아니다.

## 현재 한계

- FLIRT name recovery 입력은 stripped ELF지만 function join은 non-stripped symbol-boundary oracle에 의존한다.
- All-Rust catalog는 최종 binary에서 관찰되는 symbol만 다룬다. Source-level mono-item survival truth가 아니다.
- Rustc version detection과 signature DB coverage가 compiler patch version까지 완전히 맞는다는 보장은 없다.
- Direct FLIRT match라고 해서 exact origin이 항상 맞는 것은 아니다. Audit가 이를 별도로 측정한다.
- Propagated wrapper와 cleanup heuristic은 저장하지만 현재 신뢰 seed가 아니다.
- Oxidizer의 decompiler, enum/macro/Result/Option 복구는 사용하지 않는다.
- Oxidizer CFG는 CallKin indirect-call graph에 사용하지 않는다.
- FLIRT label은 현재 candidate/anchor/abstain 분류와 CG-WL color에 영향을 주지 않는다.
- Context view와 known-to-unknown Transfer view는 아직 구현되지 않았다.
- `__rustc`는 rust-nonstd scope에서는 제외되지만 현재 std classification positive set에는 없다.

이 경계를 유지하면 FLIRT 자체의 식별 품질, call-graph extraction 품질, CG-WL grouping 품질을 서로 독립적으로 해석할 수 있다.
