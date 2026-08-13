# Artifact와 provenance

CallKin은 하나의 분석 결과를 여러 파일로 나눈다. 파일 수를 줄이는 것보다 **어떤 정보가 어느 신뢰 경계에서 왔는지 증명하는 것**이 더 중요하기 때문이다.

이 문서는 case/build/profile/scope/track이 경로에 반영되는 방식, 각 JSON의 책임, join 규칙, stale artifact 판별법, 변경 후 재생성 범위를 정의한다.

## Artifact chain

한 case의 표준 dependency graph는 다음과 같다.

```text
source
  |
  v
build manifest -----------+
  |                       |
  +--> non-stripped ELF --+--> GT
  |                       +--> users
  |                       +--> boundaries
  |
  +--> stripped ELF ------+--> direct raw graph
                          +--> angr-augmented raw graph
                                      |
users + raw + projection policy ------+--> fixture
                                             |
GT + fixture + CG-WL mode ------------------> result

non-stripped ELF ---------------------------> all-Rust catalog
stripped ELF + direct raw ------------------> Oxidizer labels
all-Rust catalog + Oxidizer labels --------> FLIRT audit result
```

화살표의 앞 파일이 바뀌면 뒤 artifact는 stale일 수 있다. 반대 방향은 아니다. 예를 들어 CG-WL mode를 바꾸어도 fixture를 다시 만들 필요는 없다.

## 이름을 구성하는 차원

| 차원 | 현재 값 | 기본값 | 의미 |
|---|---|---|---|
| case | `family_graph_01`, `billing-client`, `fd` | 없음 | 분석 단위의 안정된 이름 |
| build | `O3S`, `O3KS` | `O3S` | `cfg(keep)` 적용 여부 |
| profile | `plain`, `min` | `plain` | compiler codegen 조건 |
| candidate scope | `subject`, `rust-nonstd` | `rust-nonstd` | target universe |
| track | `direct`, `direct-in`, `angr` | `direct` | evidence projection |
| anchor policy | `address`, `role` | `address` | anchor 초기 identity |
| mode | `full`, `out`, `in`, `out-in` | `full` | CG-WL relation signature |

`<stem>`은 `<case>.<build>`다. 예를 들어 `billing-client.O3S`다.

## Canonical path grammar

### Build artifacts

```text
gt_bin/<profile>/<stem>.gt.bin
bin/<profile>/<stem>.fixture.bin
build_info/<profile>/<stem>.json
```

### Truth-side artifacts

```text
ground_truth/[rust-nonstd/]<profile>/<stem>.gt.json
users/[rust-nonstd/]<profile>/<stem>.users.json
boundaries/<profile>/<stem>.boundaries.json
```

대괄호 부분은 `rust-nonstd` scope에서만 존재한다. `subject`는 compatibility 경로라 scope directory를 생략한다. Boundaries는 scope-independent이므로 항상 scope directory가 없다.

### Evidence artifacts

```text
extractions/<profile>/<stem>.raw.json
extractions/angr/<profile>/<stem>.raw.json
```

첫 경로는 direct static evidence다. 둘째 경로는 같은 static evidence에 angr 결과를 결합한 raw graph다. `direct-in`은 projection 차이이므로 별도 raw graph가 아니다.

### Fixture artifacts

경로 조립 순서는 고정이다.

```text
fixtures/
  [<track>/]
  [<anchor-policy>/]
  [rust-nonstd/]
  <profile>/
  <stem>.fixture.json
```

기본값은 경로에서 생략한다.

```text
track=direct        -> directory 없음
anchor=address      -> directory 없음
scope=subject       -> directory 없음
```

예:

```text
fixtures/plain/family_graph_01.O3S.fixture.json
fixtures/direct-in/role/rust-nonstd/plain/billing-client.O3S.fixture.json
fixtures/angr/role/rust-nonstd/min/fd.O3S.fixture.json
```

### Result artifacts

```text
results/<case>/<profile>/<name>.json
results/micro-corpus/<profile>/baseline.json
results/micro-corpus/<profile>/all_modes.json
```

예:

```text
results/billing-client/plain/angr.role.out-in.json
results/fd/min/direct-in.role.out-in.json
```

### FLIRT audit artifacts

```text
ground_truth/all-rust/<profile>/<stem>.catalog.json
labels/oxidizer/<profile>/<stem>.labels.json
results/<case>/<profile>/<stem>.flirt_audit.json
```

세 경로는 각각 평가 catalog, stripped-binary label evidence, 둘의 비교 결과다. 이들은 현재 fixture나 CG-WL result의 dependency가 아니다. 전체 의미는 [Oxidizer direct-FLIRT audit](flirt_audit.md)에 정의한다.

경로 생성의 단일 기준은 [paths.py](../paths.py)다. 새 축을 추가할 때 각 CLI에서 문자열을 직접 조립하지 않는다.

## 두 종류의 provenance

### Build provenance

[provenance.py](../provenance.py)의 `BuildProvenance`는 정확히 네 필드다.

```json
{
  "build_id": "one-build-identity",
  "source_sha256": "64 hex characters",
  "non_stripped_sha256": "64 hex characters",
  "stripped_sha256": "64 hex characters"
}
```

이 값은 “이 downstream artifact들이 같은 source와 같은 binary pair에서 나왔는가?”에 답한다. `build_id`는 compile 실행마다 새로 생긴다. Byte-identical binary가 다시 나와도 별도 실행이면 build ID가 다르다.

### Analysis provenance

[analysis_provenance.py](../analysis_provenance.py)의 `AnalysisProvenance`는 fixture가 어떻게 만들어졌는지 설명한다.

```json
{
  "track": "angr",
  "candidate_scope": "rust-nonstd",
  "backend": "radare2-capstone+angr",
  "extractor_version": "call-evidence-v6+angr-...",
  "raw_graph_sha256": "...",
  "candidate_selection_sha256": "...",
  "projection_config_sha256": "...",
  "anchor_policy": "role",
  "edge_policy": [
    "direct-immediate",
    "direct-tail",
    "elf-relocation",
    "angr-cfg"
  ],
  "oracle_level": "candidate-and-boundary"
}
```

이 값은 “같은 binary에서 어떤 evidence와 projection 정책으로 fixture를 만들었는가?”에 답한다. Extractor version을 build provenance에 넣으면 같은 binary에 두 분석기를 적용한 것이 서로 다른 build처럼 보이므로 두 provenance를 합치지 않는다.

## Build manifest

경로:

```text
build_info/<profile>/<stem>.json
```

현재 schema는 v3이다.

| 필드 | 의미 |
|---|---|
| `build_id` | compile 실행 identity |
| `case/build/profile/target` | build 좌표 |
| `source.kind` | `case` 또는 `subject` |
| `source.path/sha256` | 입력과 content hash |
| `compiler.*` | rustc path, sysroot, `-vV`, flags, command |
| `cargo.*` | Cargo subject의 package/bin/namespace/build 정보 |
| `strip.*` | strip path, version, flags, command |
| `artifacts.non_stripped` | GT binary path와 hash |
| `artifacts.stripped` | fixture binary path, hash, 원본 hash |

세 hash는 서로 같음을 검사하지 않는다.

```text
SHA-256(현재 source)        == manifest.source.sha256
SHA-256(현재 GT binary)     == manifest.artifacts.non_stripped.sha256
SHA-256(현재 fixture binary)== manifest.artifacts.stripped.sha256
```

`stripped_from_sha256`은 non-stripped hash를 가리켜 pair 관계를 표현한다. [build_manifest.py](../build_manifest.py)의 `load_and_verify_manifest()`는 case/build/profile/target, source, binary, canonical flags, Cargo input이 하나라도 다르면 중단한다.

## Ground truth

경로:

```text
ground_truth/[rust-nonstd/]<profile>/<stem>.gt.json
```

핵심 구조:

```json
{
  "schema_version": 6,
  "provenance": {},
  "origins": [
    {
      "origin": "billing_client::decode",
      "members": ["FUN_..."]
    }
  ],
  "symbols": {
    "FUN_...": "billing_client::decode::<Invoice>"
  },
  "cross_origin_aliases": []
}
```

`symbols`와 `origins`는 채점 전용이다. Fixture나 engine으로 전달하지 않는다. Schema v6는 한 주소가 여러 normalized origin에 속하는 cross-origin alias를 보존한다. Shared address가 없으면 extractor가 schema v5를 쓸 수 있으며 scorer는 둘 다 읽는다.

## Candidate selection

경로:

```text
users/[rust-nonstd/]<profile>/<stem>.users.json
```

이름은 역사적으로 `users`지만 현재 의미는 candidate selection이다.

```json
{
  "scope": "rust-nonstd",
  "root_namespace": "reconcile",
  "namespaces": ["billing_client", "reconcile"],
  "excluded_namespaces": ["core", "alloc", "std", "__rustc"],
  "addresses": ["0x..."],
  "function_bounds": [
    {"address": "0x...", "size": 144}
  ],
  "provenance": {}
}
```

Origin과 concrete type은 없다. [candidate_selection.py](../candidate_selection.py)는 strict validation 후 canonical JSON SHA-256을 계산하고, fixture가 그 hash를 기록한다.

## Function boundaries

경로:

```text
boundaries/<profile>/<stem>.boundaries.json
```

Candidate scope와 무관한 symbol boundary oracle이다.

```json
{
  "function_bounds": [
    {"address": "0x...", "size": 144}
  ]
}
```

Demangle 가능한 전체 Rust text function과 root 탐지에 필요한 startup boundary가 들어간다. 이름과 origin은 전달하지 않는다.

중요한 해석은 다음과 같다.

> Angr track도 완전히 stripped-only function discovery가 아니다. `CFGFast(function_starts=...)`에 이 artifact의 시작점들이 rebasing되어 전달된다.

## Raw graph

경로:

```text
extractions/<profile>/<stem>.raw.json
extractions/angr/<profile>/<stem>.raw.json
```

현재 JSON 구조 schema는 v5이고 추출 의미는 `analysis.extractor_version=call-evidence-v6...`로 구분한다.

- `schema_version`: JSON field 구조가 바뀌었는가?
- `extractor_version`: 같은 구조 안에서 transfer 해석 의미가 바뀌었는가?

핵심 필드:

| 필드 | 의미 |
|---|---|
| `root` | 선택된 Rust root linked address |
| `functions` | address, size, boundary source, r2 discovery 여부 |
| `transfers` | callsite 단위 evidence |
| `boundary_mismatches` | symbol과 r2 boundary 차이 |
| `indirect_call_summary` | angr 처리 결과 집계 |
| `oracle_level` | boundary oracle 조건 |

Transfer 하나는 다음처럼 evidence와 판단을 분리한다.

```json
{
  "source": "0x...",
  "callsite": "0x...",
  "instruction": "jmp qword ptr [rip + ...]",
  "kind": "tail-call",
  "operand_kind": "memory",
  "status": "resolved",
  "target": "0x...",
  "resolver": "elf-relocation",
  "confidence": "exact",
  "filter_reason": null,
  "angr_status": "not_applicable",
  "angr_targets": [],
  "angr_target_names": {}
}
```

Status:

- `resolved`: graph target으로 사용할 수 있다.
- `unresolved`: indirect transfer는 보았지만 target을 결정하지 못했다.
- `unmapped`: target address는 정확하지만 known function start와 join되지 않는다.
- `filtered`: target은 해결했지만 import 등 정책상 graph에서 제외한다.

Raw graph에는 candidate 목록, candidate scope, anchor policy가 없어야 한다. 동일 evidence를 여러 projection에서 재사용하기 위해서다.

## Fixture

Schema v6의 핵심 구조:

```json
{
  "schema_version": 6,
  "provenance": {},
  "analysis": {},
  "nodes": [
    {
      "id": "FUN_...",
      "type": "user",
      "scored": true,
      "anchor_kind": null,
      "color_class": null,
      "observability": {
        "resolved_out_calls": 2,
        "unresolved_indirect_out_callsites": 1,
        "address_taken_references": null,
        "resolved_in_callers": 3
      },
      "calls": [
        {"target": "FUN_...", "count": 2}
      ]
    }
  ],
  "abstentions": [
    {
      "id": "FUN_...",
      "status": "abstain",
      "reason": "no_resolved_nonself_in_or_out_edge"
    }
  ]
}
```

계약:

- `user`: `scored=true`, `anchor_kind/color_class=null`
- `anchor`: `scored=false`, `anchor_kind/color_class` 필수
- abstain: `nodes`에 없고 `abstentions`에만 존재
- anchor의 `calls`는 비어 있을 필요가 없다.
- origin, GT members, concrete type 정답은 허용되지 않는다.

### Frozen schema v4 compatibility

`subject + direct + address` 조합은 controlled micro-corpus 회귀를 위해 schema v4 compatibility projector를 사용한다.

- resolver는 `direct-immediate`, `direct-tail`만 사용한다.
- historical context selection을 보존한다.
- abstention 없는 기존 fixture shape을 유지한다.

Schema 번호만 4로 두고 새로운 relocation/abstain 의미를 넣으면 안 된다.

## Result

일반 결과는 다음 top-level 구조다.

```json
{
  "schema_version": 6,
  "run_summary": {},
  "results": [
    {
      "case": "billing-client",
      "mode": "out-in",
      "rounds": 4,
      "clusters": [],
      "origins": [],
      "pairwise": {}
    }
  ]
}
```

`--all-modes`이면 `results`에 네 mode가 들어간다. `run_summary`는 mode-independent extraction, GT, runtime facts이므로 한 번만 저장한다. 수치 의미는 [채점과 결과](scoring.md)에 정의한다.

## All-Rust catalog

경로:

```text
ground_truth/all-rust/<profile>/<stem>.catalog.json
```

일반 candidate GT와 달리 observable Rust-owned text symbol 전체를 포함하되 source root `main`은 제외한다. `origins`, `symbols`, `owners`, `cross_origin_aliases`, `id_bias`, build provenance를 저장한다.

이 파일은 direct-FLIRT label의 owner와 exact origin을 채점하기 위한 oracle이다. Candidate selection이나 fixture projection에 사용하면 GT leakage가 된다.

## Oxidizer labels

경로:

```text
labels/oxidizer/<profile>/<stem>.labels.json
```

Stripped binary를 별도 Oxidizer 환경에서 분석한 뒤 CallKin direct raw graph의 function address와 join한 artifact다.

핵심 계약:

- `provenance`와 `stripped_sha256`은 manifest와 일치한다.
- `raw_graph_sha256`은 join에 사용한 direct raw를 특정한다.
- `matches`는 direct FLIRT만 포함한다.
- propagated wrapper와 cleanup heuristic은 별도 배열에 남는다.
- raw function과 join되지 않은 주소는 `unmatched_addresses`에 보존한다.
- 현재 `seed_policy`는 `direct-flirt-only`지만 grouping seed를 뜻하지 않는다. Audit에서 known label로 인정하는 evidence 범위를 뜻한다.

## FLIRT audit result

경로:

```text
results/<case>/<profile>/<stem>.flirt_audit.json
```

이 파일은 all-Rust catalog와 Oxidizer labels의 build identity를 확인한 뒤 다음을 저장한다.

- raw graph joined match 수
- catalog joined/unmatched match 수
- standard-library classification TP/FP/FN/TN과 PR/RE
- exact origin identity precision과 catalog coverage
- direct-FLIRT known member와 unknown member가 섞인 family
- known/unknown 경계의 same-family pair 수

`all_rust_catalog_sha256`과 `oxidizer_labels_sha256`으로 두 입력을 고정한다. 이 결과는 일반 CG-WL score result와 schema와 의미가 다르다.

## 엄격한 join rules

### Manifest와 파일

`run_case.py`는 분석 전에 manifest를 검증한다. Override path를 주더라도 manifest가 기록한 binary와 다르면 거부한다.

### Raw와 users

Projector는 다음을 확인한다.

- case/build/profile
- build provenance
- candidate address가 raw function universe에 존재
- candidate마다 symbol extent 존재

그리고 candidate selection hash를 fixture에 기록한다.

### Fixture와 GT

Scorer는 다음을 확인한다.

- case/build/profile
- build provenance
- 모든 GT member에 symbol 존재
- schema v6: `GT members = scored nodes ∪ abstentions`
- legacy: `GT members = scored nodes`

주소가 우연히 같아도 서로 다른 build artifact를 결합할 수 없다.

### FLIRT catalog와 labels

Audit는 다음을 확인한다.

- case/build/profile
- full build provenance
- stripped SHA-256
- label address를 `id_bias`로 바꾼 member가 catalog에 실제로 존재하는지

Raw graph와 join되지 않은 label, raw에는 있지만 catalog에 없는 label을 서로 다른 count로 남긴다.

## Stale artifact를 찾는 순서

1. Manifest를 현재 source와 binary에 대해 검증한다.
2. GT/users/boundaries의 build provenance를 비교한다.
3. Raw의 stripped hash를 manifest와 비교한다.
4. Fixture의 raw, candidate selection, projection config hash를 확인한다.
5. Result의 provenance/analysis를 fixture와 비교한다.
6. Stored result와 현재 `scores.py` 재채점을 비교한다.
7. FLIRT audit이면 labels의 raw hash와 catalog/labels input hash를 추가로 비교한다.

JSON을 수동으로 고쳐 hash만 맞추지 않는다. 해당 producer로 다시 생성한다.

## 변경 영향표

| 변경 | 처음 다시 생성할 artifact | 이후 영향 |
|---|---|---|
| Rust source, compiler, profile, build flag | compile | 전부 |
| GT origin normalization | GT | GT, result |
| candidate scope rule | GT/users | GT, users, fixture, result |
| boundary selection | boundaries | raw, fixture, result |
| root detector | raw | raw, fixture, result |
| direct/relocation extractor | raw | direct raw, angr raw, fixture, result |
| angr merge policy | angr raw | angr fixture/result |
| projection/anchor/abstain policy | fixture | fixture, result |
| CG-WL signature/mode | 없음 | result |
| scoring formula | 없음 | result |
| all-Rust normalization/owner rule | all-Rust catalog | catalog, FLIRT audit |
| Oxidizer checkout/signature/probe policy | Oxidizer labels | labels, FLIRT audit |
| FLIRT audit metric/known-seed rule | 없음 | FLIRT audit |
| CLI formatting only | 없음 | 의미가 같으면 artifact 유지 |

Extractor semantics를 바꾸면 `RAW_GRAPH_EXTRACTOR_VERSION`을 검토한다. Field set을 바꾸면 schema version을 올린다.

## Test map

| 계약 | 주 테스트 |
|---|---|
| build, manifest, Cargo | [test_compile.py](../tests/test_compile.py) |
| origin, scope, users, aliases | [test_gt_extractor.py](../tests/test_gt_extractor.py) |
| all-Rust catalog | [test_all_rust_catalog.py](../tests/test_all_rust_catalog.py) |
| root, boundary, transfer evidence | [test_binary_extractor.py](../tests/test_binary_extractor.py) |
| projection, anchors, abstain, opaque target | [test_graph_projector.py](../tests/test_graph_projector.py) |
| angr classification/merge | [test_angr_adapter.py](../tests/test_angr_adapter.py) |
| actual angr execution | [test_angr_integration.py](../tests/test_angr_integration.py) |
| CG-WL | [test_engine.py](../tests/test_engine.py) |
| join, metrics, frozen results | [test_scores.py](../tests/test_scores.py) |
| result diagnostics | [test_run_summary.py](../tests/test_run_summary.py) |
| Oxidizer audit | [test_oxidizer_adapter.py](../tests/test_oxidizer_adapter.py), [test_flirt_audit.py](../tests/test_flirt_audit.py) |

전체 회귀:

```bash
python3 tests/run_all.py
```
