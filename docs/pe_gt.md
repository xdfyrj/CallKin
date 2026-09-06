# Windows PE GT 실험

이 문서는 PE 전체 CallKin backend가 아니다. 목적은 먼저 다음 질문만 분리해서
측정하는 것이다.

> PDB에서 얻은 정확한 Rust 함수 origin grouping을 익명 ground truth로 만들었을 때,
> stripped Windows binary 분석에 유용한 평가 입력을 만들 수 있는가?

## 입력과 출력

입력은 같은 Windows release build에서 나온 세 파일이다.

```text
subject-linked.exe   non-stripped PE32+ x86-64
subject.exe          stripped PE32+ x86-64
subject.pdb          subject-linked.exe에 대응하는 PDB
```

실행기는 먼저 다음 두 조건을 검증한다.

1. linked PE의 CodeView RSDS GUID/Age와 PDB의 GUID/Age가 일치한다.
2. linked PE와 stripped PE의 PE32+ x86-64 형식, section 이름/RVA/virtual size,
   `.text` bytes가 일치한다.

그 후 `pe_gt_extractor.py`는 `llvm-pdbutil dump -symbols`의 procedure record를 읽는다.
PDB의 `segment:offset` decimal 주소를 PE section RVA와 합쳐 link-independent한
RVA로 바꾼다. PE image base나 실행 중 ASLR 주소는 결과에 사용하지 않는다.

세 JSON의 역할은 의도적으로 다르다.

### `evaluator_catalog.json`

평가자 전용 catalog다.

- 함수 RVA와 크기
- PDB symbol name
- 정규화한 source origin
- `root/target/context` role
- linked/stripped PE와 PDB의 SHA-256
- CodeView/PDB GUID와 Age

이 파일은 함수 이름과 origin을 포함하므로 분석자에게 공개하지 않는다.

### `functions.json`

분석 A와 B에 공통으로 제공할 익명 함수 inventory다.

```json
{
  "address_space": "RVA",
  "functions": [
    {"id": "FUN_00012040", "rva": "0x12040", "size": 64, "role": "target"},
    {"id": "FUN_00011000", "rva": "0x11000", "size": 32, "role": "root"}
  ]
}
```

symbol name, origin, crate namespace, case name은 포함하지 않는다. `role`은 공개
실험에서 함수의 분석 용도를 나타낼 뿐 source identity를 나타내지 않는다.

### `gt_groups.json`

분석 B에만 제공하는 익명 GT다. PDB의 Windows식 `foo<T>`와 ELF식
`foo::<T>`를 같은 source origin 규칙으로 정규화한다. 두 개 이상의 instance와
두 개 이상의 서로 다른 concrete PDB spelling이 있는 origin만 출력한다.
따라서 singleton과 동일한 non-generic symbol의 단순 복제는 제외한다.

```json
{
  "address_space": "RVA",
  "groups": [
    {"group": "G0001", "members": ["FUN_00012040", "FUN_00012110"]}
  ]
}
```

여기에는 origin 이름, PDB name, crate namespace를 저장하지 않는다. 같은 origin의
함수들은 하나의 익명 `Gxxxx` 아래에 모인다. group에 들어가는 함수는 최소 두
개다.

## 실행

의존성을 설치한다.

```bash
python3 -m pip install -r requirements.txt
```

LLVM의 `llvm-pdbutil`이 PATH에 있어야 한다. 도구 경로를 직접 지정할 수도 있다.

```bash
python3 pe_gt_extractor.py path/to/subject.exe \
  --linked-binary path/to/subject-linked.exe \
  --pdb path/to/subject.pdb \
  --case subject \
  --candidate-scope rust-nonstd \
  --root-namespace subject_crate \
  --pdb-tool /path/to/llvm-pdbutil \
  --output-dir evaluation/pe/subject
```

subject namespace만 평가하려면 다음처럼 실행한다.

```bash
python3 pe_gt_extractor.py subject.exe \
  --linked-binary subject-linked.exe \
  --pdb subject.pdb \
  --case subject \
  --candidate-scope subject \
  --namespace subject_crate
```

기본 출력은 다음 세 파일이다.

```text
evaluation/pe/subject/evaluator_catalog.json
evaluation/pe/subject/functions.json
evaluation/pe/subject/gt_groups.json
```

PDB-derived evaluator catalog가 저장소에 들어가지 않도록 `evaluation/pe/`는
기본적으로 Git ignore 대상이다. 익명 inventory와 group만 보관하려면
`--functions-output`과 `--groups-output`으로 별도 위치를 지정한다.

## 선택 범위

`--candidate-scope rust-nonstd`는 root `main`과 `core`, `alloc`, `std`, `__rustc`
소유 함수를 제외하고 관찰 가능한 Rust 함수들을 선택한다. `--root-namespace`는
source main을 제외하고 origin을 판정하는 데 사용한다.

`--candidate-scope subject`는 `--namespace`로 지정한 crate namespace 함수만
선택한다. 두 경우 모두 함수 경계와 symbol name은 PDB에서 온다. 이 단계의 목적은
PDB를 숨긴 뒤 나중에 stripped PE 분석 결과와 익명 group을 비교할 수 있도록 평가
자료를 만드는 것이다.

## 현재 범위와 다음 단계

현재 구현은 다음을 하지 않는다.

- PE instruction에서 call edge 추출
- IAT 또는 base relocation 분석
- angr indirect-call 복구
- PE용 candidate/anchor/abstain projection
- `run_case.py`와 PE fixture 연결

따라서 이 단계의 성공은 CallKin이 PE를 분석했다는 뜻이 아니다. 먼저 익명 GT와
평가자 catalog가 안정적으로 만들어지는지 확인한 뒤, 필요성이 확인되면 PE backend를
추가한다.
