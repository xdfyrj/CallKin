# CallKin 관계 합의 선택 대조 연구

상태: 측정 및 검산 완료

C3-k16은 관계 포함 3경로 합의이고, B2-body-score는 본문 2경로 점수로 고른 대조군이다. B2-body-score의 quota는 C3에서 상속했다. macro_R는 원본 집단별 재현율의 평균이다.

## 결론

C3-k16은 세 case 모두에서 다섯 고정 random control보다 F1이 높았다. 이는 이번 고정된 대조군에서의 관찰이며 통계적 증명이나 일반화 결과가 아니다.

| case | C3 F1 | B2-body-score F1 | random5 F1 range | C3 대 B2 | macro_R C3 / B2 | TP/FP C3 / B2 |
| --- | ---: | ---: | ---: | --- | ---: | --- |
| zoxide | 0.028302 | 0.028302 | 0.023697 - 0.025357 | equal | 0.084890 / 0.084890 | 18/15 / 18/15 |
| fd | 0.052378 | 0.044619 | 0.028049 - 0.032867 | C3 higher | 0.061283 / 0.068209 | 87/56 / 74/64 |
| ripgrep-main | 0.181741 | 0.187234 | 0.166989 - 0.175048 | B2 higher | 0.134914 / 0.147182 | 428/425 / 440/403 |

fd에서는 C3 F1이 높지만 macro_R가 낮다. ripgrep-main에서는 B2-body-score가 F1, macro_R, TP에서 높다. C3 선택의 추가 가치는 program과 metric에 따라 달라지며, B2-body-score의 승리도 C3 quota를 상속한 대조군이므로 deployable pure body algorithm을 확정하지 않는다. Rescue는 모든 case에서 off였다.

Root는 21개 arm의 primary precision, recall, F1, macro_R와 exact_group_rate를 별도로 산술 검산했다. clean ZIP 재검산도 primary와 original label에서 통과했다.

## 고정 범위

설계와 실행기는 다음 commit에서 고정했다.

- 2809a1dfd7d7040539ecabe0e9bda354ef78d21f: protocol/config 설계 freeze
- a57f4230e995e68c0468f8f924d543efca38b444: quota control과 cached F6 runner freeze
- core base: 7277f7e7d1d2fa5ee781b0f0c0d6626618f3a1bf

세 case 모두 이미 결과를 본 개발 프로그램이다. C3 historical partition과 cost match를 세 case에서 확인했고, initial nominal cost difference는 최대 0.62%였다. 후보 수, eligibility, LCS cost stratum quota를 맞췄으며 degree와 CFG topology는 matching하지 않았다.

fd와 zoxide는 source-audit corrected GT/linkage를 primary로, original을 secondary로 사용했다. ripgrep-main은 corrected pair가 없어 original만 사용했다. fd의 macro_R 충돌은 이 label proxy의 원본 집단별 평균과 pairwise 집계가 다른 데서 나타나며, closure grouping은 추가 audit 대상으로 남긴다. zoxide는 C3와 B2-body-score의 F1이 같지만 accepted partition은 달랐고, 세부 내용은 [selection-diagnostic.md](selection-diagnostic.md)에 있다.

actual_alignment_cells는 실제 요청 pair마다 n_a*n_b를 합한 F6 logical budget proxy다. 모든 DP cell이나 Python operation의 실측값이 아니며, physical cache 값도 새로 계산한 pair의 같은 proxy다. timing을 latency fairness 근거로 쓰지 않는다.

## 보조표와 검산 bundle

보조표의 macro_R 이름 연결을 고친 뒤 scorer를 다시 돌렸고 기존 지표 378건은 모두 같았다. 수정 기록은 [fix-note.txt](archive/scoring-attempt1-macro-alias/fix-note.txt)에 남겼다. 기존 전체 시도는 로컬 archive에 보관하며 archive 전체를 공개 artifact로 간주하지 않는다.

[verification-bundle.zip](verification-bundle.zip)은 6,070,830 bytes이고 SHA-256은 다음과 같다.

    90e20f77e8d20d10da54629b18c3f00b9b2dfdc03c2ce7c15f77643e91728b69

이 bundle은 21개 prediction의 standalone 재채점용이다. source checkout, source rebuild, 새 observation 생성 또는 외부 연구자의 재현을 포함하지 않는다. 사용법은 [verification/README.md](verification/README.md)에 있다.

큰 raw JSON은 로컬에 남기고 gzip으로 보존한다. [source-corrected-sensitivity.json.gz](source-corrected-sensitivity.json.gz)는 압축본을 사용하며 작은 JSON은 그대로 둔다.

## 입력과 실행

이 study는 단독 실행 묶음이 아니다. 기존 body evidence, B2/C3 candidate artifact, fixture provenance와 old F4 cache가 필요하다. 다른 machine으로 경로를 옮기는 재현은 아직 검증하지 않았다. 전체 설계는 [protocol.md](protocol.md), [config.json](config.json)에 있다.

repo root에서 study 디렉터리로 이동해 selection 압축본을 복원한다.

    cd experiments/relation-control-2026-09-08
    gzip -cd selection/fd.json.gz > selection/fd.json
    gzip -cd selection/ripgrep-main.json.gz > selection/ripgrep-main.json
    gzip -cd selection/zoxide.json.gz > selection/zoxide.json
    sha256sum selection/fd.json selection/ripgrep-main.json selection/zoxide.json

준비와 실행은 repo root에서 기본 경로로 한다.

    python3.12 experiments/relation-control-2026-09-08/prepare_relation_control.py
    python3.12 experiments/relation-control-2026-09-08/run_relation_control.py
    python3.12 experiments/relation-control-2026-09-08/score_relation_control.py

## 다음 단계

hexyl은 source build까지만 확인되었다. 새 원본의 observation과 evaluation, 외부 연구자의 재현은 남아 있다. 이 결과만으로 admission PDF나 technical report의 독립 검증이라고 말할 수 없다.

주요 파일은 [results-summary.csv](results-summary.csv), [primary-deltas.json](primary-deltas.json), [random5-summary.json](random5-summary.json), [source-corrected-sensitivity.json.gz](source-corrected-sensitivity.json.gz), [candidate-diagnostics.json](candidate-diagnostics.json), [selection-diagnostic.md](selection-diagnostic.md)이다.
