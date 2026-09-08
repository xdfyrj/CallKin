# CallKin 신규 소스 검증 최종 결과

기록일: 2026-09-09

세 controlled source case의 여섯 arm, 총 18개 prediction과 score가 완료되어
보존되어 있다. 전체 confusion matrix와 cost는 [report.md](report.md)의 한 표에
모았다.

## 판단

C3는 B2보다 일관된 F1 개선을 보이지 않았다. Hexyl에서는 FP가 2개 줄어
0.021220에서 0.021277로 소폭 상승했지만, hyperfine에서는 0.087432에서
0.071823으로, tokei에서는 0.095136에서 0.092593으로 낮아졌다. B2-body-score는
C3 quota를 상속한 matched control이고, Rescue는 세 case 모두 rescued family를
만들지 않았다.

| case | highest controlled F1 | B2 F1 | C3 F1 | Rescue F1 |
| --- | ---: | ---: | ---: | ---: |
| hexyl-v0170 | exact-token-hash 0.625424 | 0.021220 | 0.021277 | 0.021277 |
| hyperfine-v1200 | exact-token-hash 0.480573 | 0.087432 | 0.071823 | 0.071823 |
| tokei-v1500 | V0-relation 0.155296 | 0.095136 | 0.092593 | 0.092593 |

Exact token hash는 hexyl과 hyperfine에서 강했지만, tokei에서는 V0보다 낮았다.
Hexyl exact arm의 TP 369개는 모두 `clap_builder`와 `anyhow` dependency origin에서
나왔다. 따라서 exact 결과도 project-source identity의 독립 증거로 해석하지 않는다.

## 보조 범위

| case | project-owned mask | previously-unobserved normalized-origin mask |
| --- | --- | --- |
| hexyl-v0170 | 37 targets, 1 positive, TP 0 | 49 targets, 2 positives, TP 0 |
| hyperfine-v1200 | 49 targets, 3 positives, TP 0 | 270 targets, 168 positives, TP 11 to 31 |
| tokei-v1500 | 102 targets, 10 positives, TP 0 to 1 | 458 targets, 219 positives, TP 7 to 71 |

`previously-unobserved`는 `not present in this inventoried normalized-origin-label
set`이라는 운영적 mask다. source definition unseen의 증명이 아니다. 세 project는
일부 dependency와 author lineage를 공유하므로 독립적인 new origin 표본으로 세지
않는다.

## CallKin-Real

Hexyl stripped fixture만을 입력으로 사용한 CallKin-Real run은 controlled
provided-boundary 조건과 별도다. GT-overlap primary에서 V0 F1 0.2828, strict,
strict + rescue, relaxed가 각각 0.0190이었다. Full 568-ID posthoc supplementary
scope에서는 각각 0.2821, 0.0189, 0.0189, 0.0189이다. Rescue component 19개는
모두 거부되었다.

Run manifest의 전체 analyzer pipeline 시간은 870.901초이고, lower-level
discovery/body/graph/stage-writing 기록은 558.688초다. 서로 다른 범위를 한
duration으로 합치지 않는다. Real은 7,056 functions를 발견했고, 567/568 GT ID를
찾았으며 complete body coverage는 0.8961이었다. 제공 boundary는 posthoc 진단으로만
사용했다.

## 재현 범위와 남은 한계

세 controlled case의 source build -> observation -> six predictions -> score 경로는
현재 로컬 artifact로 완료되어 있다. 외부 human reproduction과 portable clean
external full replay는 아직 없다. Build preflight는 같은 source path에서 canonical
hexyl byte를 재현했지만, relocated checkout과 relative source argument에서는
embedded source path와 함께 hash가 달라졌다. 이 check는 path dependence를 보인
것이지 portable replay를 증명하지 않는다.

첫 observation 시도는 GT 생성 전 `build_manifest` import error로 종료되었고,
startup `sys.path` fix 뒤에 관측을 진행했다. Evaluator-only arm-schema validation
fix는 scoring 전에 적용되었고 prediction bytes는 바뀌지 않았다. 최종
bounded closure-site audit의 세 named group 결과도 보존되어 있다. Hyperfine과
Tokei의 두 generic group은 source-consistent였고, Tokei `parse_context`의 한
pair는 cross-expression source-site false pair였지만 style/template site 배정은
ambiguous했다. Primary GT/linkage와 score는 바뀌지 않았다. Scoring agent가
artifact bundle을 준비 중이다.

Angr의 unsupported Iop 경고는 observation metadata와 log에 보존되어 있다. 이
자료는 bounded body/graph evidence를 제공하지만 full callgraph coverage를 주장하지
않는다.

Hexyl source audit는 normalized `hexyl::run::{{closure}}` 한 쌍을
`src/main.rs:342`와 `src/main.rs:353`의 서로 다른 closure로 확인했다. Versioned
secondary split에서는 project-owned positive가 P0이 되며 frozen primary는 바뀌지
않는다. Old fd audit는 `regex.rs:3613` Builder closure와 `regex.rs:1916` Clone
closure가 한 address를 공유할 수 있음을 확인했고, 2 positive와 2,211 negative인
2,213 previously scored pair를 ambiguity-neutral로 만들었다. 두 audit 모두 retained
symbol membership와 unique source-origin identity를 구분하며 compiler DefId나
semantic MonoItem identity를 증명하지 않는다.

## 링크

- [상세 report](report.md)
- [Frozen protocol](protocol.md)
- [Frozen config](config.json)
- [Hash manifest](hash-manifest.json)
- [Exposed origin labels](exposed-origins.json)
- [Hexyl score](scores/hexyl-v0170/scores.json)
- [Hyperfine score](scores/hyperfine-v1200/scores.json)
- [Tokei score](scores/tokei-v1500/scores.json)
- [CallKin-Real report](real/hexyl-v0170/real-run-report.md)
- [CallKin-Real supplementary scope](real/hexyl-v0170/real-run-supplementary.json)
- [Verification bundle ZIP](verification-bundle.zip)
- [Build reproducibility check](build-repro-check.md)
- [Hexyl source audit](audit/hexyl-source-audit.md)
- [Hyperfine and Tokei project-source audit](audit/project-source-audit.md)
- [Old fd ambiguity sensitivity](audit/sensitivity-audit.md)
