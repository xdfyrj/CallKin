# Runtime diagnostic

이 메모는 코드 구조에서 도출한 정적 비용 가설이다. 실제 병목, 지연 시간, 메모리 사용량을 측정했다는 뜻이 아니며, 새 F4 실행이나 프로파일링 결과도 아니다.

## 명목 비용과 lookup 비용

동결 실험의 nominal alignment cell은 `relation_control.py:91-95`의

```text
c = len(first.instructions) * len(second.instructions)
```

즉 `n_a * n_b`이다. `compare_bodies`는 `align_function_bodies(..., with_instructions=False)`를 호출한다(`body_similarity.py:121-127`). 블록 후보 정렬은 `_align_blocks`(`383-423`)에서 이뤄지고, filter를 통과한 block pair의 LCS는 `_sequence_ratio -> _lcs_length`(`294-312`)가 계산한다. 블록이 각 body의 instruction을 중복 없이 partition한다고 가정하자. 블록별 명령 수를 `i_a`, `i_b`, 전체 instruction 수를 `n_a = I_a`, `n_b = I_b`, 블록 수를 `B_a`, `B_b`, `_align_blocks`의 degree/terminal filter를 통과해 block-pair LCS를 실제 호출한 쌍 수를 `P`라 하면 그 block-pair LCS DP 셀의 합은

```text
sum(i_a * i_b for block pairs passed to _align_blocks) <= n_a * n_b
```

모든 쌍이 통과하면 등호가 될 수 있지만, zero-length block이 있으면 다른 경우에도 등호가 가능하다. 이 부등식은 `_align_blocks` 안의 block-pair LCS 셀 합에만 적용된다. full F4의 global body LCS, matched-block 단계의 추가 LCS 또는 모든 F4 DP cell과 Python 작업량의 상한이나 전체 count가 아니다. 따라서 nominal budget은 전체 F4 비용의 상한이 아니라 LCS cell work를 위한 proxy다.

`_align_blocks`의 바깥 루프마다 `sequence_a`를 한 번 만들지만(`395-396`), 안쪽의 각 통과 쌍마다 `sequence_b`를 다시 만든다(`397-404`). `_block_instruction_items`(`355-365`)는 호출할 때마다 전체 instruction offset dictionary를 재구성하고(`359`, `O(n_b)`), 전체 block-label dictionary도 재구성한다(`360`, `O(B_b)`). 모든 filter가 통과하면 이 lookup만

```text
O(B_a * B_b * (n_b + B_b))
```

가 된다. 그러므로 질문한 `O(B_a * B_b * I_b)` 성장은 정적으로 성립한다. filter가 걸리면 `B_a * B_b` 대신 `P`를 쓴다. 바깥쪽 `sequence_a` 생성에도 `O(B_a * (n_a + B_a))`가 든다.

## 추가 반복 작업

- `aligned_instruction_numerator`(`130-145`)는 선택된 블록 쌍마다 `_block_instruction_count`를 호출한다. 이 함수는 전체 offset set과 block map을 매번 다시 만든다(`426-431`).
- 같은 구간에서 `_sequence_ratio`와 `_ngram_jaccard`가 각각 양쪽 `_block_sequence`를 호출하므로 선택된 쌍마다 네 번 lookup과 tokenization이 반복된다(`135-143`).
- 전체 body `sequence_ratio`도 별도로 `O(n_a * n_b)` LCS를 수행한다(`186-187`). 이는 block LCS nominal 합계에 추가된다.
- `_edge_consistency`는 matched block마다 양쪽 전체 edge를 스캔한다(`461-481`). `_terminals`도 terminal마다 `any(...)`로 edge를 다시 스캔한다(`434-448`). 후보 정렬 비용 `sort(candidates)`도 최대 `O(P log P)`다.
- `with_instructions=True`인 다른 호출에서는 `_lcs_pairs`가 블록 쌍마다 `i_a * i_b` 표를 만든다(`234-243`, `315-348`). 현재 F4 경로에는 명시적으로 포함되지 않는다.

## 가장 작은 미래 최적화 후보

의미를 보존하는 최소 후보는 비교 호출 안에서 body별 local immutable index 하나를 만들고(`instructions_by_offset`, `blocks_by_label`, `items/tokens_by_block`), `_align_blocks`, `_block_instruction_count`, aligned numerator가 이를 공유하게 하는 것이다. 네 번의 sequence 호출도 같은 block sequence를 재사용한다. filter, 후보 정렬 순서, LCS tie-break, 반환값은 그대로 둔다. 전역 캐시 대신 호출 수명 내 index만 사용하면 stale state와 정책 변경을 피하면서 lookup 재구축 항을 줄일 수 있다. 이 제안은 아직 구현하거나 측정하지 않는다.
