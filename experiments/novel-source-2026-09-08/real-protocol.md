# CallKin-Real prototype protocol

Status: `FROZEN`; run awaits the root ACK commit. Hashes for this protocol,
config, and environment lock are in `real-freeze-hashes.json`. This is a separate
stripped-only condition and does not revise the frozen controlled protocol.

## Identity and isolation

- Checkout: clean detached `CallKin-Real` worktree at commit
  `68ffa8dc1285546a1db52096a905a36fec094bd6`.
- Case: `hexyl-v0170`, build/profile labels `O3S/plain` for reporting only.
- Input: stripped fixture SHA-256
  `b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a`.
- Output root: `experiments/novel-source-2026-09-08/real/hexyl-v0170`.
- Discovery/inference receives only the stripped binary. GT, boundaries,
  linkage, users, controlled bodies, and controlled candidates are evaluator
  inputs or references after the run, never analysis inputs.

## Fixed run

Use CPython 3.12.3 from `novel-source-real-venv`, `--no-flirt`,
`--component-budgeted-v1`, and `top_k=16` (all in `real-config.json`). Apply
`prlimit --as=12884901888` and `timeout 3600s` around the complete analyzer.
The discovery backends are radare2 `aaa`/`aflj`, angr `CFGFast` with
`auto_load_libs=False`, and Capstone body decoding. No analyzer-internal
wall/RSS limit exists.

F6 remains frozen at structure threshold `0.95`, slot threshold `1.0`,
informative-slot requirement, opaque-indirect abstention, 10,000 detailed
comparisons, and 500,000,000 alignment cells. F7 remains `f7-rescue-v1` with
64-member, 4,096-comparison, and 500,000,000-cell limits. A budget refusal is
reported as refusal/NA, never as prefix quality. The component-budgeted mode
intentionally performs a legitimate selected-partition run: whole candidate
components that fit are processed, while deferred components and their
functions remain recorded and are reported as coverage/deferral diagnostics.
If the whole queue/case fails resource checks or cannot produce a valid
partition, quality is `NA`.

## Scoring and joins

The gated six-step sequence is: (1) verify the clean checkout, interpreter,
and stripped-input hashes; (2) run the named analyzer under the external
resource envelope; (3) freeze and hash every produced artifact; (4) perform
the post-run static-VA/ID-bias join check without feeding anything back; (5)
run the standard evaluator with the separately named GT and linkage files;
and (6) package the result with resource, body, component, and boundary
diagnostics.

After output preservation, run `evaluate.py` with the named hexyl GT and
linkage audit. Confirm before scoring: the GT/linkage sets agree on exactly
568 IDs; the run binary hash equals the fixture hash; each produced function’s
actual static ELF VA encodes to its `FUN_{va+0x100000}` ID; and static ELF VAs
are used without a PIE runtime base. Real may miss GT IDs; report the exact
Real∩GT intersection and misses, with misses treated as discovery outcomes,
not join failures. The evaluator’s primary grouping/discovery scope is the
568 GT-labelled targets overlapping the Real member universe. Report all-Real
discovery, body coverage, incomplete bodies, selected/deferred components and
functions, and GT misses as diagnostics. Count missing GT targets as
unresolved/missed diagnostics only; members absent from GT are outside the
score and are not automatic FPs.
Also retain a supplementary posthoc metric over the full 568-ID GT denominator,
with missing IDs counted as unresolved; neither this metric nor the boundary
oracle enters discovery or inference.

No-FLIRT output has no direct-label or propagation score. F10 catalog scoring
is deferred: it needs a validated `scope=all-rust` catalog, matching
`id_bias`, owner/origin fields, direct labels, and propagation prediction.

The controlled extraction used Python 3.10.14 and the controlled inference
used Python 3.12.3; this Real run uses Python 3.12.3 for all stages. The Rust
source/binary/compiler condition is unchanged (hexyl O3S/plain, Cargo/rustc
1.93.1), but Real discovery, `subject` scope, address anchors, and component
budgeting differ from the controlled provided-boundary policy. Treat these
runtime, scope, and policy differences as separate conditions and make no
causal cross-condition quality claim.
