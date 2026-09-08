# CallKin prospective novel-source validation

Status: **FROZEN-DESIGN - outcomes not run**
Date: 2026-09-08
Reference design: relation-control protocol `40b976a652a639c28bdd1705ebbe4230ad2877d7fcaaef159b6e4a09190fb53e`
Current CallKin base: `28f84a1b355e40688c7f4c34b2a59f37fc7b60b6`

This protocol fixes the prospective validation before any new observation,
ground truth, prediction, or score is created. It extends the already frozen
CallKin method to three pinned Rust releases. The release projects are the
ordered cases `hexyl-v0170`, `hyperfine-v1200`, and `tokei-v1500`. They share
some dependencies (and hexyl/hyperfine share an author lineage), so they are
new project sources, not three independent new origins. No new feature family
or performance patch is introduced. The existing CallKin-Real discovery line
remains a separate future gate and run. Provided-boundary validation is not
conflated with a stripped-only discovery run.

## Question and estimands

For the retrieval arms at `k=16`, compare the relation-aware C3 candidate
selection with the B2 token+CFG selection, a quota-matched body-only control,
and the existing Rescue stage. The primary endpoint is pairwise F1, reported
per case; raw pairs are never pooled in a way that lets one case dominate.
Primary comparisons are:

1. B2 versus C3 under the same absolute F6 ceilings of 10,000 comparisons and
   500,000,000 logical alignment cells. Their initial candidate costs may
   differ, and the actual costs are reported.
2. C3 versus B2-body-score, where count, eligibility, and nominal cost strata
   are inherited from C3 for each case.
3. C3 strict versus C3 plus the existing Rescue rule. Rescue has an additional
   budget, so this comparison makes no equal-budget claim.

Precision, recall, macro origin recall (`macro_R`), exact-group rate, stage
outcomes, and candidate/actual cost are secondary descriptive measures. No
threshold is tuned, replaced, or relaxed from outcomes. Three cases do not
support a p-value, significance claim, or general claim about Rust programs.

Candidate retrieval and preparation have an independent per-case ceiling of
1,800 seconds and 12 GiB of address space. A timeout or address-space failure
is recorded as an upstream retrieval failure and gives affected downstream
quality fields `NA`; it is never converted to zero quality. This ceiling is
separate from the strict F6 comparison and alignment budgets.

## Frozen source and build inputs

The release pins and staged-source hashes are taken from
`../relation-control-2026-09-08/novel-source-preparation.md` (SHA-256
`9d1535f658c290c6deedeffc6562091a0bf9355db7457be96de544b849d197f6`).

| case | repository/tag | exact commit | Cargo.lock SHA-256 | CallKin input SHA-256 |
| --- | --- | --- | --- | --- |
| `hexyl-v0170` | `sharkdp/hexyl` `v0.17.0` | `8eb6d4771ce1ec7af65d06bd335457783b77d557` | `8ea5d9783696026e5ca55d669dd91b38d8613e9fe4f5a5ad701281142adf291d` | `0e0785df51a78ca453206c35f17778187ac5cd1c0be9e41bdfe358c25aa7ac42` |
| `hyperfine-v1200` | `sharkdp/hyperfine` `v1.20.0` | `975fe108c4ee7bd2600d10758207b44ca3dae738` | `f3b341ae4c03197e61ee9e9b157c3a8669ea0cce23da68ded1e085fcbca8b9ba` | `2fa13b0357e24bf845533b481a7143e139bd4f358f1fe59f4642a522508d0592` |
| `tokei-v1500` | `XAMPPRocky/tokei` `v15.0.0` | `c14f744716272fadeb27a74443cdffa0af35f82f` | `99552aa36b2763e9662aa36a783e6a010f90dae794f796659eeb721d2cb99000` | `8aa20aefef3b9ee563a3002fdb443f10cd43daed5bec9066909d0642e6f79141` |

The configured main input root is
`/mnt/c/Users/sumyr/playground/REV/CallKin`. Source paths are relative to that
root, under `workspace/relation-control-2026-09-08/sources/`, and must remain
detached at these commits and clean. `Cargo.toml` and `git archive HEAD` hashes
are also recorded in `hash-manifest.json`. Cargo must use `--locked`; the
single binary target identified by the preparation metadata is used for each
case.

The build is Linux `x86_64-unknown-linux-gnu` with Cargo/rustc `1.93.1` and
LLVM `21.1.8`, CallKin build `O3S`, profile `plain`: opt-level 3, debuginfo 0,
debug assertions off, overflow checks off, codegen-units 16, LTO false, panic
unwind, and `strip = "none"` before deriving the stripped fixture. Build jobs
are capped at 2 and each build has a 1,800-second wall limit. All three builds
were completed before this protocol was written. Their manifests and binary
hashes are preserved in `BUILD-STATUS.md` and `BUILD-ADDITIONAL.md` (SHA-256
`e8fac44400d52a004c8c764cbca3274de2b025bd3ef34766181265fc5d58791d` and
`fc8bcf1b519320cd73af5a74b37b7e1c55572b4991db610a5c91fd522dc3de08`). Those
records contain no symbols, GT, extraction, observation, metrics, or quality
result.

Extraction uses Sage's Python 3.10.14 environment with angr 9.2.165, r2pipe
1.9.8, Capstone 5.0.3, pycparser 2.22, pyelftools 0.31, and radare2 5.5.0.
Inference uses Python 3.12.3. Address-space protection is 12 GiB, maximum
extraction wall time is 3,600 seconds, and inference is limited to 1,800
seconds and 12 GiB per arm. At most two heavy cases may run concurrently.
Cache time is not a latency fairness measure.

## Data flow and label separation

For each case the gated order is:

`source checkout -> locked build -> provided-boundary observation -> six
predictions -> prediction hashes -> label scoring`.

The target boundary oracle is the provided non-stripped Rust symbol extents.
A raw source-symbol GT/catalog is created to supply those boundaries and to
make the later label artifact, but its origin labels never enter retrieval,
candidate selection, F4, F6, or Rescue. The clustering process receives only
the extracted body evidence,
fixture, and named candidate input. It must not receive GT, linkage, origin
names, source-audit notes, or prior decisions. All six prediction artifacts
are written and SHA-256 pinned before any label file is opened by the scorer.

The primary label is the original symbol-normalization GT plus its linkage
artifact for the same case and target universe. The existing positive,
negative, duplicate-neutral, unresolved-neutral, and ambiguous-neutral rules
are preserved. A later source audit, if one is needed, is a separately
versioned sensitivity analysis; it cannot retrofit the primary label after
seeing outcomes.

Primary metrics use all targets. Two secondary views are evaluated without
changing predictions. `project-owned` uses the existing
`gt_extractor.belongs_to_subject(origin, namespaces)` prefix logic with the
case namespace (`hexyl`, `hyperfine`, or `tokei`). The `previously-unobserved`
view means only "not present in this inventoried normalized-origin-label set."
It is not a claim that the source definition is unseen. The set is the union
of every `origins[*].origin` and every
`cross_origin_aliases[*].origins` in the 13 pinned files listed in
`hash-manifest.json`. The resulting compact set is stored as
`exposed-origins.json` (4,530 labels, SHA-256
`73f6879dc40fb3e4ddaddd2bb06942ff01ec503388051901294abdab3580a557`).

For either secondary view, retain only target addresses with exactly one known
origin satisfying the mask. Clip each already-produced predicted cluster to
that universe without regrouping, and report members outside the mask as
out-of-mask cluster contamination. If the filtered universe has no evaluable
positive pairs, recall, macro_R, and exact-group rate are `NA`; F1 still uses
the existing formula for its evaluable pairs, and an FP-only score is not
treated as evidence of positive recovery. A sparse secondary view does not
replace a case or alter the primary denominator, and it cannot support a
source-generalization claim when it has no independent positive families.

## Arms and candidate rules

The six fixed arm IDs in `config.json` are:

| arm | rule | F6/Rescue |
| --- | --- | --- |
| `V0-relation` | Existing V0 relation partition, `out-in` mode | no F6 |
| `exact-token-hash` | Exact equality of `TokenProfile.exact_token_hash` for complete, nonempty, non-opaque bodies | no F6 |
| `B2-token-cfg` | Intersection of independent token and CFG top-16 views | strict F6 |
| `C3-token-cfg-relation` | Intersection of independent token, CFG, and relation top-16 views | strict F6 |
| `B2-body-score` | B2 pool selected by pure body score under C3 strata | strict F6 |
| `C3-rescue` | C3 strict result followed by existing Rescue | strict F6 + Rescue |

"Intersection" means a pair is retained only when it is selected by every
named view; it is not the union of view candidates. `exact-token-hash` uses
the existing canonical TokenProfile hash, which includes mnemonic, operand
shape, constant category, and control-flow shape. It does not use raw bytes,
concrete constant values, addresses, names, or GT. V0 and exact-token outputs
are still prediction artifacts and are scored under the same label rules; they
have no F6 alignment budget.

For B2 and C3, endpoint failure reasons are `missing`, `incomplete`, and
`opaque`. A pair carries the deduplicated sorted union of both endpoint
reasons. No reason-priority rule is used. An eligible pair has no reason and
has nominal cost

`c = len(instructions_left) * len(instructions_right)`.

Ineligible and zero-cost pairs use cost 0. Positive cost uses the fixed
integer bin `e = c.bit_length() - 1` and
`sub = ((c - 2**e) * 16) // 2**e`; the canonical stratum label is compact,
sorted-key JSON. For each case and stratum, B2-body-score selects exactly the
C3 count from the B2 pool, preserving C3 eligibility and cost strata. A pool
shortfall is a selection failure: no replacement, adjacent-bin merge, or quota
relaxation. Its only selection keys are B2 token score, CFG score, body
instruction lengths for strata, and canonical pair IDs. Order is body-score
minimum descending, body-score mean descending, left ID ascending, right ID
ascending; scores are not rounded. It does not match score distributions and
does not read GT, linkage, relation flags, source audits, or old clusters.
Because its quotas are inherited from C3, B2-body-score is a matched control,
not a standalone deployable body-only method.

Selection manifests and control candidate hashes are frozen before any F4
cache is opened. Report forced strata, nominal cost deviations, C3 overlap,
and graph degree/component summaries as diagnostics; do not match degree,
topology, or relation flags after selection. A fresh F4 cache is built from
the new case bodies. A deterministic math cache may be shared within a new
case, but cache hits never reduce arm logical cost and no old-case F4 feature
cache is reused.

## F6, Rescue, and cost accounting

Strict F6 keeps the existing policy: structure threshold 0.95, slot threshold
1.0, no structure reject threshold, at least one informative slot,
abstention on opaque indirect jumps, unchanged tri-state decisions and
complete-link. Every strict arm has an independent ceiling of 10,000 detailed
comparisons and 500,000,000 logical alignment cells. The entire candidate
queue is priced first. If it exceeds either ceiling, the arm is
`budget-refused` and quality fields are `NA`; no prefix quality is reported.
If a later on-demand complete-link merge exceeds remaining budget, record a
normal `comparison_budget` blocked merge and continue where existing F6 does.
Resource interruption is `resource-incomplete` and is also `NA`, never zero.

The existing `f7-rescue-v1` rule is enabled only for `C3-rescue` and consumes
the C3 strict partition. Its candidate input is the top-16 retrieval from each
of token, CFG, and relation, retaining pairs selected by any two of the three
views. Its explicit additional budget is
`max_component_members=64`, `max_comparisons=4096`, and
`max_alignment_cells=500000000`; store these values in the Rescue artifact's
`budget.to_dict()` and charge Rescue comparisons/cells separately from strict
F6. Rescue cost is additional, so C3-rescue is not a same-budget arm.
Record candidate, on-demand, total logical, physical cache, wall-time, and
maximum-RSS fields separately.

## Metrics, execution, and freeze gate

For every case and arm, retain target/candidate counts, eligible and
ineligible reasons, stage counts, TP/FP/FN/TN, precision, recall, F1,
macro_R, exact-group rate, and raw logical cost. Stage totals for each
non-neutral positive must reconcile with the target positive-pair count.
Report C3 versus B2 and C3 versus body-score per case, and Rescue deltas with
their additional cost. No random controls are added here; the prior study's
21 arms (15 random, 3 C3, and 3 body-score) remain separate.

The first authorized execution is hexyl source through observation, all six
prediction artifacts, hash freeze, and score. Only after that case's artifacts
are preserved may hyperfine and then tokei proceed. A minimal reproduction
package will eventually cover source, build, observation, prediction, and
score. External human review is pending an explicit future step. No result is
claimed by this draft.

Root approval is required before replacing `DRAFT`, setting the protocol,
config, and implementation hashes, opening the new F4 cache, or creating any
new GT, observation, prediction, or score. Approval must confirm the source
pins, exposure-file hashes and sorted-label-set hash, six arm IDs,
intersection semantics, quota/stratum formulas, label separation, resource
ceilings, explicit Rescue budget, and output paths in `config.json`.
