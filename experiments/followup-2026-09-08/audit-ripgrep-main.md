# Preliminary source audit: ripgrep-main

Date: 2026-09-08

This is an LLM-agent review of source-level consistency for the 16 frozen ripgrep-main records. It is not external-human verification and does not establish compiler-internal origin IDs. I did not inspect predictions, experiment results, or other reviewers' judgments.

## Frozen inputs and artifact checks

- Protocol version reviewed (commit ba1a214): 18e1d93df36555c5ae504c6f08250af6963b5305eadf9b6f493013b8a36210a1
- Protocol at completion (commit 0ccf51a): ebe463808b7d8461e0e5dd4f7f340c64c51b73c40b2553082d1a926e46d11705
- Audit sample SHA-256: 589e153719947ce42dd56bf8a73455b6702b3ababea0bce507d4e53a76b7bcda
- Non-stripped O3S binary: d3ddcfad8e01728ce22ee9dd41c924c7ad7bc0b5d5749a21f8730f12ab61d94a (matches build record)
- Stripped O3S binary: 235f599b6f95f41ab16cfb42750a3a7be47d14347b35a8df328a7e66a32cebf9 (matches build record)
- Root Cargo.lock: 7a7d39cda8a03930e578f1dbb724e055771901842eca239e03b01e19da946a64 (matches build record)
- Current subject checkout: clean at fc3dd04b7ca18ec8be97704dc098bbd062bad244.
- All 101 retained addresses matched their listed symbols after the fixed -0x100000 analysis-image rebase and nm -n -C lookup on the verified non-stripped binary.

The build source digest 7e7500d11eb1583cc688e4880588a5b91b53b1f33ad150a72c226a32171f125a reproduces, but sha256_cargo_inputs() omits crates/**. It therefore does not pin the audited workspace files to the exact build. The JSON records the clean Git revision, Git blob, and file SHA-256. For registry sources, each cached .crate hash matches Cargo.lock, and archive extraction reproduces the audited file hash.

Protocol commit 0ccf51a was added concurrently after this review began. Its new execution-resource paragraph does not change the source-audit rules used here.

## Assessment counts

| Stratum | Groups | Source-consistent | Source-conflict | Unresolved |
|---|---:|---:|---:|---:|
| Random | 10 | 10 | 0 | 0 |
| Purposeful | 6 | 6 | 0 | 0 |
| Total | 16 | 16 | 0 | 0 |

No absent mapping was forced, and no sampled record conflicts with the existing source-origin/linkage policy. Derive-generated and closure cases remain explicit and carry lower confidence.

## Group findings

| ID | Members | Definition and source span | Assessment | Reason |
|---|---:|---|---|---|
| ripgrep-main-01 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:5274-5275, derive(Debug) Passthru | source-consistent | One derive invocation; three copies of one exact mangled identity. |
| ripgrep-main-02 | 6 | grep-searcher 0.1.17, crates/searcher/src/searcher/glue.rs:117-131 | source-consistent | Six raw hashes map to generic SliceByLine<M,S>::run. |
| ripgrep-main-03 | 4 | ignore 0.4.29, crates/ignore/src/lib.rs:261-266 | source-consistent | Generic Error::with_path; one address aliases two raw instantiations. |
| ripgrep-main-04 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:1524-1535 | source-consistent | Three copies of exact DfaSizeLimit::doc_long identity. |
| ripgrep-main-05 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:1137-1138, derive(Debug) ContextSeparator | source-consistent | One derive invocation; generated body is not handwritten source. |
| ripgrep-main-06 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:3339-3341 | source-consistent | Sole IncludeZero::name_negated definition. |
| ripgrep-main-07 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:1521-1523 | source-consistent | Sole DfaSizeLimit::doc_short definition. |
| ripgrep-main-08 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:5589-5615 | source-consistent | Sole PreGlob::doc_long definition. |
| ripgrep-main-09 | 2 | aho-corasick 1.1.4, src/nfa/noncontiguous.rs:659-661 | source-consistent | Exact concrete NFA::patterns_len identity in checksum-pinned crate. |
| ripgrep-main-10 | 3 | ripgrep 15.2.0, crates/core/flags/defs.rs:4901-4903 | source-consistent | Sole NoUnicode::doc_short definition. |
| ripgrep-main-11 | 1 | grep-printer 0.3.1, crates/printer/src/jsont.rs:94-109 and 119-134 | source-consistent | The two definitions are correctly represented by a singleton shared-address placeholder; the linkage policy marks every touching pair ambiguous-neutral. |
| ripgrep-main-12 | 1 | regex-automata 0.4.15, src/dfa/automaton.rs:1939-1941 | source-consistent | Generic forwarding Automaton-for-&A method; singleton. |
| ripgrep-main-13 | 1 | walkdir 2.5.0, src/lib.rs:1024-1027 | source-consistent | Sole closure in DirList::next; no standalone source name. |
| ripgrep-main-14 | 2 | regex-automata 0.4.15, src/dfa/automaton.rs:1919-1921 | source-consistent | Two A monomorphizations of one forwarding method. |
| ripgrep-main-15 | 1 | crossbeam-epoch 0.9.20, src/atomic.rs:211-213 | source-consistent | Blanket Pointable-for-T drop method; singleton. |
| ripgrep-main-16 | 62 | serde_core 1.0.228, src/ser/mod.rs:1855-1862 | source-consistent | One default method, many erased Self/K/V monomorphizations. |

The JSON preserves every sample ID, member, and symbol and records excerpts, source hashes, checksum checks, reasoning, and uncertainty.

## Strongest label and provenance findings

1. Shared address is not source identity, and the policy handles this case correctly. ripgrep-main-11 maps one address to distinct Match and Context methods, while schema-6 ground truth uses shared-address@FUN_00306c40, preserves both in cross_origin_aliases, and linkage returns ambiguous-neutral for every touching pair. The initial source-conflict assessment was therefore changed to source-consistent-with-neutral-policy; the underlying source-multiplicity observation is preserved. This is not an algorithm error.
2. ripgrep-main-16 has 62 of 101 audited members and contributes 1,891 of 1,935 within-group pairs (97.7%). It is consistent only at generic-definition granularity; pair weighting would be dominated by erased monomorphizations and aliases.
3. Address members and source instances are not one-to-one. Several non-generic methods repeat the same exact identity at different addresses, while ripgrep-main-03 has two raw instantiations at one address.
4. Ten records use workspace files under crates/** that the build digest omitted. Current source and binary symbols agree, but exact-build workspace identity is unproved.
5. Derived methods, the closure, and generic trait methods retain their stated uncertainty. Source consistency does not prove compiler-internal origin IDs.

## Scope limitation

This audit checks consistency with actual definitions in the available source. It does not infer why code was duplicated or coalesced, recover erased substitutions, prove exact-build identity for omitted workspace files, or constitute independent human verification.
