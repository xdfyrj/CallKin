# Minimal multiview-consensus replay

This package reproduces two k=16 CallKin study arms for the controlled family_axis_03 case:

- body2: token and CFG views, requiring both views.
- combined3: token, CFG, and relation views, requiring all three views.

Run from the repository root with the verified interpreter:

    python3.12 experiments/followup-2026-09-08/minimal/replay.py

The wrapper calls the repository's current build_multiview_candidate_artifact_from_files(), build_consensus_artifact(), F6 family builder, and linkage-aware evaluator. It checks the exact output hashes measured from this controlled replay.

## Reproduction boundary

This is a cached-observation replay. It starts from body.json and fixture.json. It does not rebuild the Rust binary, extract function boundaries, run radare2, Capstone, or angr, project the relation fixture, regenerate body evidence, or recreate linkage.json from the non-stripped binary.

The omitted upstream artifacts are:

| Artifact | Original SHA-256 | Size |
|---|---|---:|
| non-stripped binary | fe9dda21a8393a59a05dc7fe6d9b1823de47c03e7dd2b6a302c0475a90f874d3 | 3,896,000 bytes |
| stripped binary | 0db0a2394c248625e4e776920395cf8e809080205a2113ac2d0965a8c2993ec8 | 350,776 bytes |
| raw angr graph | deeff0a7da5283340bc45bc2c51153accad56f3414de9fed628d9b8cb172286a | 1,439,557 bytes |
| function boundaries | 35d86ef2ec9d1612c43a47686b6cba2dad34d33072586a7f0cba94f80a8fdb7e | 32,911 bytes |

These files are unnecessary after the cached-observation boundary. The committed package is under 200 KB; adding them would raise it above 5.8 MB. A full source-to-score reproduction must rerun compile.py, gt_extractor.py, binary_extractor.py with the angr subject/role settings, graph projection, body_extractor.py, and the mangled-linkage audit before invoking this replay.

family_graph_01 was also inspected. Its retained fixture and GT are smaller, but no body artifact or linkage audit exists in the inspected main or legacy worktrees. It cannot supply an existing complete F5 to F6 to linkage-evaluation replay without new upstream evidence.

## Prediction and evaluation separation

Before prediction, replay.py opens and hash-checks only body.json, fixture.json, and policy.json. It then completes and writes both arms' raw multiview unions, all-active-view consensus F5 artifacts, and F6 artifacts.

Only after both predictions exist does it hash-check source.rs, build.json, ground-truth.json, linkage.json, and LICENSE. Evaluation then opens GT and linkage data. Neither predictor receives source text, build metadata, GT, linkage, symbols, or source-origin names.

source.rs and build.json remain in the package for provenance inspection. They never enter prediction.

## Fixed method

Both arms use:

- k = 16
- out-in graph mode
- angr track, subject scope, role anchors
- all-active-view consensus
- the unchanged formal F6 policy: structure 0.95, informative slot 1.0, opaque-indirect abstention, 10,000 comparisons, and 500,000,000 alignment cells

No threshold or candidate rule was tuned against this controlled case.

## Measured result

| Arm | Consensus pairs | F6 comparisons | Alignment cells | TP | FP | FN | TN | F1 | Exact families |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| body2 | 172 | 172 | 9,159 | 26 | 0 | 0 | 164 | 1.0 | 3 |
| combined3 | 113 | 113 | 7,242 | 26 | 0 | 0 | 164 | 1.0 | 3 |

On this small control, the relation consensus removes 59 candidates and 1,917 alignment cells without changing the scored partition. This is a controlled replay result, not evidence of generalization or relation-specific superiority.

Expected generated hashes:

| Output | SHA-256 |
|---|---|
| out/body2-multiview-union.json | b557f97f200a9e7ac12d3020015b1ecb3ec1902c1ca3df29bf06840e1a37a203 |
| out/body2-f5.json | 580342283f9b66fb10248b6878d6ee3f3bea6fca28bc0895c51c8713b3074465 |
| out/body2-f6.json | 44a00ed256176866405bc68a7f91bb75da63208d7e3c0bfee89a844b06bed684 |
| out/body2-evaluation.json | e80ad92084421ee8dc7dc3f92c98858a967acd201bb26e0d9db22918269acbff |
| out/combined3-multiview-union.json | 3f8fa0e62e806a0ae1011ccb5774b3d0609f2f42a2c047400dfc543629da4d17 |
| out/combined3-f5.json | 8e8dec1f232c90a447eacd8641ccfe30445394e95d6ba9a13cb23c9ff6b62983 |
| out/combined3-f6.json | 3bf8d015e96408f7ae46ccfd8bd4bcb3f447e145ddda44800e5d5f648f5d05d1 |
| out/combined3-evaluation.json | b99bfb44edcbb479a5334f5f6125d588125973a476b6121f7b72ab088bafd170 |

## Packaged input provenance

The cached files came from the local legacy worktree v0-engine-py-f1 at Git HEAD a162e87ca7685dd270de3ad7d22a3f0dce7bdf08. The generated artifacts were untracked in that dirty worktree, so the commit identifies the surrounding code state rather than an artifact commit. Each copied byte stream is pinned below.

| Package file | Original path in v0-engine-py-f1 | SHA-256 |
|---|---|---|
| source.rs | src/family_axis_03.rs | 22ef7aa42dc8d5b784bee9d60bf142225253fec9ff044c53ee5bb1ecf44b0221 |
| build.json | build_info/plain/family_axis_03.O3S.json | c4b47bf4dfec609fc2cc134a6606604ca011b47c066beabf76ddae59bcf7a025 |
| body.json | body_evidence/subject/plain/family_axis_03.O3S.body.json | 3413c522ffe652c3af9874641b588d8bfa44bba73a4dfa830c3fbbdc89feb4f0 |
| fixture.json | fixtures/angr/role/plain/family_axis_03.O3S.fixture.json | 5a98273a266f285a3c193f619c162440c06d713be8a50669e107af764a0ad567 |
| ground-truth.json | ground_truth/plain/family_axis_03.O3S.gt.json | c8611d94ff28b8eddbc7fb977594944dfc0487a472319d48dd4350dd26b3801e |
| linkage.json | results/family_axis_03/plain/family_axis_03.O3S.gt-mangled-audit.json | f91e8f8d98e224cf19fb48260231653a8599a0a287ddfd5dc9ff65bde1b1f633 |
| policy.json | configs/v1.formal.json | 77f394244c67b6633698e80af5265da4544c8ad5033aff7d0474a5ff8f1eebfa |
| LICENSE | repository LICENSE | 7ce87f09e6213feb0846af3b492b180f51171b43d1bb1c3c0f101795e471998b |

The build record identifies rustc 1.93.1, x86_64-unknown-linux-gnu, optimization level 3, 16 codegen units, no LTO, and panic=unwind. Its source and binary hashes agree with the packaged source and omitted binaries. Fixture and body provenance identify the same stripped binary and raw graph.

The replay was measured on Linux 6.6.114.1-microsoft-standard-WSL2, glibc 2.39, with CPython 3.12.3 built by GCC 13.3.0. The surrounding follow-up worktree was at commit 8d5375c19578cd67aa8abfdcf0d46c9cec897a83; exact output hashes guard against later behavior changes.

## Authorship and license

family_axis_03.rs was introduced by sumyr <sumyr@naver.com> in commit d55f48094bf8c52edc2351cc9b38b879846a434d on 2026-08-28. The generated JSON files contain no separate author field. The repository declares Copyright (c) 2026 sumyr under the MIT License, reproduced in LICENSE.
