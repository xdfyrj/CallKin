# Novel source preparation

Preparation date: 2026-09-08. This document records source selection and provenance only. No target was built, extracted, executed, scored, or used to create GT/results. The three source trees are staged under the ignored path `workspace/relation-control-2026-09-08/sources/`.

## Release and source pins

The GitHub release API was checked on 2026-09-08. For each project, the first API row is the latest listed non-draft, non-prerelease release and is on or before the cutoff date. Each checkout is detached at the exact release tag; `git status --porcelain` is empty.

| rank | official repository / release | published UTC, prerelease, draft | exact tag commit | package / edition / rust-version | lockfile SHA-256 | declared license and files |
| ---: | --- | --- | --- | --- | --- | --- |
| 1 | [sharkdp/hexyl](https://github.com/sharkdp/hexyl), [v0.17.0](https://github.com/sharkdp/hexyl/releases/tag/v0.17.0) | 2026-02-14T12:56:31Z, false, false | `8eb6d4771ce1ec7af65d06bd335457783b77d557` | `hexyl`, 2021, 1.88 | `8ea5d9783696026e5ca55d669dd91b38d8613e9fe4f5a5ad701281142adf291d` | `MIT/Apache-2.0`; `LICENSE-APACHE` `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`, `LICENSE-MIT` `f9c4c77baa3828004ee54b8a4f2db2e88ed44a6237a493965bf551fac0fcb62d` |
| 2 | [sharkdp/hyperfine](https://github.com/sharkdp/hyperfine), [v1.20.0](https://github.com/sharkdp/hyperfine/releases/tag/v1.20.0) | 2025-11-18T08:38:43Z, false, false | `975fe108c4ee7bd2600d10758207b44ca3dae738` | `hyperfine`, 2018, 1.88.0 | `f3b341ae4c03197e61ee9e9b157c3a8669ea0cce23da68ded1e085fcbca8b9ba` | `MIT OR Apache-2.0`; `LICENSE-APACHE` `c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4`, `LICENSE-MIT` `1dfee18c2ff07ce551de4d6a1d2db158c0380746b488a7f0d08c8e0d3568b7c3` |
| 3 | [XAMPPRocky/tokei](https://github.com/XAMPPRocky/tokei), [v15.0.0](https://github.com/XAMPPRocky/tokei/releases/tag/v15.0.0) | 2026-09-06T17:29:00Z, false, false | `c14f744716272fadeb27a74443cdffa0af35f82f` | `tokei`, 2021, 1.71 | `99552aa36b2763e9662aa36a783e6a010f90dae794f796659eeb721d2cb99000` | `MIT OR Apache-2.0`; `LICENCE-APACHE` `ebd8153ef4d2d160d0bdc76a1821ac2a0eb1f57e8c056f3674032f8140c41745`, `LICENCE-MIT` `ee1201a73de9b44ad1ef02a2f9f82705b1350b878e2bab3c3fb6282daf038a73` |

Raw release records checked: [hexyl releases API](https://api.github.com/repos/sharkdp/hexyl/releases?per_page=10), [hyperfine releases API](https://api.github.com/repos/sharkdp/hyperfine/releases?per_page=10), and [tokei releases API](https://api.github.com/repos/XAMPPRocky/tokei/releases?per_page=10).

Additional local hashes for the exact staged inputs:

| project | Cargo.toml SHA-256 | CallKin Cargo-input SHA-256 | `git archive HEAD` SHA-256 |
| --- | --- | --- | --- |
| hexyl | `da6100d14c9d19c5c9659ac7d050149156c063cedc83b50c2f11e74dccdb6ddb` | `0e0785df51a78ca453206c35f17778187ac5cd1c0be9e41bdfe358c25aa7ac42` | `71ee3a7f70f1d4423cac347cf9cc2542b766b5b734c215867fea7bfb58eff51c` |
| hyperfine | `f8cb3b04244c3832bff112d3bb0b6a1b2845b641dafa35e9c85c2518af1c2f78` | `2fa13b0357e24bf845533b481a7143e139bd4f358f1fe59f4642a522508d0592` | `5136235c3b8288c227223139eb764f6687b84a6d3f6b9495cbd3ac89caa50951` |
| tokei | `696414e46ee5d591d361e9162b7b7b5890a2955778bb1b427c322cf926dfd234` | `8aa20aefef3b9ee563a3002fdb443f10cd43daed5bec9066909d0642e6f79141` | `25c4acb8a1385c73716c8fd9ba75bf150573488503ed685c53d12d09198a3d38` |

The CallKin-input hash follows `build_manifest.sha256_cargo_inputs`: manifest, lockfile, optional build/toolchain files, `src/**`, and `.cargo/**`. It is a preparation hash, not a build manifest or a result identity.

## Manifest and Linux-target checks

`CARGO_NET_OFFLINE=true cargo metadata --offline --locked --no-deps --format-version 1` was run for metadata inspection only. It reported exactly one binary target for every package:

| project | purpose | binary target | other targets | direct/build dependency shape | repository size proxy |
| --- | --- | --- | --- | --- | --- |
| hexyl | terminal hex viewer | implicit `hexyl` binary from `src/main.rs` | one lib, one example, one integration test | 9 direct runtime dependencies; no build script or target-specific dependency section | 25 tracked files, 7 Rust files, 3,380 Rust lines, 68 lock packages |
| hyperfine | command-line benchmarker | implicit `hyperfine` binary from `src/main.rs` | three tests, one build script | 12 direct runtime dependencies, Linux `libc`/`nix`, Windows `windows-sys`, and two build dependencies | 69 tracked files, 41 Rust files, 6,305 Rust lines, 173 lock packages |
| tokei | code statistics tool | `tokei` binary, `required-features = ["cli"]`; `default` includes `cli` | one lib, one test, one build script | 26 direct dependency entries including optional CLI/serialization features, plus four build dependencies | 261 tracked files, 25 Rust files, 5,025 Rust lines, 208 lock packages |

All three declare a minimum Rust version below the frozen local `rustc 1.93.1`. The next build must use the CallKin O3S override: opt-level 3, debuginfo 0, debug assertions off, overflow checks off, codegen-units 16, LTO false, panic unwind, and `strip = "none"` before the derived `strip --strip-all` fixture. Upstream release profiles differ: hexyl and hyperfine request LTO/codegen-units 1, while tokei requests thin LTO and panic abort. Do not inherit those release profiles for this comparison.

Manifest metadata is a readiness check only. No compilation has been attempted, so binary production remains pending the next protocol gate.

## Namespace and dependency overlap

Existing CallKin project namespaces from the retained subjects are `billing_client`, `reconcile`, `delta`, `dust`, `fd`, `rg`, and `zoxide` (plus the synthetic `family_graph_*` cases). New package namespaces are `hexyl`, `hyperfine`, and `tokei`; exact project-namespace intersection is empty.

The pre-preparation source/research scan found no `hexyl` or `tokei` project reference. `hyperfine` appeared only in documentation/benchmark references (`fd` README and delta benchmark files), with no hyperfine subject, Cargo dependency, or CallKin artifact. This is a local source-presence check, not a proof of semantic independence.

Common Cargo dependency names are a separate caveat. The following are the unions of direct, target-specific, and build dependency names that also occur in the current subject manifests:

| project | overlapping dependency names in current subjects |
| --- | --- |
| hexyl | `anyhow`, `clap`, `clap_complete`, `libc`, `terminal_size` |
| hyperfine | `anyhow`, `clap`, `clap_complete`, `libc`, `nix`, `once_cell`, `serde`, `serde_json`, `shell-words` |
| tokei | `aho-corasick`, `clap`, `crossbeam-channel`, `etcetera`, `ignore`, `log`, `once_cell`, `rayon`, `regex`, `serde`, `serde_json` |

`hexyl` and `hyperfine` both list David Peter as author, and David Peter is also an author of the existing fd projects (`fd` and `fd-1160`). `tokei` lists Erin Power, so it provides a distinct author/project lineage. Shared dependencies and shared author lineage must be reported separately from project-source namespace identity.

## Readiness and remaining gate

All three candidates are source-preparation ready: official non-prerelease release, exact tag/commit, checked-in lockfile, recognized license files, one Linux-capable Cargo binary target, clean staged tree, and compatibility with the frozen rustc/profile at the manifest level. None is yet declared unseen.

Before any build or observation, root should preserve these pins, verify the staged source against the official release/tag again if the checkout moves, assign an experiment-specific CallKin case namespace, and keep all output paths outside the retained canonical corpus. Only after the source tree and its dependency overlap are accepted should the normal `compile.py -> run_case.py` path be allowed to create build/evidence artifacts.
