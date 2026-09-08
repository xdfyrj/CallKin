# Hexyl build reproducibility preflight

Date: 2026-09-08. This is a bounded source-to-artifact reproducibility check for the already selected hexyl v0.17.0 source. It does not add an independent source-validation result: no target execution, `run_case.py`, extractor, symbol analysis, GT generation, F4, scoring, or performance observation was performed.

## Fixed inputs

The untouched canonical source is `/mnt/c/Users/sumyr/playground/REV/CallKin/workspace/relation-control-2026-09-08/sources/hexyl`, detached at tag `v0.17.0`, commit `8eb6d4771ce1ec7af65d06bd335457783b77d557`. Its tree was clean before the preflight and remained clean afterward. `Cargo.toml` SHA-256 is `da6100d14c9d19c5c9659ac7d050149156c063cedc83b50c2f11e74dccdb6ddb`; `Cargo.lock` SHA-256 is `8ea5d9783696026e5ca55d669dd91b38d8613e9fe4f5a5ad701281142adf291d`; the CallKin Cargo-input SHA-256 is `0e0785df51a78ca453206c35f17778187ac5cd1c0be9e41bdfe358c25aa7ac42`.

Both builds used exactly one build process at a time, `CARGO_BUILD_JOBS=2`, a 1800-second timeout, `compile.py`, `subject`, case `hexyl-v0170`, `--build O3S`, `--profile plain`, target `x86_64-unknown-linux-gnu`, and the existing CallKin profile override. The observed tools were `rustc 1.93.1 (01f6ddf75 2026-02-11)` with LLVM `21.1.8`, `cargo 1.93.1 (083ac5135 2025-12-15)`, and GNU binutils `strip 2.42`.

## Same-path rebuild

The first build used the original source path and wrote only to `reproduction/build-check/same-path/`:

```text
CARGO_BUILD_JOBS=2 timeout 1800s python3 compile.py /mnt/c/Users/sumyr/playground/REV/CallKin/workspace/relation-control-2026-09-08/sources/hexyl subject --case hexyl-v0170 --build O3S --profile plain --gt-binary experiments/novel-source-2026-09-08/reproduction/build-check/same-path/hexyl-v0170.O3S.gt.bin --fixture-binary experiments/novel-source-2026-09-08/reproduction/build-check/same-path/hexyl-v0170.O3S.fixture.bin --manifest experiments/novel-source-2026-09-08/reproduction/build-check/same-path/hexyl-v0170.O3S.build.json
```

`compile.py` exited `0`; `load_and_verify_manifest` passed with build ID `d41e6b0756f54d92851cb76b5dec7aca`. The fresh GT is 5,123,088 bytes with SHA-256 `5a659a2bd5e57feaf8ef6bcfb2b2973625f45f5e239e2a323cb8cf28a943d48e`; the fresh stripped fixture is 1,324,496 bytes with SHA-256 `b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a`. Both hashes exactly match the untouched canonical artifacts, and `cmp` passed for both files. The same-path manifest SHA-256 is `60520fef88793ff1a21da0d96078da2d08f2cfb5a2b0f31f860a753a2cc64169`; its compile-log SHA-256 is `b4364d28b7df7115034d1b0b731297386b178251d2e6eb921609e8c596ee990c`.

An independent `pyelftools` comparison between canonical and same-path GT and fixture found exact `SHF_EXECINSTR` section name, `sh_addr`, and raw-byte matches for `.text` @ `0x4d240` (976,832 bytes), `.init` @ `0x13ba00` (27), `.fini` @ `0x13ba1c` (13), and `.plt` @ `0x13ba30` (48). The Cargo target/config temporary directory differed between the canonical manifest (`/tmp/hexyl-v0170.plain.O3S.n_jt0mai`) and this rebuild (`/tmp/hexyl-v0170.plain.O3S.8id4mab4`), while the bytes remained identical in this check.

## Relocated-source rebuild

The clean pinned checkout was cloned to `reproduction/build-check/relocated-source/hexyl` with:

```text
git clone --local --no-hardlinks /mnt/c/Users/sumyr/playground/REV/CallKin/workspace/relation-control-2026-09-08/sources/hexyl experiments/novel-source-2026-09-08/reproduction/build-check/relocated-source/hexyl
```

Because the source repository is shallow, Git reported that `--local`/hard-link optimization was ignored and performed the clone through the local origin. The resulting clone is detached at the same `8eb6d4771ce1ec7af65d06bd335457783b77d557` / `v0.17.0`, is clean, and has the same `Cargo.toml`, `Cargo.lock`, and CallKin Cargo-input hashes listed above. No source file was changed.

The second build wrote only to `reproduction/build-check/relocated-path/`. Its source argument was a relative relocated path from the worktree, as shown exactly here:

```text
CARGO_BUILD_JOBS=2 timeout 1800s python3 compile.py experiments/novel-source-2026-09-08/reproduction/build-check/relocated-source/hexyl subject --case hexyl-v0170 --build O3S --profile plain --gt-binary experiments/novel-source-2026-09-08/reproduction/build-check/relocated-path/hexyl-v0170.O3S.gt.bin --fixture-binary experiments/novel-source-2026-09-08/reproduction/build-check/relocated-path/hexyl-v0170.O3S.fixture.bin --manifest experiments/novel-source-2026-09-08/reproduction/build-check/relocated-path/hexyl-v0170.O3S.build.json
```

`compile.py` exited `0`; `load_and_verify_manifest` passed with build ID `0854deed2919449f952ae03d40b7966c`. The relocated GT is 5,123,152 bytes with SHA-256 `233fa58d4e23e6e6a9524f8e06e46cca5860ef6db4bc5ef0c1396704466bc96f`; the relocated stripped fixture is 1,324,560 bytes with SHA-256 `286645a91f8a7ed5118e62a05a74f5cca84c927991fd1c2210a6fe432350b1a5`. Both differ from the canonical hashes above. The relocated manifest SHA-256 is `2f751d39b7274ffba35f383e2f9a7a44d7ac38c8d4875727a55bdb9c06c2110d`; its compile-log SHA-256 is `1328fe3d24929d141938daef18d392c8a71f3d9ce2ee2e0b47499326a5dc655f`.

The relocated GT and fixture remain a matched strip pair: their `SHF_EXECINSTR` section maps are exact to each other, and the manifest `stripped_from_sha256` points to the relocated GT hash. Against the canonical pair, however, `pyelftools` found the same four executable section names but not exact name/address/byte identity: `.text` moved from `0x4d240` to `0x4d280` and has the same 976,832-byte length but 378 differing bytes; `.init`, `.fini`, and `.plt` raw bytes are equal while their addresses shift by `0x40` (`0x13ba00`->`0x13ba40`, `0x13ba1c`->`0x13ba5c`, `0x13ba30`->`0x13ba70`).

The observed non-executable layout change is `.rodata` growing from 94,876 to 94,940 bytes. Read-only inspection found the embedded source path string changed from `/mnt/c/Users/sumyr/playground/REV/CallKin/workspace/relation-control-2026-09-08/sources/hexyl/src/lib.rs` (104 bytes) to `/mnt/c/Users/sumyr/playground/REV/CallKin/worktrees/followup-2026-09-08/experiments/novel-source-2026-09-08/reproduction/build-check/relocated-source/hexyl/src/lib.rs` (166 bytes). This is an observation about the produced bytes, not a claim that other path-sensitive inputs were ruled out. The relocated invocation also changed the source argument from absolute to relative spelling, so this bounded check jointly varies source location and argument spelling; it does not isolate those two factors.

## Finding

For this pinned source and frozen toolchain, changing only the Cargo temporary target/config directory did not change bytes: the same-path rebuild exactly reproduced both canonical artifacts. Relocating the source checkout and invoking it through the relocated path produced different GT and stripped hashes and failed exact executable-section comparison, with an embedded source path and a 64-byte read-only layout increase observed alongside the difference. The result is a reproducibility preflight for designing the portable kit; the relocated path variant is not an independent new-source validation.
