# Hexyl build status

Build date: 2026-09-08. This records the authorized source build only. No produced binary was executed; no `run_case.py`, extractor, symbol inspection, GT, metrics, or observation step was run.

## Result

`PASS` - `compile.py` exited 0 for case `hexyl-v0170`, source kind `subject`, build `O3S`, profile `plain`, target `x86_64-unknown-linux-gnu`. Cargo used `CARGO_BUILD_JOBS=2`; the preserved log is `build/hexyl-v0170/compile.log`.

## Input and tool identity

- Source: `/mnt/c/Users/sumyr/playground/REV/CallKin/workspace/relation-control-2026-09-08/sources/hexyl`
- Source tag/commit: `v0.17.0` / `8eb6d4771ce1ec7af65d06bd335457783b77d557`
- Source tree status after build: clean
- Cargo.lock SHA-256: `8ea5d9783696026e5ca55d669dd91b38d8613e9fe4f5a5ad701281142adf291d`
- CallKin Cargo-input SHA-256: `0e0785df51a78ca453206c35f17778187ac5cd1c0be9e41bdfe358c25aa7ac42`
- Cargo: 1.93.1 (083ac5135 2025-12-15)
- rustc: 1.93.1 (01f6ddf75 2026-02-11), LLVM 21.1.8
- strip: GNU binutils 2.42, `--strip-all`

The manifest records the frozen plain/O3S profile override: opt-level 3, debuginfo 0, debug assertions off, overflow checks off, codegen-units 16, LTO false, panic unwind, and `strip = "none"` before deriving the stripped fixture.

## Artifact and manifest verification

Manifest: `build/hexyl-v0170/hexyl-v0170.O3S.build.json`

| artifact | path | bytes | manifest SHA-256 | recomputed SHA-256 |
| --- | --- | ---: | --- | --- |
| non-stripped | `build/hexyl-v0170/hexyl-v0170.O3S.gt.bin` | 5,123,088 | `5a659a2bd5e57feaf8ef6bcfb2b2973625f45f5e239e2a323cb8cf28a943d48e` | `5a659a2bd5e57feaf8ef6bcfb2b2973625f45f5e239e2a323cb8cf28a943d48e` |
| stripped fixture | `build/hexyl-v0170/hexyl-v0170.O3S.fixture.bin` | 1,324,496 | `b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a` | `b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a` |

The manifest `stripped_from_sha256` equals the non-stripped SHA-256. `file(1)` identifies both artifacts as x86-64 Linux ELF executables; the first is not stripped and the second is stripped. The manifest source, Cargo manifest/lockfile, compiler/profile, target, and artifact hash fields were checked against the pinned preparation metadata.

## Independent verification

`build_manifest.load_and_verify_manifest` independently passed for `hexyl-v0170` / `O3S` / `plain` / `x86_64-unknown-linux-gnu`. A read-only `pyelftools` check compared all `SHF_EXECINSTR` sections by section name, `sh_addr`, and raw bytes between the two artifacts; the exact matching sections were `.text`, `.init`, `.fini`, and `.plt`. This section comparison did not execute the target or perform symbol, GT, or extraction analysis.

The build outputs remain confined to `build/hexyl-v0170/`, which is ignored by the study-local `.gitignore`. This status document is the only study-level file added after the build.
