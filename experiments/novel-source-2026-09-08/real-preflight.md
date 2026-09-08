# CallKin-Real stripped-only preflight

Status: preparation only; the Real protocol/config are frozen, but no
CallKin-Real analysis or target execution has run. The controlled-study
`config.json`, hashes, observations, GT, linkage, and predictions remain
unchanged and are not inputs to discovery or inference.

The isolated source checkout is
`/mnt/c/Users/sumyr/playground/REV/CallKin-Real/worktrees/novel-source-2026-09-08`,
detached at `68ffa8dc1285546a1db52096a905a36fec094bd6`. It is clean. The dirty
main checkout remains at `main` with only the pre-existing edits to
`analyze.py`, `docs/usage.md`, and `test_oracle_firewall.py`; those edits were
not discarded or merged. The clean-worktree SHA-256 values are recorded below
for the analysis inputs:

```
analyze.py                         0cdf1d74b7ec44ddde1920bd5dfdccd54abbd2f43bca6798650532f629103c3a
callkin_real.py                    579afed06c325de27dbb27453a801353acff0674c6c9568b0c6c1c591afc7c5e
evaluate.py                        f8b98a6869e8fe30391e661b1d2ec9aaf02b9fc0f12e856e728cb0e7fd0bc071
requirements.txt                   9798185ee9a71b8c13ad87a0df24431f0545ba84bd796b51aa6bfafee8c19c68
frozen_v1/configs/v1.formal.json  77f394244c67b6633698e80af5265da4544c8ad5033aff7d0474a5ff8f1eebfa
```

The preserved dirty-main diff is limited to those three files and has SHA-256
`05970703543ad1730b6820ae0cc70713bca33eff5d304911a5ee97c60bb29323`; the
`analyze.py` change is documentation-only and the third change adds a test
call. The Real run uses the clean detached checkout above.

The only analysis input is the stripped ELF:
`build/hexyl-v0170/hexyl-v0170.O3S.fixture.bin`, SHA-256
`b067e03a3c6911409d64eff3027b11a05f5364c33f08e1bbb777b343b142594a`.
It is ELF64 x86-64 PIE (`ET_DYN`), with static `p_vaddr` base zero and entry
`0x4d240`. CallKin-Real uses static link-time VAs; no runtime module-base
offset may be applied.

The prepared interpreter is
`/mnt/c/Users/sumyr/playground/REV/CallKin/workspace/novel-source-real-venv/bin/python`
(CPython 3.12.3). Primary pins are r2pipe 1.9.8, angr 9.2.165, Capstone
5.0.3, pyelftools 0.31, pefile 2024.8.26, and pycparser 2.22; the complete
transitive freeze is `real-environment-lock.txt`. Radare2 is `/usr/bin/r2`
5.5.0. The lock SHA-256 is
`7aff9404b3b870e65c36c604a47be031778ed5fe737b1bccdfecbcfbf5445e3f`.
The controlled extraction used Sage Python 3.10.14 and controlled inference
used Python 3.12.3; Real uses Python 3.12.3 for all stages. The Rust
source/binary/compiler condition is unchanged (hexyl O3S/plain, Cargo/rustc
1.93.1), but Real discovery, `subject` scope, address anchors, and component
budgeting differ from the controlled provided-boundary policy. These runtime,
scope, and policy differences are separate conditions and must not support a
causal cross-condition quality claim.

After root freezes this prototype protocol, run from the clean worktree with
the external 12-GiB address-space and 3,600-second wall limits:

```bash
/usr/bin/prlimit --as=12884901888 -- /usr/bin/timeout \
  --signal=TERM --kill-after=10s 3600s \
  /mnt/c/Users/sumyr/playground/REV/CallKin/workspace/novel-source-real-venv/bin/python \
  analyze.py \
  /mnt/c/Users/sumyr/playground/REV/CallKin/worktrees/followup-2026-09-08/experiments/novel-source-2026-09-08/build/hexyl-v0170/hexyl-v0170.O3S.fixture.bin \
  --case hexyl-v0170 \
  --output-dir /mnt/c/Users/sumyr/playground/REV/CallKin/worktrees/followup-2026-09-08/experiments/novel-source-2026-09-08/real/hexyl-v0170 \
  --no-flirt --component-budgeted-v1
```

`--no-flirt` removes the Oxidizer dependency and produces no direct-label or
propagation artifact. `--component-budgeted-v1` derives a whole-component F5
queue for the frozen F6 ceiling. Defaults are `top_k=16`, F6 maximum 10,000
comparisons and 500,000,000 alignment cells, and F7 maximum 64 members,
4,096 comparisons, and 500,000,000 alignment cells. These F6/F7 budgets do
not replace the external analyzer resource envelope. Component budgeting is
intentional partial processing: selected whole components are validly
processed and deferred components/functions are retained as diagnostics. A
whole-queue/case resource or budget failure is `NA`.

Only after the named run completes may the separate evaluator read the
controlled GT and linkage files. Before that, the GT and linkage ID sets must
agree exactly on 568 IDs. The standard evaluator joins exact `FUN_` IDs; the
Real and linkage bias is `0x100000` (1,048,576). Real does not need to find all
568: validate each produced function’s actual static ELF VA against its
`FUN_{va+bias}` ID, then report Real∩GT and Real-missed IDs. A miss is a
discovery outcome, not a join failure. Primary quality is over the 568
GT-labelled targets that overlap the Real grouping universe; the full
discovered Real universe, component-selected/deferred functions and
components, and body coverage are diagnostics. A supplementary posthoc view
may retain the full 568-ID GT denominator and count missing IDs as unresolved;
this view never enters discovery or inference. A non-GT Real member is not
automatically an FP. The GT/linkage files must never be passed to
`analyze.py`.

The F10 catalog scorer is a different contract: it requires an `all-rust`
catalog with `id_bias`, owners, and matching stripped hash plus a direct-label
artifact and propagation prediction. No hexyl all-Rust catalog exists in this
study, and it is not applicable to this no-FLIRT run.
