# Concrete Null Test

This directory preserves the two generic/concrete function-body counterexamples
used in the CallKin technical report. It contains the source pair, four retained
ELF artifacts, their original build notes, and a static regression check.

Run from any directory with Python 3.12 or later:

```bash
python experiments/concrete-null/test_concrete_null_test.py
```

The test reads the symbol extents from the non-stripped O3 files and compares the
corresponding bytes in the stripped O3S files. It does not execute the binaries.
The u8 pair is 78 bytes; the i32 pair is 166 bytes. Both corresponding pairs
must match the published SHA-256 values.

The recorded compiler is rustc 1.93.1 (LLVM 21.1.8), targeting x86-64 Linux.
All four source functions use `#[inline(never)]`. These are controlled existence
counterexamples, not a frequency estimate or a claim that all generic functions
become byte-identical to concrete code.

`manifest.json` records the exact retained files. The original build notes keep
their historical local paths; those paths are provenance, not required inputs.
Recompiling under another directory or compiler may change symbols and extents.
Do not overwrite these retained artifacts when trying a new build.

Source and artifacts were imported from the local `rust-loss` research repository
(base commit `161cdc5155b5096b58ccd0b19f7844e4230a3d36`). The original repository
and its Ghidra project remain preserved locally. Rust library license notices are
in the repository's `third_party/licenses/` directory.
