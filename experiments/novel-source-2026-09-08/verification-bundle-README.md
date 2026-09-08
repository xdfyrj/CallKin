# CallKin novel-source retained-output verification

This package verifies retained outputs for `hexyl-v0170`, `hyperfine-v1200`,
and `tokei-v1500`. It contains all 18 prediction artifacts, their terminal
metadata, original GT/linkage labels, the pinned normalized-origin exposure
list, and the three retained score JSON/CSV pairs.

Run the standalone checker after extraction with the pinned interpreter:

```text
env -u PYTHONPATH /usr/bin/python3.12 verify_retained_bundle.py .
```

The checker recomputes primary and both masked secondary pair metrics using the
bundled linkage policy and checks all 54 quality views against the retained
scores. It also checks member hashes, prediction hashes, exact label joins,
exposure-list canonical hashing, metadata identity, and compact CSV shape.

This is retained-output rescoring. It does not rebuild source or binaries,
recreate body/fixture/raw-graph observations, rerun candidate selection or
inference, or independently verify omitted candidate caches. Candidate SHA
pins remain in retained metadata and are checked when the original study
scorer ran; candidate files are omitted to keep this package bounded.

The `real/` entries document the separately frozen CallKin-Real hexyl
condition. Raw Real logs, scripts, resource dumps, binaries, source trees,
body evidence, candidate caches, and build artifacts are excluded.
