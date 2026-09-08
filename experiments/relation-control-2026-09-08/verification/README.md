# Relation-control retained-prediction recheck

This bundle verifies the frozen relation-control outputs by rescoring retained
predictions with the bundled `linkage_overlay.py`. It does not contain body
observations, candidate caches, disassembly, source checkout, or an inference
runner. It cannot create a new prediction and is not an external-human or
full source-to-score reproduction.

After extracting `verification-bundle.zip`, run:

    python3 verification/recheck.py

The checker verifies the SHA-256 manifest, frozen config/protocol identity,
all configured case/arm metadata, and each completed prediction hash. It
independently checks the exact target join and recomputes TP, FP, FN, TN,
precision, recall, and F1 under primary and original linkage labels. A
`budget-refused` or `resource-incomplete` arm must have no prediction and
keeps all quality fields as `NA`; it is never converted to a zero score.

The primary label is source-corrected for fd and zoxide, with the original
label as secondary sensitivity. ripgrep-main uses its original labels only.
The optional `--include-selection` builder flag includes compressed selection
manifests for provenance; it does not add observation data.
