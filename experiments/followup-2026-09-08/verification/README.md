# Retained-prediction recheck

Extract verification-bundle.zip, then run:

    python3 recheck.py

Only the Python standard library is required. The bundled linkage_overlay.py is the existing CallKin pair-label implementation. The script verifies file hashes and independently aggregates TP/FP/FN/TN from actual predicted clusters and the linkage labels for every completed configuration. Budget-refused configurations have no prediction and remain NA. It also checks the two source-correction sensitivity results.

This is a rescore of retained predictions, not a rebuild or fresh prediction generation. Input observations and candidate caches for the three large programs are not in this bundle. The separate minimal/replay.py example generates F5/F6 predictions from small bundled observations. Neither is external-human or full source-to-score reproduction.
