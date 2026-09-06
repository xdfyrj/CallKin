# Retained research results

These JSON files are byte-for-byte copies of completed research outputs, not
new measurements made during repository integration. `manifest.json` records
each original output path and SHA-256.

- The three `*.evaluation.json` files use the same target universe and neutral
  pair rules for V0, strict V1, rescue and relaxed variants.
- WL-depth results and the runtime sidecar retain the original experiment identity.
- The complete raw body/extraction caches are not part of the default Git checkout.
  Unit tests and bundled golden fixtures do not require those caches.
- Re-running with the integrated source creates a new execution identity. Compare
  the stated metrics and inputs; do not expect a newly generated run manifest to
  have the hash of an older commit's report.

The results do not establish general F1 improvement: strict V1 reduces false
merges in all three programs, while F1 improves only in ripgrep. Rescue has a
positive development example and is not independently established as a general
recovery method.
