# Hexyl diagnostic

This is a read-only diagnostic of the frozen `hexyl-v0170` outcome. Every count is conditional on the retained normalized mangled-origin labels. It does not add labels, alter rules, tune thresholds, or claim source-definition independence.

The exact token-hash arm recovers `369` positive pairs (`F1=0.625424`), while strict `C3-token-cfg-relation` recovers `8` (`F1=0.021277`). Their complete primary metrics are:

| arm | TP/FP/FN/TN | precision | recall | F1 | macro_R | exact |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| exact-token-hash | 369/84/358/159626 | 0.814570 | 0.507565 | 0.625424 | 0.337751 | 0.146341 |
| C3-token-cfg-relation | 8/17/719/159693 | 0.320000 | 0.011004 | 0.021277 | 0.102787 | 0.073171 |

The exact arm's `369` TP are entirely shared dependency origins: `298` from `clap_builder` and `71` from `anyhow`; Hexyl-owned origins contribute `0`. The top three groups are all `clap_builder::builder::value_parser::AnyValueParser` origins and contribute `164/369` TP (`44.44%`):

| origin | positive pairs | exact recovered | accepted cluster evidence | strict C3 first-loss counts |
| --- | ---: | ---: | --- | --- |
| `<P as clap_builder::builder::value_parser::AnyValueParser>::type_id` | 78 | 78 | cluster 0, 13/13 | not retrieved 78 |
| `<P as clap_builder::builder::value_parser::AnyValueParser>::clone_any` | 78 | 55 | cluster 7, 11/13 | not retrieved 77; structure failed 1 |
| `<P as clap_builder::builder::value_parser::AnyValueParser>::possible_values` | 55 | 31 | clusters 5 and 6, 11/11 (one outside member) | not retrieved 27; slot policy failed 28 |

Strict C3's global first-loss counts are `not_retrieved_or_requested=413`, `observation_ineligible=53`, `structure_failed=93`, `slot_policy_failed=160`, and `recovered=8`. For the `possible_values` example `FUN_00167bb0`-`FUN_00167d00`, all structural, sequence, call, constant, and relation fields are `1.0` and the decision remains `unknown` under the strict slot policy. The exact arm groups equal TokenProfile hashes; the strict arm first loses many pairs before detailed comparison, then rejects some structurally similar pairs under its fixed slot policy.

The one project-owned positive pair is `hexyl::run::{{closure}}` at `FUN_0015b1a0` and `FUN_0015b260`. The pinned source is `sharkdp/hexyl` `v0.17.0`, commit `8eb6d4771ce1ec7af65d06bd335457783b77d557`; `src/main.rs:353-357` defines `parse_byte_count`, capturing `block_size` and used at lines 360 and 393. Both bodies decode completely with no opaque jumps, but their exact token hashes differ (`68f532...` versus `97633d...`) and neither strict B2/C3 candidate contains the pair. Both strict arms therefore first lose it as `not_retrieved_or_requested`; exact-token-hash has no accepted cluster containing it, so it is an FN.

The two previously unobserved normalized-origin positive pairs are:

| origin | addresses | B2/C3 result | exact-token result |
| --- | --- | --- | --- |
| `hexyl::run::{{closure}}` | `FUN_0015b1a0`-`FUN_0015b260` | candidate absent; not retrieved | no accepted pair; FN |
| `anyhow::context::impl_for=core::result::Result<T,E>::context` | `FUN_00173730`-`FUN_001737d0` | candidate absent; not retrieved | no accepted pair; FN |

The Anyhow bodies also have complete, non-opaque evidence but different exact token hashes (`a153cc...` versus `698752...`). The full raw mangled identities, body hashes, candidate-presence checks, mask metrics, provenance hashes, and strict stage counts are in [hexyl-diagnostic.json](hexyl-diagnostic.json). This dependency-heavy result explains the observed arm gap under the frozen label universe; it does not establish that exact-token recovery is independent source-definition evidence for Hexyl.

The companion [hexyl-source-audit.md](hexyl-source-audit.md) resolves the Hexyl closure pair at source-site granularity: `FUN_0015b260` is the line-342 seek `map_err` closure, while `FUN_0015b1a0` is the line-353 `parse_byte_count` closure. The normalized `hexyl::run::{{closure}}` positive is therefore a source-aware false positive under the authorized secondary split; the primary scores above remain frozen and unchanged. The exact six-arm before/after sensitivity is in [hexyl-source-site-sensitivity.md](hexyl-source-site-sensitivity.md).
