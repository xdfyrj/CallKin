# Zoxide source-grounded preliminary audit — 2026-09-08

This audit reviews only the 16 frozen zoxide records in `audit-sample.json` under the frozen `protocol.md`. I did not read prediction/result files or other audit judgments. Assessments mean source-level consistency only; they are neither rustc internal origin-ID proof nor independent human validation. Unknown evidence remains unresolved.

## Result

| Assessment | Count |
|---|---:|
| source-consistent | 14 |
| source-conflict | 1 |
| unresolved | 1 |
| total | 16 |

The strongest potential label problem is **zoxide-10**. The normalized path `parse_line::{{closure}}` groups three machine functions, but the exact zoxide source contains three different lexical closure definitions at lines 42, 45, and 48. Their raw ELF symbol hashes, sizes, constants, and behavior differ and map one-to-one to those three sites. This is source-conflict if the normalized group is treated as one positive source origin.

The second notable issue is **zoxide-11**. The frozen record lists three anyhow symbols at one shared address, while the ELF symbol table reports a fourth alias, `<alloc::borrow::Cow<B> as core::fmt::Display>::fmt`, at the same address. The existing shared-address neutral rule is preserved, so this record remains unresolved rather than being relabeled.

## Frozen provenance

- Protocol SHA-256: `ebe463808b7d8461e0e5dd4f7f340c64c51b73c40b2553082d1a926e46d11705`
- Audit sample SHA-256: `589e153719947ce42dd56bf8a73455b6702b3ababea0bce507d4e53a76b7bcda`
- Build-info SHA-256: `0a316f47b8b7e0c5721c645783043b13c2dc4a8afb3e5adff37370f27b8022a0`
- Source-tree SHA-256 recorded by build info: `3302869e7a42a926fc3e6113bf793f9bed85f75850c466838064a12db66a2154`
- Cargo.lock SHA-256: `71b25bc9910a0587d7a719bd8f2910a88d77ef2f9f3c8b6eb477f9ff7d552508`
- Cargo.toml SHA-256: `17c749d4633ce9b24382b2d18c1456d451f6c200f97b041bf16a24e762add453`
- Non-stripped input binary SHA-256: `a37ccf63601b2012ba0edbc2ab63d9442f4830fbb41e6b87f1c43a16f32dba7c`
- Compiler: rustc 1.93.1 (`01f6ddf75`, 2026-02-11), x86_64-unknown-linux-gnu
- Profile: opt-level 3, 16 codegen units, no LTO, debuginfo 0, panic unwind

The `FUN_` identifiers retain the frozen Ghidra addresses. Matching ELF symbols are at those hexadecimal addresses minus the `0x100000` Ghidra image base.

The unpacked registry directories have no `.cargo-checksum.json`, so per-file comparison against that file was unavailable. Each locally cached `.crate` archive was SHA-256 checked against the relevant lock entry. The zoxide dependencies matched zoxide's Cargo.lock; addr2line and object matched the rustc 1.93.1 sysroot library Cargo.lock.

| Package | Version | Package SHA-256 / lock checksum | Match |
|---|---:|---|---|
| anyhow | 1.0.102 | `7f202df86484c868dbad7eaa557ef785d5c66295e41b460ef922eca0723b842c` | zoxide lock |
| askama | 0.16.0 | `f1bf825125edd887a019d0a3a837dcc5499a68b0d034cc3eb594070c3e18addc` | zoxide lock |
| bincode | 1.3.3 | `b1f45e9417d87227c7a56d22e471c6206462cba514c7590c09aff4cf6d1ddcad` | zoxide lock |
| clap_builder | 4.6.0 | `714a53001bf66416adb0e2ef5ac857140e7dc3a0c48fb28b2f10762fc4b5069f` | zoxide lock |
| time | 0.3.47 | `743bd48c283afc0388f9b8827b976905fb217ad9e647fae3a379a9283c4def2c` | zoxide lock |
| aliasable | 0.1.3 | `250f629c0161ad8107cf89319e990051fae62832fd343083bea452d93e2205fd` | zoxide lock |
| ouroboros | 0.18.5 | `1e0f050db9c44b97a94723127e6be766ac5c340c48f2c4bb3ffa11713744be59` | zoxide lock |
| ouroboros_macro | 0.18.5 | `3c7028bdd3d43083f6d8d4d5187680d0d3560d54df4cc9d752005268b41e64d0` | zoxide lock |
| addr2line | 0.25.1 | `1b5d307320b3181d6d7954e663bd7c774a838b8220fe0593c86d9fb09f498b4b` | rustc sysroot lock |
| object | 0.37.3 | `ff76201f031d8863c38aa7f905eca4f53abbfa15f609db4277d44cd8938f33fe` | rustc sysroot lock |

## Record findings

### zoxide-01 — source-consistent

- Members: `FUN_0016dee0`, `FUN_0016df80`, `FUN_0016e030`, `FUN_0016e140`, `FUN_0016e1c0`, `FUN_0016e2b0`, `FUN_0016e360`
- Frozen symbol: `anyhow::error::context_drop_rest`
- Definition: anyhow 1.0.102, `src/error.rs:835-849`
- Source file SHA-256: `38aaae2c0067c25137d6528bb1e32dc60122efe285559d50bbca854a0656d8fc`
- Evidence: the exact generic definition `context_drop_rest<C, E>` branches on `TypeId::of::<C>()` and drops the complementary field of `ContextError<C,E>`. Seven local bodies in zoxide CGU 03 vary from 0x7b to 0x107 bytes, which is consistent with C,E monomorphs.
- Limitation: the source supports one origin but does not prove rustc internal origin IDs for all seven functions.

### zoxide-02 — source-consistent

- Members: `FUN_0016cb10`, `FUN_0016fec0`
- Frozen symbol: `<time::error::try_from_parsed::TryFromParsed as core::fmt::Display>::fmt`
- Definition: time 0.3.47, `src/error/try_from_parsed.rs:19-29`
- Source file SHA-256: `30474fc2c707471bcfbd314a098b15dfd7c009af85f67a845f669e4dfa69d23f`
- Evidence: one exact Display impl matches `InsufficientInformation` or delegates `ComponentRange(err)` to `err.fmt(f)`. The binary contains two 0x51-byte copies in zoxide CGUs 02 and 03.
- Limitation: source does not explain why rustc retained two copies.

### zoxide-03 — source-consistent

- Members: `FUN_00179730`, `FUN_0017a2c0`
- Frozen symbol: `<clap_builder::builder::value_parser::EnumValueParser<E> as clap_builder::builder::value_parser::TypedValueParser>::parse_ref`
- Definition: clap_builder 4.6.0, `src/builder/value_parser.rs:1091-1137`
- Source file SHA-256: `4342c19e43fc783b7adea44c74d3bd35a13ee0f7982d79e63867c9d7258d4042`
- Evidence: the exact generic trait method enumerates `E::value_variants()`, finds a matching possible value, clones it, and returns E. The two binary bodies have different sizes, 0xb81 and 0x6cb, consistent with different E monomorphs.
- Ambiguity: concrete E substitutions are erased by the demangled names.

### zoxide-04 — source-consistent

- Members: `FUN_0016caf0`, `FUN_0016fea0`
- Frozen symbol: `<time::error::try_from_parsed::TryFromParsed as core::error::Error>::source`
- Definition: time 0.3.47, `src/error/try_from_parsed.rs:50-58`
- Source file SHA-256: `30474fc2c707471bcfbd314a098b15dfd7c009af85f67a845f669e4dfa69d23f`
- Evidence: the sole Error::source impl returns `None` for insufficient information and `Some(err)` for component range. The binary has two 0x12-byte copies in zoxide CGUs 02 and 03.
- Limitation: common compiler origin remains unproved.

### zoxide-05 — source-consistent

- Members: `FUN_0016e5d0`, `FUN_0016e6a0`
- Frozen symbol: `anyhow::error::context_chain_drop_rest`
- Definition: anyhow 1.0.102, `src/error.rs:868-888`
- Source file SHA-256: `38aaae2c0067c25137d6528bb1e32dc60122efe285559d50bbca854a0656d8fc`
- Evidence: one generic `context_chain_drop_rest<C>` definition drops the context or recursively invokes the next error's `object_drop_rest` vtable entry. The bodies are 0xc2 and 0xf5 bytes, consistent with C monomorphs.
- Ambiguity: concrete C types are absent from displayed symbols.

### zoxide-06 — source-consistent

- Members: `FUN_0016ac90`, `FUN_0016d4d0`
- Frozen symbol: `<askama::error::Error as core::error::Error>::source`
- Definition: askama 0.16.0 archive, `src/error.rs:71-83`
- Source file SHA-256: `a167bbb03d02c7e627867a7f3cb1e2b4cf2c8369e30d084c361dc5a4e82cf4ab`
- Evidence: the sole StdError::source impl handles the exact Error variants, including cfg-gated wrapped sources. The binary has two 0x2b-byte copies in zoxide CGUs 02 and 03.
- Limitation: the unpacked crate was absent; the source was read from the checksum-matching local crate archive.

### zoxide-07 — source-consistent

- Members: `FUN_001defc0`, `FUN_001df130`
- Frozen symbol: `<clap_builder::util::flat_set::FlatSet<T> as core::iter::traits::collect::FromIterator<T>>::from_iter`
- Definition: clap_builder 4.6.0, `src/util/flat_set.rs:103-111`
- Source file SHA-256: `6c7852c7fe57346ac77e84ca32a4856ebf55b6e7540cc15635077d548481160b`
- Evidence: one generic FromIterator impl constructs a FlatSet and inserts every value. The two functions are 0x16e and 0x476 bytes, consistent with different T/iterator monomorphs.
- Ambiguity: concrete monomorph types are not retained in the demangled symbols.

### zoxide-08 — source-consistent

- Members: `FUN_0016b1b0`, `FUN_0016d620`
- Frozen symbol: `<time::error::parse::Parse as core::fmt::Display>::fmt`
- Definition: time 0.3.47, `src/error/parse.rs:29-39`
- Source file SHA-256: `14efda450fb37c06de9ea4d88849433d21d3003e127ef48abf6ec2da773973ae`
- Evidence: the sole Display impl delegates its parse-error variants. The binary contains two identical-size 0xe3-byte copies in zoxide CGUs 02 and 03.
- Limitation: source consistency does not establish why both copies survived code generation.

### zoxide-09 — source-consistent

- Members: `FUN_0017f2c0`, `FUN_0017f3d0`
- Frozen symbol: `bincode::internal::deserialize_seed`
- Definition: bincode 1.3.3, `src/internal.rs:109-124`
- Source file SHA-256: `ac343424a43899f4f9d44855484bc84cd86a07fafc9ae721d92a2095afeb8b05`
- Evidence: one generic function creates a SliceReader and Deserializer, invokes `seed.deserialize`, and checks trailing bytes. Bodies of 0x108 and 0x237 bytes are consistent with different T,O substitutions.
- Ambiguity: concrete generic substitutions are absent from displayed symbols.

### zoxide-10 — source-conflict

- Members: `FUN_00191360`, `FUN_00191460`, `FUN_001915a0`
- Frozen normalized symbol: `zoxide::import::autojump::Iter<R>::parse_line::{{closure}}`
- Definition context: zoxide 0.10.0, `src/import/autojump.rs:40-56`; separate closure sites at lines 42, 45, and 48
- Source file SHA-256: `3f667b41f84e2c664449f369e4a45ff7e65eeb273af07e9ee26688ce5a8d2d70`
- Evidence:
  - `FUN_00191360`: ELF 0x91360, size 0xf7, raw hash `h2429bb82563ad62e`; loads the 13-byte invalid-UTF-8 context and matches line 42.
  - `FUN_00191460`: ELF 0x91460, size 0x13c, raw hash `h3bc09c508947c4e3`; formats the invalid-rank context and matches line 48.
  - `FUN_001915a0`: ELF 0x915a0, size 0xd2, raw hash `hd1c51497fea92d1e`; builds the invalid-entry formatted error and matches line 45.
- Judgment: these are three lexical source definitions, not three demonstrated instances of one closure definition.
- Limitation: zoxide line tables were unavailable for these local functions, so the site mapping uses exact source semantics, constants, calls, raw symbol hashes, and disassembly.

### zoxide-11 — unresolved

- Member: `FUN_00188200`
- Frozen symbols:
  - `<anyhow::wrapper::DisplayError<M> as core::fmt::Debug>::fmt`
  - `<anyhow::wrapper::DisplayError<M> as core::fmt::Display>::fmt`
  - `<anyhow::wrapper::MessageError<M> as core::fmt::Display>::fmt`
- Definitions: anyhow 1.0.102, `src/wrapper.rs:22-29,36-43,45-52`
- Source file SHA-256: `079218e1d8c9374f52311b1c7971f7fbdeba4d7af1b0749c0d535010f1232697`
- Evidence: these are three distinct impl methods with tiny delegating bodies. At ELF VMA 0x88200, nm reports all three plus `<alloc::borrow::Cow<B> as core::fmt::Display>::fmt`, each size 0x14.
- Judgment: keep the existing shared-address neutral treatment. The source supports distinct definitions; it does not prove the folding/aliasing mechanism, and the frozen symbol list is not exhaustive relative to nm.

### zoxide-12 — source-consistent

- Member: `FUN_00225630`
- Frozen symbol: `<&[u8] as object::read::read_ref::ReadRef>::read_bytes_at_until`
- Definition: object 0.37.3, `src/read/read_ref.rs:126-152`; method at 141-152
- Source file SHA-256: `e4cde2146aa97d5968d954a2c09e6fa0eec79d743ce7917e4b90a2afe0570f4c`
- Evidence: the exact &[u8] trait method converts range endpoints, slices the input, and returns bytes preceding `memchr(delimiter)`. The ELF has one public 0x4f-byte function with the exact raw symbol.
- Limitation: object is not in zoxide Cargo.lock; version provenance comes from the recorded rustc sysroot lock.

### zoxide-13 — source-consistent

- Member: `FUN_00222e90`
- Frozen symbol: `addr2line::unit::ResUnit<R>::find_function_or_location::{{closure}}`
- Definition: addr2line 0.25.1, `src/unit.rs:169-193`; closure at 179-192
- Source file SHA-256: `ec201e91333dc8919ab64f0144025521c46ac897679538432a84788af5244667`
- Evidence: `find_function_or_location` calls `dwarf_and_unit(ctx).map(move |r| { ... })`. The 0x2de-byte ELF function resolves directly through addr2line to `/rust/deps/addr2line-0.25.1/src/unit.rs:179`.
- Limitation: this direct source line still is not a compiler internal origin ID.

### zoxide-14 — source-consistent

- Member: `FUN_001860a0`
- Frozen symbol: `<zoxide::db::ouroboros_impl_database::Database as core::ops::drop::Drop>::drop`
- Subject source: zoxide 0.10.0, `src/db/mod.rs:15-23`, file SHA-256 `c2f15520277af47cc5bf158f8b1e5f99e1e111f9d9cd4dc190d37fbde6a0bf60`
- Generator source: ouroboros_macro 0.18.5, `src/generate/drop.rs:6-22`, extracted source SHA-256 `f68309aee77b775deb038a26b0ff350663d26b1ee5d9a11e03384b28995342ca`
- Evidence: `#[self_referencing]` is applied to Database. The exact macro generator emits an impl Drop whose body calls `self.actual_data.assume_init_drop()`. The binary contains one 0xcd-byte function naming `ouroboros_impl_database::Database`.
- Limitation: the generated method has no handwritten source span; attribution uses the exact macro invocation and checksum-matching generator.

### zoxide-15 — source-consistent

- Member: `FUN_0017f610`
- Frozen symbol: `<aliasable::boxed::AliasableBox<T> as core::ops::drop::Drop>::drop`
- Definition: aliasable 0.1.3, `src/boxed.rs:67-74`
- Source file SHA-256: `c4f381710fb24569959b20f52525f4b3121faf6038ee7f10c874bb4097695de8`
- Evidence: the generic Drop impl reclaims the aliasable pointer as a UniqueBox so normal deallocation runs. The binary contains one 0x2f-byte matching function.
- Limitation: this singleton supplies no within-group cross-check.

### zoxide-16 — source-consistent

- Members: `FUN_0016b9d0`, `FUN_0016baa0`, `FUN_0016bb60`, `FUN_0016bc20`, `FUN_0016bcd0`, `FUN_0016bd80`, `FUN_0016be50`, `FUN_0016bf10`, `FUN_0016bfd0`, `FUN_0016c090`, `FUN_0016c170`, `FUN_0016c230`, `FUN_0016c2f0`, `FUN_0016c3b0`, `FUN_0016c480`, `FUN_0016c540`, `FUN_0016c600`, `FUN_0016c6a0`, `FUN_0016c740`
- Frozen symbol: `anyhow::error::<impl anyhow::Error>::construct`; normalized origin rewrites this to `impl=anyhow::Error`
- Definition: anyhow 1.0.102, `src/error.rs:272-299`; function at 278-299
- Source file SHA-256: `38aaae2c0067c25137d6528bb1e32dc60122efe285559d50bbca854a0656d8fc`
- Evidence: one generic unsafe `construct<E>` boxes `ErrorImpl<E>`, erases E through `Own::cast`, and returns Error. Nineteen binary bodies in zoxide CGU 02 range from 0x9d to 0xd1 bytes, consistent with many E monomorphizations.
- Limitation: normalization erases concrete substitutions. The source supports a common definition but does not prove every compiler instance has one internal origin ID.

## Interpretation limits

The 14 source-consistent judgments mean the exact locked source contains one matching definition, and generic/codegen variation plausibly explains the observed members. They do not certify compiler provenance. The one source-conflict is direct evidence that name normalization can collapse distinct lexical closures. The unresolved shared-address record remains neutral under the frozen protocol and is not converted into either a positive or negative label.
