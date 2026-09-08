# Preliminary source audit: fd

Date: 2026-09-08

Scope: the 16 `fd-*` records in `audit-sample.json`. This audit used `protocol.md`, the fd source checkout, its `Cargo.lock`, the plain O3S build metadata, registry source copies, and the non-stripped binary’s symbol/disassembly evidence. It did not read predictions, results, or other audit judgments.

## Outcome

| Assessment | Records |
| --- | ---: |
| source-consistent | 15 |
| source-conflict | 1 |
| unresolved | 0 |

The clear label problem is **fd-09**: its two members are two different closure expressions in `WorkerState::build_overrides`, collapsed by closure-name normalization. **fd-11** is a valid shared-address boundary record: one address carries `cause` and `source`, which are two source methods and must remain neutral rather than become a positive source-definition pair.

These counts describe source-level consistency only. They do not establish rustc `DefId`, mono-item identity, or independent human verification.

## Provenance and checksum checks

- fd package: 10.4.2, Git commit `3c20fff2796199071d888c39438d79e270112a02`.
- Build metadata source SHA-256: `a01ffcf11c3e42ddcbade0a5453b25b676aa8b3cb410f044eae7a175a461c542`.
- Current `Cargo.lock` SHA-256: `ad1600fe99a6978ebd58ea8ac643896e6a8f1143da30e9aa4dff2e0753606736`, matching the build metadata.
- Current `Cargo.toml` SHA-256: `dcf000dd16375a089d6d829354ac1d5d953bc49451cc5f002bdbd6373763e86c`, matching the build metadata.
- Non-stripped binary SHA-256: `61d845af2b2f394c7439603f198e8439efdfdfcb80b189a40c55b754e3ee8fa9`, matching the build metadata.
- Compiler: rustc 1.93.1, commit `01f6ddf7588f42ae2d7eb0a2f21d44e8e96674cf`.

The extracted registry directories have `.cargo-ok` and `.cargo_vcs_info.json`, but no `.cargo-checksum.json`. I therefore hashed the cached `.crate` archives. Each applicable archive hash matched its `Cargo.lock` checksum:

| Crate | Version | Cargo.lock / cached archive SHA-256 | Registry VCS SHA-1 |
| --- | --- | --- | --- |
| aho-corasick | 1.1.4 | `ddd31a130427c27518df266943a5308ed92d4b226cc639f5a8f1002816174301` | `17f8b32e3b7c845ef3c5429b823804f552f14ec9` |
| anyhow | 1.0.102 | `7f202df86484c868dbad7eaa557ef785d5c66295e41b460ef922eca0723b842c` | `5c657b32522023a9f7ef883fb08582fd8e656b1a` |
| clap_builder | 4.5.60 | `24a241312cea5059b13574bb9b3861cabf758b879c15190b37b6d6fd63ab6876` | `20aac9d46e0852292bd43d845b6d9cb69c598c9e` |
| crossbeam-epoch | 0.9.18 | `5b82ac4a3c2ca9c3460964f020e1402edd5753411d7737aa39c3714ad1b5420e` | `9c3182abebb36bdc9446d75d4644190fef70fa01` |
| hashbrown | 0.16.1 | `841d1cc9bed7f9236f321df977030373f4a4163ae1a7dbfe1a51a2c1a51d9100` | `1876e4f02708b93903d55ef598f68e82a826518f` |
| jiff | 0.2.23 | `1a3546dc96b6d42c5f24902af9e2538e82e39ad350b0c766eb3fbf2d8f3d8359` | `e5b7f0d061e4da9598aed73f6171e78baa8b007f` |
| regex-automata | 0.4.14 | `6e1dd4122fc1595e8162618945476892eefca7b88c52820e74af6262213cae8f` | `5e195de266e203441b2c8001d6ebefab1161a59e` |
| walkdir | 2.5.0 | `29790946404f91d9c5d06f9874efddea1dc06c5efe94541a7d6863108e3a5e4b` | `4f26be4d450910916ea11533b2efc52b9a6483bc` |

`object` is absent from fd’s `Cargo.lock`. The binary embeds `/rust/deps/object-0.37.3`, identifying a compiler/sysroot dependency. The reference registry archive for object 0.37.3 hashes to `ff76201f031d8863c38aa7f905eca4f53abbfa15f609db4277d44cd8938f33fe` and records VCS SHA-1 `916c47b90e5c0bea139ca4bdfc53811f7d2c3383`; this does not prove that the sysroot copy has that exact revision.

Sample `FUN_` addresses use an analysis image base of `0x100000`. For example, `FUN_0027a400` maps to ELF `0x17a400`. The same subtraction maps all 108 sampled members to the matching non-stripped ELF symbols.

## Record findings

### fd-01 — source-consistent

Members: `FUN_002b1850`, `FUN_0034ab10`, `FUN_003d96f0`, `FUN_0041bac0`, `FUN_00451580`.

Source: aho-corasick 1.1.4, `src/nfa/contiguous.rs:319-321`, within the sole `unsafe impl Automaton for NFA`.

```rust
fn prefilter(&self) -> Option<&Prefilter> {
    self.prefilter.as_ref()
}
```

All five rebased addresses are separate ELF-local copies of this method. The concrete receiver and unique source method support one source definition. Code-generation duplication is plausible, but compiler origin IDs were not available.

### fd-02 — source-consistent

Members: `FUN_002b08c0`, `FUN_0034a3c0`, `FUN_003d8fa0`, `FUN_0041b370`, `FUN_00450d40`.

Source: aho-corasick 1.1.4, `src/dfa.rs:218-226`.

```rust
fn next_state(&self, _anchored: Anchored, sid: StateID, byte: u8) -> StateID {
    let class = self.byte_classes.get(byte);
    self.trans[(sid.as_u32() + u32::from(class)).as_usize()]
}
```

Each member resolves to the DFA `Automaton::next_state` implementation. The source contains one matching concrete method; the five emitted copies are source-consistent without proving compiler-level identity.

### fd-03 — source-consistent

Members: `FUN_002b1770`, `FUN_0034aa30`, `FUN_003d9610`, `FUN_0041b9e0`, `FUN_004514a0`.

Source: aho-corasick 1.1.4, `src/nfa/contiguous.rs:286-288`.

```rust
fn min_pattern_len(&self) -> usize {
    self.min_pattern_len
}
```

All five addresses resolve to this NFA trait method. No second matching source definition was found.

### fd-04 — source-consistent

Members: `FUN_00269f00`, `FUN_0026a020`, `FUN_0026a140`.

Source: clap_builder 4.5.60, `src/parser/matches/arg_matches.rs:1434-1448`.

```rust
impl<T> Iterator for Values<T> {
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(next) = self.iter.next() {
            self.len -= 1;
            Some(next)
        } else {
            None
        }
    }
}
```

The three addresses are generic instantiations of this definition. ELF `0x16a140` additionally has two distinct Rust symbol hashes at the same address; both still name the same source method.

### fd-05 — source-consistent

Members: `FUN_002c3f60`, `FUN_004c2480`.

Source: clap_builder 4.5.60, `src/error/mod.rs:668-684`.

```rust
pub(crate) fn value_validation(...) -> Self {
    let mut err = Self::new(ErrorKind::ValueValidation).set_source(err);
    // feature-gated context insertion
    err
}
```

Both addresses resolve to `Error<F>::value_validation`. One copy is attributed to an fd codegen unit and the other to a clap_builder codegen unit, consistent with one generic source method emitted in different compilation contexts.

### fd-06 — source-consistent, derive-qualified

Members: `FUN_00396670`, `FUN_003b5510`.

Source anchor: regex-automata 0.4.14, `src/util/prefilter/memchr.rs:65-66`.

```rust
#[derive(Clone, Debug)]
pub(crate) struct Memchr2(u8, u8);
```

Both addresses resolve to `Debug::fmt` for `Memchr2`. There is one derive site, but no explicit source span for the generated `fmt` body. This supports source consistency while leaving macro-expansion and compiler-item identity unproved.

### fd-07 — source-consistent

Members: `FUN_002b0300`, `FUN_002b03d0`, `FUN_002b0470`, `FUN_002b0540`, `FUN_002b0620`, `FUN_002b0700`.

Source: anyhow 1.0.102, `src/error.rs:778-785`.

```rust
unsafe fn object_reallocate_boxed<E>(e: Own<ErrorImpl>)
    -> Box<dyn StdError + Send + Sync + 'static>
{
    let unerased_own = e.cast::<ErrorImpl<E>>();
    Box::new(unsafe { unerased_own.boxed() }._object)
}
```

All six addresses carry distinct symbol hashes for this generic function. They are consistent with one definition instantiated for several `E` types; those concrete types were not recovered.

### fd-08 — source-consistent, compiler-vendor-qualified

Members: `FUN_00329200`, `FUN_0034f5f0`, `FUN_003c7090`, `FUN_003c7340`, `FUN_0041e370`, `FUN_0041e580`.

Source reference: hashbrown 0.16.1, `src/map.rs:1841-1852`.

```rust
pub fn insert(&mut self, k: K, v: V) -> Option<V> {
    let hash = make_hash::<K, S>(&self.hash_builder, &k);
    match self.find_or_find_insert_index(hash, &k) {
        // replace or insert
    }
}
```

The addresses resolve to six `HashMap::insert` instances in ignore, globset, regex_automata, and lscolors codegen units. Binary paths identify `/rust/deps/hashbrown-0.16.1`. Although `Cargo.lock` also contains hashbrown 0.15.5, no sampled member was tied to it. The exact revision of the compiler-vendored 0.16.1 copy remains unproved.

### fd-09 — source-conflict

Members: `FUN_0027a400`, `FUN_0027a470`.

Source: fd 10.4.2, `src/walk.rs:336-344`.

```rust
builder
    .add(pattern)
    .map_err(|e| anyhow!("Malformed exclude pattern: {}", e))?;

builder
    .build()
    .map_err(|_| anyhow!("Mismatch in exclude patterns"))
```

`FUN_0027a400` maps to ELF `0x17a400`, a 104-byte closure that performs formatting before constructing an `anyhow::Error`; this matches the line-339 `|e|` closure. `FUN_0027a470` maps to ELF `0x17a470`, a 71-byte closure that loads a fixed 28-byte message; this matches the line-344 `|_|` closure.

These are two distinct closure expressions, not monomorphizations of one closure. The normalized parent-function closure name has merged separate source definitions.

### fd-10 — source-consistent

Members: `FUN_004c45d0`, `FUN_004c4610`, `FUN_004c4650`.

Source: clap_builder 4.5.60, `src/error/mod.rs:354-360`.

```rust
pub(crate) fn extend_context_unchecked<const N: usize>(
    mut self,
    context: [(ContextKind, ContextValue); N],
) -> Self {
    self.inner.context.extend_unchecked(context);
    self
}
```

All three addresses resolve to this function with different symbol hashes. Generic `Error<F>` and const-generic `N` account for multiple emitted specializations.

### fd-11 — source-consistent shared-address boundary

Member: `FUN_00335b90`.

Source: walkdir 2.5.0, `src/error.rs:199-217`.

```rust
fn cause(&self) -> Option<&dyn error::Error> {
    self.source()
}

fn source(&self) -> Option<&(dyn error::Error + 'static)> {
    match self.inner {
        ErrorInner::Io { ref err, .. } => Some(err),
        ErrorInner::Loop { .. } => None,
    }
}
```

ELF address `0x235b90` carries both method symbols at exactly the same address. The source has two definitions. This confirms the record’s shared-address nature and the need to keep it neutral; it must not be interpreted as a same-definition positive.

### fd-12 — source-consistent, sysroot-qualified

Member: `FUN_0050cb20`.

Source reference: compiler-vendored object 0.37.3, `src/read/read_ref.rs:141-152`.

```rust
fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8)
    -> Result<&'a [u8]>
{
    let bytes = self.get(start..end).ok_or(())?;
    match memchr::memchr(delimiter, bytes) {
        Some(len) => bytes.get(..len).ok_or(()),
        None => Err(()),
    }
}
```

The rebased address resolves to the concrete `ReadRef for &[u8]` method. The binary embeds object 0.37.3 source paths, but fd’s `Cargo.lock` has no object package. The registry copy supports the source-level mapping without proving the sysroot’s exact source revision.

### fd-13 — source-consistent, closure-qualified

Members: `FUN_002714d0`, `FUN_0028a490`, `FUN_0028a4e0`, `FUN_0028a530`, `FUN_0035bca0`, `FUN_0035fc50`, `FUN_0035fca0`, `FUN_0035fcf0`, `FUN_003696e0`, `FUN_0036d210`.

Source: jiff 0.2.23, `src/error/mod.rs:740-749`.

```rust
fn context(self, consequent: impl IntoError) -> Result<T, Error> {
    self.map_err(|err| {
        err.into_error().context_impl(consequent.into_error())
    })
}
```

The method contains exactly one closure expression, and all ten members resolve to it with distinct hashes. Generic `T`, `E`, and consequent types explain the multiplicity, but their address-level assignments were not recovered.

### fd-14 — source-consistent, shim-qualified

Members: `FUN_0026e6a0`, `FUN_0026e730`, `FUN_0026e7d0`, `FUN_0026e860`.

Underlying source: clap_builder 4.5.60, `src/parser/matches/arg_matches.rs:1893-1896`.

```rust
fn unwrap_downcast_into<T: Any + Clone + Send + Sync + 'static>(value: AnyValue) -> T {
    value.downcast_into().expect(INTERNAL_ERROR_MSG)
}
```

All four addresses are distinct `reify.shim` symbols associated with this generic function. A reify shim is compiler-generated and has no independent source span, so the group is consistent only at the underlying-definition level.

### fd-15 — source-consistent, trait-qualified

Member: `FUN_00336600`.

Source: crossbeam-epoch 0.9.18, `src/atomic.rs:194-214`.

```rust
impl<T> Pointable for T {
    unsafe fn drop(ptr: usize) {
        drop(Box::from_raw(ptr as *mut T));
    }
}
```

The rebased address resolves to the blanket `Pointable::drop` implementation. The concrete `T` and compiler item identity are not present in the normalized symbol.

### fd-16 — source-consistent, monomorphization-qualified

Members (52): `FUN_00379c60`, `FUN_00379cd0`, `FUN_00379d40`, `FUN_00379db0`, `FUN_00379e20`, `FUN_00379ea0`, `FUN_00379f20`, `FUN_00379f90`, `FUN_0037a000`, `FUN_0037a070`, `FUN_0037a0e0`, `FUN_0037a160`, `FUN_0037a1e0`, `FUN_0037a250`, `FUN_0037a2c0`, `FUN_0037a330`, `FUN_0037a3a0`, `FUN_0037a410`, `FUN_0037a480`, `FUN_0037a4f0`, `FUN_0037a560`, `FUN_0037a5e0`, `FUN_0037a660`, `FUN_0037a6d0`, `FUN_0037a740`, `FUN_0037a7b0`, `FUN_0037a820`, `FUN_0037a890`, `FUN_0037a900`, `FUN_0037a970`, `FUN_0037a9e0`, `FUN_0037aa50`, `FUN_0037aac0`, `FUN_0037ab30`, `FUN_0037aba0`, `FUN_0037ac10`, `FUN_0037ac80`, `FUN_0037acf0`, `FUN_0037ad60`, `FUN_0037add0`, `FUN_0037ae40`, `FUN_0037aeb0`, `FUN_0037af20`, `FUN_0037af90`, `FUN_0037b000`, `FUN_0037b080`, `FUN_0037b0f0`, `FUN_0037b160`, `FUN_0037b1d0`, `FUN_0037b240`, `FUN_0037b2b0`, `FUN_0037b320`.

Source: jiff 0.2.23, `src/util/b.rs:689-703`.

```rust
impl<B, P> core::fmt::Display for RawBoundsError<B>
where
    B: Bounds<Primitive = P>,
    P: core::fmt::Display,
{
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "parameter '{what}' is not in the required range of {min}..={max}", ...)
    }
}
```

All 52 rebased addresses are ELF-local symbols for this item with distinct hashes and specialization-specific constants or formatting references. They are consistent with one generic source definition instantiated for many bound-marker types. Exact `B` assignments and compiler origin IDs were not established.

## Interpretation limits

This review goes beyond a name lookup by checking the actual definitions, crate versions, source archives, ELF address mapping, and—in the fd-09 conflict—the closures’ distinct source expressions and machine behavior. It still cannot prove compiler-internal identity. Trait dispatch, derive expansion, closures, generated shims, and monomorphization all weaken a direct name-to-definition inference. The work is an LLM-assisted internal audit, not an external or independent human audit.
