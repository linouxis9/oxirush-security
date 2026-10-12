# Changelog

All notable changes to `oxirush-security` are recorded here.

## Unreleased (0.3.0)

### Breaking changes relative to 0.2.0

No public function panics on its arguments any more. 0.2.0 took the
algorithm, the direction, the bearer and the COUNT as integers and panicked
on a value out of range, as its `# Panics` sections said. A value that a
specification bounds now has a type that holds only the values in range,
and what a type cannot say is a `Result`. Every call below changes.

- **New types**, at the crate root and in `nas_5gs`, `nas_eps` and `common`:

  | Type | Values | From an integer |
  |------|--------|-----------------|
  | `IntegrityAlgorithm` | `Null`, `Snow3g`, `Aes`, `Zuc`, also named `NIA0` to `NIA3` and `EIA0` to `EIA3` | `try_from(u8)`, `Err(UnsupportedAlgorithm)` for 4 and above |
  | `CipheringAlgorithm` | `Null`, `Snow3g`, `Aes`, `Zuc`, also named `NEA0` to `NEA3` and `EEA0` to `EEA3` | `try_from(u8)` |
  | `Direction` | `Uplink` (0), `Downlink` (1) | `try_from(u8)` |
  | `NasCount` | 0 to 2^24 - 1 | `new(u32)`, `try_from(u32)`, `from_parts(overflow, sequence_number)` |
  | `AccessKeyCount` | `Nas(NasCount)`, or `Handover` for 2^32 - 1 | `try_from(u32)`; a `NasCount` converts into it |
  | `NasConnection` (5GS) | `ThreeGpp` (1), `Non3Gpp` (2) | `try_from(u8)` |
  | `Bearer` | 0 to 31 | `new(u8)`, `try_from(u8)`; a `NasConnection` converts into it |

  `u8::from` and `u32::from` give the number back.

- **NAS integrity and ciphering.** `nas_mac` and `nas_cipher` take these
  types and cannot fail:

  ```rust
  // 0.2.0
  let mac = nas_5gs::nas_mac(&key, count, 1, 0, &message, 2);
  nas_eps::nas_cipher(&key, count, 1, &mut data, 2);

  // 0.3.0
  let count = NasCount::new(count)?;
  let mac = nas_5gs::nas_mac(
      &key, count, NasConnection::ThreeGpp, Direction::Uplink, &message, IntegrityAlgorithm::NIA2,
  );
  nas_eps::nas_cipher(&key, count, Direction::Downlink, &mut data, CipheringAlgorithm::EEA2);
  ```

  `nas_container_mac`, `nas_eps::re_establishment_nas_mac`,
  `service_request_short_mac` and `service_request_short_mac_with_header`
  take them too. `re_establishment_nas_mac` returns a `Result`, for a cell
  identity above 28 bits, and so does
  `service_request_short_mac_with_header`, for a first octet that is not
  that of a SERVICE REQUEST.

- **The algorithms.** `nas_mac` and `nas_cipher` at the crate root are now
  those of `nas_5gs`, for a NAS message. In 0.2.0 the root had the
  algorithms themselves under these names, which take any 32-bit COUNT and a
  5-bit BEARER. They are renamed after what they are, in `common`, in
  `common::nia` and `common::nea`, at the crate root, and in
  `nas_5gs::security` and `nas_eps::security`:

  | 0.2.0 | 0.3.0 |
  |-------|-------|
  | `common::nas_mac(key, count, bearer: u8, direction: u8, message, algo_id: u8) -> u32` | `nia_mac(key, count, Bearer, Direction, message, IntegrityAlgorithm) -> u32` |
  | `common::nas_mac_bits(.., bit_length, algo_id) -> u32` | `nia_mac_bits(.., bit_length, IntegrityAlgorithm) -> Result<u32, SecurityError>` |
  | `common::nas_cipher(key, count, bearer, direction, data, algo_id)` | `nea_cipher(key, count, Bearer, Direction, data, CipheringAlgorithm)` |
  | `common::nas_cipher_bits(.., bit_length, algo_id)` | `nea_cipher_bits(.., bit_length, CipheringAlgorithm) -> Result<(), SecurityError>` |
  | `nia1_mac(.., message, bit_length) -> u32` | `nia1_mac_bits(.., message, bit_length) -> Result<u32, SecurityError>`; `nia1_mac(.., message) -> u32` is the MAC of whole octets |
  | `nia3_mac(.., message, bit_length) -> u32` | `nia3_mac_bits(..)` and `nia3_mac(..)`, likewise |
  | `nia2_mac_bits(..) -> u32` | `-> Result<u32, SecurityError>` |
  | `nea1_cipher_bits`, `nea2_cipher_bits`, `nea3_cipher_bits` | `-> Result<(), SecurityError>` |

  Each takes a `Bearer` and a `Direction` where 0.2.0 took two `u8`. The
  whole-octet functions cannot fail. A `*_bits` function returns
  `Err(BitLengthExceedsData)` for a length that the buffer does not hold.
  Call `nia_mac` or `nea_cipher` where an input is outside NAS, such as the
  test sets of TS 33.401 Annex C or a PDCP COUNT, and `nas_mac` or
  `nas_cipher` for a NAS message.

- **Algorithm keys.** A function for each key replaces `derive_nas_key`,
  `derive_as_key` and `nas_eps::derive_sgnb_algorithm_key`, which took the
  algorithm type distinguisher and the algorithm identity as two `u8`. Each
  returns the 128-bit key, so the call to `extract_128` goes away:

  | 0.2.0 | 0.3.0 |
  |-------|-------|
  | `extract_128(&derive_nas_key(&k, 0x01, id))` | `derive_knas_enc(&k, CipheringAlgorithm)` |
  | `extract_128(&derive_nas_key(&k, 0x02, id))` | `derive_knas_int(&k, IntegrityAlgorithm)` |
  | `extract_128(&derive_as_key(&k, 0x03, id))` | `derive_krrc_enc(&k, CipheringAlgorithm)` |
  | `extract_128(&derive_as_key(&k, 0x04, id))` | `derive_krrc_int(&k, IntegrityAlgorithm)` |
  | `extract_128(&derive_as_key(&k, 0x05, id))` | `derive_kup_enc(&k, CipheringAlgorithm)` |
  | `extract_128(&derive_as_key(&k, 0x06, id))` | `derive_kup_int(&k, IntegrityAlgorithm)` |
  | `nas_eps::derive_sgnb_algorithm_key(&s_kgnb, type, id)` | `nas_5gs::derive_krrc_enc(&s_kgnb, ..)` and the three beside it, which are the function of TS 33.501 Annex A.8 that TS 33.401 Annex A.19 names |

  They exist in `nas_5gs` (from KAMF and KgNB) and in `nas_eps` (from KASME
  and KeNB). For the 256-bit output, or for an identity that is reserved,
  build the input yourself: `kdf(&k, &build_s(0x69, &[&[type], &[id]])?)`.

- **Key derivations that take a NAS COUNT** take a `NasCount`:
  `derive_kn3iwf`, `derive_mapped_kasme_idle`,
  `derive_mapped_kasme_handover`, `derive_kasme_srvcc`, `derive_kamf_prime`
  and its `_idle` and `_handover` forms, and in `nas_eps`
  `derive_ck_ik_handover`, `derive_nas_token_full`, `derive_nas_token`,
  `derive_ck_ik_srvcc`, `derive_ck_ik_idle_mobility` and
  `derive_mapped_kamf_idle`. `derive_kamf_prime` and its two forms return
  the key and no longer a `Result`.

- **KgNB and KeNB.** `derive_kgnb` and `nas_eps::derive_kenb` take a
  `NasCount`, or `AccessKeyCount::Handover` where 0.2.0 took `0xffff_ffff`
  for a handover (TS 33.501 §6.9.2.3.3, §8.3.2 and §8.4.2).
  `AccessKeyCount::try_from(u32)` reads a stored value that is one or the
  other. 0.2.0 let `derive_kenb` take any 32-bit value, although the EPS NAS
  COUNT has 24 bits (TS 24.301 §4.4.3.1).

- **Functions that return a `Result` where 0.2.0 panicked:**

  | Function | Error |
  |----------|-------|
  | `derive_kausf`, `derive_kseaf`, `derive_kamf`, `nas_eps::derive_kn`, `kdf::build_s` | `InputTooLong` for a parameter above 65535 octets |
  | `compute_xres_star`, which now returns `[u8; 16]` and no longer a `Vec<u8>` | `InputTooLong`, and `InvalidParameter` for an XRES that is not 4 to 16 octets long |
  | `derive_kng_ran_star`, `derive_kng_ran_star_ng_enb`, `nas_eps::derive_kenb_star` | `OutOfRange` for a PCI or an ARFCN above its largest value |
  | `build_guti_bytes`, which takes the PLMN as `&[u8; 3]` and returns `[u8; 11]` | `OutOfRange` for an AMF Set ID above 10 bits or an AMF Pointer above 6 |
  | `plmn_to_bytes`, which now returns `[u8; 3]` and no longer a `Vec<u8>` | `InvalidParameter` for an MCC or an MNC that is not decimal digits of the right number |
  | `tbcd_encode`, `msin_to_bcd` | `InvalidParameter` for a character that the encoding does not have |

- **Algorithm selection.** `select_integrity_algo` and
  `select_ciphering_algo` return an `Option<IntegrityAlgorithm>` and an
  `Option<CipheringAlgorithm>`, and their `*_with_preference` forms take the
  preference as a slice of those. 0.2.0 ignored a preference above 3, which
  can no longer be written.

- **`SecurityError`** is `#[non_exhaustive]`, so a `match` on it needs a
  wildcard arm, and has three more variants: `OutOfRange`,
  `UnsupportedAlgorithm` and `BitLengthExceedsData`. It is now `Clone`,
  `PartialEq` and `Eq`. `IntegrityAlgorithm`, `CipheringAlgorithm`,
  `SupiType`, `SuciSchemeOutput`, `NaiProtectionScheme` and `TnapKeyUsage`
  are `#[non_exhaustive]` too.

- **Keystream generators.** `Snow3G::generate` and `Zuc::generate`, which
  returned a `Vec<u32>` of a length that the caller gave, are replaced by
  `next_word()` and `fill(&mut [u32])`, which allocate nothing.

- **Removed.** `derive_kausf_standard`, deprecated since 0.1.0: call
  `derive_kausf`.

- **TBCD decoding.** `tbcd_decode` decodes the TS 29.002 TBCD-STRING: 0xA to
  0xE are "*", "#", "a", "b" and "c", and the first 0xF filler ends the
  value. 0.2.0 dropped those nibbles and a 0xF anywhere, so "12*3" decoded as
  "123" and a filler in the middle joined the digits around it. Where the
  value must be decimal, such as an IMSI or an MSIN, call
  `plmn::try_tbcd_decode`, which returns `None` for anything else, or check
  the string that `tbcd_decode` returns. `tbcd_encode` accepts the same
  characters.
- **Profile B ephemeral key.** Profile-B SUCI deconcealment (`suci_decrypt_b`,
  `suci_to_supi`) rejects an uncompressed ephemeral public key, which 0.2.0
  accepted: Profile B always applies point compression (TS 33.501 Annex
  C.3.4) and TS 33.514 §4.2.1.3 has the SIDF reject such a SUCI. Expect
  `SecurityError::Ecies` from `suci_decrypt_b` and `None` from `suci_to_supi`
  for it. A caller that has to deconceal the 65-octet form all the same, in
  a lab for instance, compresses the point before the call: `02` for an even
  Y or `03` for an odd one, then X, which is the key that 0.2.0 gave the KDF.
  A private key that is not 32 octets long is
  `SecurityError::InvalidKeyLength` instead of a panic.
- **SUCI concealment inputs.** `suci_scheme_output_a`, `suci_scheme_output_b`
  and `suci_conceal` with Profile A or Profile B return
  `SecurityError::Ecies` for an empty scheme input. 0.2.0 concealed it into a
  scheme output without ciphertext, which `suci_decrypt_a` and
  `suci_decrypt_b` refuse with that error. `suci_scheme_output_b` returns it
  too for a home network public key that is neither a 33-octet compressed nor
  a 65-octet uncompressed point, the two forms its documentation names; 0.2.0
  also took the x-only SEC1 encoding of tag 0x05, which p256 decodes. Pass at
  least one octet to conceal, and the key in one of the two forms.

### Changed

- The dependencies are those of the current RustCrypto generation: sha2
  0.11, aes 0.9, p256 0.14 and x25519-dalek 3, where 0.2.0 had sha2 0.10,
  aes 0.8, p256 0.13 and x25519-dalek 2. getrandom 0.4 gives the ephemeral
  keys of SUCI; `hmac`, `cipher` and `rand_core` are no longer direct
  dependencies. p256 is built without its default features, `aes` with its
  `zeroize` and `hazmat` features, and the minimum versions are `aes` 0.9.2,
  `zeroize` 1.9 and `subtle` 2.6. The minimum supported Rust version stays
  1.88, for a project whose resolver chooses dependencies by Rust version,
  as resolver 3 does: a dependency may publish a version that needs a newer
  Rust.
- A failure of the system's random number generator while a SUCI is
  concealed is `SecurityError::Ecies`, where 0.2.0 panicked.
- `thiserror` is no longer a dependency, nor the `derive` feature of
  `zeroize`: `SecurityError`, `Snow3G` and `Zuc` implement by hand what the
  macros gave them, with the same error texts.
- The crate denies `unsafe` code outside one module, `common::simd`, and
  warns on a public item without documentation. The 35 items that had none,
  among them `Snow3G`, `Zuc` and the `SecurityError` variants, are
  documented. 0.2.0 had no `unsafe` code.
- SNOW 3G, ZUC, 128-EIA1, 128-EIA3 and AES-CMAC neither index memory nor
  branch on a secret value. 0.2.0 read its S-boxes and its MULα and DIVα
  tables at indices taken from the key and the keystream, and its
  multiplications in GF(2^64) and GF(2^128) branched on their bits, which
  showed both to whoever measures time or shares a cache. Now, in scalar
  code, which every target has:
  - S1 of SNOW 3G and the S-box S1 of ZUC are one round of AES, which the
    `aes` crate runs on the AES instructions of the processor or as a
    bitsliced routine;
  - the S-box SQ of SNOW 3G is read whole and narrowed down through masks,
    and S0 of ZUC is three four-bit S-boxes, each a word that is shifted;
  - MULα, DIVα, the multiplications of 128-EIA1 and the sums of 128-EIA3
    are carry-less products, made with shifts and integer multiplications,
    and the reduction modulo 2^31 - 1 of ZUC has no branch;
  - a mask that a secret bit gives goes through `core::hint::black_box`:
    without it the compiler turned the selection of SQ into conditional
    jumps on bits of the state.

  The compiled code was read for x86-64 with Rust 1.98.1, and no timing
  was measured: the documentation says what was checked.
- SNOW 3G and ZUC also have a form on the vector instructions of the
  processor, which runs when it has them: SSSE3, SSE4.1, AES-NI and
  PCLMULQDQ on x86-64, and AES on AArch64. The crate looks at the processor
  when the program runs. Nothing is asked of the build, and the scalar code
  runs elsewhere. The property is the same:
  - an S-box is read with shuffle instructions, whose index is an operand
    and not an address;
  - S1 of SNOW 3G and the S-box inside S1 of ZUC are the AES instruction,
    and the products of 128-EIA1 and 128-EIA3 the carry-less multiplication
    instruction;
  - SNOW 3G is clocked three times at once, with one pass over the rows of
    SQ for the three clocks.

  The calls of this code, once the processor is seen to have the
  instructions, are the `unsafe` code of the crate; the code itself takes
  and returns values and is not `unsafe`. The tests compare the two forms.
  The AArch64 form was compiled and not run by its authors: CI runs the
  tests on an AArch64 machine.
- `benches/` measures both forms, on one core of an AMD Ryzen 7 5700G with
  Rust 1.98.1 here: the lowest median of four runs, and of two for the
  scalar code and for 0.2.0 in the same benchmark. On the vector
  instructions and a 1500-octet message, 128-EEA1 takes 2.5 µs and 128-EEA3
  3.2 µs, where 0.2.0 took 5.1 µs and 5.2 µs; 128-EIA1 takes 1.1 µs and
  128-EIA3 4.1 µs, where 0.2.0 took 8.4 µs and 13.8 µs. On a 64-octet
  message the four take 0.31 µs to 0.47 µs, where 0.2.0 took 0.53 µs to
  0.99 µs. The scalar code is slower than 0.2.0 for ciphering, which is the
  cost of tables that are not read at a secret index: 17.3 µs for 128-EEA1
  and 11.0 µs for 128-EEA3 on 1500 octets, 4.3 µs for 128-EIA1 and 13.4 µs
  for 128-EIA3, and 1.3 µs to 2.0 µs for the four on 64 octets.
- 128-EEA2 encrypts eight counter blocks in one call to the cipher, and
  128-EIA2 keeps its subkeys and its state in words. On a 1500-octet message
  they take 0.69 µs and 1.8 µs, where 0.2.0 took 2.8 µs each; on a 64-octet
  message 0.15 µs and 0.22 µs, where 0.2.0 took 0.15 µs and 0.24 µs.
- A key derivation takes 0.22 µs, where 0.2.0 took 0.16 µs: HMAC-SHA-256
  now wipes its hash states, its key block and its inner hash.

### Added

- Cargo features, so that a caller who needs the key derivations and the
  algorithms alone builds 14 crates and no procedural macro, without the
  standard library and without an allocator:

  | Feature | What the crate has | Needs |
  |---------|--------------------|-------|
  | none (`default-features = false`) | The algorithms, NAS integrity and ciphering, the key derivations, the selection of the algorithms, 5G-GUTI and `plmn_to_bytes` | `core` alone |
  | `alloc` | And what returns a `Vec` or a `String`: `build_s`, `tbcd_encode`, `tbcd_decode`, `plmn_from_bytes`, and `SecurityError::Ecies` | An allocator |
  | `std`, a default | And the choice of the vector code of SNOW 3G and ZUC when the program runs | The standard library |
  | `suci`, a default | And SUCI concealment and deconcealment with the null scheme, Profile A and Profile B, which bring X25519 and P-256: 41 crates | `alloc`, and a source of random numbers for `getrandom` |
  | `nai`, a default | And the SUCI and SUPI of the NAI format, which bring Unicode normalization and IDNA: 71 crates | `suci` |

  The crate is `no_std` without `std`. It then runs SNOW 3G and ZUC on
  vector instructions when the build enables them for its target, and on
  scalar code otherwise. CI builds each set of features for
  `thumbv7em-none-eabihf` and `aarch64-unknown-none`.

  The key derivations no longer build the string S of TS 33.220: its
  parts go to the hasher one after the other, and a parameter that is a
  key has no copy to wipe.

  0.2.0 had no feature and 76 crates. Without `nai`, `suci_to_supi` returns
  `None` for a SUCI in a NAI format.
- Four `cargo fuzz` targets under `fuzz/`, which CI runs for a minute each:
  `suci` (a SUCI of a NAS message, a scheme output and a NAI from a peer),
  `suci_round_trip` (what is concealed is deconcealed), `identity` (5G-GUTI,
  5G-S-TMSI, PLMN and TBCD, each encoded back to its octets) and
  `algorithms` (every algorithm at any length in bits, on vector
  instructions and in scalar code).
- `benches/`, a package of its own that times the algorithms, the key
  derivations and SUCI with criterion and profiles them with pprof. The
  published crate does not have it, and the crate has no dependency for it.
- A `SECURITY.md` that says how to report a vulnerability.
- `constant_time_eq` compares two octet strings through `subtle`, in a time
  that depends on their lengths and not on where they differ: RES* with
  XRES*, HRES* with HXRES*, or another value derived from a key with the one
  a peer sent. The documentation of `compute_xres_star` and
  `compute_hres_star` points to it.
- The examples of the README are compiled and run with the doctests, and
  `tests/readme.rs` compares what each prints with the text under it.
- Test vector for 128-EIA2 set 7 (TS 33.401 Annex C.2.7), the
  non-byte-aligned set that 0.2.0 did not cover.
- 128-EEA1 tests on the six UEA2 design conformance sets (TS 35.218), which
  TS 33.401 Annex C.3 reuses for 128-EEA1.
- A 5G AKA key chain test from the TS 35.208 test set 1 MILENAGE outputs
  through KAUSF, XRES*, HXRES*, KSEAF, KAMF, KNASenc, KNASint, KgNB, and NH.
  `tests/five_g_aka_chain.py` derives the same values with the HMAC-SHA-256
  of Python's standard library. KSEAF, KAMF, the 5GS NAS keys,
  NH, and XRES* had no test before.
- SUCI tests on every TS 33.501 Annex C.4 data set, including the null
  scheme and the ephemeral key, shared key, encryption key, ICB, MAC key,
  ciphertext, and MAC tag of the Profile A and Profile B sets.

### Fixed

- The algorithms count octets, not bits. On a 32-bit target the length of
  a buffer of 512 MiB or more, multiplied by 8, overflowed `usize`: a debug
  build panicked, and in a release build the whole-octet `nas_cipher`,
  `nas_mac` and `nia2_mac` took the wrapped product for the length to
  process. `nia1_mac` and `nia3_mac` converted the bit length with `as`,
  which dropped its high bits.
- The AES-128-CTR of SUCI Profile A and Profile B counts over the whole
  16-octet block. Only the low 32 bits were incremented, so a plaintext
  longer than one block (a NAI username) was concealed or deconcealed
  differently from other implementations when those bits of the ICB were
  about to wrap.
- `suci_to_supi` and `suci_to_string` ignore spare bit 4 of the first octet
  of a binary SUCI, as they do spare bit 8 (TS 24.501 §9.11.3.4); a SUCI with
  that bit set was not decoded.
- The word copies of the key that 128-EEA1, 128-EIA1 and `Snow3G` make are
  wiped.
- Profile A checks X25519 contributory behavior with the dependency's
  constant-time all-zero comparison.
- Key material stayed in memory after use: the HMAC-SHA-256 state of every
  KDF (hmac 0.12 and sha2 0.10 do not clear it), the SUCI ECIES KDF output,
  hash state and AES-CTR keystream, the HRES* hash state, and the 128-EEA2
  keystream blocks, which the README said were wiped. The KDFs, HRES* and
  SUCI now use the SHA-256 of sha2 0.11 with its `zeroize` feature, which
  wipes the chaining value and the block buffer when the hasher is dropped,
  and the keystream blocks are wiped. HMAC is written in this crate over
  that hasher and wipes the block of the key and the inner hash, which
  hmac 0.13 leaves on the stack.
- The 0.2.0 notes credited this crate with a NAS context and
  `protect_re_establishment`, which oxirush-nas provides; the README said
  NAS-context keys were wiped here. Both now describe this crate.
- The `re_establishment_nas_mac` documentation says that the 28-bit reading
  of the target Cell-ID is this crate's interpretation, for which no test
  data or other implementation exists.
- The `suci_to_supi` documentation says that a SUCI in a NAI format gives
  the `username@realm` SUPI without a prefix; it promised
  `imsi-<MCC><MNC><MSIN>` for every SUCI.

## 0.2.0 - 2026-09-27

### Breaking changes relative to 0.1.0

- **MSRV.** The minimum supported Rust version is now 1.88.

- **Module layout.** 5GS functions moved to `oxirush_security::nas_5gs`,
  shared primitives to `oxirush_security::common`, and EPS functions are in
  `oxirush_security::nas_eps`. The crate root still re-exports the 5GS and
  common functions.
- **Range checks.** `build_guti_bytes` panics on an AMF Set ID wider than
  10 bits or an AMF Pointer wider than 6 bits in release builds too; 0.1.0
  checked them only with debug assertions and masked the pointer otherwise.
- **Raw algorithm inputs.** EEA/EIA primitives now panic instead of masking a
  bearer above 31 or a direction above 1, and bit-oriented variants panic
  when the declared bit length exceeds the supplied buffer.
- **EPS re-establishment MAC.** `re_establishment_nas_mac` accepts the target
  28-bit Cell-ID as a checked `u32` instead of an arbitrary byte slice.

### Added

- EPS key hierarchy and NAS security per TS 33.401 (`nas_eps`): KASME, KeNB,
  NH, KeNB*, NAS and AS keys, CK'/IK' mappings, NAS token, SRVCC keys,
  S-KeNB, LWIP-PSK, S-KWT, K_n, HASHMME (`compute_hash_mme`), the EPS NAS
  MAC and ciphering wrappers with bearer 0, the SERVICE REQUEST short MAC,
  and `re_establishment_nas_mac` (TS 33.401 §7.4.4).
- 5GS↔EPS key mapping (TS 33.501 Annexes A.14 and A.15),
  `derive_kasme_srvcc` (Annex A.21), and `nas_container_mac`
  (TS 33.501 §6.9.2.3.3).
- 5GS `derive_as_key` (Annex A.8 RRC and UP keys), `derive_kn3iwf` (Annex
  A.9, non-3GPP access), `derive_kng_ran_star` (A.11), and
  `derive_kng_ran_star_ng_enb` (A.12).
- Test vectors for 128-EEA2 sets 4 to 6, 128-EIA1 sets 6 and 7, 128-EEA3 sets
  3 to 5, SNOW 3G set 4 up to z2500, and ZUC set 4.
- Arbitrary-bit `nas_cipher_bits`, `nea1_cipher_bits`, `nea2_cipher_bits`,
  `nea3_cipher_bits`, `nas_mac_bits`, and `nia2_mac_bits`, including all
  non-byte-aligned TS 33.401 Annex C.2 EIA2 vectors.
- Operator-ordered `select_integrity_algo_with_preference` and
  `select_ciphering_algo_with_preference`; the compatibility wrappers keep
  their existing default order.
- `# Panics` sections on every function that panics on out-of-range input.

### Changed

- The AES and cipher dependencies wipe key schedules on drop (`zeroize`
  feature), and CK‖IK copies, key-bearing KDF S strings, and
  SNOW 3G/ZUC keystreams are wiped after use.
- 128-EIA2 uses the shared bit-oriented AES-CMAC implementation, including
  partial final blocks, instead of the former whole-octet-only dependency.
- 128-EEA1/EIA1 use MULα and DIVα tables computed at compile time instead of
  recomputing them on every clock.
- Documentation cites TS 33.401 Annex B and the UEA2/UIA2 and EEA3/EIA3
  specifications for the algorithm constructions.

### Fixed

- `build_guti_bytes` wrote the 5G-GUTI identity octet as 0x02 during
  development of this release; it writes 0xF2 again (TS 24.501 Figure
  9.11.3.4.1), and `parse_s_tmsi` checks only the type-of-identity bits.
- The EPS re-establishment MAC authenticates exactly the 28 significant
  target Cell-ID bits.
- Binary SUCI decoding applies the TS 24.501 receiver fallbacks for non-zero
  spare bits and unused SUPI-format code points while canonical construction
  remains strict.
