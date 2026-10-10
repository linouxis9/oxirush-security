# Changelog

All notable changes to `oxirush-security` are recorded here.

## Unreleased (0.3.0)

### Breaking changes relative to 0.2.0

- **KeNB derivation.** `nas_eps::derive_kenb` panics on a COUNT above
  2^24 - 1 other than the all-ones handover sentinel, like
  `nas_5gs::derive_kgnb`; 0.2.0 accepted any 32-bit value, although the EPS
  NAS COUNT has 24 bits (TS 24.301 §4.4.3.1). Check a COUNT that is not known
  to be in range before the call, and pass `0xffff_ffff` only for the 5GS to
  EPS handover of TS 33.501 §8.3.2.
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

### Changed

- p256 is built without its default features, and the minimum versions are
  `rand_core` 0.6.4, `zeroize` 1.5, and `subtle` 2.4.1.
- The crate forbids `unsafe` code, of which it had none, and warns on a
  public item without documentation. The 35 items that had none, among them
  `Snow3G`, `Zuc` and the `SecurityError` variants, are documented.

- SNOW 3G, ZUC, 128-EIA1 and the 128-EIA2 subkey doubling avoid secret-dependent
  indexing and branches in source: S-box and MULα/DIVα lookups read the whole table through masks, and
  the GF(2^64) and GF(2^128) multiplications and the ZUC reduction modulo
  2^31 - 1 have no branch on secret bits. Table lookups indexed by key or
  keystream bits, and those branches, exposed a timing risk. Compiled-code
  timing has not been audited across supported targets. 128-EEA1 and 128-EEA3
  take about 10 times longer (58 µs and 48 µs for a 1500-octet message on
  a 2020s x86-64 core, release build), 128-EIA1 and 128-EIA3 are slower by
  less on such a message and take 4 to 7 times longer on a 64-octet one, and
  128-EEA2 and 128-EIA2 are unchanged.

### Added

- The examples of the README are compiled and run with the doctests.
- Test vector for 128-EIA2 set 7 (TS 33.401 Annex C.2.7), the
  non-byte-aligned set that 0.2.0 did not cover.
- 128-EEA1 tests on the six UEA2 design conformance sets (TS 35.218), which
  TS 33.401 Annex C.3 reuses for 128-EEA1.
- A 5G AKA key chain test from the TS 35.208 test set 1 MILENAGE outputs
  through KAUSF, XRES*, HXRES*, KSEAF, KAMF, KNASenc, KNASint, KgNB, and NH,
  checked against free5GC and CryptoMobile. KSEAF, KAMF, the 5GS NAS keys,
  NH, and XRES* had no test before.
- SUCI tests on every TS 33.501 Annex C.4 data set, including the null
  scheme and the ephemeral key, shared key, encryption key, ICB, MAC key,
  ciphertext, and MAC tag of the Profile A and Profile B sets.

### Fixed

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
  SUCI now run SHA-256 over sha2's compression function with state that is
  wiped on drop, and the keystream blocks are wiped; `hmac` is no longer a
  direct dependency.
- The 0.2.0 notes credited this crate with a NAS context and
  `protect_re_establishment`, which oxirush-nas provides; the README said
  NAS-context keys were wiped here. Both now describe this crate.
- The `re_establishment_nas_mac` documentation says that the 28-bit reading
  of the target Cell-ID is this crate's interpretation, for which no test
  data or other implementation exists.
- `derive_kausf`, `derive_kseaf`, `derive_kamf`, and `compute_xres_star`
  document that they panic on a KDF parameter longer than 65535 octets,
  which a two-octet L field cannot encode (TS 33.220 Annex B.2).
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
