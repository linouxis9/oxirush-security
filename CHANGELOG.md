# Changelog

All notable changes to `oxirush-security` are recorded here.

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
  target Cell-ID bits, and the NAS context can consume the matching uplink
  COUNT atomically through `protect_re_establishment`.
- Binary SUCI decoding applies the TS 24.501 receiver fallbacks for non-zero
  spare bits and unused SUPI-format code points while canonical construction
  remains strict.
