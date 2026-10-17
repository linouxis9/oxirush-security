# Changelog

All notable changes to `oxirush-security` are recorded here.

## Unreleased (0.3.0)

### Breaking changes relative to 0.2.0

Every call changes. 0.2.0 took keys as arrays of octets and the algorithm,
the direction, the bearer and the COUNT as integers, and panicked on a value
out of range. In 0.3.0 a key has a type, a value that a specification
bounds has a type that holds only the values in range, and what a type
cannot say is a `Result`. No public function panics on its arguments.

- **Where things are.** Each item has one path.

  | Path | What is there |
  |------|---------------|
  | `oxirush_security::` | What both systems share: the algorithms (`nia_mac`, `nea_cipher` and their `*_bits` forms), the batches, the keyed contexts, `IntegrityAlgorithm`, `CipheringAlgorithm`, `Direction`, `Bearer`, `NasCount`, `AccessKeyCount`, `SecurityError`, `Ck`, `Ik`, `Rand`, `Autn`, `Plmn`, `tbcd`, `identity` (the module of oxirush-utils), `Snow3G`, `Zuc`, `constant_time_eq`, the selection of the algorithms and `implementation` |
  | `oxirush_security::kdf::` | `kdf`, `build_s` and `extract_128` of TS 33.220 |
  | `oxirush_security::nas_5gs::` | The keys of TS 33.501 and their derivations, `nas_mac`, `nas_cipher`, `NasConnection`, `Supi`, `SupiType`, `Suci`, `ProtectionScheme`, `RoutingIndicator`, `Guti`, `STmsi`, `MobileIdentityType` |
  | `oxirush_security::nas_eps::` | The keys of TS 33.401 and their derivations, `nas_mac`, `nas_cipher`, the short MAC, the re-establishment MAC, `compute_hash_mme` |
  | `oxirush_security::milenage::` | MILENAGE, new in 0.3.0: see Added |

  `common` is private, and so are `nas_5gs::kdf`, `nas_5gs::security`,
  `nas_5gs::suci`, `nas_5gs::guti`, `nas_5gs::algo` and their counterparts
  of `nas_eps`: `nas_5gs::kdf::derive_kamf` is `nas_5gs::derive_kamf`. The
  crate root no longer has the 5GS functions under bare names:
  `oxirush_security::derive_kamf` is `nas_5gs::derive_kamf`, and
  `oxirush_security::nas_mac` is `nas_5gs::nas_mac`. The keys that one
  system maps to the other are all in `nas_5gs`, where TS 33.501 defines
  them: `nas_eps::derive_mapped_kamf_idle` and
  `nas_eps::derive_mapped_kamf_handover` moved there.

- **Keys.** A key has a type of its own, and a function takes the key that
  its clause names: KNASenc does not compile where KNASint is expected.

  | Module | 256 bits | 128 bits |
  |--------|----------|----------|
  | root | | `Ck`, `Ik` |
  | `nas_5gs` | `KAusf`, `KSeaf`, `KAmf`, `KGnb`, `Nh`, `KN3iwf`, `KSn`, `KTnap`, `KIab` | `KNasInt`, `KNasEnc`, `KRrcInt`, `KRrcEnc`, `KUpInt`, `KUpEnc`, `ResStar`, `XresStar`, `HresStar`, `HxresStar` |
  | `nas_eps` | `KAsme`, `KEnb`, `Nh`, `NasToken`, `LwipPsk`, `SKwt`, `Kn` | `KNasInt`, `KNasEnc`, `KRrcInt`, `KRrcEnc`, `KUpInt`, `KUpEnc`, `CkPrime`, `IkPrime`, `CkSrvcc`, `IkSrvcc` |

  `K::new(&octets)` and `K::from_slice(&slice)?` make one, and
  `key.as_octets()` gives the octets back. A key is wiped when it is
  dropped, is not `Copy`, compares in constant time, and `{:?}` prints its
  name without an octet. `Rand` and `Autn` are built and viewed the same
  way; they travel in clear, are printed whole and are not wiped.

  ```rust
  // 0.2.0
  let k_amf = derive_kamf(&k_seaf, "208930000000001", &[0, 0]);
  let k_nas_int = extract_128(&derive_nas_key(&k_amf, 0x02, 2));
  let mac = nas_mac(&k_nas_int, count, 1, 0, &message, 2);

  // 0.3.0
  let supi = Supi::imsi("208930000000001")?;
  let k_amf = derive_kamf(&k_seaf, &supi, &[0, 0])?;
  let k_nas_int = derive_knas_int(&k_amf, IntegrityAlgorithm::NIA2);
  let mac = nas_mac(
      &k_nas_int, NasCount::new(count)?, NasConnection::ThreeGpp, Direction::Uplink,
      &message, IntegrityAlgorithm::NIA2,
  );
  ```

- **Inputs.**

  | Type | Values | From an integer |
  |------|--------|-----------------|
  | `IntegrityAlgorithm` | `Null`, `Snow3g`, `Aes`, `Zuc`, also named `NIA0` to `NIA3` and `EIA0` to `EIA3` | `try_from(u8)`, `Err(UnsupportedAlgorithm)` for 4 and above |
  | `CipheringAlgorithm` | `Null`, `Snow3g`, `Aes`, `Zuc`, also named `NEA0` to `NEA3` and `EEA0` to `EEA3` | `try_from(u8)` |
  | `Direction` | `Uplink` (0), `Downlink` (1) | `try_from(u8)` |
  | `NasCount` | 0 to 2^24 - 1 | `new(u32)`, `try_from(u32)`, `from_parts(overflow, sequence_number)` |
  | `AccessKeyCount` | `Nas(NasCount)`, or `Handover` for 2^32 - 1 | `try_from(u32)`; a `NasCount` converts into it |
  | `nas_5gs::NasConnection` | `ThreeGpp` (1), `Non3Gpp` (2) | `try_from(u8)` |
  | `Bearer` | 0 to 31 | `new(u8)`, `try_from(u8)`; a `NasConnection` converts into it |
  | `Plmn` | An MCC of three digits and an MNC of two or three | `new("208", "93")`, `from_nas_octets([u8; 3])` |

  `u8::from` and `u32::from` give the number back. An algorithm prints as
  `128-NIA2/128-EIA2`, and `name_5gs()` and `name_eps()` give one name.

- **NAS integrity and ciphering.** `nas_5gs::nas_mac`, `nas_cipher` and
  `nas_container_mac` take a `&KNasInt` or a `&KNasEnc`, a `NasCount`, a
  `NasConnection`, a `Direction` and the algorithm, and cannot fail. Those
  of `nas_eps` take no connection. `nas_eps::re_establishment_nas_mac`
  returns a `Result`, for a cell identity above 28 bits, and so does
  `service_request_short_mac_with_header`, for a first octet that is not
  that of a SERVICE REQUEST.

- **The algorithms.** In 0.2.0 `nas_mac` and `nas_cipher` at the crate root
  were the algorithms themselves, with any 32-bit COUNT and a 5-bit BEARER.
  They are named after what they are, and take a key of the algorithm,
  which is any KNASint, KRRCint or KUPint for a MAC and any KNASenc,
  KRRCenc or KUPenc for a cipher:

  | 0.2.0 | 0.3.0 |
  |-------|-------|
  | `common::nas_mac(key, count, bearer: u8, direction: u8, message, algo_id: u8) -> u32` | `nia_mac(&key, count, Bearer, Direction, message, IntegrityAlgorithm) -> u32` |
  | `common::nas_mac_bits(.., bit_length, algo_id) -> u32` | `nia_mac_bits(.., bit_length, IntegrityAlgorithm) -> Result<u32, SecurityError>` |
  | `common::nas_cipher(key, count, bearer, direction, data, algo_id)` | `nea_cipher(&key, count, Bearer, Direction, data, CipheringAlgorithm)` |
  | `common::nas_cipher_bits(.., bit_length, algo_id)` | `nea_cipher_bits(.., bit_length, CipheringAlgorithm) -> Result<(), SecurityError>` |
  | `nia1_mac`, `nia2_mac`, `nia2_mac_bits`, `nia3_mac`, `nea1_cipher` to `nea3_cipher_bits` | `nia_mac`, `nia_mac_bits`, `nea_cipher` or `nea_cipher_bits` with the algorithm |

  The whole-octet functions cannot fail. A `*_bits` function returns
  `Err(BitLengthExceedsData)` for a length that the buffer does not hold.
  A test set of TS 33.401 Annex C gives its key as octets:
  `nas_eps::KNasInt::new(&octets)`.

- **Key derivations.** Each takes and returns the types of its keys. Those
  that 0.2.0 let panic return a `Result`.

  | 0.2.0 | 0.3.0, in `nas_5gs` |
  |-------|---------------------|
  | `derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak) -> [u8; 32]` | `derive_kausf(&Ck, &Ik, sn_name, &Autn) -> Result<KAusf, _>`, which reads SQN xor AK in the AUTN |
  | `derive_kausf_standard`, deprecated since 0.1.0 | removed: `derive_kausf` |
  | `derive_kseaf(&kausf, sn_name) -> [u8; 32]` | `derive_kseaf(&KAusf, sn_name) -> Result<KSeaf, _>` |
  | `derive_kamf(&kseaf, supi_digits: &str, abba) -> [u8; 32]` | `derive_kamf(&KSeaf, &Supi, abba) -> Result<KAmf, _>` |
  | `extract_128(&derive_nas_key(&kamf, 0x01, id))` | `derive_knas_enc(&KAmf, CipheringAlgorithm) -> KNasEnc` |
  | `extract_128(&derive_nas_key(&kamf, 0x02, id))` | `derive_knas_int(&KAmf, IntegrityAlgorithm) -> KNasInt` |
  | `extract_128(&derive_as_key(&kgnb, 0x03 to 0x06, id))` | `derive_krrc_enc`, `derive_krrc_int`, `derive_kup_enc`, `derive_kup_int`, from a `&KGnb` or a `&KSn` |
  | `compute_xres_star(&ck, &ik, sn_name, &rand, xres) -> Vec<u8>` | `compute_xres_star(&Ck, &Ik, sn_name, &Rand, xres) -> Result<XresStar, _>` |
  | `compute_hres_star(&rand, &res_star) -> [u8; 16]` | `compute_hres_star(&Rand, &ResStar) -> HresStar` |
  | `derive_kgnb(&kamf, ul_nas_count: u32)` | `derive_kgnb(&KAmf, impl Into<AccessKeyCount>) -> KGnb`: a `NasCount`, or `AccessKeyCount::Handover` where 0.2.0 took `0xffff_ffff` |
  | `derive_kn3iwf(&kamf, u32)` | `derive_kn3iwf(&KAmf, NasCount) -> KN3iwf` |
  | `derive_nh(&kamf, &sync_input)` | `derive_nh(&KAmf, &KGnb or &Nh) -> Nh` |
  | `derive_kng_ran_star(&base_key, pci, arfcn_dl) -> [u8; 32]` and its `_ng_enb` form | `(&KGnb or &Nh, pci, arfcn_dl) -> Result<KGnb, _>`, `OutOfRange` for a PCI or an ARFCN above its largest value |
  | `derive_kamf_prime(&kamf, direction, u32) -> Result<[u8; 32], _>` and its `_idle` and `_handover` forms | `(&KAmf, .., NasCount) -> KAmf` |
  | `derive_mapped_kasme_idle`, `derive_mapped_kasme_handover`, `derive_kasme_srvcc` | `(&KAmf, NasCount) -> nas_eps::KAsme` |
  | `nas_eps::derive_mapped_kamf_idle(&kasme, u32)` | `nas_5gs::derive_mapped_kamf_idle(&nas_eps::KAsme, NasCount) -> KAmf` |
  | `nas_eps::derive_mapped_kamf_handover(&kasme, &nh)` | `nas_5gs::derive_mapped_kamf_handover(&nas_eps::KAsme, &nas_eps::Nh) -> KAmf` |
  | `derive_ksn(&base_key, sn_counter)` | `derive_ksn(&KGnb, sn_counter) -> KSn` |
  | `derive_sor_mac_ausf`, `derive_sor_mac_ue`, `derive_upu_mac_ausf`, `derive_upu_mac_ue` | the same, from a `&KAusf` |
  | `derive_tnap_usage_key(&base_key, usage)` | `derive_tnap_usage_key(&KN3iwf, usage) -> KTnap` |
  | `derive_kiab(&base_key, donor, node)` | `derive_kiab(&KGnb, donor, node) -> KIab` |

  | 0.2.0 | 0.3.0, in `nas_eps` |
  |-------|---------------------|
  | `derive_kasme(&ck, &ik, sn_id: &[u8; 3], &sqn_xor_ak) -> [u8; 32]` | `derive_kasme(&Ck, &Ik, Plmn, &Autn) -> KAsme` |
  | `derive_kenb(&kasme, u32)` | `derive_kenb(&KAsme, impl Into<AccessKeyCount>) -> KEnb`. 0.2.0 took any 32-bit value, although the EPS NAS COUNT has 24 bits |
  | `derive_nh`, `derive_kenb_star` | `derive_nh(&KAsme, &KEnb or &Nh) -> Nh`; `derive_kenb_star(&KEnb or &Nh, pci, earfcn_dl) -> Result<KEnb, _>` |
  | `extract_128(&derive_nas_key(&kasme, type, id))` | `derive_knas_enc`, `derive_knas_int`, from a `&KAsme` |
  | `extract_128(&derive_as_key(&kenb, type, id))` | `derive_krrc_enc`, `derive_krrc_int`, `derive_kup_enc`, `derive_kup_int`, from a `&KEnb` |
  | `derive_sgnb_algorithm_key(&s_kgnb, type, id)` | `derive_skgnb(&KEnb, scg_counter) -> nas_5gs::KGnb`, then `nas_5gs::derive_krrc_enc` and the three beside it, the function of TS 33.501 Annex A.8 that TS 33.401 Annex A.19 names |
  | `derive_ck_ik_handover`, `derive_ck_ik_idle_mobility(&kasme, u32) -> [u8; 32]` | `(&KAsme, NasCount) -> (CkPrime, IkPrime)` |
  | `derive_ck_ik_srvcc(&kasme, u32) -> [u8; 32]` | `(&KAsme, NasCount) -> (CkSrvcc, IkSrvcc)` |
  | `derive_nas_token(&kasme, u32) -> [u8; 2]`, `derive_nas_token_full` | `derive_nas_token(&KAsme, NasCount) -> NasToken`, whose `transmitted()` gives the 16 bits that are sent |
  | `derive_kasme_handover`, `derive_kasme_idle_mobility` | the same, from a `&Ck` and a `&Ik`, to a `KAsme` |
  | `derive_skenb`, `derive_lwip_psk`, `derive_skwt` | `(&KEnb, counter) -> KEnb`, `LwipPsk`, `SKwt` |
  | `derive_kn(mk, f_n, imsi) -> [u8; 32]` | `-> Result<Kn, _>` |

  `derive_kausf`, `derive_kseaf`, `derive_kamf`, `compute_xres_star`,
  `nas_eps::derive_kn` and `kdf::build_s` return `InputTooLong` for a
  parameter above 65535 octets, where 0.2.0 panicked. `compute_xres_star`
  returns `InvalidParameter` for an XRES that is not 4 to 16 octets long,
  and `derive_kamf` for an ABBA that is not 2 to 255.

  `kdf::kdf` and `kdf::extract_128` return a `Zeroizing` array, which is
  wiped when it is dropped and which `*` reads. For the 256 bits of an
  algorithm key, or for an identity that is reserved, build the input:
  `kdf(k_amf.as_octets(), &build_s(0x69, &[&[kind], &[id]])?)`.

- **The SUPI.** `derive_kamf` took the SUPI as a string, and a string in
  another form than the one of TS 33.501 Annex A.7.0 gave another KAMF
  without an error. `nas_5gs::Supi` is the SUPI: `Supi::imsi(digits)`,
  `Supi::network_specific(nai)`, `Supi::gli(nai)`, `Supi::gci(nai)`, or
  `Supi::parse("imsi-208930000000001")` for the text of a service based
  interface. `identity()` is what KAMF takes, and `{}` prints the text
  with its type in front.

- **The identities are those of oxirush-utils.** The PLMN, the TBCD
  strings, the 5G-GUTI, the 5G-S-TMSI, the type of a mobile identity, the
  SUPI and its type, the routing indicator and the protection scheme of a
  SUCI are the values of the crate that the OxiRush crates share, which
  `oxirush_security::identity` is, at the paths of this list: `Guti`,
  `STmsi` and `MobileIdentityType` are its `Guti5g`, `STmsi5g` and
  `MobileIdentityType5gs`. Its readers are canonical: `from_nas_octets`
  refuses a spare bit that is set, and `from_nas_octets_tolerant` reads it
  with a list of what was not by the clause. An identity that is refused
  is `SecurityError::Identity`, with the member at fault and why, where a
  function of this crate takes one. It adds oxirush-utils to the tree of
  the crate and no other crate, needs no allocator without `alloc`, and
  takes `base64` and `hex` out of that of `nai`.

- **The SUCI.** `nas_5gs::Suci` replaces the functions that took and
  returned octets and strings. It holds the SUPI type, the home network,
  the routing indicator, the protection scheme, the home network public
  key identifier and the scheme output, each of which it gives, so that a
  SIDF chooses its private key from what it read.

  | 0.2.0 | 0.3.0 |
  |-------|-------|
  | `msin_to_bcd`, `suci_scheme_output_a`, `suci_scheme_output_b`, `suci_conceal` | `Suci::conceal_imsi(plmn, msin, RoutingIndicator, Protection)`, then `to_nas_octets()` |
  | `suci_to_supi(&octets, Some(&key)) -> Option<String>` | `Suci::from_nas_octets(&octets)?.deconceal(Some(&key)) -> Result<Supi, SuciError>` |
  | `suci_decrypt_a`, `suci_decrypt_b` | `Suci::deconceal` |
  | `suci_to_string(&octets)` | `Suci::from_nas_octets(&octets)?` with `{}` |
  | `parse_nai_suci`, `encode_nai_suci`, `NaiSuci` | `Suci::from_nai`, `Suci::to_nai() -> Result<String, SuciError>` |
  | `conceal_network_specific_supi`, `NaiProtectionScheme` | `Suci::conceal_nai(&supi, RoutingIndicator, Protection)` |
  | `deconceal_nai_suci`, `deconceal_network_specific_suci` | `Suci::deconceal` |
  | a home network key as octets | `HomeNetworkPrivateKey::profile_a`, `profile_b`, and its `public_key()`; `HomeNetworkPublicKey::profile_a`, `profile_b` |
  | `SuciSchemeOutput` | `SchemeOutput`, from `Suci::scheme_output()` |

  The errors are `SuciError`, which says which step failed: a truncated
  identity, an unknown scheme, a missing key or one of the other profile,
  a malformed point, a MAC that does not match, a plaintext that is no
  identity. Its documentation says what a SIDF may tell a peer. A NAI that
  is refused gives `SuciError::Nai` with the field at fault and why, and
  one whose username or realm is above 253 octets is refused before it is
  normalized. The two forms of a SUCI are the `ImsiSuci` and the `NaiSuci`
  of oxirush-utils, which check the parts against each other; the text of
  the service based interfaces writes the protection scheme as one
  hexadecimal digit, as the pattern of `SupiOrSuci` of TS 29.571 has it
  (`suci-0-208-93-0-c-1-aabb` for the first scheme of the operator).
  `ProtectionScheme` is its identifier: `ProtectionScheme::new(12)` and
  `identifier()`, with `NULL`, `PROFILE_A` and `PROFILE_B`, where a
  reserved one is refused. `routing_indicator()` gives a
  `RoutingIndicator`, whose `as_str()` has its digits.

  De-concealment with Profile B refuses an uncompressed ephemeral public
  key, which 0.2.0 accepted: Profile B always compresses the point
  (TS 33.501 Annex C.3.4), and TS 33.514 §4.2.1.3 has the SIDF refuse such
  a SUCI. Concealment refuses an empty MSIN or username, which 0.2.0
  concealed into a scheme output that it then refused, and a home network
  public key identifier of 0 or 255 with a profile, in both formats.

- **5G-GUTI, 5G-S-TMSI, PLMN, TBCD.**

  | 0.2.0 | 0.3.0 |
  |-------|-------|
  | `build_guti_bytes(&plmn, region, set, pointer, tmsi) -> Vec<u8>` | `Guti::new(Plmn, region, set, pointer, tmsi)?.to_nas_octets() -> [u8; 11]` |
  | `parse_guti_tmsi(&identity) -> Option<u32>` | `Guti::from_nas_octets(&identity)?`, or `from_nas_octets_tolerant` for a spare bit that is set, with `tmsi()`, `plmn()`, `amf_region_id()`, `amf_set_id()`, `amf_pointer()`, `s_tmsi()` |
  | `parse_s_tmsi(&identity) -> Option<u32>` | `STmsi::from_nas_octets(&identity)?.tmsi()` |
  | `mobile_identity_type(&identity) -> u8` | `MobileIdentityType::of(identity[0]) -> Result<MobileIdentityType, identity::Error>` |
  | `plmn_to_bytes(mcc, mnc) -> Vec<u8>` | `Plmn::new(mcc, mnc)?.to_nas_octets() -> [u8; 3]` |
  | `plmn_from_bytes(&octets) -> Option<(String, String)>` | `Plmn::from_nas_octets(octets)?`, with `mcc()` and `mnc()` |
  | `tbcd_encode(value) -> Vec<u8>` | `tbcd::encode(value) -> Result<Vec<u8>, identity::Error>` |
  | `tbcd_decode(&octets) -> String`, `try_tbcd_decode` | `tbcd::decode(&octets) -> Result<String, identity::Error>` |

  An identity is read whole and strictly: a length that is not that of the
  identity, a type octet of another identity, a digit that is none, or a
  filler before the end is an error, where 0.2.0 read what it could.
  `tbcd::decode` decodes the TBCD-STRING of TS 29.002, in which 0xA to 0xE
  are `*`, `#`, `a`, `b` and `c`; 0.2.0 dropped them, and a filler
  anywhere.

- **The NAS COUNT.** `NasCount` gives the next value and that of a
  received message, so that a COUNT is not used twice by mistake:
  `next()` and `estimate(sequence_number)` return
  `Err(NasCountExhausted)` where the COUNT would wrap around,
  `estimate_from_low_bits(low_bits, bits)` reads the five or four bits of
  a short message, and the `wrapping_` forms are for a context with the
  null integrity algorithm, which may wrap (TS 24.501 §4.4.3.1 and
  §4.4.3.5, TS 24.301 §4.4.3.1 and §4.4.3.5).

- **Algorithm selection.** `select_integrity_algo` and
  `select_ciphering_algo` return an `Option<IntegrityAlgorithm>` and an
  `Option<CipheringAlgorithm>`, and their `*_with_preference` forms take
  the preference as a slice of those.

- **`SecurityError`** is `#[non_exhaustive]`, `Clone`, `PartialEq` and
  `Eq`. Its variants are `InvalidKeyLength`, `InvalidParameter`,
  `Identity`, `InputTooLong`, `OutOfRange`, `UnsupportedAlgorithm`,
  `BitLengthExceedsData`, `NasCountExhausted` and `MacFailure`; `Ecies` is
  gone, with the errors of SUCI in `SuciError`. The public enums are
  `#[non_exhaustive]` and the public structs have private fields.

- **Keystream generators.** `Snow3G::generate` and `Zuc::generate`, which
  returned a `Vec<u32>`, are replaced by `next_word()` and
  `fill(&mut [u32])`, which allocate nothing. `Snow3G::new` takes its key
  and its IV by reference.

- **Features.** `default-features = false` gives the crate without the
  standard library, without an allocator and without SUCI: see Added.

- **The stack.** Each operation that computes with a key needs the stack
  that is cleared after it, 1536 to 18432 octets by kind of work and 49152
  in a build with debug assertions: see Changed.

### Changed

- **What an operation leaves.** The values that the code names were wiped
  in part in 0.2.0: the HMAC-SHA-256 state of every derivation, the KDF
  output and the keystream of SUCI, and the keystream blocks of 128-EEA2
  stayed in memory. They are wiped now, and so is what the compiler puts
  on the stack and in the registers: the work of each operation that
  computes with a key runs in a frame of its own, and when it has returned
  the stack below is set to zero over a fixed number of octets, with the
  registers that a function need not give back on x86-64 and AArch64.

  `leftovers/` in the repository runs every such operation on x86-64 and
  looks for its key, its round keys, its subkeys, the stages of its
  generator, its keystream and its HMAC values on the stack and in the
  registers: it finds 1267 to 1904 of them without the clearing, by the
  build, and none with it, in eighteen optimized builds with Rust 1.99,
  1.98 and 1.88, and CI runs it at each change and each week.
  `emulated-aarch64/` does the same for 22 operations on an emulated
  AArch64 processor. The front page of the documentation says what stays:
  what an operation returns, the copies that a program makes by moving a
  key, and an unoptimized build without debug assertions.

  What is cleared is at least twice the deepest work of each kind that was
  seen, and the scan fails above three quarters. The `aes` crate has code
  for 64 blocks side by side on AVX-512F from its version 0.9.3, with a
  frame for as many whatever the number that it is given, and it writes
  ZMM16 and ZMM17, which are not cleared: 128-EEA2 without the vector code
  went 1500 octets deeper on such a processor than on another. The counter
  mode without the vector code now runs inside the code that `aes` has
  chosen: it gives the code without instructions the 2 or 4 blocks that it
  works on at once, encrypts eight counter blocks one after the other on
  the AES instructions, and calls no code for more. What `aes` still does
  for AVX-512F before it calls the counter mode is counted in what is
  cleared on x86, from the frames of the binaries.

  The clearing adds about 16 ns to a message of AES with a keyed context,
  18 ns from a key, 30 ns to a message of SNOW 3G or ZUC and to a
  derivation, and 75 to 140 ns to each algorithm of a batch.
  `RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the crate without
  it.

- **Timing.** SNOW 3G, ZUC, AES, 128-EIA1, 128-EIA3 and AES-CMAC neither
  index memory nor branch on a secret value. 0.2.0 read its S-boxes and
  its MULα and DIVα tables at indices taken from the key and the
  keystream, and its multiplications in GF(2^64) and GF(2^128) branched on
  their bits, which showed both to whoever measures time or shares a
  cache. In scalar code, which every target has, S1 of SNOW 3G and the
  S-box S1 of ZUC are one round of AES, the S-box SQ is read whole and
  narrowed down through masks, S0 of ZUC is three four-bit S-boxes, and
  the multiplications are carry-less products. The compiled code was read
  for x86-64 with Rust 1.98.1, and no timing was measured: the
  documentation says what was checked.

- **Vector and AES instructions.** SNOW 3G, ZUC and AES run on the vector,
  AES and carry-less multiplication instructions of the processor when it
  has them: SSSE3, SSE4.1, AES-NI and PCLMULQDQ on x86-64, and AES on
  AArch64. The crate asks the processor when the program runs, with or
  without the standard library, and `implementation()` says which code
  runs. An S-box is read with shuffle instructions, whose index is an
  operand and not an address; SNOW 3G is clocked three times at once; AES
  is the crate's own key expansion and rounds, eight counter blocks at a
  time. The calls of this code and the instructions that clear the stack
  and the registers are the only `unsafe` code of the crate, in one
  private module; 0.2.0 had none. The tests compare the vector code with
  the scalar code, and `emulated-aarch64/` runs the AArch64 form on an
  emulated processor, where it gives what the scalar code and the x86-64
  code give. CI runs both, and the tests on an AArch64 machine.

- **Speed.** On one core of an AMD Ryzen 7 5700G, with the clearing, a
  1500-octet message takes 2.3 µs with 128-EEA1, 0.19 µs
  with 128-EEA2 and 3.2 µs with 128-EEA3, where 0.2.0 took
  5.1 µs, 2.8 µs and 5.2 µs; its MAC takes 0.41 µs,
  0.98 µs and 3.6 µs, where 0.2.0 took 8.4 µs, 2.8 µs and
  13.8 µs. A 64-octet message takes 0.052 µs to 0.50 µs for the six, where 0.2.0 took
  0.15 µs to 0.99 µs. The scalar code is slower than 0.2.0 for ciphering
  with SNOW 3G and ZUC, which is the cost of tables that are not read at a
  secret index. A key derivation takes 0.24 µs, where 0.2.0 took
  0.16 µs without wiping its HMAC state. `benches/README.md` has the
  figures.

- **Dependencies.** sha2 0.11, aes 0.9, p256 0.14 and x25519-dalek 3,
  where 0.2.0 had sha2 0.10, aes 0.8, p256 0.13 and x25519-dalek 2.
  getrandom 0.4 gives the ephemeral keys of SUCI. `hmac`, `cipher`,
  `rand_core` and `thiserror` are no longer dependencies, nor the `derive`
  feature of `zeroize`. The lowest versions that the manifest allows are
  the lowest that build each set of features, and CI tests with them. The
  minimum supported Rust version stays 1.88.

- A failure of the system's random number generator while a SUCI is
  concealed is `SuciError::RandomSource`, where 0.2.0 panicked.

- The crate warns on a public item without documentation: the 35 that had
  none are documented.

### Added

- **MILENAGE** (TS 35.205 to TS 35.208), and the authentication of
  TS 33.102 on it, in `oxirush_security::milenage`. 0.2.0 took CK, IK, RES
  and SQN ⊕ AK from the caller.

  | Item | What it is |
  |------|------------|
  | `K`, `Op`, `Opc`, `Ak`, `AkStar`, `Xres` | Keys: wiped when they are dropped, compared in constant time, printed as their name alone |
  | `Sqn`, `Amf`, `MacA`, `MacS`, `Res`, `Auts` | Values that travel in clear or in an AUTN, printed whole. `Sqn::try_from(u64)` refuses a number above 2^48 - 1 and `get()` gives it back; `Amf::separation_bit()` |
  | `Opc::from_op(&K, &Op)` | OPc = OP ⊕ E[OP]K |
  | `Milenage::new(&K, &Opc)`, `with_constants(&K, &Opc, Constants)` | A subscriber, with the constants c1 to c5 and r1 to r5 of TS 35.206 §4.1 or with those of its operator (§5.3), which `Constants::new` checks |
  | `f1`, `f1_star`, `f2`, `f3`, `f4`, `f5`, `f5_star`, `f2345` | The functions, each from one TEMP: MAC-A, MAC-S, RES, CK, IK, AK, AK\* |
  | `authentication_vector(&Rand, &Sqn, &Amf) -> AuthenticationVector` | RAND, XRES, CK, IK and AUTN = SQN ⊕ AK \|\| AMF \|\| MAC-A (TS 33.102 §6.3.2); `xres_star(sn_name)` gives XRES\* of 5GS |
  | `check_autn(&Rand, &Autn) -> Result<UsimResponse, SecurityError>` | The USIM: SQN, MAC-A compared in constant time, then RES, CK and IK (§6.3.3); `Err(MacFailure)` for a MAC that is not the one of K; `res_star(sn_name)` gives RES\*. Whether the SQN is fresh and the AMF has the separation bit is the caller's to decide |
  | `auts(&Rand, &Sqn) -> Auts`, `verify_auts(&Rand, &Auts) -> Result<Sqn, SecurityError>` | The AUTS of SQNMS with MAC-S over an AMF of zeros (§6.3.3), and its reading in the home network (§6.3.5) |
  | `authentication_vector_batch(&mut [VectorJob])`, `check_autn_batch(&mut [AutnJob])` | The same for many subscribers: on the AES instructions the key expansions and the encryptions of eight run side by side, and a thousand take half the time of a call for each |

  Each operation runs on the AES instructions of the processor where it
  has them and on the `aes` crate elsewhere, needs no allocator, and
  clears the stack and the registers after its work as the other
  operations do. `Implementation::milenage()` and
  `milenage_side_by_side()` say which code runs. An authentication vector
  takes 0.13 µs, and 0.06 µs in a batch of a thousand, where the `milenage`
  crate 0.1.6 takes 0.26 µs; `benches/README.md` has the figures.
  `SecurityError::MacFailure` is new.

  A program that took MILENAGE from the `milenage` crate 0.1.6 calls:

  | `milenage` 0.1.6 | 0.3.0 |
  |------------------|-------|
  | `Milenage::new_with_opc(k, opc)` | `Milenage::new(&K::new(&k), &Opc::new(&opc))` |
  | `Milenage::new_with_op(k, op)` | `Milenage::new(&k, &Opc::from_op(&k, &op))`, with `k = K::new(&k)` |
  | `m.opc` | `Opc::from_op(&k, &op)` |
  | `m.f1(&rand, &sqn, &amf) -> [u8; 8]` | `m.f1(&Rand::new(&rand), &Sqn::new(&sqn), &Amf::new(&amf)) -> MacA` |
  | `m.f1star(&rand, &sqn, &amf)` | `m.f1_star(..) -> MacS` |
  | `m.f2345(&rand) -> (res, ck, ik, ak)` | `m.f2345(&rand) -> (Res, Ck, Ik, Ak)` |
  | `m.f5star(&rand)` | `m.f5_star(&rand) -> AkStar` |
  | `m.compute_res_star(mcc, mnc, &rand, &res)` | `nas_5gs::compute_res_star(&ck, &ik, sn_name, &rand, res.as_octets())`, or `response.res_star(sn_name)` after `check_autn` |
  | `m.res`, `m.ck`, `m.ik`, `m.ak`, `m.maca`, `m.macs`, `m.res_star` | The values that the functions return: a `Milenage` keeps none |
  | the AUTN, the check of an AUTN and the AUTS, written by the program | `authentication_vector`, `check_autn`, `auts`, `verify_auts` |

- **Cargo features.** The algorithms, the keys and their derivations build
  without the standard library and without an allocator, with 15 crates
  and no procedural macro; 0.2.0 had no feature and 76 crates.

  | Feature | The crate has | Needs |
  |---------|---------------|-------|
  | none (`default-features = false`) | The algorithms, the contexts and the batches, the keys and every derivation, NAS integrity and ciphering, the selection of the algorithms, the SUPI, the 5G-GUTI and the PLMN | `core` alone |
  | `alloc` | And what returns a `Vec` or a `String`: `kdf::build_s`, `tbcd::encode`, `tbcd::decode`, `Supi::into_owned` | An allocator |
  | `std`, a default | And, on an AArch64 system other than Linux, Android and Apple's, the choice of the vector code when the program runs | The standard library |
  | `suci`, a default | And `nas_5gs::Suci` with the null scheme, Profile A and Profile B: 42 crates | `alloc`, and a source of random numbers for `getrandom` |
  | `nai`, a default | And the SUCI in the NAI format and that of a SUPI that is a NAI: 70 crates | `suci` |

  On a target without an operating system the vector code runs when the
  build enables its instructions. CI builds each set of features for
  `thumbv7em-none-eabihf` and `aarch64-unknown-none`. The derivations give
  the hasher their parameters part after part: the string S of TS 33.220
  is not built, and a parameter that is a key has no copy to wipe.

- **Keyed contexts.** `IntegrityContext` and `CipheringContext` hold a key
  with its algorithm and what the algorithm computes from the key alone,
  the round keys of AES and the subkeys of CMAC: 240 and 208 octets. A
  context serves both directions, takes the COUNT and the BEARER at each
  message, and makes the job of a message for a batch. With a context
  128-EEA2 takes 29 ns on 64 octets and 128-EIA2 81 ns,
  where the functions that take a key take 52 ns and
  121 ns.

- **Batches.** `nea_cipher_batch` and `nia_mac_batch` cipher or
  authenticate many messages in one call. Each message is a `CipherJob` or
  a `MacJob` with its own key, COUNT, BEARER, DIRECTION and algorithm;
  `nas_5gs::cipher_job`, `nas_5gs::mac_job` and their counterparts of
  `nas_eps` make the job of a NAS message. SNOW 3G and ZUC generators are
  clocked side by side, four in a 128-bit vector and eight with AVX2, and
  the CBC-MAC chains of eight messages of 128-EIA2 advance together. What
  a generator or a chain does at a step depends on the lengths of the
  messages alone. Sixteen messages of 1500 octets take 10.4 µs with
  128-EEA1 and 13.9 µs with 128-EEA3 in one call, where sixteen calls
  take 36.9 µs and 51.6 µs.

- `implementation()` says which code the algorithms run on this processor:
  `Implementation::Scalar`, `Vector128` or `Vector256`, with the code of
  each algorithm and how many messages a batch works on side by side.
  `tests/implementation.rs` fails in a CI job that does not run the code
  that the job names.

- `NasCount::next`, `estimate`, `estimate_from_low_bits` and their
  `wrapping_` forms; `nas_5gs::compute_res_star` and `compute_hxres_star`;
  `XresStar::accepts` and `HxresStar::accepts`, which compare in constant
  time; `nas_eps::derive_skgnb`; `constant_time_eq`.

- Tests: MILENAGE on the six sets of TS 35.207 with their intermediate
  values and on the twenty of TS 35.208 (set 2 repeats set 1 there), its AES
  on the twenty Rijndael sets of TS 35.208 and the round keys of TS 35.207,
  and every AUTN and AUTS with one bit changed refused; 128-EIA2 set 7 of
  TS 33.401 Annex C.2.7, the six UEA2 design conformance sets of TS 35.218
  for 128-EEA1, every TS 33.501 Annex C.4 data set of SUCI with its
  intermediate values, and a 5G AKA key chain from the TS 35.208 test set 1
  outputs through KAUSF, XRES\*, HXRES\*, KSEAF, KAMF, the NAS keys, KgNB
  and NH, which `tests/five_g_aka_chain.py` derives with the HMAC-SHA-256 of
  Python. KSEAF, KAMF, the 5GS NAS keys, NH and XRES\* had no test before.
  The blocks of the README are compiled and run, and `tests/readme.rs`
  compares what each prints with the text under it.

- Four `cargo fuzz` targets under `fuzz/`, which CI runs for a minute each
  at a push and for half an hour each week; `benches/`, which times the
  algorithms, the derivations, MILENAGE and SUCI with criterion;
  `leftovers/` and `emulated-aarch64/`; a `SECURITY.md`; an advisory check
  in CI.

### Fixed

- The algorithms count octets, not bits. On a 32-bit target the length of
  a buffer of 512 MiB or more, multiplied by 8, overflowed `usize`: a
  debug build panicked, and a release build took the wrapped product for
  the length to process.
- A SUCI whose first octet has spare bit 4 set is read, as one with spare
  bit 8 is (TS 24.501 §9.11.3.4).
- Profile A checks the contributory behaviour of X25519 with the
  constant-time comparison of its dependency.
- The notes of 0.2.0 credited this crate with a NAS context and
  `protect_re_establishment`, which oxirush-nas has.
- The documentation of `re_establishment_nas_mac` says that the 28-bit
  reading of the target Cell-ID is this crate's, for which no test data or
  other implementation exists.

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
