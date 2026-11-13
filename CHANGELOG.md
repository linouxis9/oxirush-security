# Changelog

All notable changes to `oxirush-security` are recorded here.

## Unreleased

### Added

- `eap_aka_prime`: the keys of EAP-AKA' (RFC 9048), CK' and IK' of the
  network name, then K_encr, K_aut, K_re, the MSK and the EMSK of PRF', and
  KAUSF of the EMSK (TS 33.501 Annex F), tested with the vectors of RFC 9048
  Appendix D.

## 0.4.0 - 2026-11-07

### Changed

- oxirush-utils 0.2. The algorithm is its `identity::Algorithm` (`Null`,
  `Snow3g`, `Aes`, `Zuc`), which ciphering and integrity share in 5GS and EPS.
  A SUCI is its `identity::Suci`, and `nas_5gs::conceal_imsi`,
  `nas_5gs::conceal_nai` and `nas_5gs::deconceal` conceal and de-conceal one;
  `deconceal` refuses a scheme output shorter than its profile as `Truncated`.
- The default features are `std` alone; `nai` is part of `suci`. The batches
  are the feature `batch`, in the module `batch`.
- The algorithms run through the keyed contexts, which take any COUNT and
  BEARER; a NAS message keeps `nas_cipher` and `nas_mac` of its system.
- `nas_5gs::derive_kamf` takes the identity of the SUPI, as the derivation
  takes it.
- `select_integrity_algorithm` and `select_ciphering_algorithm` take the
  preference; `DEFAULT_INTEGRITY_PREFERENCE` and `DEFAULT_CIPHERING_PREFERENCE`
  are the default one.
- `nas_eps::service_request_short_mac` takes the first octet of the message.
- `Snow3G::new` takes the octets of the key and the IV.
- The keys of a change between 5GS and EPS are tested against another
  implementation (`tests/interworking_keys.py`).

### Removed

- `IntegrityAlgorithm`, `CipheringAlgorithm` and their names; `nas_5gs::Suci`,
  `HomeNetwork`, `SchemeOutput`.
- `nea_cipher`, `nea_cipher_bits`, `nia_mac`, `nia_mac_bits`, and `cipher_job`
  and `mac_job` of `nas_5gs` and `nas_eps`.
- `select_*_algo` and `select_*_algo_with_preference`,
  `service_request_short_mac_with_header`, `Code`, `Snow3G::from_bytes`.
- The re-exports of identities beside `identity`: `Plmn` and `tbcd` at the
  root, `kdf::Zeroizing`, and `Guti`, `STmsi`, `MobileIdentityType`, `Supi`,
  `SupiType`, `ProtectionScheme` and `RoutingIndicator` of `nas_5gs`.

### Migration from 0.3

| 0.3 | 0.4 |
|-----|-----|
| default features | `features = ["suci"]` to conceal or read a SUCI; `["batch"]` for the batches; `nai` is `suci` |
| `IntegrityAlgorithm::NIA2`, `CipheringAlgorithm::NEA2`, `EIA2`, `EEA2` | `identity::Algorithm::Aes` (and `Null`, `Snow3g`, `Zuc`) |
| `IntegrityAlgorithm::try_from(x)?` | `Algorithm::try_from(x).map_err(SecurityError::UnsupportedAlgorithm)?` |
| `algorithm.name_5gs()` | `{algorithm:?}`, or a name of the program's own |
| `nea_cipher(&key, count, bearer, direction, data, algorithm)` | `CipheringContext::new(&key, algorithm).cipher(count, bearer, direction, data)` |
| `nia_mac(&key, count, bearer, direction, message, algorithm)` | `IntegrityContext::new(&key, algorithm).mac(count, bearer, direction, message)` |
| `nas_5gs::cipher_job(key, count, access, direction, data, algorithm)` | `batch::CipherJob::new(key, count.get(), access.into(), direction, data, algorithm)` |
| `nea_cipher_batch(&mut jobs)`, `nia_mac_batch` | `batch::cipher(&mut jobs)`, `batch::mac` |
| `milenage::authentication_vector_batch`, `check_autn_batch` | `batch::authentication_vectors`, `batch::check_autn` |
| `select_integrity_algo(capability)` | `select_integrity_algorithm(capability, DEFAULT_INTEGRITY_PREFERENCE)` |
| `select_integrity_algo_with_preference(capability, &order)` | `select_integrity_algorithm(capability, &order)` |
| `service_request_short_mac(key, count, direction, octet, algorithm)` | `service_request_short_mac(key, count, direction, 0xc7, octet, algorithm)?` |
| `Snow3G::from_bytes(&key, &iv)`, `Snow3G::new(&words, &iv_words)` | `Snow3G::new(&key, &iv)` |
| `derive_kamf(&kseaf, &supi, &abba)` | `derive_kamf(&kseaf, supi.identity(), &abba)` |
| `Suci::conceal_imsi(..)`, `Suci::conceal_nai(..)` | `nas_5gs::conceal_imsi(..)`, `nas_5gs::conceal_nai(..)` |
| `suci.deconceal(key)` | `nas_5gs::deconceal(&suci, key)` |
| `nas_5gs::Suci::from_nas_octets(octets)?` | `identity::Suci::from_nas_octets_tolerant(octets)?.0` |
| `Suci::from_nai(text)?`, `suci.to_nai()?` | `Suci::Nai(NaiSuci::parse(text)?)`, `suci.to_nai()?.to_string()` |
| `suci.scheme_output()`, `suci.home_network()` | the parts of `Suci::Imsi` and `Suci::Nai` (`concealed_output`, `msin`, `plmn`, `realm`) |
| `oxirush_security::Plmn`, `nas_5gs::Supi`, `nas_5gs::Guti` | `oxirush_security::identity::Plmn`, `identity::Supi`, `identity::Guti5g` |
| `oxirush_security::tbcd` | `oxirush_utils::identity::tbcd` |
| `Code`, `implementation().ciphering(algorithm)` | `implementation()` |

## 0.3.0 - 2026-10-24

Every call changed from 0.2.0: a key has a type, a value that a
specification bounds has a type that holds only the values in range, and
what a type cannot say is a `Result`; no public function panics on its
arguments. Each item has one path: what both systems share at the root, the
keys and derivations of each system in `nas_5gs` and `nas_eps`, MILENAGE and
AKA in `milenage`, the KDF in `kdf`. Keys are wiped when dropped, and each
operation clears the stack and the registers that it used. Added: keyed
contexts and batches, the vector code of SNOW 3G, ZUC and AES on x86-64 and
AArch64, SUCI concealment of profiles A and B and of the NAI format, the
5GS/EPS key mappings, HASHMME, and the other derivations of TS 33.501 and
TS 33.401 Annex A.

## 0.2.0 - 2026-09-27

The EPS key hierarchy and NAS security of TS 33.401 (`nas_eps`), the 5GS/EPS
key mappings, and the module layout by system; MSRV 1.88.
