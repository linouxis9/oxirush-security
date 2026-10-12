/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! The security functions of 5GS and EPS: key derivation, NAS integrity and
//! ciphering, and SUCI concealment, per 3GPP TS 33.501 and TS 33.401.
//!
//! ```rust
//! use oxirush_security::nas_5gs::{
//!     CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, derive_knas_enc,
//!     derive_knas_int, nas_cipher, nas_mac,
//! };
//!
//! // KAMF, the key of the AMF
//! let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
//! let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();
//!
//! // The NAS keys of the algorithms that the AMF selected
//! let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
//! let k_nas_enc = derive_knas_enc(&k_amf, nea2);
//! let k_nas_int = derive_knas_int(&k_amf, nia2);
//! println!("KNASenc {}", hex::encode(k_nas_enc));
//! println!("KNASint {}", hex::encode(k_nas_int));
//!
//! // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
//! // it, then compute the MAC over the sequence number and the ciphertext
//! let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
//! let mut message = [0x7e, 0x00, 0x43];
//! nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
//! let protected = [&[count.sequence_number()][..], &message].concat();
//! let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
//! println!("ciphered {}, MAC {mac:08x}", hex::encode(message));
//! ```
//!
//! ```text
//! KNASenc f47ae570afde775373d1b313d2176f54
//! KNASint 28ddb5356880149b9fee22f2367522a4
//! ciphered b57dd5, MAC 83e4d009
//! ```
//!
//! The functions take octets. The crate stores no key and keeps no NAS
//! COUNT: the caller passes both for each message. A receiver computes the
//! MAC first, then deciphers with the same call (TS 24.501 §4.4.3). No
//! function panics on its arguments.
//!
//! The [README](https://github.com/linouxis9/oxirush-security#readme) has
//! an example for each task: the keys of a 5G AKA run and of a handover,
//! NAS protection in EPS, SUCI concealment, the algorithms on the 3GPP test
//! sets.
//!
//! # Where things are
//!
//! | Module | Contents |
//! |--------|----------|
//! | [`nas_5gs`] | TS 33.501: key derivation, NAS integrity and ciphering, algorithm selection, 5G-GUTI, and SUCI concealment |
//! | [`nas_eps`] | TS 33.401: key derivation, NAS integrity and ciphering with BEARER 0, the short MAC of a SERVICE REQUEST, HASHMME |
//! | [`common`] | What both share: the algorithms with their own ranges ([`nia_mac`], [`nea_cipher`]), SNOW 3G and ZUC, the KDF of TS 33.220, the types of the inputs, PLMN and TBCD |
//!
//! The crate root has the functions of [`nas_5gs`] and of [`common`]. The
//! functions of EPS are under [`nas_eps`], with the same names where the two
//! systems have the same thing: [`nas_eps::nas_mac`],
//! [`nas_eps::derive_knas_int`].
//!
//! # What it implements
//!
//! The last column names the kind of reference value that the tests have,
//! which [the section on tests](#what-the-tests-compare-with) explains.
//!
//! | What | Functions | Specification | Reference values |
//! |------|-----------|---------------|------------------|
//! | NAS ciphering | `nas_cipher`; the algorithms `nea_cipher`, `nea1_cipher`, `nea2_cipher`, `nea3_cipher` and their `*_bits` forms | NEA0 (null), NEA1 (SNOW 3G, 128-EEA1), NEA2 (AES-128-CTR, 128-EEA2), NEA3 (ZUC, 128-EEA3): TS 33.401 Annex B.1 | 3GPP |
//! | NAS integrity | `nas_mac`; the algorithms `nia_mac`, `nia1_mac`, `nia2_mac`, `nia3_mac` and their `*_bits` forms | NIA1 (SNOW 3G, 128-EIA1), NIA2 (AES-CMAC, 128-EIA2), NIA3 (ZUC, 128-EIA3): TS 33.401 Annex B.2 | 3GPP |
//! | Keystream generators | `Snow3G`, `Zuc` | TS 35.216, TS 35.222 | 3GPP |
//! | 5G AKA | `derive_kausf`, `compute_xres_star`, `compute_hres_star`, `derive_kseaf`, `derive_kamf`, `derive_knas_enc`, `derive_knas_int`, `derive_kgnb`, `derive_nh` | TS 33.501 Annex A.2 and A.4 to A.10 | other implementations |
//! | Other 5GS derivations | KAMF', KN3IWF, KNG-RAN\*, KSN, the RRC and UP keys, the SoR and UPU MACs, the TNAP usage keys, KIAB | TS 33.501 Annex A | calculated |
//! | EPS derivations | KASME, KNASint and KNASenc, KeNB, NH, KeNB\*, the AS keys, the NAS token, the CK'/IK' mapping, SRVCC, S-KeNB, LWIP-PSK, S-KWT, K_n | TS 33.401 Annex A | calculated |
//! | HASHMME | `nas_eps::compute_hash_mme` | TS 33.401 Annex I.2 | other implementations |
//! | 5GS/EPS key mapping | Idle mobility and connected handover in both directions, and KASME_SRVCC | TS 33.501 Annexes A.14, A.15 and A.21 | calculated |
//! | Other NAS MACs | `nas_container_mac`; `nas_eps::re_establishment_nas_mac` for UL_NAS_MAC and XDL_NAS_MAC; `nas_eps::service_request_short_mac` | TS 33.501 §6.9.2.3.3; TS 33.401 §7.4.4; TS 24.301 §9.9.3.28 | calculated |
//! | SUCI | IMSI and NAI identities with the null scheme, Profile A (X25519 ECIES) and Profile B (P-256 ECIES), and proprietary outputs kept as they are | TS 33.501 Annex C | 3GPP |
//! | 5G-GUTI, 5G-S-TMSI | `build_guti_bytes`, `parse_guti_tmsi`, `parse_s_tmsi` | TS 24.501 §9.11.3.4 | calculated |
//! | PLMN and TBCD | `plmn_to_bytes`, `plmn_from_bytes`, `tbcd_encode`, `tbcd_decode` | TS 24.501 §9.11.3.4, TS 29.002 | calculated |
//! | Algorithm selection | `select_integrity_algo`, `select_ciphering_algo` with NIA2 > NIA1 > NIA3 (never NIA0) and NEA2 > NEA1 > NEA3 > NEA0, the default order; their `*_with_preference` forms with an operator's order | TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1 | calculated |
//!
//! EPS and 5GS share the 128-bit EEA/EIA algorithm cores, and the
//! whole-octet NAS wrappers delegate to them. The `*_bits` functions take a
//! length in bits: they preserve the unused low bits of the final octet
//! when ciphering and ignore them for integrity.
//!
//! Concealment draws a fresh ephemeral key, so two SUCI outputs for one MSIN
//! differ. Profile B always applies point compression (TS 33.501
//! Annex C.3.4), and deconcealment rejects an uncompressed ephemeral point,
//! as TS 33.514 §4.2.1.3 requires.
//!
//! # Inputs and errors
//!
//! A value that a specification bounds has a type that holds only the
//! values in range: [`IntegrityAlgorithm`], [`CipheringAlgorithm`],
//! [`Direction`], [`NasCount`], [`AccessKeyCount`], [`NasConnection`] and
//! [`Bearer`]. A number from a peer or from a configuration enters through
//! `TryFrom` or `new`, which return a [`SecurityError`], and the functions
//! that take these types cannot fail. What a type cannot say is a `Result`
//! or an `Option`.
//!
//! | Input | Type or check |
//! |-------|---------------|
//! | Algorithm of a MAC, a cipher or a key | `IntegrityAlgorithm` and `CipheringAlgorithm`: the four of each that 5GS and EPS share, under both names (`NIA2` and `EIA2`). `try_from(u8)` reads an identifier and refuses 4 and above; `u8::from` gives it back |
//! | NAS COUNT | `NasCount`, 24 bits: `new`, `try_from(u32)` or `from_parts(overflow, sequence_number)` |
//! | COUNT of the KgNB and KeNB derivations | A `NasCount`, or `AccessKeyCount::Handover` for the 2^32 - 1 of a handover |
//! | NAS connection of 5GS | `NasConnection::ThreeGpp` (identifier 1) or `Non3Gpp` (2) |
//! | DIRECTION | `Direction::Uplink` or `Downlink` |
//! | COUNT and BEARER of the algorithms themselves | Any `u32`, and `Bearer`, 5 bits |
//! | Length in bits | `Err(BitLengthExceedsData)` when the buffer is shorter |
//! | PCI, ARFCN, AMF Set ID, AMF Pointer, cell identity | `Err(OutOfRange)` above the largest value |
//! | MCC, MNC, MSIN and TBCD string | `Err(InvalidParameter)` for a wrong length or character |
//! | KDF parameter of variable length | `Err(InputTooLong)` above 65535 octets |
//! | SUCI, 5G-GUTI and 5G-S-TMSI from a peer | `None` or an `Err` for what cannot be read or deconcealed |
//!
//! [`nas_mac`] and [`nas_cipher`] are the functions of NAS. They exist in
//! [`nas_5gs`] and in [`nas_eps`], and the crate root re-exports those of
//! [`nas_5gs`]. The functions named after an algorithm ([`nia_mac`],
//! [`nea_cipher`], [`nia2_mac`] and the others of [`common`]) take what the
//! algorithm takes.
//!
//! # Key material and timing
//!
//! | Subject | What the crate does |
//! |---------|---------------------|
//! | Wiped after use | Explicit buffers and owned state: CK‖IK buffers, key-bearing KDF input buffers, the SHA-256 state and the key block and inner hash of HMAC-SHA-256, SUCI ECIES KDF buffers, cipher state including the AES key schedule, and keystream buffers. The hasher and the AES cipher are those of the `sha2` and `aes` crates, built with their `zeroize` features: the crate does not compile without them. |
//! | Not wiped | Temporary copies and compiler-generated spills, which the wiping above does not all cover. Returned keys and deconcealed identities belong to the caller, who clears them when their lifetime ends. |
//! | Secret-dependent indexing and branches | SNOW 3G, ZUC, 128-EIA1, 128-EIA3 and AES-CMAC neither index memory nor branch on a secret value, in either of the two forms that SNOW 3G and ZUC have. |
//! | On vector instructions | On an x86-64 processor with SSSE3, SSE4.1, AES-NI and PCLMULQDQ, or an AArch64 one with AES, which the crate sees when the program runs: an S-box is read with shuffle instructions, whose index is an operand and not an address; S1 of SNOW 3G and the S-box inside S1 of ZUC are the AES instruction; the products of the two MACs are the carry-less multiplication instruction. SNOW 3G is clocked three times at once. |
//! | In scalar code | Elsewhere, and as the reference of the tests: S1 of SNOW 3G and the S-box S1 of ZUC are computed from one round of AES, which the `aes` crate runs as a bitsliced routine without the AES instructions. The S-box SQ of SNOW 3G is read whole and narrowed down through masks. S0 of ZUC is three four-bit S-boxes, each a word that is shifted. MULα, DIVα and the field multiplications of the two MACs are carry-less products, made with shifts and integer multiplications. A mask that a secret bit gives goes through `core::hint::black_box`. |
//! | Checked in the compiled code | Without `black_box` the compiler turned the masked selection of SQ in the scalar code into conditional jumps on bits of the state. In the release build for x86-64 with Rust 1.98.1, the functions of SNOW 3G and ZUC in both forms and of the six algorithms were read in the disassembly: their conditional jumps test a length, a loop counter, a place in a buffer, a feature of the processor or whether the generator has started, and none a secret. In the scalar code, shifts by a secret amount and multiplications of secret words remain. They take a time that does not depend on their operands on the x86-64 and AArch64 processors of today, and may not on a small processor whose multiplier stops early. |
//! | Comparison | [`constant_time_eq`] compares RES\* with XRES\*, or HRES\* with HXRES\*, through `subtle`: its time depends on the lengths and not on where the values differ. |
//! | Not measured | No timing was measured, and no other target or compiler was read. The AArch64 form is the code of the x86-64 one on other instructions; CI runs the tests on an AArch64 machine. |
//!
//! The `unsafe` code of the crate is in one module, `common::simd`, and of
//! one kind: the calls of the code that is compiled for the vector
//! instructions, once the processor is seen to have them. That code takes
//! and returns values, never a pointer.
//!
//! # What the tests compare with
//!
//! The unit tests and `tests/spec_vectors.rs` rest on four kinds of
//! reference values, which do not carry the same weight.
//!
//! | Kind | What is tested against it |
//! |------|---------------------------|
//! | **3GPP** test data | 128-EEA1/2/3 and 128-EIA1/2/3 on the TS 33.401 Annex C, TS 35.217, TS 35.218 and TS 35.223 sets, including non-byte-aligned EEA1, EEA2, EEA3, EIA1, EIA2 and EIA3 inputs; the SNOW 3G and ZUC keystreams; SUCI on every TS 33.501 Annex C.4 data set. |
//! | **RFC and FIPS** test data | HMAC-SHA-256, which is this crate's over the SHA-256 of `sha2`, on test cases 1, 2, 3, 6 and 7 of RFC 4231; SHA-256 on the examples of FIPS 180-4; the subkeys of AES-CMAC on the example of RFC 4493. |
//! | Values of **other implementations** | The 5G AKA chain from the TS 35.208 test set 1 MILENAGE outputs through KAUSF, XRES\*, HXRES\*, KSEAF, KAMF, the NAS keys, KgNB and NH, which `tests/five_g_aka_chain.py` derives with the HMAC-SHA-256 of Python's standard library over the inputs that TS 33.501 Annex A lays out; HASHMME on ATTACH REQUESTs and the values a network returned for them. |
//! | Values **calculated** in the tests | The other 5GS KDFs, the EPS and interworking KDFs, and the NAS container, short and re-establishment MACs are compared with HMAC-SHA-256 or the MAC over the parameter layout as the test writes it. The identity encodings and the algorithm selection are compared with what the test writes too. These tests keep a layout from changing unnoticed; they are not independent vectors. |
//!
//! The two forms of SNOW 3G and ZUC, on vector instructions and in scalar
//! code, are compared with each other: the keystream words of 400 keys and
//! IVs, taken in pieces of every length, and the six algorithms on messages
//! of every length up to 300 octets, in whole octets and at a length in
//! bits. The 3GPP test data goes through the form that the processor of the
//! test has. CI runs the tests on x86-64, on AArch64, and on 32-bit x86,
//! which has the scalar code alone.
//!
//! CI also fuzzes what takes octets from a peer, a minute for each of four
//! `cargo fuzz` targets under `fuzz/`: a SUCI, a scheme output and a NAI
//! are read without a panic, what is concealed is deconcealed, an identity
//! or a digit string that decodes encodes back to its octets, and every
//! algorithm takes any message at any length in bits and gives the same on
//! vector instructions and in scalar code.
//!
//! `tests/readme.rs` runs each Rust block of the README and of this page
//! and compares what it prints with the text under it.
//!
//! # Limits
//!
//! | Subject | Limit |
//! |---------|-------|
//! | Audit | The crate has not had a security audit. Its timing has been read in the source and in one compiled build, not measured. |
//! | State | It stores no keys, and it keeps neither the NAS COUNT nor replay state: those belong to the caller. |
//! | AKA | It has no MILENAGE or TUAK: CK, IK, RES and SQN xor AK come from the caller. |
//! | NAS messages | It protects octets. It does not encode a NAS message or its security header. |
//! | Re-establishment MAC | The 28-bit reading of the target Cell-ID is this crate's: no test data or other implementation exists to check it against. |
//!
//! # Terms
//!
//! | Term | Meaning |
//! |------|---------|
//! | UE, AMF, MME | The device (User Equipment), and the function of the core network that it talks NAS to: the AMF in 5GS, the MME in EPS |
//! | gNB, eNB | The base station of 5GS and of EPS |
//! | AKA | Authentication and Key Agreement. It gives the ciphering key CK, the integrity key IK, the response RES, and the sequence number SQN hidden under the anonymity key AK |
//! | KAUSF, KSEAF, KAMF | The keys of the 5GS hierarchy, each derived from the one before: of the AUSF in the home network, of the SEAF in the serving network, of the AMF |
//! | KNASenc, KNASint | The keys that cipher and authenticate NAS messages, derived from KAMF in 5GS and from KASME in EPS |
//! | KASME | The key of EPS that CK and IK give, at the place of KAMF |
//! | KgNB, KeNB, NH | The key of a base station, and the Next Hop key that replaces it at a handover |
//! | ABBA | Anti-Bidding down Between Architectures: a parameter of the KAMF derivation, `0x0000` so far |
//! | KDF | Key derivation function: HMAC-SHA-256 over a string S that TS 33.220 lays out |
//! | NAS COUNT | The 24-bit counter of the NAS messages of one direction, which the algorithms take |
//! | MAC | Message authentication code: the 32 bits that protect the integrity of a message |
//! | NEA, NIA; EEA, EIA | The ciphering and integrity algorithms, as 5GS and as EPS name them. They are the same four of each |
//! | SUPI, SUCI | The Subscription Permanent Identifier, an IMSI or a NAI, and its concealed form, the Subscription Concealed Identifier that a UE sends |
//! | IMSI, MSIN | The International Mobile Subscriber Identity, and its last part, the subscriber number that a SUCI conceals |
//! | NAI | Network Access Identifier, `username@realm` (RFC 7542) |
//! | GCI, GLI | The Global Cable Identifier and the Global Line Identifier, two identities of wireline access that are written as NAIs |
//! | PLMN, MCC, MNC | A Public Land Mobile Network, which its Mobile Country Code and its Mobile Network Code identify |
//! | 5G-GUTI, 5G-S-TMSI | The temporary identity that an AMF gives a UE, and its short form |
//! | TBCD | Telephony Binary Coded Decimal: two digits to an octet, the first in the low half |
//!
//! # Features
//!
//! Both are on by default.
//!
//! | Feature | Adds |
//! |---------|------|
//! | `suci` | `nas_5gs::suci`: SUCI concealment and deconcealment with the null scheme, Profile A (X25519) and Profile B (P-256) |
//! | `nai` | The SUCI and SUPI of the NAI format: network specific identifiers, GCI and GLI. It needs `suci`, and brings Unicode normalization and IDNA |
//!
//! Without them the crate has the key derivations and the algorithms, and
//! depends on `sha2`, `aes`, `zeroize` and `subtle` alone.
//!
//! # Specifications
//!
//! | Specification | For |
//! |---------------|-----|
//! | TS 33.501 | 5G security architecture: key derivation, algorithm IDs, SUCI |
//! | TS 33.401 | EPS security architecture: key derivation, NAS COUNT, EIA/EEA |
//! | TS 35.215, 35.216, 35.217, 35.218 | SNOW 3G modes, core, and test data |
//! | TS 35.221, 35.222, 35.223 | ZUC modes, core, and test data |

// `unsafe` is allowed in one module, `common::simd`, which says why
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

pub mod common;
pub mod nas_5gs;
pub mod nas_eps;

// The examples of the README are compiled and run with the doctests. They
// use every feature.
#[cfg(all(doctest, feature = "nai"))]
#[doc = include_str!("../README.md")]
struct Readme;

// The crate root has the 5GS functions and the shared ones. `nas_mac` and
// `nas_cipher` are those of `nas_5gs`, which take a NAS COUNT and a NAS
// connection; the algorithms with their own ranges are `nia_mac` and
// `nea_cipher`.
pub use common::{
    AccessKeyCount, Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount,
    SecurityError, constant_time_eq, extract_128, nea_cipher, nea_cipher_bits, nea1_cipher,
    nea1_cipher_bits, nea2_cipher, nea2_cipher_bits, nea3_cipher, nea3_cipher_bits, nia_mac,
    nia_mac_bits, nia1_mac, nia1_mac_bits, nia2_mac, nia2_mac_bits, nia3_mac, nia3_mac_bits,
    plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode,
};
pub use common::{error, input, nea, nia, plmn, snow3g, zuc};
#[cfg(feature = "suci")]
#[cfg_attr(docsrs, doc(cfg(feature = "suci")))]
pub use nas_5gs::suci;
pub use nas_5gs::{
    IabIpAddress, KamfMobilityDirection, NasConnection, TnapKeyUsage, build_guti_bytes,
    compute_hres_star, compute_xres_star, derive_kamf, derive_kamf_prime,
    derive_kamf_prime_handover, derive_kamf_prime_idle, derive_kausf, derive_kgnb, derive_kiab,
    derive_knas_enc, derive_knas_int, derive_kseaf, derive_ksn, derive_nh, derive_sor_mac_ausf,
    derive_sor_mac_ue, derive_tnap_usage_key, derive_upu_mac_ausf, derive_upu_mac_ue,
    mobile_identity_type, nas_cipher, nas_mac, parse_guti_tmsi, parse_s_tmsi,
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
#[cfg(feature = "nai")]
#[cfg_attr(docsrs, doc(cfg(feature = "nai")))]
pub use nas_5gs::{
    NaiProtectionScheme, NaiSuci, SuciSchemeOutput, SupiType, conceal_network_specific_supi,
    deconceal_nai_suci, deconceal_network_specific_suci, encode_nai_suci, parse_nai_suci,
};
pub use nas_5gs::{algo, guti, kdf};
#[cfg(feature = "suci")]
#[cfg_attr(docsrs, doc(cfg(feature = "suci")))]
pub use nas_5gs::{
    msin_to_bcd, suci_conceal, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b, suci_to_string, suci_to_supi,
};

/// What `cargo fuzz` drives beside the public functions. It builds the
/// crate with `--cfg fuzzing`; no other build has this module.
#[cfg(fuzzing)]
#[doc(hidden)]
pub mod fuzzing {
    /// Run `work` without the vector instructions of the processor, on the
    /// scalar code that every target has.
    pub fn scalar<R>(work: impl FnOnce() -> R) -> R {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        return crate::common::simd::scalar(work);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        work()
    }
}
