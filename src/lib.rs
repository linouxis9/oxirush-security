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
//! They are functions over octets. The crate stores no key and keeps no
//! NAS COUNT: the caller passes both for each message. No function panics
//! on its arguments.
//!
//! SNOW 3G, ZUC and the two MACs that use them run on the AES, vector and
//! carry-less multiplication instructions of an x86-64 or AArch64 processor
//! that has them, which is seen when the program runs, and on scalar code
//! elsewhere. The calls of that vector code are the `unsafe` code of the
//! crate, in one module.
//!
//! # Deriving the keys from an authentication vector
//!
//! Authentication gives CK, IK and SQN xor AK, which come from MILENAGE or
//! TUAK and not from this crate. The keys of 5GS follow from them
//! (TS 33.501 Annex A): KAUSF in the home network, KSEAF for the serving
//! network, KAMF for the AMF, then the two NAS keys of the algorithms that
//! the AMF selected.
//!
//! ```
//! use oxirush_security::nas_5gs::{
//!     CipheringAlgorithm, IntegrityAlgorithm, derive_kamf, derive_kausf, derive_knas_enc,
//!     derive_knas_int, derive_kseaf,
//! };
//!
//! // CK, IK and SQN xor AK: the MILENAGE outputs of TS 35.208 test set 1
//! let ck = [
//!     0xb4, 0x0b, 0xa9, 0xa3, 0xc5, 0x8b, 0x2a, 0x05, 0xbb, 0xf0, 0xd9, 0x87, 0xb2, 0x1b, 0xf8,
//!     0xcb,
//! ];
//! let ik = [
//!     0xf7, 0x69, 0xbc, 0xd7, 0x51, 0x04, 0x46, 0x04, 0x12, 0x76, 0x72, 0x71, 0x1c, 0x6d, 0x34,
//!     0x41,
//! ];
//! let sqn_xor_ak = [0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77];
//!
//! // The serving network name, the SUPI without its "imsi-" and the ABBA
//! let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
//! let (supi, abba) = ("208930000000001", [0x00, 0x00]);
//!
//! // KAUSF, KSEAF and KAMF
//! let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak)?;
//! let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
//! let k_amf = derive_kamf(&k_seaf, supi, &abba)?;
//!
//! // The 128-bit NAS keys of 128-NEA2 and 128-NIA2
//! let k_nas_enc = derive_knas_enc(&k_amf, CipheringAlgorithm::NEA2);
//! let k_nas_int = derive_knas_int(&k_amf, IntegrityAlgorithm::NIA2);
//! assert_eq!(k_nas_enc[..4], [0xf4, 0x7a, 0xe5, 0x70]);
//! assert_eq!(k_nas_int[..4], [0x28, 0xdd, 0xb5, 0x35]);
//! # Ok::<(), oxirush_security::SecurityError>(())
//! ```
//!
//! [`nas_5gs`] has the rest of the hierarchy: XRES\* and HXRES\*, KgNB and
//! NH, the keys of RRC and of the user plane, the keys of mobility and of
//! interworking with EPS.
//!
//! # Protecting a NAS message
//!
//! A sender ciphers the message with KNASenc, then computes the MAC with
//! KNASint over the sequence number and the ciphertext (TS 24.501
//! §4.4.3). Each takes the NAS COUNT of the message, the NAS connection
//! and the direction. A receiver computes the MAC first, then deciphers
//! with the same call.
//!
//! ```
//! use oxirush_security::nas_5gs::{
//!     CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, nas_cipher,
//!     nas_mac,
//! };
//!
//! // The NAS keys and the algorithms of the security context
//! let (k_nas_enc, k_nas_int) = ([0x11; 16], [0x22; 16]);
//! let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
//!
//! // The uplink NAS COUNT that the caller keeps, checked to be 24 bits
//! let count = NasCount::new(7)?;
//! let (access, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);
//!
//! // Cipher a REGISTRATION COMPLETE, then compute the MAC over the sequence
//! // number and the ciphertext
//! let mut message = [0x7e, 0x00, 0x43];
//! nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
//! let protected = [count.sequence_number(), message[0], message[1], message[2]];
//! let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
//! assert_eq!(mac, 0x5353_54c5);
//!
//! // The receiver deciphers with the same call
//! nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
//! assert_eq!(message, [0x7e, 0x00, 0x43]);
//!
//! // An algorithm identifier from a SECURITY MODE COMMAND is read once
//! assert_eq!(IntegrityAlgorithm::try_from(2)?, nia2);
//! assert!(IntegrityAlgorithm::try_from(5).is_err());
//! # Ok::<(), oxirush_security::SecurityError>(())
//! ```
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
