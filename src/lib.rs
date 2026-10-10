/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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

//! Security algorithms and key derivation for 5GS and EPS.
//!
//! [`nas_5gs`] implements TS 33.501 key hierarchy, algorithm selection,
//! GUTI, and SUCI. [`nas_eps`] implements TS 33.401 key hierarchy and EPS NAS
//! security use. [`common`] holds shared KDF framing, EEA/EIA algorithm cores,
//! and PLMN utilities.

pub mod common;
pub mod nas_5gs;
pub mod nas_eps;

// The examples of the README are compiled and run with the doctests.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct Readme;

// Preserve the established 5GS and shared API at the crate root.
pub use common::{
    SecurityError, extract_128, nas_cipher, nas_cipher_bits, nas_mac, nas_mac_bits, nea1_cipher,
    nea1_cipher_bits, nea2_cipher, nea2_cipher_bits, nea3_cipher, nea3_cipher_bits, nia1_mac,
    nia2_mac, nia2_mac_bits, nia3_mac, plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode,
};
pub use common::{error, nea, nia, plmn, snow3g, zuc};
pub use nas_5gs::{
    IabIpAddress, KamfMobilityDirection, NaiProtectionScheme, NaiSuci, SuciSchemeOutput, SupiType,
    TnapKeyUsage, build_guti_bytes, compute_hres_star, compute_xres_star,
    conceal_network_specific_supi, deconceal_nai_suci, deconceal_network_specific_suci,
    derive_kamf, derive_kamf_prime, derive_kamf_prime_handover, derive_kamf_prime_idle,
    derive_kausf, derive_kgnb, derive_kiab, derive_kseaf, derive_ksn, derive_nas_key, derive_nh,
    derive_sor_mac_ausf, derive_sor_mac_ue, derive_tnap_usage_key, derive_upu_mac_ausf,
    derive_upu_mac_ue, encode_nai_suci, mobile_identity_type, msin_to_bcd, parse_guti_tmsi,
    parse_nai_suci, parse_s_tmsi, select_ciphering_algo, select_ciphering_algo_with_preference,
    select_integrity_algo, select_integrity_algo_with_preference, suci_conceal, suci_decrypt_a,
    suci_decrypt_b, suci_scheme_output_a, suci_scheme_output_b, suci_to_string, suci_to_supi,
};
pub use nas_5gs::{algo, guti, kdf, suci};
