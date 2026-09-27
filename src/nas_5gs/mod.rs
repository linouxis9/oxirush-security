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

//! 5GS key derivation, algorithm selection, and subscriber identity security.

pub mod algo;
pub mod guti;
pub mod kdf;
pub mod security;
pub mod suci;

pub use crate::common::extract_128;
pub use algo::{
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
pub use guti::{build_guti_bytes, mobile_identity_type, parse_guti_tmsi, parse_s_tmsi};
pub use kdf::{
    IabIpAddress, KamfMobilityDirection, TnapKeyUsage, compute_hres_star, compute_xres_star,
    derive_as_key, derive_kamf, derive_kamf_prime, derive_kamf_prime_handover,
    derive_kamf_prime_idle, derive_kasme_srvcc, derive_kausf, derive_kgnb, derive_kiab,
    derive_kn3iwf, derive_kng_ran_star, derive_kng_ran_star_ng_enb, derive_kseaf, derive_ksn,
    derive_mapped_kasme_handover, derive_mapped_kasme_idle, derive_nas_key, derive_nh,
    derive_sor_mac_ausf, derive_sor_mac_ue, derive_tnap_usage_key, derive_upu_mac_ausf,
    derive_upu_mac_ue,
};
pub use security::{nas_cipher, nas_container_mac, nas_mac};
pub use suci::{
    NaiProtectionScheme, NaiSuci, SuciSchemeOutput, SupiType, conceal_network_specific_supi,
    deconceal_nai_suci, deconceal_network_specific_suci, encode_nai_suci, msin_to_bcd,
    parse_nai_suci, suci_conceal, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b, suci_to_string, suci_to_supi,
};
