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

// Preserve the established 5GS and shared API at the crate root.
pub use common::{
    SecurityError, extract_128, nas_cipher, nas_mac, nea1_cipher, nea2_cipher, nea3_cipher,
    nia1_mac, nia2_mac, nia3_mac, plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode,
};
pub use common::{error, nea, nia, plmn, snow3g, zuc};
pub use nas_5gs::{algo, guti, kdf, suci};
pub use nas_5gs::{
    build_guti_bytes, compute_hres_star, compute_xres_star, derive_kamf, derive_kausf,
    derive_kausf_standard, derive_kgnb, derive_kseaf, derive_nas_key, derive_nh,
    mobile_identity_type, msin_to_bcd, parse_guti_tmsi, parse_s_tmsi, select_ciphering_algo,
    select_integrity_algo, suci_conceal, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b, suci_to_string, suci_to_supi,
};

/// Compatibility alias for the EPS module.
pub use nas_eps as eps;
