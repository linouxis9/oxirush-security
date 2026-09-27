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

//! EPS key derivation and NAS security per 3GPP TS 33.401.

pub mod algo;
pub mod kdf;
pub mod security;

pub use crate::common::extract_128;
pub use algo::{select_ciphering_algo, select_integrity_algo};
pub use kdf::{
    derive_as_key, derive_ck_ik_handover, derive_ck_ik_idle_mobility, derive_ck_ik_srvcc,
    derive_kasme, derive_kasme_handover, derive_kasme_idle_mobility, derive_kenb, derive_kenb_star,
    derive_kn, derive_lwip_psk, derive_mapped_kamf_handover, derive_mapped_kamf_idle,
    derive_nas_key, derive_nas_token, derive_nas_token_full, derive_nh, derive_sgnb_algorithm_key,
    derive_skenb, derive_skwt,
};
pub use security::{
    nas_cipher, nas_mac, service_request_short_mac, service_request_short_mac_with_header,
};
