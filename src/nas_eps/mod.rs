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

//! EPS: the keys of TS 33.401 and their derivations, and NAS integrity
//! and ciphering.
//!
//! The keys that one system maps to the other are derived by TS 33.501,
//! in both directions: [`nas_5gs`](crate::nas_5gs) has
//! `derive_mapped_kasme_idle` and `derive_mapped_kasme_handover`, which
//! return a [`KAsme`], and `derive_mapped_kamf_idle` and
//! `derive_mapped_kamf_handover`, which take one.
//!
//! The algorithms, their inputs and what else 5GS has too are at the
//! [crate root](crate). Nothing here has the name of an item of
//! [`nas_5gs`](crate::nas_5gs) by accident: a key of one system does not
//! compile where the other's is expected.

mod kdf;
mod keys;
mod security;

pub use kdf::{
    compute_hash_mme, derive_ck_ik_handover, derive_ck_ik_idle_mobility, derive_ck_ik_srvcc,
    derive_kasme, derive_kasme_handover, derive_kasme_idle_mobility, derive_kenb, derive_kenb_star,
    derive_kn, derive_knas_enc, derive_knas_int, derive_krrc_enc, derive_krrc_int, derive_kup_enc,
    derive_kup_int, derive_lwip_psk, derive_nas_token, derive_nh, derive_skenb, derive_skgnb,
    derive_skwt,
};
pub use keys::{
    AccessKey, CkPrime, CkSrvcc, IkPrime, IkSrvcc, KAsme, KEnb, KNasEnc, KNasInt, KRrcEnc, KRrcInt,
    KUpEnc, KUpInt, Kn, LwipPsk, NasToken, Nh, SKwt,
};
pub use security::{
    cipher_job, mac_job, nas_cipher, nas_mac, re_establishment_nas_mac, service_request_short_mac,
    service_request_short_mac_with_header,
};
