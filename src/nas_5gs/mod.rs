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

//! 5GS: the keys of TS 33.501 and their derivations, NAS integrity and
//! ciphering, the SUPI, the SUCI and the 5G-GUTI.
//!
//! The algorithms, their inputs and what else EPS has too are at the
//! [crate root](crate). Nothing here has the name of an item of
//! [`nas_eps`](crate::nas_eps) by accident: a key of one system does not
//! compile where the other's is expected.

mod kdf;
mod keys;
mod security;
#[cfg(feature = "suci")]
mod suci;

pub use kdf::{
    IabIpAddress, KamfMobilityDirection, TnapKeyUsage, compute_hres_star, compute_hxres_star,
    compute_res_star, compute_xres_star, derive_kamf, derive_kamf_prime,
    derive_kamf_prime_handover, derive_kamf_prime_idle, derive_kasme_srvcc, derive_kausf,
    derive_kgnb, derive_kiab, derive_kn3iwf, derive_knas_enc, derive_knas_int, derive_kng_ran_star,
    derive_kng_ran_star_ng_enb, derive_krrc_enc, derive_krrc_int, derive_kseaf, derive_ksn,
    derive_kup_enc, derive_kup_int, derive_mapped_kamf_handover, derive_mapped_kamf_idle,
    derive_mapped_kasme_handover, derive_mapped_kasme_idle, derive_nh, derive_sor_mac_ausf,
    derive_sor_mac_ue, derive_tnap_usage_key, derive_upu_mac_ausf, derive_upu_mac_ue,
};
pub use keys::{
    AccessKey, HresStar, HxresStar, KAmf, KAusf, KGnb, KIab, KN3iwf, KNasEnc, KNasInt, KRrcEnc,
    KRrcInt, KSeaf, KSn, KTnap, KUpEnc, KUpInt, Nh, NodeKey, ResStar, XresStar,
};
/// The 5G-GUTI, the 5G-S-TMSI and the types of a 5GS mobile identity
/// (TS 24.501 §9.11.3.4), and the SUPI with its type (TS 23.003 §2.2A):
/// the values of oxirush-utils, by the names that this crate gives them.
pub use oxirush_utils::identity::{
    Guti5g as Guti, MobileIdentityType5gs as MobileIdentityType, STmsi5g as STmsi, Supi, SupiType,
};
pub use security::{NasConnection, cipher_job, mac_job, nas_cipher, nas_container_mac, nas_mac};
#[cfg(feature = "suci")]
#[cfg_attr(docsrs, doc(cfg(feature = "suci")))]
pub use suci::{
    HomeNetwork, HomeNetworkPrivateKey, HomeNetworkPublicKey, Protection, ProtectionScheme,
    RoutingIndicator, SchemeOutput, Suci, SuciError,
};
