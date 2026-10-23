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

//! The keys of the 5GS hierarchy and the values of 5G AKA, each a type of
//! its own (TS 33.501 §6.2 and Annex A).

use crate::common::keys::{algorithm_keys, key};

key! {
    /// KAUSF, the key that the home network keeps for a UE (TS 33.501
    /// Annex A.2).
    KAusf, 32
}
key! {
    /// KSEAF, the anchor key of a serving network (TS 33.501 Annex A.6).
    KSeaf, 32
}
key! {
    /// KAMF, and KAMF' after a change of AMF (TS 33.501 Annex A.7 and
    /// A.13).
    KAmf, 32
}
key! {
    /// KNASint, the NAS integrity key of 5GS (TS 33.501 Annex A.8).
    KNasInt, 16
}
key! {
    /// KNASenc, the NAS ciphering key of 5GS (TS 33.501 Annex A.8).
    KNasEnc, 16
}
key! {
    /// KgNB or Kng-eNB, and KNG-RAN\* once a target node takes it as its key
    /// (TS 33.501 Annex A.9, A.11 and A.12).
    KGnb, 32
}
key! {
    /// NH, the Next Hop parameter of 5GS (TS 33.501 Annex A.10).
    Nh, 32
}
key! {
    /// KN3IWF, which is also KWAGF, KTNGF and KTWIF (TS 33.501 Annex A.9).
    KN3iwf, 32
}
key! {
    /// KSN, the key of a secondary node (TS 33.501 Annex A.16).
    KSn, 32
}
key! {
    /// KRRCint, the RRC integrity key (TS 33.501 Annex A.8).
    KRrcInt, 16
}
key! {
    /// KRRCenc, the RRC ciphering key (TS 33.501 Annex A.8).
    KRrcEnc, 16
}
key! {
    /// KUPint, the user plane integrity key (TS 33.501 Annex A.8).
    KUpInt, 16
}
key! {
    /// KUPenc, the user plane ciphering key (TS 33.501 Annex A.8).
    KUpEnc, 16
}
key! {
    /// KTIPSec, KTNAP or KFT, by the usage that it was derived for
    /// (TS 33.501 Annex A.22).
    KTnap, 32
}
key! {
    /// KIAB, the key of an IAB node and its donor (TS 33.501 Annex A.23).
    KIab, 32
}
key! {
    /// RES\*, the response that a UE computes (TS 33.501 Annex A.4).
    ResStar, 16
}
key! {
    /// XRES\*, the response that the home network expects (TS 33.501
    /// Annex A.4).
    XresStar, 16
}
key! {
    /// HRES\*, which the SEAF computes from the RES\* of a UE (TS 33.501
    /// Annex A.5).
    HresStar, 16
}
key! {
    /// HXRES\*, which the AUSF computes from XRES\* and gives the SEAF
    /// (TS 33.501 Annex A.5).
    HxresStar, 16
}

algorithm_keys!(IntegrityKey: KNasInt, KRrcInt, KUpInt);
algorithm_keys!(CipheringKey: KNasEnc, KRrcEnc, KUpEnc);

impl XresStar {
    /// Whether `res_star` is the response that was expected, compared in
    /// a time that does not depend on where the two differ (TS 33.501
    /// §6.1.3.2).
    pub fn accepts(&self, res_star: &ResStar) -> bool {
        crate::common::ct::constant_time_eq(self.as_octets(), res_star.as_octets())
    }
}

impl HxresStar {
    /// Whether `hres_star`, which the SEAF computed from the RES\* of the
    /// UE, is the one that was expected (TS 33.501 §6.1.3.2), compared in a
    /// time that does not depend on where the two differ. HRES\* and
    /// HXRES\* are two types, so that `==` does not compare them by
    /// mistake.
    ///
    /// ```
    /// use oxirush_security::Rand;
    /// use oxirush_security::nas_5gs::{ResStar, XresStar, compute_hres_star, compute_hxres_star};
    ///
    /// // The AUSF gives the SEAF the RAND and HXRES*, from the XRES* of the vector
    /// let rand = Rand::new(&[0x23; 16]);
    /// let hxres_star = compute_hxres_star(&rand, &XresStar::new(&[0x5c; 16]));
    ///
    /// // The SEAF computes HRES* from the RES* of the UE, and compares
    /// let hres_star = compute_hres_star(&rand, &ResStar::new(&[0x5c; 16]));
    /// assert!(hxres_star.accepts(&hres_star));
    /// let wrong = compute_hres_star(&rand, &ResStar::new(&[0x5d; 16]));
    /// assert!(!hxres_star.accepts(&wrong));
    /// ```
    pub fn accepts(&self, hres_star: &HresStar) -> bool {
        crate::common::ct::constant_time_eq(self.as_octets(), hres_star.as_octets())
    }
}

/// A key that the next key of a handover is derived from: KgNB, or NH
/// (TS 33.501 Annex A.10 to A.12). KSN is the KgNB of a secondary node.
pub trait AccessKey: crate::common::keys::sealed::Key256 {}

macro_rules! access_keys {
    ($($name:ident),+) => {$(
        impl crate::common::keys::sealed::Key256 for $name {
            fn key_octets(&self) -> &[u8; 32] {
                self.as_octets()
            }
        }
    )+};
}
access_keys!(KGnb, Nh, KSn);

impl AccessKey for KGnb {}
impl AccessKey for Nh {}

/// A key that RRC and user plane keys are derived from: KgNB, or the KSN
/// of a secondary node (TS 33.501 Annex A.8).
pub trait NodeKey: crate::common::keys::sealed::Key256 {}

impl NodeKey for KGnb {}
impl NodeKey for KSn {}
