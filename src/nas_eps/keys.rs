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

//! The keys of the EPS hierarchy, each a type of its own (TS 33.401 §6.2
//! and Annex A).

use crate::common::keys::{algorithm_keys, key};

key! {
    /// KASME, and K'ASME after a mapping from another system (TS 33.401
    /// Annex A.2, A.10 and A.11).
    KAsme, 32
}
key! {
    /// KNASint, the NAS integrity key of EPS (TS 33.401 Annex A.7).
    KNasInt, 16
}
key! {
    /// KNASenc, the NAS ciphering key of EPS (TS 33.401 Annex A.7).
    KNasEnc, 16
}
key! {
    /// KeNB, KeNB\* once a target eNB takes it as its key, and S-KeNB
    /// (TS 33.401 Annex A.3, A.5 and A.15).
    KEnb, 32
}
key! {
    /// NH, the Next Hop parameter of EPS (TS 33.401 Annex A.4).
    Nh, 32
}
key! {
    /// KRRCint, the RRC integrity key (TS 33.401 Annex A.7).
    KRrcInt, 16
}
key! {
    /// KRRCenc, the RRC ciphering key (TS 33.401 Annex A.7).
    KRrcEnc, 16
}
key! {
    /// KUPint, the user plane integrity key (TS 33.401 Annex A.7).
    KUpInt, 16
}
key! {
    /// KUPenc, the user plane ciphering key (TS 33.401 Annex A.7).
    KUpEnc, 16
}
key! {
    /// CK', the ciphering key that KASME maps to for UTRAN or GERAN
    /// (TS 33.401 Annex A.8 and A.13).
    CkPrime, 16
}
key! {
    /// IK', the integrity key that KASME maps to for UTRAN or GERAN
    /// (TS 33.401 Annex A.8 and A.13).
    IkPrime, 16
}
key! {
    /// CKSRVCC, the ciphering key of SRVCC (TS 33.401 Annex A.12).
    CkSrvcc, 16
}
key! {
    /// IKSRVCC, the integrity key of SRVCC (TS 33.401 Annex A.12).
    IkSrvcc, 16
}
key! {
    /// The 256 bits of the NAS token (TS 33.401 Annex A.9).
    NasToken, 32
}
key! {
    /// LWIP-PSK, the key of LTE/WLAN integration with IPsec (TS 33.401
    /// Annex A.16).
    LwipPsk, 32
}
key! {
    /// S-KWT, the key of LTE/WLAN aggregation (TS 33.401 Annex A.18).
    SKwt, 32
}
key! {
    /// K_n, a subscriber key of an IOPS network (TS 33.401 Annex A.17).
    Kn, 32
}

algorithm_keys!(IntegrityKey: KNasInt, KRrcInt, KUpInt);
algorithm_keys!(CipheringKey: KNasEnc, KRrcEnc, KUpEnc);

impl NasToken {
    /// The two octets that a message carries: the 16 least significant
    /// bits (TS 33.401 Annex A.9).
    pub fn transmitted(&self) -> [u8; 2] {
        let [.., high, low] = *self.as_octets();
        [high, low]
    }
}

/// A key that the next key of a handover is derived from: KeNB, or NH
/// (TS 33.401 Annex A.4 and A.5).
pub trait AccessKey: crate::common::keys::sealed::Key256 {}

macro_rules! access_keys {
    ($($name:ident),+) => {$(
        impl crate::common::keys::sealed::Key256 for $name {
            fn key_octets(&self) -> &[u8; 32] {
                self.as_octets()
            }
        }

        impl AccessKey for $name {}
    )+};
}
access_keys!(KEnb, Nh);
