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

//! The inputs and the outputs of the MILENAGE functions, each a type of its
//! own, with the lengths of TS 35.206 §2.4 and TS 33.102 §6.3.7.
//!
//! K, OP and OPc, and what is derived from them that the network does not
//! send, are keys: they are wiped when they are dropped and `{:?}` prints
//! their name alone. SQN, AMF, MAC-A, MAC-S, RES and AUTS travel in clear
//! or in an AUTN, and print whole.

use crate::common::error::SecurityError;
use crate::common::keys::{key, public_value};

key! {
    /// K, the key of a subscriber, which its USIM and its home network
    /// share (TS 35.206 §2.3). MILENAGE takes a K of 128 bits.
    K, 16
}
key! {
    /// OP, the Operator Variant Algorithm Configuration Field
    /// (TS 35.206 §3). An operator may keep it secret, so it is a key:
    /// [`Opc::from_op`] gives the OPc that the functions take.
    Op, 16
}
key! {
    /// OPc, which a USIM or a home network keeps for a subscriber in the
    /// place of OP: OP ⊕ E\[OP\]K (TS 35.206 §4.1).
    Opc, 16
}
key! {
    /// AK, the anonymity key that f5 gives, which conceals SQN in an AUTN
    /// (TS 33.102 §6.3.2).
    Ak, 6
}
key! {
    /// AK\*, the anonymity key that f5\* gives, which conceals SQNMS in an
    /// AUTS (TS 33.102 §6.3.3).
    AkStar, 6
}
key! {
    /// XRES, the response that the network expects from the USIM: f2 of
    /// the RAND that it sent (TS 33.102 §6.3.2). [`Xres::accepts`]
    /// compares the RES of a UE with it.
    Xres, 8
}

public_value! {
    /// SQN, a sequence number of 48 bits (TS 33.102 §6.3.7): that of an
    /// AUTN, or SQNMS, the highest that a USIM has taken. `{:?}` prints its
    /// octets; [`Sqn::get`] gives it as a number.
    Sqn, 6
}
public_value! {
    /// AMF, the Authentication Management Field of an AUTN (TS 33.102
    /// Annex H). `{:?}` prints its octets.
    Amf, 2
}
public_value! {
    /// MAC-A, the 64 bits of an AUTN that f1 gives (TS 35.206 §2.4).
    MacA, 8
}
public_value! {
    /// MAC-S, the 64 bits of an AUTS that f1\* gives (TS 35.206 §2.4).
    MacS, 8
}
public_value! {
    /// RES, the response of a USIM: the 64 bits that f2 gives
    /// (TS 35.206 §2.4). A UE sends it, or RES\* which 5GS derives from it:
    /// `{:?}` prints its octets.
    Res, 8
}
public_value! {
    /// AUTS, what a USIM sends for a SQN out of range: SQNMS ⊕ AK\*, then
    /// MAC-S (TS 33.102 §6.3.3). `{:?}` prints its octets.
    Auts, 14
}

impl Opc {
    /// OPc from OP and K: OP ⊕ E\[OP\]K (TS 35.206 §4.1), which a home
    /// network computes once for each subscriber.
    pub fn from_op(k: &K, op: &Op) -> Self {
        super::kernel::opc_of(k, op)
    }
}

impl Xres {
    /// Whether `res` is the response that was expected, compared in a time
    /// that does not depend on where the two differ (TS 33.102 §6.3.3).
    pub fn accepts(&self, res: &Res) -> bool {
        crate::common::ct::constant_time_eq(self.as_octets(), res.as_octets())
    }
}

impl Sqn {
    /// The largest SQN, 2^48 - 1.
    pub const MAX: u64 = (1 << 48) - 1;

    /// The number, 0 to 2^48 - 1, whose first octet is the high one.
    pub fn get(&self) -> u64 {
        let mut octets = [0; 8];
        octets[2..].copy_from_slice(&self.0);
        u64::from_be_bytes(octets)
    }
}

impl TryFrom<u64> for Sqn {
    type Error = SecurityError;

    /// The SQN of a number, or [`SecurityError::OutOfRange`] above
    /// 2^48 - 1.
    fn try_from(value: u64) -> Result<Self, SecurityError> {
        if value > Self::MAX {
            return Err(SecurityError::OutOfRange {
                field: "SQN",
                maximum: Self::MAX,
                got: value,
            });
        }
        let octets = value.to_be_bytes();
        Ok(Self(*octets.last_chunk().expect("eight octets")))
    }
}

impl Amf {
    /// Bit 0, the high bit of the first octet: the AMF separation bit
    /// (TS 33.102 Annex H). A UE that accesses EPS or 5GS refuses an AUTN
    /// without it (TS 33.401 §6.1.1, TS 33.501 §6.1.3.2).
    pub fn separation_bit(&self) -> bool {
        self.0[0] & 0x80 != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_print_their_name_and_values_their_octets() {
        assert_eq!(format!("{:?}", K::new(&[0x5a; 16])), "K(..)");
        assert_eq!(format!("{:?}", Op::new(&[0x5a; 16])), "Op(..)");
        assert_eq!(format!("{:?}", Opc::new(&[0x5a; 16])), "Opc(..)");
        assert_eq!(format!("{:?}", Ak::new(&[0x5a; 6])), "Ak(..)");
        assert_eq!(format!("{:?}", AkStar::new(&[0x5a; 6])), "AkStar(..)");
        assert_eq!(format!("{:?}", Xres::new(&[0x5a; 8])), "Xres(..)");

        let sqn = Sqn::new(&[0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]);
        assert_eq!(format!("{sqn:?}"), "Sqn(ff9bb4d0b607)");
        assert_eq!(format!("{:?}", Amf::new(&[0xb9, 0xb9])), "Amf(b9b9)");
        let mac = [0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf, 0xaf, 0xb3];
        assert_eq!(format!("{:?}", MacA::new(&mac)), "MacA(4a9ffac354dfafb3)");
        assert_eq!(format!("{:?}", MacS::new(&mac)), "MacS(4a9ffac354dfafb3)");
        assert_eq!(format!("{:?}", Res::new(&mac)), "Res(4a9ffac354dfafb3)");
        assert_eq!(
            format!("{:?}", Auts::new(&[0x11; 14])),
            "Auts(1111111111111111111111111111)"
        );
    }

    #[test]
    fn a_sqn_is_a_number_of_48_bits() {
        let sqn = Sqn::new(&[0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]);
        assert_eq!(sqn.get(), 0xff9b_b4d0_b607);
        assert_eq!(Sqn::try_from(0xff9b_b4d0_b607), Ok(sqn));
        assert_eq!(Sqn::try_from(0).map(|sqn| sqn.get()), Ok(0));
        assert_eq!(Sqn::try_from(Sqn::MAX).map(|sqn| sqn.get()), Ok(Sqn::MAX));
        assert_eq!(
            Sqn::try_from(1 << 48),
            Err(SecurityError::OutOfRange {
                field: "SQN",
                maximum: Sqn::MAX,
                got: 1 << 48,
            })
        );
    }

    #[test]
    fn the_separation_bit_is_the_high_bit_of_the_amf() {
        assert!(Amf::new(&[0x80, 0x00]).separation_bit());
        assert!(Amf::new(&[0xb9, 0xb9]).separation_bit());
        assert!(!Amf::new(&[0x7f, 0xff]).separation_bit());
    }

    #[test]
    fn xres_accepts_its_res_alone() {
        let xres = Xres::new(&[0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf]);
        assert!(xres.accepts(&Res::new(&[0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf])));
        assert!(!xres.accepts(&Res::new(&[0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbe])));
    }
}
