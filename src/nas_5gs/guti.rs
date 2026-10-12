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

//! The 5G-GUTI and the 5G-S-TMSI as 5GS mobile identities
//! (TS 24.501 §9.11.3.4).
//!
//! [`Guti`] and [`STmsi`] are whole values: `from_octets` takes the
//! octets of the identity from the one that has its type, with nothing
//! after them, and gives every part; `to_octets` writes them back.

use crate::common::error::SecurityError;
use crate::common::plmn::Plmn;

/// The type of identity of a 5GS mobile identity, the three low bits of
/// its first octet (TS 24.501 Table 9.11.3.4.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum MobileIdentityType {
    /// No identity.
    NoIdentity = 0,
    /// SUCI.
    Suci = 1,
    /// 5G-GUTI.
    Guti = 2,
    /// IMEI.
    Imei = 3,
    /// 5G-S-TMSI.
    STmsi = 4,
    /// IMEISV.
    Imeisv = 5,
    /// MAC address.
    MacAddress = 6,
    /// EUI-64.
    Eui64 = 7,
}

impl MobileIdentityType {
    /// The type of the identity whose octets these are, from the one after
    /// its length. `None` for no octets.
    pub fn of(identity: &[u8]) -> Option<Self> {
        Some(match identity.first()? & 0x07 {
            0 => Self::NoIdentity,
            1 => Self::Suci,
            2 => Self::Guti,
            3 => Self::Imei,
            4 => Self::STmsi,
            5 => Self::Imeisv,
            6 => Self::MacAddress,
            _ => Self::Eui64,
        })
    }
}

fn checked(field: &'static str, value: u16, maximum: u16) -> Result<u16, SecurityError> {
    if value <= maximum {
        Ok(value)
    } else {
        Err(SecurityError::OutOfRange {
            field,
            maximum: maximum.into(),
            got: value.into(),
        })
    }
}

/// The first octet of an identity that has no digit in it: bits 8 to 5
/// are "1111" and bits 3 to 1 the type. Bit 4 is spare, which a receiver
/// ignores.
fn first_octet_is(octet: u8, kind: MobileIdentityType) -> bool {
    octet & 0xf7 == 0xf0 | kind as u8
}

/// A 5G-GUTI: the PLMN, the AMF Region ID, the AMF Set ID, the AMF Pointer
/// and the 5G-TMSI (TS 23.003 §2.10.1).
///
/// ```
/// use oxirush_security::Plmn;
/// use oxirush_security::nas_5gs::Guti;
///
/// let guti = Guti::new(Plmn::new("208", "93")?, 0xca, 0x3fe, 0x01, 0x1234_5678)?;
/// let octets = guti.to_octets();
/// assert_eq!(octets, [0xf2, 0x02, 0xf8, 0x39, 0xca, 0xff, 0x81, 0x12, 0x34, 0x56, 0x78]);
///
/// let read = Guti::from_octets(&octets)?;
/// assert_eq!(read, guti);
/// assert_eq!((read.amf_set_id(), read.amf_pointer(), read.tmsi()), (0x3fe, 0x01, 0x1234_5678));
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Guti {
    plmn: Plmn,
    amf_region_id: u8,
    s_tmsi: STmsi,
}

impl Guti {
    /// The 5G-GUTI of its parts.
    ///
    /// An `amf_set_id` above its 10 bits or an `amf_pointer` above its 6
    /// is [`SecurityError::OutOfRange`].
    pub fn new(
        plmn: Plmn,
        amf_region_id: u8,
        amf_set_id: u16,
        amf_pointer: u8,
        tmsi: u32,
    ) -> Result<Self, SecurityError> {
        Ok(Self {
            plmn,
            amf_region_id,
            s_tmsi: STmsi::new(amf_set_id, amf_pointer, tmsi)?,
        })
    }

    /// The 5G-GUTI of the eleven octets of its mobile identity, from the
    /// one that has the type (TS 24.501 Figure 9.11.3.4.1).
    ///
    /// Another number of octets, a first octet that is not that of a
    /// 5G-GUTI, or a PLMN that is not decimal digits is
    /// [`SecurityError::InvalidParameter`].
    pub fn from_octets(identity: &[u8]) -> Result<Self, SecurityError> {
        let Ok(octets) = <&[u8; 11]>::try_from(identity) else {
            return Err(SecurityError::InvalidParameter(
                "a 5G-GUTI mobile identity is 11 octets long",
            ));
        };
        if !first_octet_is(octets[0], MobileIdentityType::Guti) {
            return Err(SecurityError::InvalidParameter(
                "the first octet is not that of a 5G-GUTI",
            ));
        }
        let [_, plmn_1, plmn_2, plmn_3, amf_region_id, rest @ ..] = *octets;
        Ok(Self {
            plmn: Plmn::from_octets(&[plmn_1, plmn_2, plmn_3])?,
            amf_region_id,
            s_tmsi: STmsi::from_parts(rest),
        })
    }

    /// The eleven octets of the mobile identity:
    ///
    /// ```text
    ///   [0]      0xF2: bits 8-5 "1111", a spare bit, type 010
    ///   [1..3]   PLMN
    ///   [4]      AMF Region ID
    ///   [5..6]   AMF Set ID (10 bits), AMF Pointer (6 bits)
    ///   [7..10]  5G-TMSI
    /// ```
    pub fn to_octets(&self) -> [u8; 11] {
        let [plmn_1, plmn_2, plmn_3] = self.plmn.to_octets();
        let [set, set_and_pointer, tmsi @ ..] = self.s_tmsi.parts();
        let mut octets = [
            0xf2,
            plmn_1,
            plmn_2,
            plmn_3,
            self.amf_region_id,
            set,
            set_and_pointer,
            0,
            0,
            0,
            0,
        ];
        octets[7..].copy_from_slice(&tmsi);
        octets
    }

    /// The PLMN.
    pub fn plmn(&self) -> Plmn {
        self.plmn
    }

    /// The AMF Region ID.
    pub fn amf_region_id(&self) -> u8 {
        self.amf_region_id
    }

    /// The AMF Set ID, of 10 bits.
    pub fn amf_set_id(&self) -> u16 {
        self.s_tmsi.amf_set_id
    }

    /// The AMF Pointer, of 6 bits.
    pub fn amf_pointer(&self) -> u8 {
        self.s_tmsi.amf_pointer
    }

    /// The 5G-TMSI.
    pub fn tmsi(&self) -> u32 {
        self.s_tmsi.tmsi
    }

    /// Its 5G-S-TMSI: the AMF Set ID, the AMF Pointer and the 5G-TMSI.
    pub fn s_tmsi(&self) -> STmsi {
        self.s_tmsi
    }
}

/// A 5G-S-TMSI: the AMF Set ID, the AMF Pointer and the 5G-TMSI
/// (TS 23.003 §2.10.1).
///
/// ```
/// use oxirush_security::nas_5gs::STmsi;
///
/// let s_tmsi = STmsi::from_octets(&[0xf4, 0xff, 0x81, 0x12, 0x34, 0x56, 0x78])?;
/// assert_eq!((s_tmsi.amf_set_id(), s_tmsi.amf_pointer()), (0x3fe, 0x01));
/// assert_eq!(s_tmsi.tmsi(), 0x1234_5678);
/// assert_eq!(s_tmsi.to_octets(), [0xf4, 0xff, 0x81, 0x12, 0x34, 0x56, 0x78]);
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct STmsi {
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
}

impl STmsi {
    /// The 5G-S-TMSI of its parts.
    ///
    /// An `amf_set_id` above its 10 bits or an `amf_pointer` above its 6
    /// is [`SecurityError::OutOfRange`].
    pub fn new(amf_set_id: u16, amf_pointer: u8, tmsi: u32) -> Result<Self, SecurityError> {
        Ok(Self {
            amf_set_id: checked("AMF Set ID", amf_set_id, 0x3ff)?,
            amf_pointer: checked("AMF Pointer", amf_pointer.into(), 0x3f)? as u8,
            tmsi,
        })
    }

    /// The 5G-S-TMSI of the seven octets of its mobile identity, from the
    /// one that has the type (TS 24.501 Figure 9.11.3.4.5).
    ///
    /// Another number of octets, or a first octet that is not that of a
    /// 5G-S-TMSI, is [`SecurityError::InvalidParameter`].
    pub fn from_octets(identity: &[u8]) -> Result<Self, SecurityError> {
        let Ok(octets) = <&[u8; 7]>::try_from(identity) else {
            return Err(SecurityError::InvalidParameter(
                "a 5G-S-TMSI mobile identity is 7 octets long",
            ));
        };
        if !first_octet_is(octets[0], MobileIdentityType::STmsi) {
            return Err(SecurityError::InvalidParameter(
                "the first octet is not that of a 5G-S-TMSI",
            ));
        }
        let [_, parts @ ..] = *octets;
        Ok(Self::from_parts(parts))
    }

    /// The seven octets of the mobile identity:
    ///
    /// ```text
    ///   [0]      0xF4: bits 8-5 "1111", a spare bit, type 100
    ///   [1..2]   AMF Set ID (10 bits), AMF Pointer (6 bits)
    ///   [3..6]   5G-TMSI
    /// ```
    pub fn to_octets(&self) -> [u8; 7] {
        let mut octets = [0xf4; 7];
        octets[1..].copy_from_slice(&self.parts());
        octets
    }

    /// The AMF Set ID, of 10 bits.
    pub fn amf_set_id(&self) -> u16 {
        self.amf_set_id
    }

    /// The AMF Pointer, of 6 bits.
    pub fn amf_pointer(&self) -> u8 {
        self.amf_pointer
    }

    /// The 5G-TMSI.
    pub fn tmsi(&self) -> u32 {
        self.tmsi
    }

    /// The six octets that a 5G-GUTI ends with and a 5G-S-TMSI has after
    /// its first.
    fn parts(&self) -> [u8; 6] {
        let [set_high, set_low] = (self.amf_set_id << 6).to_be_bytes();
        let [tmsi_0, tmsi_1, tmsi_2, tmsi_3] = self.tmsi.to_be_bytes();
        [
            set_high,
            set_low | self.amf_pointer,
            tmsi_0,
            tmsi_1,
            tmsi_2,
            tmsi_3,
        ]
    }

    fn from_parts(parts: [u8; 6]) -> Self {
        let [set_high, set_low, tmsi @ ..] = parts;
        Self {
            amf_set_id: u16::from_be_bytes([set_high, set_low]) >> 6,
            amf_pointer: set_low & 0x3f,
            tmsi: u32::from_be_bytes(tmsi),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plmn() -> Plmn {
        Plmn::new("208", "93").unwrap()
    }

    /// TS 24.501 Figure 9.11.3.4.1: the AMF Set ID takes octet 9 and bits
    /// 8 and 7 of octet 10, and the AMF Pointer bits 6 to 1 of octet 10.
    #[test]
    fn a_guti_is_its_eleven_octets() {
        let guti = Guti::new(plmn(), 0x01, 0x001, 0x02, 0x1122_3344).unwrap();
        let octets = [
            0xf2, 0x02, 0xf8, 0x39, 0x01, 0x00, 0x42, 0x11, 0x22, 0x33, 0x44,
        ];
        assert_eq!(guti.to_octets(), octets);
        let read = Guti::from_octets(&octets).unwrap();
        assert_eq!(read, guti);
        assert_eq!(read.plmn(), plmn());
        assert_eq!(read.amf_region_id(), 0x01);
        assert_eq!((read.amf_set_id(), read.amf_pointer()), (0x001, 0x02));
        assert_eq!(read.tmsi(), 0x1122_3344);
        assert_eq!(read.s_tmsi(), STmsi::new(0x001, 0x02, 0x1122_3344).unwrap());

        let largest = Guti::new(plmn(), 0xca, 0x3ff, 0x3f, u32::MAX).unwrap();
        assert_eq!(largest.to_octets()[5..7], [0xff, 0xff]);
        assert_eq!(Guti::from_octets(&largest.to_octets()), Ok(largest));
        let mixed = Guti::new(plmn(), 0, 0x2a5, 0x15, 0).unwrap();
        assert_eq!(mixed.to_octets()[5..7], [0xa9, 0x55]);
        assert_eq!(Guti::from_octets(&mixed.to_octets()), Ok(mixed));
    }

    #[test]
    fn a_guti_is_read_whole_or_not_at_all() {
        let octets = Guti::new(plmn(), 0xca, 0x3ff, 0x3f, 0x1234_5678)
            .unwrap()
            .to_octets();
        let refused = |octets: &[u8]| Guti::from_octets(octets).unwrap_err().to_string();
        // Octets after the identity, and too few of them
        let mut long = octets.to_vec();
        long.push(0xaa);
        assert_eq!(
            refused(&long),
            "invalid parameter: a 5G-GUTI mobile identity is 11 octets long"
        );
        assert!(Guti::from_octets(&octets[..10]).is_err());
        assert!(Guti::from_octets(&[]).is_err());
        // Bits 8 to 5 of the first octet are "1111", and the type 010
        for first in [0x02, 0xe2, 0xf4, 0xf1, 0x72] {
            let mut other = octets;
            other[0] = first;
            assert_eq!(
                refused(&other),
                "invalid parameter: the first octet is not that of a 5G-GUTI",
                "{first:#04x}"
            );
        }
        // The spare bit is ignored, and written as zero
        let mut spare = octets;
        spare[0] = 0xfa;
        assert_eq!(Guti::from_octets(&spare).unwrap().to_octets(), octets);
        // A PLMN that is not decimal digits
        let mut no_plmn = octets;
        no_plmn[1..4].copy_from_slice(&[0xff, 0xff, 0xff]);
        assert!(Guti::from_octets(&no_plmn).is_err());
    }

    #[test]
    fn the_parts_of_a_guti_have_their_ranges() {
        assert_eq!(
            Guti::new(plmn(), 0, 0x400, 0, 0),
            Err(SecurityError::OutOfRange {
                field: "AMF Set ID",
                maximum: 0x3ff,
                got: 0x400
            })
        );
        assert_eq!(
            STmsi::new(0, 0x40, 0),
            Err(SecurityError::OutOfRange {
                field: "AMF Pointer",
                maximum: 0x3f,
                got: 0x40
            })
        );
    }

    /// TS 24.501 Figure 9.11.3.4.5.
    #[test]
    fn an_s_tmsi_is_its_seven_octets() {
        let s_tmsi = STmsi::new(0x3ff, 0x3f, 7).unwrap();
        let octets = [0xf4, 0xff, 0xff, 0, 0, 0, 7];
        assert_eq!(s_tmsi.to_octets(), octets);
        assert_eq!(STmsi::from_octets(&octets), Ok(s_tmsi));
        assert_eq!(s_tmsi.tmsi(), 7);
        // A 5G-GUTI is not one, nor are eight octets
        assert!(STmsi::from_octets(&[0xf2, 0xff, 0xff, 0, 0, 0, 7]).is_err());
        assert!(STmsi::from_octets(&[0x04, 0xff, 0xff, 0, 0, 0, 7]).is_err());
        assert!(STmsi::from_octets(&[0xf4, 0xff, 0xff, 0, 0, 0, 7, 0xaa]).is_err());
        assert!(STmsi::from_octets(&octets[..6]).is_err());
    }

    #[test]
    fn the_type_of_an_identity_is_in_its_first_octet() {
        use MobileIdentityType::*;
        let kinds = [
            NoIdentity, Suci, Guti, Imei, STmsi, Imeisv, MacAddress, Eui64,
        ];
        for (bits, kind) in (0u8..).zip(kinds) {
            assert_eq!(MobileIdentityType::of(&[0xf8 | bits, 0x55]), Some(kind));
            assert_eq!(kind as u8, bits);
        }
        assert_eq!(MobileIdentityType::of(&[]), None);
    }
}
