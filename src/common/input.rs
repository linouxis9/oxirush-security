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

//! The inputs of the algorithms and of the key derivations, as types that
//! hold only the values the specifications allow.
//!
//! A value from a peer or from a configuration enters through `TryFrom` or
//! `new`, which return a [`SecurityError`] for one that is out of range.
//! The functions that take these types then have nothing left to refuse.

use crate::common::error::SecurityError;

/// An integrity algorithm of 5GS or EPS.
///
/// 5GS names them NIA0 and 128-NIA1 to 128-NIA3 (TS 33.501 §5.11.1.2) and
/// EPS EIA0 and 128-EIA1 to 128-EIA3 (TS 33.401 §5.1.4.2). They are the
/// same algorithms with the same identifiers, so one type serves both, and
/// the constants give each variant the two names of the specifications.
///
/// `TryFrom<u8>` reads an identifier and `u8::from` gives it back.
///
/// ```
/// use oxirush_security::{IntegrityAlgorithm, SecurityError};
///
/// // The identifier of a SECURITY MODE COMMAND
/// let algorithm = IntegrityAlgorithm::try_from(2)?;
/// assert_eq!(algorithm, IntegrityAlgorithm::NIA2);
/// assert_eq!(algorithm, IntegrityAlgorithm::EIA2);
/// assert_eq!(u8::from(algorithm), 2);
///
/// // 4 to 7 are reserved
/// assert_eq!(IntegrityAlgorithm::try_from(4), Err(SecurityError::UnsupportedAlgorithm(4)));
/// # Ok::<(), SecurityError>(())
/// ```
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum IntegrityAlgorithm {
    /// NIA0 and EIA0, the null algorithm: the MAC is zero. It is for
    /// unauthenticated emergency sessions only (TS 33.501 §5.5.2,
    /// TS 33.401 §5.1.4.1).
    Null = 0,
    /// 128-NIA1 and 128-EIA1, based on SNOW 3G.
    Snow3g = 1,
    /// 128-NIA2 and 128-EIA2, based on AES in CMAC mode.
    Aes = 2,
    /// 128-NIA3 and 128-EIA3, based on ZUC.
    Zuc = 3,
}

impl IntegrityAlgorithm {
    /// NIA0 of 5GS.
    pub const NIA0: Self = Self::Null;
    /// 128-NIA1 of 5GS.
    pub const NIA1: Self = Self::Snow3g;
    /// 128-NIA2 of 5GS.
    pub const NIA2: Self = Self::Aes;
    /// 128-NIA3 of 5GS.
    pub const NIA3: Self = Self::Zuc;
    /// EIA0 of EPS.
    pub const EIA0: Self = Self::Null;
    /// 128-EIA1 of EPS.
    pub const EIA1: Self = Self::Snow3g;
    /// 128-EIA2 of EPS.
    pub const EIA2: Self = Self::Aes;
    /// 128-EIA3 of EPS.
    pub const EIA3: Self = Self::Zuc;
}

impl TryFrom<u8> for IntegrityAlgorithm {
    type Error = SecurityError;

    fn try_from(identifier: u8) -> Result<Self, SecurityError> {
        match identifier {
            0 => Ok(Self::Null),
            1 => Ok(Self::Snow3g),
            2 => Ok(Self::Aes),
            3 => Ok(Self::Zuc),
            _ => Err(SecurityError::UnsupportedAlgorithm(identifier)),
        }
    }
}

impl From<IntegrityAlgorithm> for u8 {
    fn from(algorithm: IntegrityAlgorithm) -> u8 {
        algorithm as u8
    }
}

/// A ciphering algorithm of 5GS or EPS.
///
/// 5GS names them NEA0 and 128-NEA1 to 128-NEA3 (TS 33.501 §5.11.1.1) and
/// EPS EEA0 and 128-EEA1 to 128-EEA3 (TS 33.401 §5.1.3.2). They are the
/// same algorithms with the same identifiers, so one type serves both, and
/// the constants give each variant the two names of the specifications.
///
/// `TryFrom<u8>` reads an identifier and `u8::from` gives it back.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CipheringAlgorithm {
    /// NEA0 and EEA0, the null algorithm: the data is left as it is.
    Null = 0,
    /// 128-NEA1 and 128-EEA1, based on SNOW 3G.
    Snow3g = 1,
    /// 128-NEA2 and 128-EEA2, based on AES in CTR mode.
    Aes = 2,
    /// 128-NEA3 and 128-EEA3, based on ZUC.
    Zuc = 3,
}

impl CipheringAlgorithm {
    /// NEA0 of 5GS.
    pub const NEA0: Self = Self::Null;
    /// 128-NEA1 of 5GS.
    pub const NEA1: Self = Self::Snow3g;
    /// 128-NEA2 of 5GS.
    pub const NEA2: Self = Self::Aes;
    /// 128-NEA3 of 5GS.
    pub const NEA3: Self = Self::Zuc;
    /// EEA0 of EPS.
    pub const EEA0: Self = Self::Null;
    /// 128-EEA1 of EPS.
    pub const EEA1: Self = Self::Snow3g;
    /// 128-EEA2 of EPS.
    pub const EEA2: Self = Self::Aes;
    /// 128-EEA3 of EPS.
    pub const EEA3: Self = Self::Zuc;
}

impl TryFrom<u8> for CipheringAlgorithm {
    type Error = SecurityError;

    fn try_from(identifier: u8) -> Result<Self, SecurityError> {
        match identifier {
            0 => Ok(Self::Null),
            1 => Ok(Self::Snow3g),
            2 => Ok(Self::Aes),
            3 => Ok(Self::Zuc),
            _ => Err(SecurityError::UnsupportedAlgorithm(identifier)),
        }
    }
}

impl From<CipheringAlgorithm> for u8 {
    fn from(algorithm: CipheringAlgorithm) -> u8 {
        algorithm as u8
    }
}

/// The DIRECTION input of the algorithms: 0 for uplink and 1 for downlink
/// (TS 33.501 §6.4.3.1, TS 33.401 Annex B).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    /// From the UE to the network.
    Uplink = 0,
    /// From the network to the UE.
    Downlink = 1,
}

impl TryFrom<u8> for Direction {
    type Error = SecurityError;

    fn try_from(bit: u8) -> Result<Self, SecurityError> {
        match bit {
            0 => Ok(Self::Uplink),
            1 => Ok(Self::Downlink),
            _ => Err(SecurityError::OutOfRange {
                field: "DIRECTION",
                maximum: 1,
                got: bit.into(),
            }),
        }
    }
}

impl From<Direction> for u8 {
    fn from(direction: Direction) -> u8 {
        direction as u8
    }
}

/// The five-bit BEARER input of the algorithms (TS 33.401 Annex B).
///
/// 5GS NAS sets it to the NAS connection identifier, for which
/// [`NasConnection`](crate::nas_5gs::NasConnection) converts into this
/// type, and EPS NAS to zero. The functions of `nas_5gs` and `nas_eps` do
/// that; this type is for the algorithms themselves, which the test data of
/// 3GPP and the protocols of the access stratum give any five-bit value.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bearer(pub(crate) u8);

impl Bearer {
    /// BEARER 0, which EPS NAS uses.
    pub const ZERO: Self = Self(0);
    /// The largest BEARER, 31.
    pub const MAX: Self = Self(0x1f);

    /// A BEARER, or [`SecurityError::OutOfRange`] above 31.
    pub const fn new(value: u8) -> Result<Self, SecurityError> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(SecurityError::OutOfRange {
                field: "BEARER",
                maximum: Self::MAX.0 as u64,
                got: value as u64,
            })
        }
    }

    /// The value, 0 to 31.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for Bearer {
    type Error = SecurityError;

    fn try_from(value: u8) -> Result<Self, SecurityError> {
        Self::new(value)
    }
}

impl From<Bearer> for u8 {
    fn from(bearer: Bearer) -> u8 {
        bearer.0
    }
}

/// A NAS COUNT of 5GS or EPS: 24 bits, the 16-bit NAS overflow counter
/// followed by the 8-bit NAS sequence number (TS 24.501 §4.4.3.1,
/// TS 24.301 §4.4.3.1).
///
/// The crate keeps no NAS COUNT: this is the value that a caller passes for
/// one message, checked once. The algorithms take it padded with eight zero
/// bits to 32, as those clauses require.
///
/// ```
/// use oxirush_security::{NasCount, SecurityError};
///
/// // From the overflow counter that the receiver estimates and the
/// // sequence number of the message
/// let count = NasCount::from_parts(0x0001, 0x2a);
/// assert_eq!(count.get(), 0x0000_012a);
/// assert_eq!((count.overflow(), count.sequence_number()), (0x0001, 0x2a));
///
/// // From a stored value
/// assert_eq!(NasCount::new(0x0000_012a)?, count);
/// assert!(NasCount::new(1 << 24).is_err());
/// # Ok::<(), SecurityError>(())
/// ```
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NasCount(u32);

impl NasCount {
    /// NAS COUNT 0, the first of a security context.
    pub const ZERO: Self = Self(0);
    /// The largest NAS COUNT, 2^24 - 1.
    pub const MAX: Self = Self(0x00ff_ffff);

    /// A NAS COUNT, or [`SecurityError::OutOfRange`] above 2^24 - 1.
    pub const fn new(value: u32) -> Result<Self, SecurityError> {
        if value <= Self::MAX.0 {
            Ok(Self(value))
        } else {
            Err(SecurityError::OutOfRange {
                field: "NAS COUNT",
                maximum: Self::MAX.0 as u64,
                got: value as u64,
            })
        }
    }

    /// The NAS COUNT of a NAS overflow counter and a NAS sequence number.
    pub const fn from_parts(overflow: u16, sequence_number: u8) -> Self {
        Self(((overflow as u32) << 8) | sequence_number as u32)
    }

    /// The value, 0 to 2^24 - 1.
    pub const fn get(self) -> u32 {
        self.0
    }

    /// The NAS overflow counter, the 16 most significant bits.
    pub const fn overflow(self) -> u16 {
        (self.0 >> 8) as u16
    }

    /// The NAS sequence number, the 8 least significant bits: the octet
    /// that a security protected NAS message carries.
    pub const fn sequence_number(self) -> u8 {
        self.0 as u8
    }
}

impl TryFrom<u32> for NasCount {
    type Error = SecurityError;

    fn try_from(value: u32) -> Result<Self, SecurityError> {
        Self::new(value)
    }
}

impl From<NasCount> for u32 {
    fn from(count: NasCount) -> u32 {
        count.0
    }
}

/// The COUNT from which KgNB or KeNB is derived (TS 33.501 Annex A.9,
/// TS 33.401 Annex A.3).
///
/// It is the uplink NAS COUNT of the message that started the derivation,
/// or 2^32 - 1 at a handover, a value that no NAS message can have
/// (TS 33.501 §6.9.2.3.3, §8.3.2 and §8.4.2). A [`NasCount`] converts into
/// it, so the functions take either.
///
/// ```
/// use oxirush_security::{AccessKeyCount, NasCount, SecurityError};
///
/// // A stored 32-bit value is one or the other, or an error
/// assert_eq!(AccessKeyCount::try_from(7)?, AccessKeyCount::Nas(NasCount::new(7)?));
/// assert_eq!(AccessKeyCount::try_from(u32::MAX)?, AccessKeyCount::Handover);
/// assert!(AccessKeyCount::try_from(1 << 24).is_err());
/// # Ok::<(), SecurityError>(())
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AccessKeyCount {
    /// The uplink NAS COUNT of a NAS message.
    Nas(NasCount),
    /// 2^32 - 1, at an N2 handover with a KAMF change and at a handover
    /// between EPS and 5GS.
    Handover,
}

impl AccessKeyCount {
    /// The 32-bit value that the key derivation takes.
    pub const fn get(self) -> u32 {
        match self {
            Self::Nas(count) => count.get(),
            Self::Handover => u32::MAX,
        }
    }
}

impl From<NasCount> for AccessKeyCount {
    fn from(count: NasCount) -> Self {
        Self::Nas(count)
    }
}

impl TryFrom<u32> for AccessKeyCount {
    type Error = SecurityError;

    fn try_from(value: u32) -> Result<Self, SecurityError> {
        if value == u32::MAX {
            Ok(Self::Handover)
        } else {
            NasCount::new(value).map(Self::Nas)
        }
    }
}

impl From<AccessKeyCount> for u32 {
    fn from(count: AccessKeyCount) -> u32 {
        count.get()
    }
}

/// The octets that a length in bits covers, or the error for a length that
/// the buffer does not hold.
pub(crate) fn octets_of(bit_length: u64, available: usize) -> Result<usize, SecurityError> {
    usize::try_from(bit_length.div_ceil(8))
        .ok()
        .filter(|octets| *octets <= available)
        .ok_or(SecurityError::BitLengthExceedsData {
            bits: bit_length,
            octets: available,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TS 33.501 §5.11.1 and TS 33.401 §5.1.3.2 and §5.1.4.2 give the four
    /// algorithms the identifiers 0 to 3 in both systems.
    #[test]
    fn algorithm_identifiers_are_those_of_both_specifications() {
        for (identifier, integrity, ciphering) in [
            (0, IntegrityAlgorithm::Null, CipheringAlgorithm::Null),
            (1, IntegrityAlgorithm::Snow3g, CipheringAlgorithm::Snow3g),
            (2, IntegrityAlgorithm::Aes, CipheringAlgorithm::Aes),
            (3, IntegrityAlgorithm::Zuc, CipheringAlgorithm::Zuc),
        ] {
            assert_eq!(IntegrityAlgorithm::try_from(identifier), Ok(integrity));
            assert_eq!(CipheringAlgorithm::try_from(identifier), Ok(ciphering));
            assert_eq!(u8::from(integrity), identifier);
            assert_eq!(u8::from(ciphering), identifier);
        }
        assert_eq!(IntegrityAlgorithm::NIA1, IntegrityAlgorithm::EIA1);
        assert_eq!(IntegrityAlgorithm::NIA3, IntegrityAlgorithm::Zuc);
        assert_eq!(CipheringAlgorithm::NEA2, CipheringAlgorithm::EEA2);
        assert_eq!(CipheringAlgorithm::EEA0, CipheringAlgorithm::Null);
        for reserved in 4..=u8::MAX {
            assert_eq!(
                IntegrityAlgorithm::try_from(reserved),
                Err(SecurityError::UnsupportedAlgorithm(reserved))
            );
            assert_eq!(
                CipheringAlgorithm::try_from(reserved),
                Err(SecurityError::UnsupportedAlgorithm(reserved))
            );
        }
    }

    #[test]
    fn direction_is_one_bit() {
        assert_eq!(Direction::try_from(0), Ok(Direction::Uplink));
        assert_eq!(Direction::try_from(1), Ok(Direction::Downlink));
        assert_eq!(u8::from(Direction::Downlink), 1);
        assert!(Direction::try_from(2).is_err());
    }

    #[test]
    fn bearer_is_five_bits() {
        assert_eq!(Bearer::new(31), Ok(Bearer::MAX));
        assert_eq!(Bearer::try_from(0), Ok(Bearer::ZERO));
        assert_eq!(u8::from(Bearer::MAX), 31);
        assert_eq!(
            Bearer::new(32),
            Err(SecurityError::OutOfRange {
                field: "BEARER",
                maximum: 31,
                got: 32
            })
        );
    }

    /// TS 24.501 §4.4.3.1: a NAS sequence number (8 least significant bits)
    /// concatenated with a NAS overflow counter (16 most significant bits).
    #[test]
    fn nas_count_is_twenty_four_bits() {
        assert_eq!(NasCount::new(0x00ff_ffff), Ok(NasCount::MAX));
        assert_eq!(NasCount::from_parts(0xffff, 0xff), NasCount::MAX);
        assert_eq!(NasCount::from_parts(0x1234, 0x56).get(), 0x0012_3456);
        assert_eq!(NasCount::MAX.overflow(), 0xffff);
        assert_eq!(NasCount::new(0x0102).unwrap().sequence_number(), 0x02);
        assert_eq!(NasCount::try_from(7), NasCount::new(7));
        assert_eq!(NasCount::from_parts(0, 7), NasCount::new(7).unwrap());
        assert_eq!(u32::from(NasCount::MAX), 0x00ff_ffff);
        assert_eq!(
            NasCount::try_from(0x0100_0000),
            Err(SecurityError::OutOfRange {
                field: "NAS COUNT",
                maximum: 0x00ff_ffff,
                got: 0x0100_0000
            })
        );
        assert!(NasCount::new(u32::MAX).is_err());
    }

    /// TS 33.501 §6.9.2.3.3: 2^32 - 1 is "not in the normal NAS COUNT
    /// range", so it is a value of its own and nothing between is one.
    #[test]
    fn access_key_count_is_a_nas_count_or_all_ones() {
        assert_eq!(AccessKeyCount::from(NasCount::MAX).get(), 0x00ff_ffff);
        assert_eq!(AccessKeyCount::Handover.get(), u32::MAX);
        assert_eq!(u32::from(AccessKeyCount::Handover), u32::MAX);
        assert_eq!(
            AccessKeyCount::try_from(u32::MAX),
            Ok(AccessKeyCount::Handover)
        );
        assert!(AccessKeyCount::try_from(u32::MAX - 1).is_err());
        assert!(AccessKeyCount::try_from(0x0100_0000).is_err());
    }

    #[test]
    fn a_bit_length_is_within_the_buffer() {
        assert_eq!(octets_of(0, 0), Ok(0));
        assert_eq!(octets_of(1, 1), Ok(1));
        assert_eq!(octets_of(8, 1), Ok(1));
        assert_eq!(octets_of(9, 2), Ok(2));
        assert_eq!(
            octets_of(9, 1),
            Err(SecurityError::BitLengthExceedsData { bits: 9, octets: 1 })
        );
        assert!(octets_of(u64::MAX, 16).is_err());
    }
}
