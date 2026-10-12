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
use core::fmt;

/// An integrity algorithm of 5GS or EPS.
///
/// 5GS names them NIA0 and 128-NIA1 to 128-NIA3 (TS 33.501 §5.11.1.2) and
/// EPS EIA0 and 128-EIA1 to 128-EIA3 (TS 33.401 §5.1.4.2). They are the
/// same algorithms with the same identifiers, so one type serves both, and
/// the constants give each variant the two names of the specifications.
///
/// `TryFrom<u8>` reads an identifier and `u8::from` gives it back.
/// [`name_5gs`](Self::name_5gs) and [`name_eps`](Self::name_eps) give the
/// name that a log of one system writes, and `{}` both.
///
/// ```
/// use oxirush_security::{IntegrityAlgorithm, SecurityError};
///
/// // The identifier of a SECURITY MODE COMMAND
/// let algorithm = IntegrityAlgorithm::try_from(2)?;
/// assert_eq!(algorithm, IntegrityAlgorithm::NIA2);
/// assert_eq!(algorithm, IntegrityAlgorithm::EIA2);
/// assert_eq!(u8::from(algorithm), 2);
/// assert_eq!(algorithm.name_5gs(), "128-NIA2");
/// assert_eq!(algorithm.name_eps(), "128-EIA2");
/// assert_eq!(algorithm.to_string(), "128-NIA2/128-EIA2");
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

    /// Its name in 5GS: `NIA0`, `128-NIA1`, `128-NIA2` or `128-NIA3`
    /// (TS 33.501 §5.11.1.2).
    pub const fn name_5gs(self) -> &'static str {
        match self {
            Self::Null => "NIA0",
            Self::Snow3g => "128-NIA1",
            Self::Aes => "128-NIA2",
            Self::Zuc => "128-NIA3",
        }
    }

    /// Its name in EPS: `EIA0`, `128-EIA1`, `128-EIA2` or `128-EIA3`
    /// (TS 33.401 §5.1.4.2).
    pub const fn name_eps(self) -> &'static str {
        match self {
            Self::Null => "EIA0",
            Self::Snow3g => "128-EIA1",
            Self::Aes => "128-EIA2",
            Self::Zuc => "128-EIA3",
        }
    }
}

/// The names of both systems, such as `128-NIA2/128-EIA2`.
impl fmt::Display for IntegrityAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name_5gs(), self.name_eps())
    }
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
/// [`name_5gs`](Self::name_5gs) and [`name_eps`](Self::name_eps) give the
/// name that a log of one system writes, and `{}` both.
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

    /// Its name in 5GS: `NEA0`, `128-NEA1`, `128-NEA2` or `128-NEA3`
    /// (TS 33.501 §5.11.1.1).
    pub const fn name_5gs(self) -> &'static str {
        match self {
            Self::Null => "NEA0",
            Self::Snow3g => "128-NEA1",
            Self::Aes => "128-NEA2",
            Self::Zuc => "128-NEA3",
        }
    }

    /// Its name in EPS: `EEA0`, `128-EEA1`, `128-EEA2` or `128-EEA3`
    /// (TS 33.401 §5.1.3.2).
    pub const fn name_eps(self) -> &'static str {
        match self {
            Self::Null => "EEA0",
            Self::Snow3g => "128-EEA1",
            Self::Aes => "128-EEA2",
            Self::Zuc => "128-EEA3",
        }
    }
}

/// The names of both systems, such as `128-NEA2/128-EEA2`.
impl fmt::Display for CipheringAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.name_5gs(), self.name_eps())
    }
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
/// The crate keeps no NAS COUNT: a security context of the caller has one
/// for each direction, and this type gives what the two sides do with it.
/// The sender takes [`next`](Self::next) after each message, and a
/// receiver has the COUNT of a message from the sequence number that the
/// message carries with [`estimate`](Self::estimate). A COUNT protects one
/// message: neither gives the same one twice, and both refuse to wrap
/// around. A security context whose integrity algorithm is the null one
/// is the exception, and has [`wrapping_next`](Self::wrapping_next) and
/// [`wrapping_estimate`](Self::wrapping_estimate) (TS 24.501 §4.4.3.5,
/// TS 24.301 §4.4.3.5). The algorithms take the COUNT padded with eight
/// zero bits to 32, as those clauses require.
///
/// A context keeps an `Option<NasCount>` for each direction, `None` once
/// the COUNTs are exhausted: `count.next().ok()`.
///
/// ```
/// use oxirush_security::{NasCount, SecurityError};
///
/// // A sender: the COUNT of this message, then the one after it
/// let uplink = NasCount::new(0x0000_01ff)?;
/// assert_eq!(uplink.next()?, NasCount::from_parts(0x0002, 0x00));
/// assert_eq!(NasCount::MAX.next(), Err(SecurityError::NasCountExhausted));
///
/// // A receiver: the lowest COUNT that it still accepts is 0x1fe, and a
/// // message comes with the sequence number 0x01
/// let lowest = NasCount::new(0x0000_01fe)?;
/// let received = lowest.estimate(0x01)?;
/// assert_eq!(received, NasCount::from_parts(0x0002, 0x01));
/// // Once the MAC of the message is verified with it
/// let lowest = received.next()?;
/// assert_eq!(lowest.get(), 0x0000_0202);
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

    /// The NAS COUNT after this one: that of the next message of a
    /// sender, and the lowest that a receiver accepts after the message
    /// of this one.
    ///
    /// After 2^24 - 1 there is none, and the result is
    /// [`SecurityError::NasCountExhausted`]: a COUNT is not used twice
    /// with the same keys, so the network activates fresh NAS keys before
    /// one wraps around, and a node that has none left releases the NAS
    /// signalling connection instead of sending (TS 24.501 §4.4.3.5,
    /// TS 24.301 §4.4.3.5).
    pub const fn next(self) -> Result<Self, SecurityError> {
        if self.0 < Self::MAX.0 {
            Ok(Self(self.0 + 1))
        } else {
            Err(SecurityError::NasCountExhausted)
        }
    }

    /// The NAS COUNT after this one in a security context whose integrity
    /// algorithm is the null one, 5G-IA0 or EIA0: zero after 2^24 - 1.
    /// Such a context keeps no key that a COUNT could be used twice with,
    /// and "the UE and the AMF shall allow NAS COUNT wrap around"
    /// (TS 24.501 §4.4.3.5, and TS 24.301 §4.4.3.5 for EPS). With any
    /// other algorithm, [`next`](Self::next).
    pub const fn wrapping_next(self) -> Self {
        Self((self.0 + 1) & Self::MAX.0)
    }

    /// The NAS COUNT of a received message, from the NAS sequence number
    /// that it carries (TS 24.501 §4.4.3.1, TS 24.301 §4.4.3.1).
    ///
    /// `self` is the lowest NAS COUNT that the receiver still accepts:
    /// one more than the largest that it has verified, or zero in a new
    /// security context. The estimate is the smallest NAS COUNT from
    /// there on that ends with the sequence number, so a sequence number
    /// below the expected one means that the overflow counter went up by
    /// one. A message that is replayed gets a COUNT other than the one it
    /// was protected with, and its MAC is then wrong.
    ///
    /// The caller verifies the MAC with the estimate and, only when it is
    /// right, keeps [`next`](Self::next) of the estimate as the lowest
    /// that it accepts. An estimate above 2^24 - 1 is
    /// [`SecurityError::NasCountExhausted`].
    pub const fn estimate(self, sequence_number: u8) -> Result<Self, SecurityError> {
        self.estimate_from_low_bits(sequence_number, 8)
    }

    /// The NAS COUNT of which a message carries only the `bits` least
    /// significant bits, estimated as [`estimate`](Self::estimate) does:
    ///
    /// - 5 for the short sequence number of an EPS SERVICE REQUEST, of
    ///   which "the receiver shall estimate the remaining 3 most
    ///   significant bits" (TS 24.301 §4.4.3.1 and §9.9.3.19);
    /// - 4 for the downlink NAS COUNT of a handover from E-UTRAN to UTRAN
    ///   or GERAN (TS 24.301 §9.9.2.6, TS 33.401 §9.2.1) and of SRVCC
    ///   from 5GS (TS 33.501 Annex J);
    /// - 8 for the downlink NAS COUNT of a handover from 5GS to EPS
    ///   (TS 33.501 §8.3.2), which is [`estimate`](Self::estimate).
    ///
    /// The bits of `low_bits` above `bits` are ignored. A `bits` that is
    /// not 1 to 8 is [`SecurityError::OutOfRange`].
    pub const fn estimate_from_low_bits(
        self,
        low_bits: u8,
        bits: u32,
    ) -> Result<Self, SecurityError> {
        match self.ahead(low_bits, bits) {
            Ok(estimate) if estimate <= Self::MAX.0 => Ok(Self(estimate)),
            Ok(_) => Err(SecurityError::NasCountExhausted),
            Err(error) => Err(error),
        }
    }

    /// [`estimate`](Self::estimate) in a security context whose integrity
    /// algorithm is the null one, where the NAS COUNT wraps around: after
    /// 2^24 - 1 the estimate goes on from zero (TS 24.501 §4.4.3.5,
    /// TS 24.301 §4.4.3.5).
    pub const fn wrapping_estimate(self, sequence_number: u8) -> Self {
        match self.ahead(sequence_number, 8) {
            Ok(estimate) => Self(estimate & Self::MAX.0),
            // Eight bits are within the range
            Err(_) => self,
        }
    }

    /// [`estimate_from_low_bits`](Self::estimate_from_low_bits) in a
    /// security context whose integrity algorithm is the null one, where
    /// the NAS COUNT wraps around. A `bits` that is not 1 to 8 is
    /// [`SecurityError::OutOfRange`].
    pub const fn wrapping_estimate_from_low_bits(
        self,
        low_bits: u8,
        bits: u32,
    ) -> Result<Self, SecurityError> {
        match self.ahead(low_bits, bits) {
            Ok(estimate) => Ok(Self(estimate & Self::MAX.0)),
            Err(error) => Err(error),
        }
    }

    /// The smallest number from this COUNT on whose `bits` low bits are
    /// those of `low_bits`: at most 2^24 + 254.
    const fn ahead(self, low_bits: u8, bits: u32) -> Result<u32, SecurityError> {
        if bits == 0 || bits > 8 {
            return Err(SecurityError::OutOfRange {
                field: "bits of a NAS sequence number",
                maximum: 8,
                got: bits as u64,
            });
        }
        let mask = (1u32 << bits) - 1;
        let ahead = (low_bits as u32 & mask).wrapping_sub(self.0 & mask) & mask;
        Ok(self.0 + ahead)
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

    /// TS 33.501 §5.11.1 and TS 33.401 §5.1.3.2 and §5.1.4.2: the names
    /// of the algorithms in each system.
    #[test]
    fn an_algorithm_has_the_name_of_each_system() {
        let integrity = [
            (IntegrityAlgorithm::Null, "NIA0", "EIA0"),
            (IntegrityAlgorithm::Snow3g, "128-NIA1", "128-EIA1"),
            (IntegrityAlgorithm::Aes, "128-NIA2", "128-EIA2"),
            (IntegrityAlgorithm::Zuc, "128-NIA3", "128-EIA3"),
        ];
        for (algorithm, name_5gs, name_eps) in integrity {
            assert_eq!(algorithm.name_5gs(), name_5gs);
            assert_eq!(algorithm.name_eps(), name_eps);
            assert_eq!(algorithm.to_string(), format!("{name_5gs}/{name_eps}"));
        }
        let ciphering = [
            (CipheringAlgorithm::Null, "NEA0", "EEA0"),
            (CipheringAlgorithm::Snow3g, "128-NEA1", "128-EEA1"),
            (CipheringAlgorithm::Aes, "128-NEA2", "128-EEA2"),
            (CipheringAlgorithm::Zuc, "128-NEA3", "128-EEA3"),
        ];
        for (algorithm, name_5gs, name_eps) in ciphering {
            assert_eq!(algorithm.name_5gs(), name_5gs);
            assert_eq!(algorithm.name_eps(), name_eps);
            assert_eq!(algorithm.to_string(), format!("{name_5gs}/{name_eps}"));
        }
    }

    /// TS 24.501 §4.4.3.1 and TS 24.301 §4.4.3.1: the sender increases
    /// the NAS COUNT by one after each message, and the overflow counter
    /// with it when the sequence number wraps around.
    #[test]
    fn a_sender_has_the_next_nas_count_until_the_last() {
        let count = |value| NasCount::new(value).unwrap();
        assert_eq!(NasCount::ZERO.next(), Ok(count(1)));
        assert_eq!(count(0xff).next(), Ok(NasCount::from_parts(1, 0)));
        assert_eq!(count(0x00ff_fffe).next(), Ok(NasCount::MAX));
        // No COUNT is used twice: there is none after the last
        assert_eq!(NasCount::MAX.next(), Err(SecurityError::NasCountExhausted));
        // A context keeps `None` from there on
        assert_eq!(NasCount::MAX.next().ok(), None);
    }

    /// TS 24.501 §4.4.3.5 and TS 24.301 §4.4.3.5: "When the 5G-IA0 is used
    /// as the NAS integrity algorithm, the UE and the AMF shall allow NAS
    /// COUNT wrap around."
    #[test]
    fn the_nas_count_of_the_null_integrity_algorithm_wraps_around() {
        let count = |value| NasCount::new(value).unwrap();
        assert_eq!(NasCount::ZERO.wrapping_next(), count(1));
        assert_eq!(count(0xff).wrapping_next(), count(0x100));
        assert_eq!(NasCount::MAX.wrapping_next(), NasCount::ZERO);

        // Below the last COUNTs, the estimates are those that do not wrap
        for (lowest, sequence_number) in [(0, 0), (0x105, 0x04), (0x1ff, 0x00), (0xff_ff00, 0xff)] {
            let lowest = count(lowest);
            assert_eq!(
                Ok(lowest.wrapping_estimate(sequence_number)),
                lowest.estimate(sequence_number)
            );
        }
        // After them, the overflow counter goes on from zero
        assert_eq!(count(0x00ff_ff01).wrapping_estimate(0x00), NasCount::ZERO);
        assert_eq!(count(0x00ff_fff0).wrapping_estimate(0x05), count(0x05));
        assert_eq!(NasCount::MAX.wrapping_estimate(0xff), NasCount::MAX);
        assert_eq!(NasCount::MAX.wrapping_estimate(0xfe), count(0xfe));
        let estimate =
            |lowest, low_bits, bits| count(lowest).wrapping_estimate_from_low_bits(low_bits, bits);
        assert_eq!(estimate(0x00ff_ffff, 0x00, 5), Ok(NasCount::ZERO));
        assert_eq!(estimate(0x00ff_fffe, 0x1f, 5), Ok(NasCount::MAX));
        assert_eq!(estimate(0x25, 0x04, 5), Ok(count(0x44)));
        assert_eq!(estimate(0x1f8, 0x2, 4), Ok(count(0x202)));
        assert!(estimate(0, 0, 0).is_err());
        assert!(estimate(0, 0, 9).is_err());
        // Every lowest COUNT near the end and every sequence number: the
        // first COUNT from there on, modulo 2^24, that ends with it
        for lowest in 0x00ff_fe00..=0x00ff_ffff {
            for sequence_number in 0..=255u8 {
                let expected = (lowest..lowest + 256)
                    .find(|value| *value as u8 == sequence_number)
                    .unwrap();
                assert_eq!(
                    count(lowest).wrapping_estimate(sequence_number),
                    count(expected & 0x00ff_ffff)
                );
            }
        }
    }

    /// TS 24.501 §4.4.3.1: "the sequence number part of the estimated NAS
    /// COUNT value shall be equal to the sequence number in the received
    /// NAS message", and "the receiver selects the estimated NAS overflow
    /// counter so that the estimated NAS COUNT value is higher than the
    /// stored NAS COUNT value".
    #[test]
    fn a_receiver_estimates_the_nas_count_from_the_sequence_number() {
        let count = |value| NasCount::new(value).unwrap();
        for (lowest, sequence_number, estimate) in [
            // The message that is expected, and one after a gap
            (0x0000_0000, 0x00, 0x0000_0000),
            (0x0000_0105, 0x05, 0x0000_0105),
            (0x0000_0105, 0x90, 0x0000_0190),
            (0x0000_0005, 0x90, 0x0000_0090),
            // A sequence number below the expected one: the overflow
            // counter went up
            (0x0000_01f0, 0x02, 0x0000_0202),
            (0x0000_01ff, 0x00, 0x0000_0200),
            (0x0000_0105, 0x04, 0x0000_0204),
            (0x00ff_ff00, 0xff, 0x00ff_ffff),
        ] {
            let got = count(lowest).estimate(sequence_number).unwrap();
            assert_eq!(got, count(estimate), "{lowest:#x}, {sequence_number:#x}");
            assert_eq!(got.sequence_number(), sequence_number);
            assert!(got >= count(lowest));
            assert!(got.get() - lowest < 256);
        }
        // A message that is replayed has an estimate above the COUNT that
        // protected it: 0x105 was verified, and comes again
        let lowest = count(0x0105).next().unwrap();
        assert_eq!(lowest.estimate(0x05), Ok(count(0x0205)));
        // No estimate after the last COUNT
        assert_eq!(
            count(0x00ff_ff01).estimate(0x00),
            Err(SecurityError::NasCountExhausted)
        );
        assert_eq!(NasCount::MAX.estimate(0xff), Ok(NasCount::MAX));
    }

    /// The five bits of the sequence number of an EPS SERVICE REQUEST
    /// (TS 24.301 §9.9.3.19), and the four of a downlink NAS COUNT at a
    /// handover (§9.9.2.6).
    #[test]
    fn a_nas_count_is_estimated_from_fewer_bits() {
        let count = |value| NasCount::new(value).unwrap();
        let estimate =
            |lowest, low_bits, bits| count(lowest).estimate_from_low_bits(low_bits, bits);
        assert_eq!(estimate(0x1f8, 0x2, 4), Ok(count(0x202)));
        assert_eq!(estimate(0x1f8, 0xf8, 8), Ok(count(0x1f8)));
        assert_eq!(estimate(0x25, 0x04, 5), Ok(count(0x44)));
        assert_eq!(estimate(0x25, 0x05, 5), Ok(count(0x25)));
        // The bits above those that are carried are ignored: the octet of
        // a SERVICE REQUEST has its KSI there
        assert_eq!(estimate(0x25, 0xe5, 5), Ok(count(0x25)));
        assert_eq!(estimate(0x00ff_ffff, 0x0f, 4), Ok(NasCount::MAX));
        assert_eq!(
            estimate(0x00ff_ffff, 0x00, 8),
            Err(SecurityError::NasCountExhausted)
        );
        for bits in [0, 9, 32, u32::MAX] {
            assert_eq!(
                estimate(0, 0, bits),
                Err(SecurityError::OutOfRange {
                    field: "bits of a NAS sequence number",
                    maximum: 8,
                    got: bits.into()
                })
            );
        }
        // With eight bits, every lowest COUNT and every sequence number
        for lowest in (0..0x400).chain(0x00ff_fe00..=0x00ff_ffff) {
            for sequence_number in 0..=255u8 {
                let expected = (lowest..lowest + 256)
                    .find(|value| *value as u8 == sequence_number)
                    .unwrap();
                assert_eq!(
                    count(lowest).estimate(sequence_number).ok(),
                    NasCount::new(expected).ok()
                );
            }
        }
    }

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
