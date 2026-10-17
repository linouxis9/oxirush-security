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

//! The error type of the crate.

/// What a function of this crate refuses.
///
/// No public function panics on its arguments: a value that the
/// specification does not allow is either impossible to write, because the
/// parameter has a type of its own, or returned as one of these.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// A key, or a value of an authentication, that does not have the
    /// length of its type.
    InvalidKeyLength {
        /// Length of a value of the type, in octets.
        expected: usize,
        /// Length of the slice that was passed, in octets.
        got: usize,
    },
    /// A parameter that the operation cannot take, such as a length that
    /// its field does not have. The text says which.
    InvalidParameter(&'static str),
    /// An identity that is not one: a PLMN, a SUPI, a 5G-GUTI, a
    /// 5G-S-TMSI or a TBCD string, with the member at fault and why. The
    /// identities are the values of oxirush-utils, whose error it is.
    Identity(oxirush_utils::identity::Error),
    /// A KDF parameter longer than its two-octet length field can express.
    InputTooLong {
        /// Longest parameter the length field can express, in octets.
        maximum: usize,
        /// Length of the parameter that was passed, in octets.
        got: usize,
    },
    /// A number above the largest that its field holds: a NAS COUNT above
    /// 2^24 - 1, a BEARER above 31, a PCI, an ARFCN, an AMF Set ID, an AMF
    /// Pointer or a cell identity.
    OutOfRange {
        /// The field, as the specification names it.
        field: &'static str,
        /// Largest value of the field.
        maximum: u64,
        /// The value that was passed.
        got: u64,
    },
    /// An algorithm identifier that names none of the algorithms of this
    /// crate: 4 to 7 are reserved, and a larger number is no identifier.
    UnsupportedAlgorithm(u8),
    /// A length in bits that is more than the buffer holds.
    BitLengthExceedsData {
        /// The length that was passed, in bits.
        bits: u64,
        /// Length of the buffer, in octets.
        octets: usize,
    },
    /// A NAS COUNT after the largest, 2^24 - 1. A NAS COUNT protects one
    /// message under its keys, so there is none to wrap around to: the
    /// security context is to be replaced by a new one.
    NasCountExhausted,
    /// A MAC of an authentication that is not the one that the key of the
    /// subscriber gives: the MAC-A of an AUTN, which a UE answers with the
    /// cause "MAC failure" (TS 33.102 §6.3.3), or the MAC-S of an AUTS,
    /// after which the home network does not take its SQN (§6.3.5).
    MacFailure,
}

impl core::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected}, got {got}")
            }
            Self::InvalidParameter(reason) => write!(f, "invalid parameter: {reason}"),
            Self::Identity(error) => write!(f, "invalid identity: {error}"),
            Self::InputTooLong { maximum, got } => {
                write!(f, "input too long: maximum {maximum} octets, got {got}")
            }
            Self::OutOfRange {
                field,
                maximum,
                got,
            } => write!(f, "{field} out of range: maximum {maximum}, got {got}"),
            Self::UnsupportedAlgorithm(identifier) => {
                write!(f, "unsupported algorithm identifier {identifier}")
            }
            Self::BitLengthExceedsData { bits, octets } => write!(
                f,
                "bit length {bits} exceeds the {octets} octets of the buffer"
            ),
            Self::NasCountExhausted => {
                f.write_str("no NAS COUNT is left after 16777215: a new security context is needed")
            }
            Self::MacFailure => f.write_str("MAC failure: the MAC is not the one that K gives"),
        }
    }
}

impl core::error::Error for SecurityError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Identity(error) => Some(error),
            _ => None,
        }
    }
}

/// An identity that oxirush-utils refuses, where the crate takes one.
impl From<oxirush_utils::identity::Error> for SecurityError {
    fn from(error: oxirush_utils::identity::Error) -> Self {
        Self::Identity(error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The text of each variant.
    #[test]
    fn each_error_says_what_was_refused() {
        for (error, text) in [
            (
                SecurityError::InvalidKeyLength {
                    expected: 32,
                    got: 31,
                },
                "invalid key length: expected 32, got 31",
            ),
            (
                SecurityError::InvalidParameter("ABBA is 2 to 255 octets long"),
                "invalid parameter: ABBA is 2 to 255 octets long",
            ),
            (
                SecurityError::from(crate::Plmn::new("208", "9").unwrap_err()),
                "invalid identity: `mnc` has 1 digit, and has 2 or 3",
            ),
            (
                SecurityError::InputTooLong {
                    maximum: 65535,
                    got: 65536,
                },
                "input too long: maximum 65535 octets, got 65536",
            ),
            (
                SecurityError::OutOfRange {
                    field: "NAS COUNT",
                    maximum: 0x00ff_ffff,
                    got: 0x0100_0000,
                },
                "NAS COUNT out of range: maximum 16777215, got 16777216",
            ),
            (
                SecurityError::UnsupportedAlgorithm(5),
                "unsupported algorithm identifier 5",
            ),
            (
                SecurityError::BitLengthExceedsData {
                    bits: 17,
                    octets: 2,
                },
                "bit length 17 exceeds the 2 octets of the buffer",
            ),
            (
                SecurityError::NasCountExhausted,
                "no NAS COUNT is left after 16777215: a new security context is needed",
            ),
            (
                SecurityError::MacFailure,
                "MAC failure: the MAC is not the one that K gives",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        // It is an error type that crosses threads and boxes
        fn is_an_error<T: core::error::Error + Send + Sync + 'static>() {}
        is_an_error::<SecurityError>();
    }
}
