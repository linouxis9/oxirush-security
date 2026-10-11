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

//! The error type of the crate.

/// What a function of this crate refuses.
///
/// No public function panics on its arguments: a value that the
/// specification does not allow is either impossible to write, because the
/// parameter has a type of its own, or returned as one of these.
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecurityError {
    /// A SUCI home network key that does not have the length of its profile.
    InvalidKeyLength {
        /// Length of a key of the profile, in octets.
        expected: usize,
        /// Length of the key that was passed, in octets.
        got: usize,
    },
    /// A SUCI ECIES operation that cannot be carried out: a key that the
    /// profile does not accept, an empty scheme input, a scheme output that
    /// is too short, a protection scheme other than the null scheme,
    /// Profile A and Profile B, or a failure of the system's random number
    /// generator. The text says which.
    Ecies(String),
    /// The MAC tag of a SUCI scheme output is not the one computed over its
    /// ciphertext.
    MacMismatch,
    /// A parameter that the operation cannot take, such as a malformed SUCI
    /// NAI, a home network private key that is missing or a string with a
    /// character that its encoding does not have. The text says which.
    InvalidParameter(&'static str),
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
}

impl core::fmt::Display for SecurityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength { expected, got } => {
                write!(f, "invalid key length: expected {expected}, got {got}")
            }
            Self::Ecies(reason) => write!(f, "ECIES error: {reason}"),
            Self::MacMismatch => f.write_str("MAC verification failed"),
            Self::InvalidParameter(reason) => write!(f, "invalid parameter: {reason}"),
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
        }
    }
}

impl std::error::Error for SecurityError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// The texts, which 0.2.0 already had for its five variants.
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
                SecurityError::Ecies("scheme output too short".into()),
                "ECIES error: scheme output too short",
            ),
            (SecurityError::MacMismatch, "MAC verification failed"),
            (
                SecurityError::InvalidParameter("malformed SUCI NAI"),
                "invalid parameter: malformed SUCI NAI",
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
        ] {
            assert_eq!(error.to_string(), text);
        }
        // It is an error type that crosses threads and boxes
        fn is_an_error<T: std::error::Error + Send + Sync + 'static>() {}
        is_an_error::<SecurityError>();
    }
}
