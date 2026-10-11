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
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecurityError {
    /// A SUCI home network key that does not have the length of its profile.
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength {
        /// Length of a key of the profile, in octets.
        expected: usize,
        /// Length of the key that was passed, in octets.
        got: usize,
    },
    /// A SUCI ECIES operation that cannot be carried out: a key that the
    /// profile does not accept, an empty scheme input, a scheme output that
    /// is too short, or a protection scheme other than the null scheme,
    /// Profile A and Profile B. The text says which.
    #[error("ECIES error: {0}")]
    Ecies(String),
    /// The MAC tag of a SUCI scheme output is not the one computed over its
    /// ciphertext.
    #[error("MAC verification failed")]
    MacMismatch,
    /// A parameter that the operation cannot take, such as a malformed SUCI
    /// NAI, a home network private key that is missing or a string with a
    /// character that its encoding does not have. The text says which.
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    /// A KDF parameter longer than its two-octet length field can express.
    #[error("input too long: maximum {maximum} octets, got {got}")]
    InputTooLong {
        /// Longest parameter the length field can express, in octets.
        maximum: usize,
        /// Length of the parameter that was passed, in octets.
        got: usize,
    },
    /// A number above the largest that its field holds: a NAS COUNT above
    /// 2^24 - 1, a BEARER above 31, a PCI, an ARFCN, an AMF Set ID, an AMF
    /// Pointer or a cell identity.
    #[error("{field} out of range: maximum {maximum}, got {got}")]
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
    #[error("unsupported algorithm identifier {0}")]
    UnsupportedAlgorithm(u8),
    /// A length in bits that is more than the buffer holds.
    #[error("bit length {bits} exceeds the {octets} octets of the buffer")]
    BitLengthExceedsData {
        /// The length that was passed, in bits.
        bits: u64,
        /// Length of the buffer, in octets.
        octets: usize,
    },
}
