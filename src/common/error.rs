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

//! The error type of the operations that can fail at run time.

/// Security error types for oxirush-security.
///
/// Used for operations that can genuinely fail at runtime (e.g., invalid
/// external key material in SUCI ECIES). Internal operations on fixed-size
/// arrays use `.expect()` instead, since their sizes are compile-time guaranteed.

#[derive(Debug, thiserror::Error)]
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
    /// curve does not accept, a scheme output that is too short, or a
    /// protection scheme other than the null scheme, Profile A and Profile
    /// B. The text says which.
    #[error("ECIES error: {0}")]
    Ecies(String),
    /// The MAC tag of a SUCI scheme output is not the one computed over its
    /// ciphertext.
    #[error("MAC verification failed")]
    MacMismatch,
    /// A parameter that the operation cannot take, such as a NAS COUNT above
    /// 24 bits, a malformed SUCI NAI or a home network private key that is
    /// missing. The text says which.
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
}
