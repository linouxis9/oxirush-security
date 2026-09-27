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

/// Security error types for oxirush-security.
///
/// Used for operations that can genuinely fail at runtime (e.g., invalid
/// external key material in SUCI ECIES). Internal operations on fixed-size
/// arrays use `.expect()` instead, since their sizes are compile-time guaranteed.

#[derive(Debug, thiserror::Error)]
pub enum SecurityError {
    #[error("invalid key length: expected {expected}, got {got}")]
    InvalidKeyLength { expected: usize, got: usize },
    #[error("ECIES error: {0}")]
    Ecies(String),
    #[error("MAC verification failed")]
    MacMismatch,
    #[error("invalid parameter: {0}")]
    InvalidParameter(&'static str),
    #[error("input too long: maximum {maximum} octets, got {got}")]
    InputTooLong { maximum: usize, got: usize },
}
