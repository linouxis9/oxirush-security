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

//! Which code the algorithms run on this processor.
//!
//! The crate has scalar code for every target, and for x86-64 and AArch64
//! code on the vector, AES and carry-less multiplication instructions,
//! which it uses when the processor has them. [`implementation`] says which
//! runs, so that a program can log it and a test can require it.
//!
//! The processor is asked when the program first calls an algorithm, and
//! without the standard library: by CPUID on x86-64, and through the
//! auxiliary vector of Linux and Android on AArch64, while every AArch64
//! processor of Apple has the instructions. On another AArch64 system the
//! standard library asks, with the `std` feature. On a target without an
//! operating system, and on such a system without `std`, the vector code
//! runs when the build enables its instructions (`-C target-feature`,
//! `-C target-cpu`). The values are the same in every case.

use crate::common::input::{CipheringAlgorithm, IntegrityAlgorithm};
use core::fmt;

/// The code that the algorithms run on this processor.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Implementation {
    /// Scalar code for SNOW 3G and ZUC, and the `aes` crate for AES. A
    /// batch is its messages one after the other.
    Scalar,
    /// SNOW 3G, ZUC and AES on the vector, AES and carry-less
    /// multiplication instructions of 128 bits: SSSE3, SSE4.1, AES-NI and
    /// PCLMULQDQ on x86-64, NEON and AES on AArch64. In a batch, four
    /// SNOW 3G or ZUC generators, eight CBC-MAC chains and the MILENAGE of
    /// eight subscribers run side by side.
    Vector128,
    /// [`Vector128`](Self::Vector128), and in a batch of more than four
    /// messages eight SNOW 3G or ZUC generators side by side, on AVX2.
    Vector256,
}

/// The code of one algorithm for one message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Code {
    /// The null algorithm computes nothing.
    Null,
    /// Scalar code of this crate, which every target has.
    Scalar,
    /// The `aes` crate: the AES instructions where that crate finds them,
    /// and bitsliced code elsewhere.
    AesCrate,
    /// This crate's code on vector instructions of 128 bits.
    Vector,
    /// This crate's key expansion and rounds on the AES instructions.
    AesInstructions,
}

impl Implementation {
    /// The code of a ciphering algorithm for one message.
    pub fn ciphering(self, algorithm: CipheringAlgorithm) -> Code {
        match (algorithm, self) {
            (CipheringAlgorithm::Null, _) => Code::Null,
            (CipheringAlgorithm::Aes, Self::Scalar) => Code::AesCrate,
            (CipheringAlgorithm::Aes, _) => Code::AesInstructions,
            (_, Self::Scalar) => Code::Scalar,
            _ => Code::Vector,
        }
    }

    /// The code of an integrity algorithm for one message.
    pub fn integrity(self, algorithm: IntegrityAlgorithm) -> Code {
        match (algorithm, self) {
            (IntegrityAlgorithm::Null, _) => Code::Null,
            (IntegrityAlgorithm::Aes, Self::Scalar) => Code::AesCrate,
            (IntegrityAlgorithm::Aes, _) => Code::AesInstructions,
            (_, Self::Scalar) => Code::Scalar,
            _ => Code::Vector,
        }
    }

    /// How many messages of a ciphering algorithm
    /// [`nea_cipher_batch`](crate::nea_cipher_batch) works on side by
    /// side: 1, 4 or 8. It is 1 for 128-EEA2, whose counter blocks are
    /// encrypted eight at a time for one message.
    pub fn ciphering_side_by_side(self, algorithm: CipheringAlgorithm) -> usize {
        match algorithm {
            CipheringAlgorithm::Snow3g | CipheringAlgorithm::Zuc => self.generators(),
            CipheringAlgorithm::Null | CipheringAlgorithm::Aes => 1,
        }
    }

    /// How many messages of an integrity algorithm
    /// [`nia_mac_batch`](crate::nia_mac_batch) works on side by side: 1, 4
    /// or 8.
    pub fn integrity_side_by_side(self, algorithm: IntegrityAlgorithm) -> usize {
        match (algorithm, self) {
            (IntegrityAlgorithm::Snow3g | IntegrityAlgorithm::Zuc, _) => self.generators(),
            (IntegrityAlgorithm::Aes, Self::Vector128 | Self::Vector256) => 8,
            _ => 1,
        }
    }

    /// The code of the AES of MILENAGE for one subscriber.
    pub fn milenage(self) -> Code {
        match self {
            Self::Scalar => Code::AesCrate,
            Self::Vector128 | Self::Vector256 => Code::AesInstructions,
        }
    }

    /// How many subscribers
    /// [`milenage::authentication_vector_batch`](crate::milenage::authentication_vector_batch)
    /// and [`milenage::check_autn_batch`](crate::milenage::check_autn_batch)
    /// work on side by side: 1 or 8.
    pub fn milenage_side_by_side(self) -> usize {
        match self {
            Self::Scalar => 1,
            Self::Vector128 | Self::Vector256 => 8,
        }
    }

    /// The SNOW 3G or ZUC generators that a batch clocks together.
    fn generators(self) -> usize {
        match self {
            Self::Scalar => 1,
            Self::Vector128 => 4,
            Self::Vector256 => 8,
        }
    }
}

impl fmt::Display for Implementation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Scalar => "scalar code, and the aes crate for AES",
            Self::Vector128 => {
                "vector and AES instructions of 128 bits, four generators side by side in a batch"
            }
            Self::Vector256 => {
                "vector and AES instructions of 128 bits, eight generators side by side in a batch on AVX2"
            }
        })
    }
}

impl fmt::Display for Code {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Null => "nothing",
            Self::Scalar => "scalar code",
            Self::AesCrate => "the aes crate",
            Self::Vector => "vector instructions",
            Self::AesInstructions => "AES instructions",
        })
    }
}

/// The code that the algorithms run on this processor.
///
/// ```
/// use oxirush_security::{CipheringAlgorithm, implementation};
///
/// let implementation = implementation();
/// println!("NEA2 runs on {}", implementation.ciphering(CipheringAlgorithm::NEA2));
/// ```
pub fn implementation() -> Implementation {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        use crate::common::simd::{available, wide_available};
        match (available(), wide_available()) {
            (true, true) => Implementation::Vector256,
            (true, false) => Implementation::Vector128,
            (false, _) => Implementation::Scalar,
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    Implementation::Scalar
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What `implementation` names is what the vector module would run.
    #[test]
    fn the_implementation_follows_the_paths_that_are_allowed() {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            use crate::common::simd::{narrow, scalar};
            assert_eq!(scalar(implementation), Implementation::Scalar);
            assert_ne!(narrow(implementation), Implementation::Vector256);
        }
        let all = [
            Implementation::Scalar,
            Implementation::Vector128,
            Implementation::Vector256,
        ];
        for (implementation, generators) in all.into_iter().zip([1, 4, 8]) {
            let (nea1, nia3) = (CipheringAlgorithm::NEA1, IntegrityAlgorithm::NIA3);
            assert_eq!(implementation.ciphering_side_by_side(nea1), generators);
            assert_eq!(implementation.integrity_side_by_side(nia3), generators);
            assert_eq!(
                implementation.ciphering_side_by_side(CipheringAlgorithm::NEA2),
                1
            );
            assert_eq!(
                implementation.ciphering(CipheringAlgorithm::NEA0),
                Code::Null
            );
        }
        assert_eq!(
            Implementation::Scalar.integrity(IntegrityAlgorithm::NIA2),
            Code::AesCrate
        );
        assert_eq!(
            Implementation::Vector128.integrity(IntegrityAlgorithm::NIA2),
            Code::AesInstructions
        );
        assert_eq!(
            Implementation::Vector128.integrity_side_by_side(IntegrityAlgorithm::NIA2),
            8
        );
        assert_eq!(
            Implementation::Vector256.ciphering(CipheringAlgorithm::NEA3),
            Code::Vector
        );
        assert_eq!(Implementation::Scalar.milenage(), Code::AesCrate);
        assert_eq!(Implementation::Vector128.milenage(), Code::AesInstructions);
        assert_eq!(Implementation::Scalar.milenage_side_by_side(), 1);
        assert_eq!(Implementation::Vector256.milenage_side_by_side(), 8);
    }
}
