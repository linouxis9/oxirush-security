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

/// The code that the algorithms run on this processor.
///
/// ```
/// use oxirush_security::implementation;
///
/// // What a program logs when it starts
/// println!("oxirush-security runs on {}", implementation());
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
        assert_eq!(
            Implementation::Scalar.to_string(),
            "scalar code, and the aes crate for AES"
        );
    }
}
