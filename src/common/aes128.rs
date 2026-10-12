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

//! AES-128 with its key: the crate's own key expansion and rounds on the
//! AES instructions of a processor that has them with the vector code, and
//! the `aes` crate elsewhere.
//!
//! A block that is a number has its first octet as the low one.

use crate::common::nea::CTR_GROUP;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::{AesSchedule, Instructions};
use aes::Aes128Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use zeroize::Zeroize;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use zeroize::Zeroizing;

/// AES-128 with the round keys of one key, which are wiped with it.
// The round keys of the `aes` crate are larger than the crate's own. A
// context holds either, and there is no allocator to put the larger in.
#[allow(clippy::large_enum_variant)]
#[derive(Clone)]
pub(crate) enum Aes128 {
    /// On the AES instructions.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Instructions(Instructions, Zeroizing<[AesSchedule; 1]>),
    /// The `aes` crate, which wipes its round keys.
    Crate(Aes128Enc),
}

impl Aes128 {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if let Some(instructions) = Instructions::detect() {
            return Self::Instructions(instructions, instructions.aes_schedules([key]));
        }
        Self::of_crate(key)
    }

    /// AES-128 of the `aes` crate, for a processor that is known not to
    /// have the instructions.
    pub(crate) fn of_crate(key: &[u8; 16]) -> Self {
        Self::Crate(Aes128Enc::new(key.into()))
    }

    /// The round keys, on the AES instructions.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn schedule(&self) -> Option<(Instructions, &AesSchedule)> {
        match self {
            Self::Instructions(instructions, schedules) => Some((*instructions, &schedules[0])),
            Self::Crate(_) => None,
        }
    }

    /// Encrypt a block.
    pub(crate) fn encrypt(&self, block: u128) -> u128 {
        match self {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Self::Instructions(instructions, schedules) => {
                let mut blocks = [block];
                instructions.aes_encrypt(schedules.each_ref(), &mut blocks);
                blocks[0]
            }
            Self::Crate(cipher) => {
                let mut octets = block.to_le_bytes();
                cipher.encrypt_block((&mut octets).into());
                let encrypted = u128::from_le_bytes(octets);
                octets.zeroize();
                encrypted
            }
        }
    }

    /// Counter mode, as 128-EEA2 has it: the counter blocks begin with the
    /// eight octets of `prefix` and end with their number, from zero.
    pub(crate) fn ctr(&self, prefix: [u8; 8], data: &mut [u8]) {
        let cipher = match self {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Self::Instructions(instructions, schedules) => {
                return instructions.aes_ctr(&schedules[0], u64::from_le_bytes(prefix), data);
            }
            Self::Crate(cipher) => cipher,
        };

        // The counter blocks of a group are encrypted in one call
        let mut keystream = [aes::Block::default(); CTR_GROUP];
        let mut counter = 0u64;
        for group in data.chunks_mut(16 * CTR_GROUP) {
            let blocks = &mut keystream[..group.len().div_ceil(16)];
            for block in blocks.iter_mut() {
                block[..8].copy_from_slice(&prefix);
                block[8..].copy_from_slice(&counter.to_be_bytes());
                counter += 1;
            }
            cipher.encrypt_blocks(blocks);
            for (octets, block) in group.chunks_mut(16).zip(blocks.iter()) {
                for (octet, key_octet) in octets.iter_mut().zip(block) {
                    *octet ^= key_octet;
                }
            }
        }

        // A group overwrites the blocks of the one before it: the array
        // holds keystream in as many blocks as the longest group had
        let written = CTR_GROUP.min(data.len().div_ceil(16));
        for block in &mut keystream[..written] {
            block.as_mut_slice().zeroize();
        }
    }
}
