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

//! AES-128 with a key: the round keys that a context keeps for the AES
//! instructions of a processor that has them with the vector code, and the
//! `aes` crate for a processor without them.
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

/// The round keys of a key that a context keeps: those of the AES
/// instructions, 176 octets, on a processor that has them. A context
/// keeps none elsewhere: the round keys of the `aes` crate are four times
/// as large, and it expands the key for each message.
///
/// A context has the two fields of this type beside its own, so that they
/// take no more room than their octets.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) type Schedule = Zeroizing<AesSchedule>;
/// The instructions, when the round keys of a context are those of its
/// key.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) type Expanded = Option<Instructions>;

/// On a target without the vector code, a context keeps no round keys.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) type Schedule = ();
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
pub(crate) type Expanded = ();

/// No round keys: those of a context whose algorithm is not AES.
pub(crate) fn no_round_keys() -> (Expanded, Schedule) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    return (None, Zeroizing::new([0; 11]));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    ((), ())
}

/// The round keys of `key`, on a processor with the AES instructions.
pub(crate) fn expand(key: &[u8; 16]) -> (Expanded, Schedule) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        let schedules = instructions.aes_schedules([key]);
        return (Some(instructions), Zeroizing::new(schedules[0]));
    }
    let _ = key;
    no_round_keys()
}

/// The round keys that a context keeps, as the functions of AES take
/// them.
#[derive(Clone, Copy)]
pub(crate) struct RoundKeys<'a> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    schedule: Option<(Instructions, &'a AesSchedule)>,
    context: core::marker::PhantomData<&'a ()>,
}

impl<'a> RoundKeys<'a> {
    /// Those of the two fields of a context.
    pub(crate) fn of(expanded: &'a Expanded, schedule: &'a Schedule) -> Self {
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        let ((), ()) = (expanded, schedule);
        Self {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            schedule: expanded.map(|instructions| (instructions, &**schedule)),
            context: core::marker::PhantomData,
        }
    }

    /// The round keys on the AES instructions, when they were expanded.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn schedule(self) -> Option<(Instructions, &'a AesSchedule)> {
        self.schedule
    }
}

/// AES-128 of the `aes` crate with a key, for a processor without the AES
/// instructions: it expands the key, and wipes its round keys.
pub(crate) struct Aes128(Aes128Enc);

impl Aes128 {
    pub(crate) fn new(key: &[u8; 16]) -> Self {
        Self(Aes128Enc::new(key.into()))
    }

    /// Encrypt a block where it is. A chain of blocks keeps one array for
    /// them all and wipes it once.
    pub(crate) fn encrypt_in_place(&self, block: &mut [u8; 16]) {
        self.0.encrypt_block(block.into());
    }

    /// Encrypt a block.
    pub(crate) fn encrypt(&self, block: u128) -> u128 {
        let mut octets = block.to_le_bytes();
        self.0.encrypt_block((&mut octets).into());
        let encrypted = u128::from_le_bytes(octets);
        octets.zeroize();
        encrypted
    }

    /// Counter mode, as 128-EEA2 has it: the counter blocks begin with the
    /// eight octets of `prefix` and end with their number, from zero.
    pub(crate) fn ctr(&self, prefix: [u8; 8], data: &mut [u8]) {
        let cipher = &self.0;

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
