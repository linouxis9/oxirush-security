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

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::{AesSchedule, Instructions};
use aes::Aes128Enc;
use aes::cipher::consts::U16;
use aes::cipher::typenum::Unsigned;
use aes::cipher::{
    BlockCipherEncBackend, BlockCipherEncClosure, BlockCipherEncrypt, BlockSizeUser, KeyInit,
    ParBlocks,
};
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
        self.0.encrypt_with_backend(Counter { prefix, data });
    }
}

/// The most blocks that the code of the `aes` crate without instructions
/// works on at once: 2 with words of 32 bits, 4 with words of 64.
const BITSLICED: usize = 4;

/// The counter blocks that are made, then encrypted one after the other
/// on the AES instructions, before the octets of the message are written.
const GROUP: usize = 8;

/// Counter mode over `data`, for the code that the `aes` crate has chosen
/// for the processor.
///
/// That code encrypts some number of blocks side by side. Its code without
/// instructions has them in the bits of its words and costs the same for
/// one block as for [`BITSLICED`]: it is given the counter blocks so many
/// at a time. Its codes on the AES instructions take 8 blocks, 30 on VAES
/// and 64 on AVX-512F, with a frame for as many whatever the number of
/// blocks of a message, and the last one writes registers that this crate
/// does not clear. They are not called: on these instructions the counter
/// blocks are encrypted one after the other, which the processor overlaps,
/// with the same frame and one register on each of them. What an
/// operation uses of the stack then does not follow the processor that it
/// runs on.
struct Counter<'a> {
    prefix: [u8; 8],
    data: &'a mut [u8],
}

/// The counter block of a number.
fn counter_block(prefix: &[u8; 8], number: u64) -> aes::Block {
    let mut block = aes::Block::default();
    block[..8].copy_from_slice(prefix);
    block[8..].copy_from_slice(&number.to_be_bytes());
    block
}

/// Add a block of keystream to the octets of a message, 16 or fewer for
/// its last ones.
#[inline(always)]
fn add_keystream(octets: &mut [u8], keystream: &aes::Block) {
    if let Ok(whole) = <&mut [u8; 16]>::try_from(&mut *octets) {
        // As one number: an octet at a time is most of the time of a block
        // on the AES instructions
        let keystream = u128::from_ne_bytes((*keystream).into());
        *whole = (u128::from_ne_bytes(*whole) ^ keystream).to_ne_bytes();
    } else {
        for (octet, key_octet) in octets.iter_mut().zip(keystream) {
            *octet ^= key_octet;
        }
    }
}

impl BlockSizeUser for Counter<'_> {
    type BlockSize = U16;
}

impl BlockCipherEncClosure for Counter<'_> {
    #[inline(always)]
    fn call<B: BlockCipherEncBackend<BlockSize = U16>>(self, backend: &B) {
        let Self { prefix, mut data } = self;
        let side_by_side = B::ParBlocksSize::USIZE;
        let mut number = 0u64;
        if side_by_side <= BITSLICED {
            // The blocks of a group in one call, the last group whole as
            // well: a call costs the same for fewer blocks
            let mut blocks = ParBlocks::<B>::default();
            while !data.is_empty() {
                let (group, rest) = data.split_at_mut(data.len().min(16 * side_by_side));
                for block in blocks.iter_mut() {
                    *block = counter_block(&prefix, number);
                    number += 1;
                }
                backend.encrypt_par_blocks_inplace(&mut blocks);
                for (octets, block) in group.chunks_mut(16).zip(blocks.iter()) {
                    add_keystream(octets, block);
                }
                data = rest;
            }
            for block in blocks.iter_mut() {
                block.as_mut_slice().zeroize();
            }
        } else {
            // The counter blocks of a group first, then their encryption
            // one after the other, which the processor overlaps: it does
            // not when the octets of the message are written between two
            // of them
            let mut blocks = [aes::Block::default(); GROUP];
            for group in data.chunks_mut(16 * GROUP) {
                let blocks = &mut blocks[..group.len().div_ceil(16)];
                for block in blocks.iter_mut() {
                    *block = counter_block(&prefix, number);
                    number += 1;
                }
                for block in blocks.iter_mut() {
                    backend.encrypt_block_inplace(block);
                }
                for (octets, block) in group.chunks_mut(16).zip(blocks.iter()) {
                    add_keystream(octets, block);
                }
            }
            for block in &mut blocks {
                block.as_mut_slice().zeroize();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aes::cipher::consts::{U2, U4, U8, U30};
    use aes::cipher::{ParBlocksSizeUser, array::ArraySize, inout::InOut};
    use core::marker::PhantomData;

    /// A code that says it encrypts `Blocks` blocks side by side, and
    /// encrypts each with the `aes` crate.
    struct Code<'a, Blocks>(&'a Aes128, PhantomData<Blocks>);

    impl<Blocks> BlockSizeUser for Code<'_, Blocks> {
        type BlockSize = U16;
    }

    impl<Blocks: ArraySize> ParBlocksSizeUser for Code<'_, Blocks> {
        type ParBlocksSize = Blocks;
    }

    impl<Blocks: ArraySize> BlockCipherEncBackend for Code<'_, Blocks> {
        fn encrypt_block(&self, mut block: InOut<'_, '_, aes::Block>) {
            let mut octets: [u8; 16] = block.clone_in().into();
            self.0.encrypt_in_place(&mut octets);
            *block.get_out() = octets.into();
        }
    }

    /// The counter mode gives the same octets whatever the number of
    /// blocks that the code of the `aes` crate takes side by side: 2 or 4
    /// without instructions, together, and 8 or 30 on instructions, one
    /// after the other. A processor runs one of them alone.
    #[test]
    fn the_counter_mode_is_the_same_for_each_code_of_the_aes_crate() {
        let key: [u8; 16] = core::array::from_fn(|at| 0x3c ^ (at as u8).wrapping_mul(29));
        let aes = Aes128::new(&key);
        let prefix = [0x39, 0x8a, 0x59, 0xb4, 0xac, 0, 0, 0];
        let text: [u8; 301] = core::array::from_fn(|at| (at as u8).wrapping_mul(7));
        for length in (0..=145).chain([255, 256, 257, 300, 301]) {
            // Each block from the encryption of its counter block
            let mut expected = text;
            for (number, octets) in expected[..length].chunks_mut(16).enumerate() {
                let mut block = [0u8; 16];
                block[..8].copy_from_slice(&prefix);
                block[8..].copy_from_slice(&(number as u64).to_be_bytes());
                aes.encrypt_in_place(&mut block);
                for (octet, key_octet) in octets.iter_mut().zip(block) {
                    *octet ^= key_octet;
                }
            }
            fn with<Blocks: ArraySize>(aes: &Aes128, prefix: [u8; 8], data: &mut [u8]) {
                Counter { prefix, data }.call(&Code::<Blocks>(aes, PhantomData));
            }
            for code in [with::<U2>, with::<U4>, with::<U8>, with::<U30>] {
                let mut data = text;
                code(&aes, prefix, &mut data[..length]);
                assert_eq!(data, expected, "{length} octets");
            }
            // And the code that this processor has
            let mut data = text;
            aes.ctr(prefix, &mut data[..length]);
            assert_eq!(data, expected, "{length} octets");
        }
    }
}
