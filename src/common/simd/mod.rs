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

//! SNOW 3G, ZUC and the carry-less multiplication on the vector, AES and
//! polynomial-multiplication instructions of x86-64 and AArch64.
//!
//! This is the one module of the crate with `unsafe` code, and all of it is
//! of one kind: a call of a function that is compiled for instructions
//! which the build does not assume. Such a call is sound when the processor
//! has the instructions, which [`available`] has seen at run time before
//! every one of them. The functions themselves, in the module of the
//! architecture, are safe code.
//!
//! The scalar generators of `snow3g` and `zuc` are used where the
//! instructions are missing, and the tests compare the two.
#![allow(unsafe_code)]

use core::sync::atomic::{AtomicU8, Ordering};
use zeroize::{Zeroize, Zeroizing};

#[macro_use]
#[deny(unsafe_code)]
mod generators;
#[deny(unsafe_code)]
mod tables;

#[cfg(target_arch = "aarch64")]
#[deny(unsafe_code)]
#[path = "aarch64.rs"]
mod arch;
#[cfg(target_arch = "x86_64")]
#[deny(unsafe_code)]
#[path = "x86_64.rs"]
mod arch;

#[cfg(any(test, all(fuzzing, feature = "std")))]
std::thread_local! {
    /// Set by [`scalar`] for the thread that compares the two paths.
    static SCALAR_ONLY: core::cell::Cell<bool> = const { core::cell::Cell::new(false) };
}

/// Run `work` with the vector paths turned off in this thread, as on a
/// processor without the instructions.
#[cfg(any(test, all(fuzzing, feature = "std")))]
pub(crate) fn scalar<R>(work: impl FnOnce() -> R) -> R {
    let before = SCALAR_ONLY.replace(true);
    let result = work();
    SCALAR_ONLY.set(before);
    result
}

/// What [`available`] found: 0 before it has looked, 1 without the
/// instructions and 2 with them.
static DETECTED: AtomicU8 = AtomicU8::new(0);

/// Whether the processor has the instructions of the vector paths.
#[inline]
pub(crate) fn available() -> bool {
    #[cfg(any(test, all(fuzzing, feature = "std")))]
    if SCALAR_ONLY.get() {
        return false;
    }
    match DETECTED.load(Ordering::Relaxed) {
        0 => detect(),
        found => found == 2,
    }
}

/// Look at the processor, once, and remember what it has.
#[cold]
#[inline(never)]
fn detect() -> bool {
    let detected = arch::detected();
    DETECTED.store(if detected { 2 } else { 1 }, Ordering::Relaxed);
    detected
}

/// SNOW 3G on vector instructions. It exists only on a processor that has
/// them: [`Snow3g::new`] is the one way to make it.
pub(crate) struct Snow3g {
    /// The sixteen stages of the LFSR are `lfsr[at..at + 16]`. Three clocks
    /// write the next three words after them and move `at` by three.
    lfsr: [u32; 32],
    at: usize,
    /// R1, R2 and R3 of the FSM.
    r: [u32; 3],
    /// The keystream words of the last three clocks, and how many of them,
    /// at the end, no call has taken yet.
    ready: [u32; 3],
    pending: usize,
}

impl Snow3g {
    /// The generator from the sixteen stages that the key and the IV give,
    /// or `None` on a processor without the instructions.
    pub(crate) fn new(stages: [u32; 16]) -> Option<Self> {
        if !available() {
            return None;
        }
        // SAFETY: the processor has the instructions that the function is
        // compiled for, which `available` has just seen.
        Some(unsafe { arch::snow3g_new(stages) })
    }

    /// The next keystream words.
    pub(crate) fn fill(&mut self, words: &mut [u32]) {
        // SAFETY: `self` was made by `new`, which found the instructions
        // that the function is compiled for. A processor does not lose
        // them.
        unsafe { arch::snow3g_fill(self, words) }
    }
}

impl Zeroize for Snow3g {
    fn zeroize(&mut self) {
        self.lfsr.zeroize();
        self.at.zeroize();
        self.r.zeroize();
        self.ready.zeroize();
        self.pending.zeroize();
    }
}

/// ZUC on vector instructions. It exists only on a processor that has
/// them: [`Zuc::new`] is the one way to make it.
pub(crate) struct Zuc {
    /// The sixteen stages of the LFSR are `lfsr[at..at + 16]`. A clock
    /// writes the next one after them and moves `at` by one.
    lfsr: [u32; 32],
    at: usize,
    /// R1 and R2 of the nonlinear function.
    r: [u32; 2],
}

impl Zuc {
    /// The generator from the sixteen stages that the key and the IV give,
    /// or `None` on a processor without the instructions.
    pub(crate) fn new(stages: [u32; 16]) -> Option<Self> {
        if !available() {
            return None;
        }
        // SAFETY: the processor has the instructions that the function is
        // compiled for, which `available` has just seen.
        Some(unsafe { arch::zuc_new(stages) })
    }

    /// The next keystream words.
    pub(crate) fn fill(&mut self, words: &mut [u32]) {
        // SAFETY: `self` was made by `new`, which found the instructions
        // that the function is compiled for. A processor does not lose
        // them.
        unsafe { arch::zuc_fill(self, words) }
    }
}

impl Zeroize for Zuc {
    fn zeroize(&mut self) {
        self.lfsr.zeroize();
        self.at.zeroize();
        self.r.zeroize();
    }
}

/// The eleven round keys of AES-128. The first octet of a round key, as of
/// a block, is the low one of the number.
pub(crate) type AesSchedule = [u128; 11];

/// The instructions of the vector code, seen on this processor: what the
/// functions that need them ask for.
#[derive(Clone, Copy)]
pub(crate) struct Instructions(());

impl Instructions {
    /// `None` on a processor without the instructions.
    pub(crate) fn detect() -> Option<Self> {
        available().then_some(Self(()))
    }

    /// 128-EIA3 over whole groups of 32 bits of a message, with the
    /// keystream word that follows each: the tag and the window after
    /// them.
    pub(crate) fn eia3_groups(
        self,
        tag: u32,
        window: u64,
        groups: &[[u8; 4]],
        words: &[u32],
    ) -> (u32, u64) {
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::eia3_groups(tag, window, groups, words) }
    }

    /// The round keys of each key of AES-128. They are wiped with what
    /// holds them.
    pub(crate) fn aes_schedules<const N: usize>(
        self,
        keys: [&[u8; 16]; N],
    ) -> Zeroizing<[AesSchedule; N]> {
        let mut schedules = Zeroizing::new([[0; 11]; N]);
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::aes_schedules(keys, &mut schedules) };
        schedules
    }

    /// Encrypt each block with its round keys.
    pub(crate) fn aes_encrypt<const N: usize>(
        self,
        schedules: [&AesSchedule; N],
        blocks: &mut [u128; N],
    ) {
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::aes_encrypt(schedules, blocks) }
    }

    /// The CBC-MAC of each message with its round keys: its block `first`,
    /// if it has one, the blocks of its `body` and its block `last`.
    pub(crate) fn aes_cbc_mac<const N: usize>(
        self,
        schedules: [&AesSchedule; N],
        first: [Option<u128>; N],
        body: [&[[u8; 16]]; N],
        last: &[u128; N],
    ) -> [u128; N] {
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::aes_cbc_mac(schedules, first, body, last) }
    }

    /// AES in counter mode on one message, whose counter blocks begin
    /// with the eight octets of `prefix` and end with their number.
    pub(crate) fn aes_ctr(self, schedule: &AesSchedule, prefix: u64, data: &mut [u8]) {
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::aes_ctr(schedule, prefix, data) }
    }

    /// 128-EIA1 over the blocks of 64 bits of a message, the last of which
    /// is `last`: their evaluation at P, times P.
    pub(crate) fn eia1_blocks(self, p: u64, blocks: &[[u8; 8]], last: Option<u64>) -> u64 {
        // SAFETY: `self` was made by `detect`, which found the
        // instructions that the function is compiled for.
        unsafe { arch::eia1_blocks(p, blocks, last) }
    }
}

/// The carry-less product of two words, low word then high word, or `None`
/// on a processor without the instruction.
#[inline]
pub(crate) fn carry_less_product(x: u64, y: u64) -> Option<(u64, u64)> {
    if !available() {
        return None;
    }
    // SAFETY: the processor has the instructions that the function is
    // compiled for, which `available` has just seen.
    Some(unsafe { arch::carry_less_product(x, y) })
}

#[cfg(test)]
mod tests {
    use super::{available, scalar};
    use crate::common::ct::{clmul64, clmul128};
    use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm};
    use crate::common::nea::{nea_cipher, nea_cipher_bits};
    use crate::common::nia::{nia_mac, nia_mac_bits};
    use crate::common::snow3g::Snow3G;
    use crate::common::zuc::Zuc;

    /// Numbers that look random, the same at every run.
    fn random(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    fn octets<const N: usize>(next: &mut impl FnMut() -> u64) -> [u8; N] {
        core::array::from_fn(|_| next() as u8)
    }

    /// The tests below compare what the vector instructions give with what
    /// the scalar code gives. On a processor without the instructions both
    /// are the scalar code, and they say so.
    fn vector_path() -> bool {
        if !available() {
            eprintln!("this processor has no vector path: the scalar code is compared with itself");
        }
        available()
    }

    /// The words of both generators, taken in pieces of every length so
    /// that SNOW 3G, which makes three at once, has words left over in
    /// every way.
    #[test]
    fn the_vector_generators_give_the_words_of_the_scalar_ones() {
        vector_path();
        let mut next = random(0x9e37_79b9_7f4a_7c15);
        for round in 0..400 {
            let (key, iv): ([u8; 16], [u8; 16]) = (octets(&mut next), octets(&mut next));
            // A key and an IV of one repeated octet now and then: the
            // S-boxes then see the same octet in every place
            let (key, iv) = match round % 8 {
                6 => ([key[0]; 16], [iv[0]; 16]),
                7 => ([0xff; 16], [0x00; 16]),
                _ => (key, iv),
            };
            let pieces: Vec<usize> = (0..40).map(|_| (next() % 9) as usize).collect();

            let mut vector = Snow3G::from_bytes(&key, &iv);
            let mut reference = scalar(|| Snow3G::from_bytes(&key, &iv));
            for &piece in &pieces {
                let (mut words, mut expected) = (vec![0; piece], vec![0; piece]);
                vector.fill(&mut words);
                reference.fill(&mut expected);
                assert_eq!(words, expected, "SNOW 3G, key {key:02x?}, IV {iv:02x?}");
                assert_eq!(vector.next_word(), reference.next_word());
            }

            let mut vector = Zuc::new(&key, &iv);
            let mut reference = scalar(|| Zuc::new(&key, &iv));
            for &piece in &pieces {
                let (mut words, mut expected) = (vec![0; piece], vec![0; piece]);
                vector.fill(&mut words);
                reference.fill(&mut expected);
                assert_eq!(words, expected, "ZUC, key {key:02x?}, IV {iv:02x?}");
                assert_eq!(vector.next_word(), reference.next_word());
            }
        }
    }

    /// The six algorithms on both paths, on messages of every length up to
    /// 300 octets and of some longer ones, in whole octets and at every
    /// number of bits of the last octet.
    #[test]
    fn the_six_algorithms_give_the_same_on_both_paths() {
        vector_path();
        let mut next = random(0xd1b5_4a32_d192_ed03);
        let lengths = (0..=300).chain([511, 512, 513, 767, 768, 1500, 2999, 3000]);
        for length in lengths {
            let key: [u8; 16] = octets(&mut next);
            let count = next() as u32;
            let bearer = Bearer::new((next() % 32) as u8).unwrap();
            let direction = Direction::try_from((next() % 2) as u8).unwrap();
            let message: Vec<u8> = (0..length).map(|_| next() as u8).collect();
            let bits = (8 * length as u64).saturating_sub(next() % 8);

            for algorithm in [
                CipheringAlgorithm::Snow3g,
                CipheringAlgorithm::Aes,
                CipheringAlgorithm::Zuc,
            ] {
                let (mut data, mut expected) = (message.clone(), message.clone());
                nea_cipher(&key, count, bearer, direction, &mut data, algorithm);
                scalar(|| nea_cipher(&key, count, bearer, direction, &mut expected, algorithm));
                assert_eq!(data, expected, "{algorithm:?}, {length} octets");

                let (mut data, mut expected) = (message.clone(), message.clone());
                nea_cipher_bits(&key, count, bearer, direction, &mut data, bits, algorithm)
                    .unwrap();
                scalar(|| {
                    nea_cipher_bits(
                        &key,
                        count,
                        bearer,
                        direction,
                        &mut expected,
                        bits,
                        algorithm,
                    )
                })
                .unwrap();
                assert_eq!(data, expected, "{algorithm:?}, {bits} bits");
            }

            for algorithm in [
                IntegrityAlgorithm::Snow3g,
                IntegrityAlgorithm::Aes,
                IntegrityAlgorithm::Zuc,
            ] {
                let mac = nia_mac(&key, count, bearer, direction, &message, algorithm);
                let expected =
                    scalar(|| nia_mac(&key, count, bearer, direction, &message, algorithm));
                assert_eq!(mac, expected, "{algorithm:?}, {length} octets");

                let mac = nia_mac_bits(&key, count, bearer, direction, &message, bits, algorithm);
                let expected = scalar(|| {
                    nia_mac_bits(&key, count, bearer, direction, &message, bits, algorithm)
                });
                assert_eq!(mac, expected, "{algorithm:?}, {bits} bits");
            }
        }
    }

    #[test]
    fn the_carry_less_product_is_that_of_the_scalar_code() {
        vector_path();
        let mut next = random(0x2545_f491_4f6c_dd1d);
        let edges = [0, 1, u64::MAX, 1 << 63, 0x8000_0000_0000_0001];
        for round in 0..20_000 {
            let (x, y) = match round {
                0..25 => (edges[round / 5], edges[round % 5]),
                _ => (next(), next()),
            };
            assert_eq!(clmul128(x, y), scalar(|| clmul128(x, y)), "{x:#x} {y:#x}");
            assert_eq!(clmul64(x, y), scalar(|| clmul64(x, y)), "{x:#x} {y:#x}");
        }
    }

    /// The key expansion and the cipher of FIPS 197, Appendices A.1 and
    /// C.1, and several keys side by side against the `aes` crate.
    #[test]
    fn aes_on_the_instructions_is_that_of_fips_197() {
        use aes::Aes128Enc;
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let Some(instructions) = super::Instructions::detect() else {
            eprintln!("this processor has no AES instructions: nothing is compared");
            return;
        };

        let key = 0x2b7e_1516_28ae_d2a6_abf7_1588_09cf_4f3cu128.to_be_bytes();
        let schedules = instructions.aes_schedules([&key]);
        let round_key = |round: usize| u128::from_be_bytes(schedules[0][round].to_le_bytes());
        assert_eq!(round_key(0), u128::from_be_bytes(key));
        assert_eq!(round_key(1), 0xa0fa_fe17_8854_2cb1_23a3_3939_2a6c_7605);
        assert_eq!(round_key(10), 0xd014_f9a8_c9ee_2589_e13f_0cc8_b663_0ca6);

        let key = 0x0001_0203_0405_0607_0809_0a0b_0c0d_0e0fu128.to_be_bytes();
        let plaintext = 0x0011_2233_4455_6677_8899_aabb_ccdd_eeffu128.to_be_bytes();
        let schedules = instructions.aes_schedules([&key]);
        let mut block = [u128::from_le_bytes(plaintext)];
        instructions.aes_encrypt(schedules.each_ref(), &mut block);
        assert_eq!(
            u128::from_be_bytes(block[0].to_le_bytes()),
            0x69c4_e0d8_6a7b_0430_d8cd_b780_70b4_c55a
        );

        let mut next = random(0x510e_527f_ade6_82d1);
        for _ in 0..200 {
            let keys: [[u8; 16]; 8] = core::array::from_fn(|_| octets(&mut next));
            let blocks: [[u8; 16]; 8] = core::array::from_fn(|_| octets(&mut next));
            let schedules = instructions.aes_schedules(keys.each_ref());
            let mut encrypted = blocks.map(u128::from_le_bytes);
            instructions.aes_encrypt(schedules.each_ref(), &mut encrypted);
            for ((key, block), encrypted) in keys.iter().zip(blocks).zip(encrypted) {
                let mut expected = block;
                Aes128Enc::new(key.into()).encrypt_block((&mut expected).into());
                assert_eq!(encrypted.to_le_bytes(), expected, "key {key:02x?}");
            }
        }
    }

    /// `scalar` turns the vector paths off for its closure and for nothing
    /// after it.
    #[test]
    fn scalar_turns_the_vector_paths_off_for_its_closure_alone() {
        let before = available();
        assert!(!scalar(available));
        assert!(!scalar(|| scalar(available) || available()));
        assert_eq!(available(), before);
    }
}
