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

//! ZUC stream cipher (3GPP TS 35.221 / TS 35.222)
//!
//! A word-oriented stream cipher producing 32-bit keystream words.
//! Uses a 16-stage LFSR over GF(2^31-1), bit reorganization, and a nonlinear function.
//!
//! No memory access and no branch depends on the key or on the state, in
//! either of two implementations of the generator.
//!
//! On an x86-64 or AArch64 processor with the AES and vector instructions,
//! which is seen when the program runs, [`Zuc`] computes its S-boxes on
//! those instructions: the module `simd` has that code.
//!
//! Elsewhere it is the scalar code of this module. S0 is three rounds of
//! four-bit S-boxes, each a word that is shifted. S1 is an affine image of
//! the inversion of GF(2^8), as the S-box of AES is, and is computed from
//! one round of AES by the `aes` crate, with a bitsliced routine when the
//! processor has no AES instruction. The reduction modulo 2^31 - 1 has no
//! branch.
//!
//! Compiled-code timing requires target-specific assessment.

use crate::common::ct::{block_to_columns, columns_to_block, linear_map, nibble, nibbles};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd;

// ── Constants ──────────────────────────────────────────────────────────────────

/// 15-bit constants d[i] for LFSR initialization
const D: [u16; 16] = [
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC,
];

const P: u32 = 0x7FFFFFFF; // 2^31 - 1

// ── Modular arithmetic mod 2^31-1 ──────────────────────────────────────────────

/// Reduce modulo 2^31 - 1 a sum of fewer than 2^24 values below 2^31 that
/// is not zero. The result is in [1, 2^31 - 1], with 2^31 - 1 for a
/// multiple of it, as the LFSR wants, and no step branches.
#[inline]
pub(crate) fn mod31(sum: u64) -> u32 {
    const P: u64 = 0x7fff_ffff;
    // 2^31 is 1 modulo 2^31 - 1: a fold adds what is above bit 30 to what
    // is below. The first fold leaves less than 2^31 + 2^24. In the second,
    // what is above bit 30 is at most one, and is added to less than 2^24
    // when it is one: the result is at most 2^31 - 1. A fold of a number
    // that is not zero is not zero.
    let sum = (sum & P) + (sum >> 31);
    ((sum & P) + (sum >> 31)) as u32
}

// ── Linear transforms ──────────────────────────────────────────────────────────

#[inline]
pub(crate) fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

#[inline]
pub(crate) fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

// ── S-boxes ────────────────────────────────────────────────────────────────────

/// The three four-bit S-boxes of S0.
pub(crate) const P1: u64 = nibbles([9, 15, 0, 14, 15, 15, 2, 10, 0, 4, 0, 12, 7, 5, 3, 9]);
pub(crate) const P2: u64 = nibbles([8, 13, 6, 5, 7, 0, 12, 4, 11, 1, 14, 10, 15, 3, 9, 2]);
pub(crate) const P3: u64 = nibbles([2, 6, 10, 6, 0, 13, 10, 15, 3, 3, 13, 5, 0, 9, 12, 13]);

/// S0: three rounds that each add to one half of the octet a four-bit
/// S-box of the other half, then a rotation by five bits. This is how the
/// designers built the table of the specification.
#[inline]
fn s0(x: u8) -> u8 {
    let (high, low) = (x >> 4, x & 0x0f);
    let q1 = high ^ nibble(P1, low);
    let q2 = low ^ nibble(P2, q1);
    let q3 = q1 ^ nibble(P3, q2);
    ((q3 << 4) | q2).rotate_left(5)
}

/// The S-box S1 of ZUC is an affine image of the inversion of GF(2^8)
/// modulo x^8 + x^7 + x^3 + x + 1, and the S-box SR of AES one of the
/// inversion modulo x^8 + x^4 + x^3 + x + 1. The two fields are the same up
/// to a GF(2)-linear map, so S1(x) = OUT(SR(IN(x))) + S1_CONSTANT: `S1_IN`
/// takes the root x of the field of ZUC to the element 0x32 of the field of
/// AES, which is a root of the same polynomial, and `S1_OUT` with
/// `S1_CONSTANT` is the affine map that is left. Each array has the image
/// of the octet with bit `i` alone.
pub(crate) const S1_IN: [u8; 8] = [0x01, 0x32, 0x73, 0x75, 0xd9, 0xe8, 0xcd, 0x2d];
pub(crate) const S1_OUT: [u8; 8] = [0x4f, 0x90, 0x4b, 0x37, 0x34, 0x42, 0x36, 0x66];
pub(crate) const S1_CONSTANT: u8 = 0xfe;

/// The S-boxes on the two words of a clock: S0(x0) || S1(x1) || S0(x2) ||
/// S1(x3) on each.
///
/// The four octets that go through S1 take one round of AES together, each
/// as the low octet of a column of the state of AES, `block`. The first
/// row of the state has the four octets and the others are zero, so that
/// every column is (SR(x), 0x63, 0x63, 0x63) after SubBytes and ShiftRows,
/// and its second row after MixColumns is SR(x) + (2 + 3 + 1) 0x63, which
/// is SR(x).
#[inline]
fn sboxes(a: u32, b: u32, block: &mut [u8; 16]) -> (u32, u32) {
    let [a0, a1, a2, a3] = a.to_be_bytes();
    let [b0, b1, b2, b3] = b.to_be_bytes();

    let inputs = linear_map(u32::from_le_bytes([a1, a3, b1, b3]), &S1_IN);
    *block = columns_to_block(core::array::from_fn(|column| {
        (inputs >> (8 * column)) & 0xff
    }));
    let state: &mut aes::Block = block.into();
    aes::hazmat::cipher_round(state, &aes::Block::default());
    let [c0, c1, c2, c3] = block_to_columns(block).map(|column| (column >> 8) & 0xff);
    let outputs = c0 | (c1 << 8) | (c2 << 16) | (c3 << 24);
    let images = linear_map(outputs, &S1_OUT) ^ (0x0101_0101 * u32::from(S1_CONSTANT));
    let [a1, a3, b1, b3] = images.to_le_bytes();

    (
        u32::from_be_bytes([s0(a0), a1, s0(a2), a3]),
        u32::from_be_bytes([s0(b0), b1, s0(b2), b3]),
    )
}

// ── ZUC state ──────────────────────────────────────────────────────────────────

/// ZUC keystream generator: the LFSR and the two registers of the nonlinear
/// function, initialized with a key and an IV. The state is wiped on drop.
pub struct Zuc(Generator);

/// The generator on the vector instructions of the processor when it has
/// them, and the scalar one otherwise. They give the same words.
enum Generator {
    Scalar(Scalar),
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Vector(simd::Zuc),
}

impl zeroize::Zeroize for Zuc {
    fn zeroize(&mut self) {
        match &mut self.0 {
            Generator::Scalar(scalar) => scalar.zeroize(),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Generator::Vector(vector) => vector.zeroize(),
        }
    }
}

impl Drop for Zuc {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for Zuc {}

/// The sixteen stages that a key and an IV give: s[i] = k[i] || d[i] ||
/// iv[i], of 8, 15 and 8 bits.
pub(crate) fn load(key: &[u8; 16], iv: &[u8; 16]) -> [u32; 16] {
    core::array::from_fn(|i| (u32::from(key[i]) << 23) | (u32::from(D[i]) << 8) | u32::from(iv[i]))
}

impl Zuc {
    /// Initialize ZUC with 128-bit key and 128-bit IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut stages = load(key, iv);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if let Some(vector) = simd::Zuc::new(stages) {
            zeroize::Zeroize::zeroize(&mut stages);
            return Self(Generator::Vector(vector));
        }
        let scalar = Scalar::new(stages);
        zeroize::Zeroize::zeroize(&mut stages);
        Self(Generator::Scalar(scalar))
    }

    /// The next keystream word.
    pub fn next_word(&mut self) -> u32 {
        let mut word = [0];
        self.fill(&mut word);
        word[0]
    }

    /// Fill `words` with the next keystream words.
    pub fn fill(&mut self, words: &mut [u32]) {
        match &mut self.0 {
            Generator::Scalar(scalar) => scalar.fill(words),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Generator::Vector(vector) => vector.fill(words),
        }
    }
}

/// The generator in scalar code: the reference of the vector one, and what
/// runs where the processor has no instruction for it.
struct Scalar {
    /// The sixteen 31-bit stages, in a ring: stage `i` is at `head + i`
    /// modulo 16.
    s: [u32; 16],
    /// Where stage 0 is. A clock writes the new stage 15 over it and moves
    /// it by one, in place of moving fifteen stages.
    head: usize,
    r1: u32,
    r2: u32,
    started: bool,
    /// The AES state that the S-boxes work in. It is part of the generator
    /// so that it is wiped with it, and not at every clock.
    block: [u8; 16],
}

impl zeroize::Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.s.zeroize();
        self.head.zeroize();
        self.r1.zeroize();
        self.r2.zeroize();
        self.started.zeroize();
        self.block.zeroize();
    }
}

impl Scalar {
    /// The generator from its sixteen stages after the key and the IV are
    /// loaded, after the 32 clocks of the initialization.
    fn new(s: [u32; 16]) -> Self {
        let mut z = Self {
            s,
            head: 0,
            r1: 0,
            r2: 0,
            started: false,
            block: [0; 16],
        };
        for _ in 0..32 {
            let (x0, x1, x2, x3) = z.bit_reorg();
            let w = z.f(x0, x1, x2, x3);
            z.lfsr_init(w >> 1);
        }
        z
    }

    /// The next keystream word.
    fn next_word(&mut self) -> u32 {
        if !self.started {
            // TS 35.222 discards one word after initialization, once per state.
            let (x0, x1, x2, x3) = self.bit_reorg();
            let _ = self.f(x0, x1, x2, x3);
            self.lfsr_keystream();
            self.started = true;
        }
        let (x0, x1, x2, x3) = self.bit_reorg();
        let word = self.f(x0, x1, x2, x3) ^ x3;
        self.lfsr_keystream();
        word
    }

    /// Fill `words` with the next keystream words.
    fn fill(&mut self, words: &mut [u32]) {
        for word in words {
            *word = self.next_word();
        }
    }

    /// Stage `index` of the LFSR, s0 to s15.
    #[inline]
    fn stage(&self, index: usize) -> u32 {
        self.s[(self.head + index) & 15]
    }

    /// Shift the LFSR by one stage: `v` is the new s15.
    #[inline]
    fn shift(&mut self, v: u32) {
        self.s[self.head] = v;
        self.head = (self.head + 1) & 15;
    }

    /// The feedback of the LFSR before reduction: the stages of the
    /// feedback polynomial, each multiplied by its power of two
    /// (2^15 s15 + 2^17 s13 + 2^21 s10 + 2^20 s4 + (1 + 2^8) s0).
    #[inline]
    fn feedback(&self) -> u64 {
        let stage = |index: usize, shift: u32| u64::from(self.stage(index)) << shift;
        stage(15, 15) + stage(13, 17) + stage(10, 21) + stage(4, 20) + stage(0, 8) + stage(0, 0)
    }

    /// Bit Reorganization: extract X0..X3 from LFSR stages.
    #[inline]
    fn bit_reorg(&self) -> (u32, u32, u32, u32) {
        let x0 = ((self.stage(15) & 0x7FFF8000) << 1) | (self.stage(14) & 0xFFFF);
        let x1 = ((self.stage(11) & 0xFFFF) << 16) | (self.stage(9) >> 15);
        let x2 = ((self.stage(7) & 0xFFFF) << 16) | (self.stage(5) >> 15);
        let x3 = ((self.stage(2) & 0xFFFF) << 16) | (self.stage(0) >> 15);
        (x0, x1, x2, x3)
    }

    /// Nonlinear function F.
    #[inline]
    fn f(&mut self, x0: u32, x1: u32, x2: u32, x3: u32) -> u32 {
        let w = (x0 ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(x1);
        let w2 = self.r2 ^ x2;

        // Swap halves
        let u = (w1 << 16) | (w2 >> 16);
        let v = (w2 << 16) | (w1 >> 16);

        (self.r1, self.r2) = sboxes(l1(u), l2(v), &mut self.block);

        let _ = x3; // x3 used by caller for keystream output
        w
    }

    /// LFSR clock during initialization (feedback includes W).
    #[inline]
    fn lfsr_init(&mut self, w: u32) {
        let v = mod31(self.feedback() + u64::from(w & P));
        self.shift(v);
    }

    /// LFSR clock during keystream generation.
    #[inline]
    fn lfsr_keystream(&mut self) {
        let v = mod31(self.feedback());
        self.shift(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── S-boxes ────────────────────────────────────────────────────────────────────

    const S0: [u8; 256] = [
        0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D,
        0xCB, 0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53,
        0x03, 0x90, 0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B,
        0x29, 0x6E, 0xAC, 0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39,
        0x63, 0x20, 0xD4, 0x38, 0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB,
        0x14, 0x21, 0x06, 0x55, 0x9B, 0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82,
        0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C, 0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C,
        0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD, 0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A,
        0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8, 0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13,
        0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56, 0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B,
        0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE, 0xBC, 0x26, 0x95, 0x88, 0x8A,
        0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D, 0xD0, 0xDC, 0x11, 0x66,
        0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23, 0x0E, 0x86, 0xAB,
        0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1, 0xF6, 0xFA,
        0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F, 0x8E,
        0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
        0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34,
        0x60,
    ];

    const S1: [u8; 256] = [
        0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD,
        0x77, 0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9,
        0xF8, 0x42, 0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B,
        0x39, 0x43, 0xE1, 0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC,
        0x0B, 0xFA, 0x62, 0x48, 0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52,
        0xBB, 0x69, 0xF5, 0xD4, 0x87, 0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A,
        0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB, 0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23,
        0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09, 0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E,
        0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9, 0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC,
        0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9, 0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83,
        0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89, 0x01, 0xB6, 0xBD, 0x58, 0x24,
        0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4, 0xD0, 0x91, 0xC7, 0xCE,
        0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE, 0xA3, 0xEF, 0xEA,
        0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21, 0x5A, 0x6A,
        0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34, 0x88,
        0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
        0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2,
        0xF2,
    ];

    /// Values that look random, the same at every run.
    fn random() -> impl Iterator<Item = u32> {
        let mut x = 0x9e37_79b9u32;
        core::iter::repeat_with(move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        })
    }

    /// The S-boxes are the tables of the specification, on every octet.
    #[test]
    fn s0_and_s1_are_the_tables_of_the_specification() {
        let mut block = [0xa5; 16];
        for octet in 0..=u8::MAX {
            assert_eq!(s0(octet), S0[usize::from(octet)], "S0 {octet:#04x}");
            // Each of the four places that an octet goes through S1 from
            let word = 0x0101_0101 * u32::from(octet);
            let (a, b) = sboxes(word, !word, &mut block);
            let (s0_x, s1_x) = (S0[usize::from(octet)], S1[usize::from(octet)]);
            let (s0_n, s1_n) = (S0[usize::from(!octet)], S1[usize::from(!octet)]);
            assert_eq!(
                a,
                u32::from_be_bytes([s0_x, s1_x, s0_x, s1_x]),
                "{octet:#04x}"
            );
            assert_eq!(
                b,
                u32::from_be_bytes([s0_n, s1_n, s0_n, s1_n]),
                "{octet:#04x}"
            );
        }
        let table = |x: u32| {
            let [x0, x1, x2, x3] = x.to_be_bytes().map(usize::from);
            u32::from_be_bytes([S0[x0], S1[x1], S0[x2], S1[x3]])
        };
        let mut words = random();
        for _ in 0..100_000 {
            let (a, b) = (words.next().unwrap(), words.next().unwrap());
            assert_eq!(sboxes(a, b, &mut block), (table(a), table(b)));
        }
    }

    /// The feedback of the LFSR, reduced once, is the chain of additions
    /// modulo 2^31 - 1 that TS 35.222 writes, on states that look random
    /// and on those whose sum is a multiple of the modulus.
    #[test]
    fn the_feedback_is_the_sum_modulo_the_mersenne_prime() {
        /// v = a + b mod (2^31 - 1), as the specification adds.
        fn add(a: u32, b: u32) -> u32 {
            let c = a.wrapping_add(b);
            (c & P) + (c >> 31)
        }
        /// 2^n a mod (2^31 - 1): a rotation of the 31 bits.
        fn rot31(a: u32, n: u32) -> u32 {
            ((a << n) | (a >> (31 - n))) & P
        }
        let reference = |s: &[u32; 16], w: u32| {
            let mut v = rot31(s[15], 15);
            v = add(v, rot31(s[13], 17));
            v = add(v, rot31(s[10], 21));
            v = add(v, rot31(s[4], 20));
            v = add(v, rot31(s[0], 8));
            v = add(v, s[0]);
            v = add(v, w);
            if v == 0 { P } else { v }
        };
        let mut values = random();
        let mut stage = move || 1 + values.next().unwrap() % P;
        let mut zuc = Scalar::new([1; 16]);
        for round in 0..200_000 {
            let mut s: [u32; 16] = core::array::from_fn(|_| stage());
            let w = match round % 4 {
                0 => 0,
                1 => P,
                _ => stage() - 1,
            };
            if round % 8 == 7 {
                // Every stage at its largest: the largest sum there is
                s = [P; 16];
            }
            // The stages in the ring, from each place that stage 0 can be
            zuc.head = round % 16;
            for (index, stage) in s.iter().enumerate() {
                zuc.s[(zuc.head + index) & 15] = *stage;
            }
            let v = mod31(zuc.feedback() + u64::from(w));
            assert!((1..=P).contains(&v));
            assert_eq!(v, reference(&s, w), "{s:x?} {w:#x}");
        }
        // A sum that is the modulus, and twice it, is the modulus: not zero
        assert_eq!(mod31(u64::from(P)), P);
        assert_eq!(mod31(2 * u64::from(P)), P);
        assert_eq!(mod31(1 << 31), 1);
        assert_eq!(
            mod31((1 << 55) - 1),
            mod31(((1u64 << 55) - 1) % u64::from(P))
        );
    }

    #[test]
    fn split_fill_matches_single_call() {
        let key = [0x23; 16];
        let iv = [0x42; 16];
        let mut one = Zuc::new(&key, &iv);
        let mut split = Zuc::new(&key, &iv);
        let mut expected = [0; 8];
        one.fill(&mut expected);
        let mut actual = [0; 8];
        let (first, second) = actual.split_at_mut(3);
        split.fill(first);
        split.fill(second);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_zuc_test_vector_1() {
        // ZUC 1.6 (TS 35.221): all-zero key and IV
        // Note: ZUC 1.4 produced 0x27BEAD9D; ZUC 1.6 produces 0x27BEDE74
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut z = Zuc::new(&key, &iv);
        let mut ks = [0; 2];
        z.fill(&mut ks);
        assert_eq!(ks[0], 0x27BE_DE74);
        assert_eq!(ks[1], 0x0180_82DA);
    }

    #[test]
    fn test_zuc_test_vector_2() {
        // 3GPP TS 35.221 Test Set 2: all-FF key and IV
        let key = [0xFFu8; 16];
        let iv = [0xFFu8; 16];
        let mut z = Zuc::new(&key, &iv);
        let mut ks = [0; 2];
        z.fill(&mut ks);
        assert_eq!(ks[0], 0x0657_CFA0);
        assert_eq!(ks[1], 0x7096_398B);
    }

    #[test]
    fn test_zuc_test_vector_3() {
        // 3GPP TS 35.221 Test Set 3
        let key: [u8; 16] = [
            0x3D, 0x4C, 0x4B, 0xE9, 0x6A, 0x82, 0xFD, 0xAE, 0xB5, 0x8F, 0x64, 0x1D, 0xB1, 0x7B,
            0x45, 0x5B,
        ];
        let iv: [u8; 16] = [
            0x84, 0x31, 0x9A, 0xA8, 0xDE, 0x69, 0x15, 0xCA, 0x1F, 0x6B, 0xDA, 0x6B, 0xFB, 0xD8,
            0xC7, 0x66,
        ];
        let mut z = Zuc::new(&key, &iv);
        let mut ks = [0; 2];
        z.fill(&mut ks);
        assert_eq!(ks[0], 0x14F1_C272);
        assert_eq!(ks[1], 0x3279_C419);
    }
}
