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

//! SNOW 3G stream cipher (ETSI/3GPP TS 35.215 / TS 35.216)
//!
//! A word-oriented stream cipher producing 32-bit keystream words.
//! Uses a 16-stage LFSR over GF(2^32) and a 3-register FSM with two S-boxes.
//!
//! No memory access and no branch depends on the key or on the state, in
//! either of two implementations of the generator.
//!
//! On an x86-64 or AArch64 processor with the AES and vector instructions,
//! which is seen when the program runs, [`Snow3G`] clocks three times at
//! once on those instructions: the module `simd` has that code.
//!
//! Elsewhere it is the scalar code of this module. S1 is one round of AES
//! on a column, which the `aes` crate computes with a bitsliced routine
//! when the processor has no AES instruction. The S-box SQ of S2 is read
//! whole and narrowed down through masks. MULα and DIVα multiply by
//! constants of GF(2^8), bit by bit of the constants.
//!
//! Compiled-code timing requires target-specific assessment.

use crate::common::ct::{Table, block_to_columns, columns_to_block};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd;

// ── SQ S-box used by S2 (TS 35.216) ───────────────────────────────────────────

pub(crate) const SQ_OCTETS: [u8; 256] = [
    0x25, 0x24, 0x73, 0x67, 0xD7, 0xAE, 0x5C, 0x30, 0xA4, 0xEE, 0x6E, 0xCB, 0x7D, 0xB5, 0x82, 0xDB,
    0xE4, 0x8E, 0x48, 0x49, 0x4F, 0x5D, 0x6A, 0x78, 0x70, 0x88, 0xE8, 0x5F, 0x5E, 0x84, 0x65, 0xE2,
    0xD8, 0xE9, 0xCC, 0xED, 0x40, 0x2F, 0x11, 0x28, 0x57, 0xD2, 0xAC, 0xE3, 0x4A, 0x15, 0x1B, 0xB9,
    0xB2, 0x80, 0x85, 0xA6, 0x2E, 0x02, 0x47, 0x29, 0x07, 0x4B, 0x0E, 0xC1, 0x51, 0xAA, 0x89, 0xD4,
    0xCA, 0x01, 0x46, 0xB3, 0xEF, 0xDD, 0x44, 0x7B, 0xC2, 0x7F, 0xBE, 0xC3, 0x9F, 0x20, 0x4C, 0x64,
    0x83, 0xA2, 0x68, 0x42, 0x13, 0xB4, 0x41, 0xCD, 0xBA, 0xC6, 0xBB, 0x6D, 0x4D, 0x71, 0x21, 0xF4,
    0x8D, 0xB0, 0xE5, 0x93, 0xFE, 0x8F, 0xE6, 0xCF, 0x43, 0x45, 0x31, 0x22, 0x37, 0x36, 0x96, 0xFA,
    0xBC, 0x0F, 0x08, 0x52, 0x1D, 0x55, 0x1A, 0xC5, 0x4E, 0x23, 0x69, 0x7A, 0x92, 0xFF, 0x5B, 0x5A,
    0xEB, 0x9A, 0x1C, 0xA9, 0xD1, 0x7E, 0x0D, 0xFC, 0x50, 0x8A, 0xB6, 0x62, 0xF5, 0x0A, 0xF8, 0xDC,
    0x03, 0x3C, 0x0C, 0x39, 0xF1, 0xB8, 0xF3, 0x3D, 0xF2, 0xD5, 0x97, 0x66, 0x81, 0x32, 0xA0, 0x00,
    0x06, 0xCE, 0xF6, 0xEA, 0xB7, 0x17, 0xF7, 0x8C, 0x79, 0xD6, 0xA7, 0xBF, 0x8B, 0x3F, 0x1F, 0x53,
    0x63, 0x75, 0x35, 0x2C, 0x60, 0xFD, 0x27, 0xD3, 0x94, 0xA5, 0x7C, 0xA1, 0x05, 0x58, 0x2D, 0xBD,
    0xD9, 0xC7, 0xAF, 0x6B, 0x54, 0x0B, 0xE0, 0x38, 0x04, 0xC8, 0x9D, 0xE7, 0x14, 0xB1, 0x87, 0x9C,
    0xDF, 0x6F, 0xF9, 0xDA, 0x2A, 0xC4, 0x59, 0x16, 0x74, 0x91, 0xAB, 0x26, 0x61, 0x76, 0x34, 0x2B,
    0xAD, 0x99, 0xFB, 0x72, 0xEC, 0x33, 0x12, 0xDE, 0x98, 0x3B, 0xC0, 0x9B, 0x3E, 0x18, 0x10, 0x3A,
    0x56, 0xE1, 0x77, 0xC9, 0x1E, 0x9E, 0x95, 0xA3, 0x90, 0x19, 0xA8, 0x6C, 0x09, 0xD0, 0xF0, 0x86,
];

// ── GF(2^8) multiplication ─────────────────────────────────────────────────────

/// MULx: multiply by x in GF(2^8) with reduction polynomial c, without a
/// branch on the secret top bit.
#[inline]
const fn mulx(v: u8, c: u8) -> u8 {
    (v << 1) ^ (c & 0u8.wrapping_sub(v >> 7))
}

/// MULxPOW: multiply by x^i in GF(2^8) with reduction polynomial c
const fn mulxpow(v: u8, i: u32, c: u8) -> u8 {
    let mut r = v;
    let mut step = 0;
    while step < i {
        r = mulx(r, c);
        step += 1;
    }
    r
}

/// SQ, laid out for a read that does not depend on the index.
static SQ: Table = Table::new(&SQ_OCTETS);

// ── LFSR feedback helpers ──────────────────────────────────────────────────────

/// MULα as defined with MULxPOW (reduction polynomial 0xa9 for the outer
/// field: x^8 + x^7 + x^5 + x^3 + 1).
pub(crate) const fn mul_alpha_value(c: u8) -> u32 {
    ((mulxpow(c, 23, 0xa9) as u32) << 24)
        | ((mulxpow(c, 245, 0xa9) as u32) << 16)
        | ((mulxpow(c, 48, 0xa9) as u32) << 8)
        | (mulxpow(c, 239, 0xa9) as u32)
}

/// DIVα as defined with MULxPOW.
pub(crate) const fn div_alpha_value(c: u8) -> u32 {
    ((mulxpow(c, 16, 0xa9) as u32) << 24)
        | ((mulxpow(c, 39, 0xa9) as u32) << 16)
        | ((mulxpow(c, 6, 0xa9) as u32) << 8)
        | (mulxpow(c, 64, 0xa9) as u32)
}

/// For each bit of the eight constants that MULα and DIVα multiply by, the
/// octets of the two words whose constant has the bit: MULα in the low
/// word, DIVα in the high one.
///
/// MULα(c) is c times four constants of GF(2^8), one in each octet, and so
/// is DIVα(c). The constants are the octets of MULα(1) and DIVα(1).
const ALPHA_BITS: [u64; 8] = {
    let constants = (mul_alpha_value(1) as u64) | ((div_alpha_value(1) as u64) << 32);
    let mut bits = [0; 8];
    let mut bit = 0;
    while bit < 8 {
        bits[bit] = ((constants >> bit) & 0x0101_0101_0101_0101) * 0xff;
        bit += 1;
    }
    bits
};

/// MULα of one octet and DIVα of another (TS 35.216): each multiplies its
/// octet by α, or by its inverse, in the feedback polynomial of the LFSR.
///
/// The eight products go together, each in an octet of a word: the octets
/// start as the multiplicand, are multiplied by x at each step, and are
/// added where the constant has the bit of the step. Nothing is selected by
/// a bit of the multiplicands.
#[inline]
fn mul_div_alpha(mul: u8, div: u8) -> (u32, u32) {
    let mut octets = (u64::from(mul) * 0x0101_0101) | ((u64::from(div) * 0x0101_0101) << 32);
    let mut products = 0;
    for bit in ALPHA_BITS {
        products ^= octets & bit;
        // Times x: the low seven bits of each octet move up, and x^8 is
        // x^7 + x^5 + x^3 + 1, which the top bit multiplies
        octets = ((octets & 0x7f7f_7f7f_7f7f_7f7f) << 1)
            ^ (((octets >> 7) & 0x0101_0101_0101_0101) * 0xa9);
    }
    (products as u32, (products >> 32) as u32)
}

// ── 32-bit S-boxes ─────────────────────────────────────────────────────────────

/// S1: the Rijndael S-box SR on each octet, then MixColumn over the field
/// of AES (TS 35.216).
///
/// That is the round of AES on one column, without a key. With
/// `w = w0 || w1 || w2 || w3`, SNOW 3G's matrix is that of AES on the
/// column `(w3, w2, w1, w0)`, with the result in that order too. ShiftRows
/// gathers in the first column the octets 0, 5, 10 and 15 of the state of
/// AES: octet `i` of column `i`, which is octet `i` of `w` counted from the
/// low one. `block` is that state.
#[inline]
fn s1(w: u32, block: &mut [u8; 16]) -> u32 {
    *block = columns_to_block(core::array::from_fn(|column| w & (0xff << (8 * column))));
    let state: &mut aes::Block = block.into();
    aes::hazmat::cipher_round(state, &aes::Block::default());
    block_to_columns(block)[0]
}

/// S2: the S-box SQ on each octet, then MixColumn over GF(2^8) with
/// x^8 + x^6 + x^5 + x^3 + 1 (TS 35.216).
///
/// The four octets stay in one word. With r the word after SQ and 2r each
/// of its octets multiplied by x, octet i of the result is
/// 2 r[i] + 3 r[i - 1] + r[i + 1] + r[i + 2], the indices modulo four from
/// the most significant octet: SNOW 3G's matrix [2,1,1,3; 3,2,1,1; 1,3,2,1;
/// 1,1,3,2].
#[inline]
fn s2(w: u32) -> u32 {
    let r = u32::from_be_bytes(SQ.get4(w.to_be_bytes()));
    // Each octet times x: the low seven bits move up, and x^8 is
    // x^6 + x^5 + x^3 + 1, which the top bit of the octet multiplies
    let doubled = ((r & 0x7f7f_7f7f) << 1) ^ (((r >> 7) & 0x0101_0101) * 0x69);
    doubled ^ (doubled ^ r).rotate_right(8) ^ r.rotate_left(8) ^ r.rotate_left(16)
}

// ── SNOW 3G state ──────────────────────────────────────────────────────────────

/// SNOW 3G keystream generator: the LFSR and the FSM registers, initialized
/// with a key and an IV. The state is wiped on drop.
pub struct Snow3G(Generator);

/// The generator on the vector instructions of the processor when it has
/// them, and the scalar one otherwise. They give the same words.
enum Generator {
    Scalar(Scalar),
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Vector(simd::Snow3g),
}

impl zeroize::Zeroize for Snow3G {
    fn zeroize(&mut self) {
        match &mut self.0 {
            Generator::Scalar(scalar) => scalar.zeroize(),
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Generator::Vector(vector) => vector.zeroize(),
        }
    }
}

impl Drop for Snow3G {
    fn drop(&mut self) {
        zeroize::Zeroize::zeroize(self);
    }
}

impl zeroize::ZeroizeOnDrop for Snow3G {}

impl Snow3G {
    /// Initialize SNOW 3G with key and IV as 4 u32 words each.
    ///
    /// Key and IV words follow their big-endian order in the SNOW 3G core
    /// specification. EEA1/EIA1 wrappers apply their own key mapping.
    pub fn new(mut k: [u32; 4], iv: [u32; 4]) -> Self {
        let mut stages = load(&k, &iv);
        zeroize::Zeroize::zeroize(&mut k);
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        if let Some(vector) = simd::Snow3g::new(stages) {
            zeroize::Zeroize::zeroize(&mut stages);
            return Self(Generator::Vector(vector));
        }
        let scalar = Scalar::new(stages);
        zeroize::Zeroize::zeroize(&mut stages);
        Self(Generator::Scalar(scalar))
    }

    /// Initialize from 128-bit key and IV byte slices.
    ///
    /// The key and IV are four consecutive big-endian words, as in the
    /// SNOW 3G core specification. EEA1/EIA1 mode code handles its own key mapping.
    pub fn from_bytes(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let (key, _) = key.as_chunks::<4>();
        let (iv, _) = iv.as_chunks::<4>();
        let k = zeroize::Zeroizing::new([
            u32::from_be_bytes(key[0]),
            u32::from_be_bytes(key[1]),
            u32::from_be_bytes(key[2]),
            u32::from_be_bytes(key[3]),
        ]);
        let v = [
            u32::from_be_bytes(iv[0]),
            u32::from_be_bytes(iv[1]),
            u32::from_be_bytes(iv[2]),
            u32::from_be_bytes(iv[3]),
        ];
        Self::new(*k, v)
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

/// The sixteen stages of the LFSR that a key and an IV give (TS 35.216).
pub(crate) fn load(k: &[u32; 4], iv: &[u32; 4]) -> [u32; 16] {
    let n = |word: u32| word ^ 0xFFFF_FFFF;
    [
        n(k[0]),
        n(k[1]),
        n(k[2]),
        n(k[3]),
        k[0],
        k[1],
        k[2],
        k[3],
        n(k[0]),
        n(k[1]) ^ iv[3],
        n(k[2]) ^ iv[2],
        n(k[3]),
        k[0] ^ iv[1],
        k[1],
        k[2],
        k[3] ^ iv[0],
    ]
}

/// The generator in scalar code: the reference of the vector one, and what
/// runs where the processor has no instruction for it.
struct Scalar {
    /// The sixteen stages, in a ring: stage `i` is at `head + i` modulo 16.
    lfsr: [u32; 16],
    /// Where stage 0 is. A clock writes the new stage 15 over it and moves
    /// it by one, in place of moving fifteen stages.
    head: usize,
    r1: u32,
    r2: u32,
    r3: u32,
    started: bool,
    /// The AES state that S1 works in. It is part of the generator so that
    /// it is wiped with it, and not at every clock.
    block: [u8; 16],
}

impl zeroize::Zeroize for Scalar {
    fn zeroize(&mut self) {
        self.lfsr.zeroize();
        self.head.zeroize();
        self.r1.zeroize();
        self.r2.zeroize();
        self.r3.zeroize();
        self.started.zeroize();
        self.block.zeroize();
    }
}

impl Scalar {
    /// The generator from the stages that [`load`] gives, after the 32
    /// clocks of the initialization.
    fn new(lfsr: [u32; 16]) -> Self {
        let mut s = Self {
            lfsr,
            head: 0,
            r1: 0,
            r2: 0,
            r3: 0,
            started: false,
            block: [0; 16],
        };
        for _ in 0..32 {
            let f = s.clock_fsm();
            s.clock_lfsr_init(f);
        }
        s
    }

    /// The next keystream word.
    fn next_word(&mut self) -> u32 {
        if !self.started {
            // TS 35.216 discards one word after initialization, once per state.
            let _ = self.clock_fsm();
            self.clock_lfsr_keystream();
            self.started = true;
        }
        let word = self.clock_fsm() ^ self.stage(0);
        self.clock_lfsr_keystream();
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
        self.lfsr[(self.head + index) & 15]
    }

    /// Shift the LFSR by one stage: `v` is the new s15.
    #[inline]
    fn shift(&mut self, v: u32) {
        self.lfsr[self.head] = v;
        self.head = (self.head + 1) & 15;
    }

    /// The feedback of the LFSR without the FSM word:
    /// α s0 + s2 + α^-1 s11.
    #[inline]
    fn feedback(&self) -> u32 {
        let (s0, s11) = (self.stage(0), self.stage(11));
        let (mul_alpha, div_alpha) = mul_div_alpha((s0 >> 24) as u8, s11 as u8);
        (s0 << 8) ^ mul_alpha ^ self.stage(2) ^ (s11 >> 8) ^ div_alpha
    }

    /// Clock the FSM, return F.
    #[inline]
    fn clock_fsm(&mut self) -> u32 {
        let f = (self.stage(15).wrapping_add(self.r1)) ^ self.r2;
        let r = self.r2.wrapping_add(self.r3 ^ self.stage(5));
        self.r3 = s2(self.r2);
        self.r2 = s1(self.r1, &mut self.block);
        self.r1 = r;
        f
    }

    /// LFSR clock during initialization (feedback includes FSM output F).
    #[inline]
    fn clock_lfsr_init(&mut self, f: u32) {
        let v = self.feedback() ^ f;
        self.shift(v);
    }

    /// LFSR clock during keystream generation (no FSM feedback).
    #[inline]
    fn clock_lfsr_keystream(&mut self) {
        let v = self.feedback();
        self.shift(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── AES S-box (SR) used by S1 ──────────────────────────────────────────────────

    const SR: [u8; 256] = [
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB,
        0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
        0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71,
        0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
        0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6,
        0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
        0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45,
        0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
        0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44,
        0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
        0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49,
        0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
        0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
        0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1,
        0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB,
        0x16,
    ];

    /// Words that look random, the same at every run.
    fn words() -> impl Iterator<Item = u32> {
        let mut state = 0x9e37_79b9u32;
        core::iter::repeat_with(move || {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            state
        })
    }

    /// S1 as TS 35.216 writes it: SR from its table, then the matrix.
    fn s1_of_the_specification(w: u32) -> u32 {
        let [r0, r1, r2, r3] = w.to_be_bytes().map(|octet| SR[usize::from(octet)]);
        let o0 = mulx(r0, 0x1B) ^ r1 ^ r2 ^ (mulx(r3, 0x1B) ^ r3);
        let o1 = (mulx(r0, 0x1B) ^ r0) ^ mulx(r1, 0x1B) ^ r2 ^ r3;
        let o2 = r0 ^ (mulx(r1, 0x1B) ^ r1) ^ mulx(r2, 0x1B) ^ r3;
        let o3 = r0 ^ r1 ^ (mulx(r2, 0x1B) ^ r2) ^ mulx(r3, 0x1B);
        u32::from_be_bytes([o0, o1, o2, o3])
    }

    /// S2 as TS 35.216 writes it: SQ from its table, then the matrix.
    fn s2_of_the_specification(w: u32) -> u32 {
        let [r0, r1, r2, r3] = w.to_be_bytes().map(|octet| SQ_OCTETS[usize::from(octet)]);
        let o0 = mulx(r0, 0x69) ^ r1 ^ r2 ^ (mulx(r3, 0x69) ^ r3);
        let o1 = (mulx(r0, 0x69) ^ r0) ^ mulx(r1, 0x69) ^ r2 ^ r3;
        let o2 = r0 ^ (mulx(r1, 0x69) ^ r1) ^ mulx(r2, 0x69) ^ r3;
        let o3 = r0 ^ r1 ^ (mulx(r2, 0x69) ^ r2) ^ mulx(r3, 0x69);
        u32::from_be_bytes([o0, o1, o2, o3])
    }

    /// The round of AES on a column is S1, and the narrowed table is SQ: on
    /// every value of each octet with the others at two settings, and on
    /// words that look random.
    #[test]
    fn s1_and_s2_are_those_of_the_specification() {
        let mut block = [0xa5; 16];
        let each_octet = (0..4).flat_map(|position| {
            (0..=255u32).flat_map(move |octet| {
                [0u32, 0xffff_ffff]
                    .map(|others| (others & !(0xff << (8 * position))) | (octet << (8 * position)))
            })
        });
        for w in each_octet.chain(words().take(200_000)) {
            assert_eq!(
                s1(w, &mut block),
                s1_of_the_specification(w),
                "S1 {w:#010x}"
            );
            assert_eq!(s2(w), s2_of_the_specification(w), "S2 {w:#010x}");
        }
    }

    /// MULα and DIVα are the MULxPOW of TS 35.216 on every pair of octets.
    #[test]
    fn mul_alpha_and_div_alpha_are_those_of_the_specification() {
        for mul in 0..=u8::MAX {
            for div in 0..=u8::MAX {
                assert_eq!(
                    mul_div_alpha(mul, div),
                    (mul_alpha_value(mul), div_alpha_value(div)),
                    "{mul:#04x} {div:#04x}"
                );
            }
        }
        // The four powers of x of each, modulo x^8 + x^7 + x^5 + x^3 + 1
        assert_eq!(mul_div_alpha(0x01, 0x01), (0xe19f_cf13, 0x180f_40cd));
    }

    #[test]
    fn split_fill_matches_single_call() {
        let key = [0x23; 16];
        let iv = [0x42; 16];
        let mut one = Snow3G::from_bytes(&key, &iv);
        let mut split = Snow3G::from_bytes(&key, &iv);
        let mut expected = [0; 8];
        one.fill(&mut expected);
        let mut actual = [0; 8];
        let (first, second) = actual.split_at_mut(3);
        split.fill(first);
        split.fill(second);
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_snow3g_deterministic() {
        // Verify that SNOW 3G produces deterministic output and two instances
        // with the same key/IV produce the same keystream.
        let key: [u8; 16] = [
            0x2B, 0xD6, 0x45, 0x9F, 0x82, 0xC5, 0xB3, 0x00, 0x95, 0x2C, 0x49, 0x10, 0x48, 0x81,
            0xFF, 0x48,
        ];
        let iv: [u8; 16] = [
            0x72, 0xA4, 0xF2, 0x0F, 0x64, 0x00, 0x00, 0x00, 0x72, 0xA4, 0xF2, 0x0F, 0x64, 0x00,
            0x00, 0x00,
        ];
        let mut s1 = Snow3G::from_bytes(&key, &iv);
        let mut s2 = Snow3G::from_bytes(&key, &iv);
        let mut ks1 = [0; 4];
        s1.fill(&mut ks1);
        let mut ks2 = [0; 4];
        s2.fill(&mut ks2);
        assert_eq!(ks1, ks2);
        // Keystream should not be trivially zero
        assert!(ks1.iter().any(|&w| w != 0));
    }

    #[test]
    fn test_snow3g_different_iv_different_output() {
        let key = [0xAAu8; 16];
        let iv1 = [0u8; 16];
        let mut iv2 = [0u8; 16];
        iv2[0] = 1;

        let mut s1 = Snow3G::from_bytes(&key, &iv1);
        let mut s2 = Snow3G::from_bytes(&key, &iv2);
        let mut ks1 = [0; 4];
        s1.fill(&mut ks1);
        let mut ks2 = [0; 4];
        s2.fill(&mut ks2);
        assert_ne!(ks1, ks2);
    }

    // ── free5gc snow3g test vectors (direct u32 format) ────────────────────────

    #[test]
    fn test_snow3g_free5gc_tc1() {
        // From free5gc snow3g_test.go TestCase1
        let k = [0x2bd6459fu32, 0x82c5b300, 0x952c4910, 0x4881ff48];
        let iv = [0xea024714u32, 0xad5c4d84, 0xdf1f9b25, 0x1c0bf45f];
        let mut snow = Snow3G::new(k, iv);
        let mut ks = [0; 2];
        snow.fill(&mut ks);
        assert_eq!(ks[0], 0xabee9704, "free5gc TC1: z[0] mismatch");
        assert_eq!(ks[1], 0x7ac31373, "free5gc TC1: z[1] mismatch");
    }

    #[test]
    fn test_snow3g_free5gc_tc2() {
        let k = [0x8ce33e2cu32, 0xc3c0b5fc, 0x1f3de8a6, 0xdc66b1f3];
        let iv = [0xd3c5d592u32, 0x327fb11c, 0xde551988, 0xceb2f9b7];
        let mut snow = Snow3G::new(k, iv);
        let mut ks = [0; 2];
        snow.fill(&mut ks);
        assert_eq!(ks[0], 0xeff8a342, "free5gc TC2: z[0] mismatch");
        assert_eq!(ks[1], 0xf751480f, "free5gc TC2: z[1] mismatch");
    }

    // ── free5gc snow3g test vectors (TC3 and TC4) ───────────────────────────────

    #[test]
    fn test_snow3g_free5gc_tc3() {
        let k = [0x4035c668u32, 0x0af8c6d1, 0xa8ff8667, 0xb1714013];
        let iv = [0x62a54098u32, 0x1ba6f9b7, 0x4592b0e7, 0x8690f71b];
        let mut snow = Snow3G::new(k, iv);
        let mut ks = [0; 2];
        snow.fill(&mut ks);
        assert_eq!(ks[0], 0xa8c874a9, "free5gc TC3: z[0] mismatch");
        assert_eq!(ks[1], 0x7ae7c4f8, "free5gc TC3: z[1] mismatch");
    }

    #[test]
    fn test_snow3g_free5gc_tc4() {
        let k = [0x0ded7263u32, 0x109cf92e, 0x3352255a, 0x140e0f76];
        let iv = [0x6b68079au32, 0x41a7c4c9, 0x1befd79f, 0x7fdcc233];
        let mut snow = Snow3G::new(k, iv);
        let mut ks = [0; 3];
        snow.fill(&mut ks);
        assert_eq!(ks[0], 0xd712c05c, "free5gc TC4: z[0] mismatch");
        assert_eq!(ks[1], 0xa937c2a6, "free5gc TC4: z[1] mismatch");
        assert_eq!(ks[2], 0xeb7eaae3, "free5gc TC4: z[2] mismatch");
    }

    // ── NEA1 TC1 keystream check ────────────────────────────────────────────────
    // The NEA1 TC1 uses key=2bd6459f... count=0x72a4f20f bearer=0x0c dir=1.
    // The SNOW 3G IV (in u32 words) is:
    //   IV[0] = (bearer<<27)|(dir<<26) = (0x0c<<27)|(1<<26) = 0x64000000|0x04000000 = 0x64000000
    //   Wait: bearer=0x0c=12d, 12<<27=0x60000000; dir=1, 1<<26=0x04000000 → 0x64000000
    //   IV[1] = COUNT = 0x72a4f20f
    //   IV[2] = IV[0] = 0x64000000
    //   IV[3] = IV[1] = 0x72a4f20f
    // Key is byte-reversed: k[0]=key[12..16], k[1]=key[8..12], k[2]=key[4..8], k[3]=key[0..4]
    //   key = 2b d6 45 9f | 82 c5 b3 00 | 95 2c 49 10 | 48 81 ff 48
    //   k[0] = 0x4881ff48, k[1] = 0x952c4910, k[2] = 0x82c5b300, k[3] = 0x2bd6459f
    // The NEA1 test verifies encrypt→decrypt roundtrip as well as known outputs.
    // This test verifies the underlying SNOW 3G keystream for that configuration.
    #[test]
    fn test_snow3g_nea1_tc1_keystream() {
        let k = [0x4881ff48u32, 0x952c4910, 0x82c5b300, 0x2bd6459f];
        let iv = [0x64000000u32, 0x72a4f20f, 0x64000000, 0x72a4f20f];
        let mut snow = Snow3G::new(k, iv);
        let mut ks = [0; 4];
        snow.fill(&mut ks);
        // Keystream must be non-zero
        assert!(ks.iter().any(|&w| w != 0));
        // XOR plaintext[0..4] with ks[0] should give ciphertext[0..4]:
        // plaintext: 7e c6 12 72 → 0x7ec61272
        // ciphertext: 8c eb a6 29 → 0x8ceba629
        // XOR: 0x7ec61272 ^ 0x8ceba629 = f22db45b  ← that's ks[0] big-endian
        // But NEA1 uses big-endian byte order within each word:
        // ks_byte[i] = (ks[i/4] >> (24 - (i%4)*8)) as u8
        let ks0_be = ks[0].to_be_bytes();
        let pt = [0x7eu8, 0xc6, 0x12, 0x72];
        let ct = [0x8cu8, 0xeb, 0xa6, 0x29];
        for i in 0..4 {
            assert_eq!(pt[i] ^ ks0_be[i], ct[i], "byte {i} mismatch");
        }
    }
}
