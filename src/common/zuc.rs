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

//! ZUC stream cipher (3GPP TS 35.221 / TS 35.222)
//!
//! A word-oriented stream cipher producing 32-bit keystream words.
//! Uses a 16-stage LFSR over GF(2^31-1), bit reorganization, and a nonlinear function.
//! S-box lookups visit every entry and the modular reduction has no branch
//! in the source. Compiled-code timing requires target-specific assessment.

use crate::common::ct::lookup;

// ── S-boxes ────────────────────────────────────────────────────────────────────

const S0: [u8; 256] = [
    0x3E, 0x72, 0x5B, 0x47, 0xCA, 0xE0, 0x00, 0x33, 0x04, 0xD1, 0x54, 0x98, 0x09, 0xB9, 0x6D, 0xCB,
    0x7B, 0x1B, 0xF9, 0x32, 0xAF, 0x9D, 0x6A, 0xA5, 0xB8, 0x2D, 0xFC, 0x1D, 0x08, 0x53, 0x03, 0x90,
    0x4D, 0x4E, 0x84, 0x99, 0xE4, 0xCE, 0xD9, 0x91, 0xDD, 0xB6, 0x85, 0x48, 0x8B, 0x29, 0x6E, 0xAC,
    0xCD, 0xC1, 0xF8, 0x1E, 0x73, 0x43, 0x69, 0xC6, 0xB5, 0xBD, 0xFD, 0x39, 0x63, 0x20, 0xD4, 0x38,
    0x76, 0x7D, 0xB2, 0xA7, 0xCF, 0xED, 0x57, 0xC5, 0xF3, 0x2C, 0xBB, 0x14, 0x21, 0x06, 0x55, 0x9B,
    0xE3, 0xEF, 0x5E, 0x31, 0x4F, 0x7F, 0x5A, 0xA4, 0x0D, 0x82, 0x51, 0x49, 0x5F, 0xBA, 0x58, 0x1C,
    0x4A, 0x16, 0xD5, 0x17, 0xA8, 0x92, 0x24, 0x1F, 0x8C, 0xFF, 0xD8, 0xAE, 0x2E, 0x01, 0xD3, 0xAD,
    0x3B, 0x4B, 0xDA, 0x46, 0xEB, 0xC9, 0xDE, 0x9A, 0x8F, 0x87, 0xD7, 0x3A, 0x80, 0x6F, 0x2F, 0xC8,
    0xB1, 0xB4, 0x37, 0xF7, 0x0A, 0x22, 0x13, 0x28, 0x7C, 0xCC, 0x3C, 0x89, 0xC7, 0xC3, 0x96, 0x56,
    0x07, 0xBF, 0x7E, 0xF0, 0x0B, 0x2B, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xA6, 0x4C, 0x10, 0xFE,
    0xBC, 0x26, 0x95, 0x88, 0x8A, 0xB0, 0xA3, 0xFB, 0xC0, 0x18, 0x94, 0xF2, 0xE1, 0xE5, 0xE9, 0x5D,
    0xD0, 0xDC, 0x11, 0x66, 0x64, 0x5C, 0xEC, 0x59, 0x42, 0x75, 0x12, 0xF5, 0x74, 0x9C, 0xAA, 0x23,
    0x0E, 0x86, 0xAB, 0xBE, 0x2A, 0x02, 0xE7, 0x67, 0xE6, 0x44, 0xA2, 0x6C, 0xC2, 0x93, 0x9F, 0xF1,
    0xF6, 0xFA, 0x36, 0xD2, 0x50, 0x68, 0x9E, 0x62, 0x71, 0x15, 0x3D, 0xD6, 0x40, 0xC4, 0xE2, 0x0F,
    0x8E, 0x83, 0x77, 0x6B, 0x25, 0x05, 0x3F, 0x0C, 0x30, 0xEA, 0x70, 0xB7, 0xA1, 0xE8, 0xA9, 0x65,
    0x8D, 0x27, 0x1A, 0xDB, 0x81, 0xB3, 0xA0, 0xF4, 0x45, 0x7A, 0x19, 0xDF, 0xEE, 0x78, 0x34, 0x60,
];

const S1: [u8; 256] = [
    0x55, 0xC2, 0x63, 0x71, 0x3B, 0xC8, 0x47, 0x86, 0x9F, 0x3C, 0xDA, 0x5B, 0x29, 0xAA, 0xFD, 0x77,
    0x8C, 0xC5, 0x94, 0x0C, 0xA6, 0x1A, 0x13, 0x00, 0xE3, 0xA8, 0x16, 0x72, 0x40, 0xF9, 0xF8, 0x42,
    0x44, 0x26, 0x68, 0x96, 0x81, 0xD9, 0x45, 0x3E, 0x10, 0x76, 0xC6, 0xA7, 0x8B, 0x39, 0x43, 0xE1,
    0x3A, 0xB5, 0x56, 0x2A, 0xC0, 0x6D, 0xB3, 0x05, 0x22, 0x66, 0xBF, 0xDC, 0x0B, 0xFA, 0x62, 0x48,
    0xDD, 0x20, 0x11, 0x06, 0x36, 0xC9, 0xC1, 0xCF, 0xF6, 0x27, 0x52, 0xBB, 0x69, 0xF5, 0xD4, 0x87,
    0x7F, 0x84, 0x4C, 0xD2, 0x9C, 0x57, 0xA4, 0xBC, 0x4F, 0x9A, 0xDF, 0xFE, 0xD6, 0x8D, 0x7A, 0xEB,
    0x2B, 0x53, 0xD8, 0x5C, 0xA1, 0x14, 0x17, 0xFB, 0x23, 0xD5, 0x7D, 0x30, 0x67, 0x73, 0x08, 0x09,
    0xEE, 0xB7, 0x70, 0x3F, 0x61, 0xB2, 0x19, 0x8E, 0x4E, 0xE5, 0x4B, 0x93, 0x8F, 0x5D, 0xDB, 0xA9,
    0xAD, 0xF1, 0xAE, 0x2E, 0xCB, 0x0D, 0xFC, 0xF4, 0x2D, 0x46, 0x6E, 0x1D, 0x97, 0xE8, 0xD1, 0xE9,
    0x4D, 0x37, 0xA5, 0x75, 0x5E, 0x83, 0x9E, 0xAB, 0x82, 0x9D, 0xB9, 0x1C, 0xE0, 0xCD, 0x49, 0x89,
    0x01, 0xB6, 0xBD, 0x58, 0x24, 0xA2, 0x5F, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xB8, 0x95, 0xE4,
    0xD0, 0x91, 0xC7, 0xCE, 0xED, 0x0F, 0xB4, 0x6F, 0xA0, 0xCC, 0xF0, 0x02, 0x4A, 0x79, 0xC3, 0xDE,
    0xA3, 0xEF, 0xEA, 0x51, 0xE6, 0x6B, 0x18, 0xEC, 0x1B, 0x2C, 0x80, 0xF7, 0x74, 0xE7, 0xFF, 0x21,
    0x5A, 0x6A, 0x54, 0x1E, 0x41, 0x31, 0x92, 0x35, 0xC4, 0x33, 0x07, 0x0A, 0xBA, 0x7E, 0x0E, 0x34,
    0x88, 0xB1, 0x98, 0x7C, 0xF3, 0x3D, 0x60, 0x6C, 0x7B, 0xCA, 0xD3, 0x1F, 0x32, 0x65, 0x04, 0x28,
    0x64, 0xBE, 0x85, 0x9B, 0x2F, 0x59, 0x8A, 0xD7, 0xB0, 0x25, 0xAC, 0xAF, 0x12, 0x03, 0xE2, 0xF2,
];

// ── Constants ──────────────────────────────────────────────────────────────────

/// 15-bit constants d[i] for LFSR initialization
const D: [u16; 16] = [
    0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF, 0x4D78, 0x2F13, 0x6BC4, 0x1AF1,
    0x5E26, 0x3C4D, 0x789A, 0x47AC,
];

const P: u32 = 0x7FFFFFFF; // 2^31 - 1

// ── Modular arithmetic mod 2^31-1 ──────────────────────────────────────────────

/// Reduce mod 2^31-1, result in [1, 2^31-1] (0 maps to P), without a
/// branch on the secret value.
#[inline]
fn mod31(a: u32) -> u32 {
    // At most P + 1; subtract P when it is at least P, then map 0 to P.
    let r = (a & P) + (a >> 31);
    let at_least_p = (r.wrapping_sub(P) >> 31) ^ 1;
    let r = r - (P & 0u32.wrapping_sub(at_least_p));
    let zero = ((r | r.wrapping_neg()) >> 31) ^ 1;
    r | (P & 0u32.wrapping_sub(zero))
}

/// Multiply by 2^n mod (2^31-1)
#[inline]
fn rot31(a: u32, n: u32) -> u32 {
    ((a << n) | (a >> (31 - n))) & P
}

// ── Linear transforms ──────────────────────────────────────────────────────────

#[inline]
fn l1(x: u32) -> u32 {
    x ^ x.rotate_left(2) ^ x.rotate_left(10) ^ x.rotate_left(18) ^ x.rotate_left(24)
}

#[inline]
fn l2(x: u32) -> u32 {
    x ^ x.rotate_left(8) ^ x.rotate_left(14) ^ x.rotate_left(22) ^ x.rotate_left(30)
}

/// Apply S-boxes to a 32-bit word: S0(x0) || S1(x1) || S0(x2) || S1(x3)
#[inline]
fn sbox(x: u32) -> u32 {
    let b = x.to_be_bytes();
    u32::from_be_bytes([
        lookup(&S0, b[0]),
        lookup(&S1, b[1]),
        lookup(&S0, b[2]),
        lookup(&S1, b[3]),
    ])
}

// ── ZUC state ──────────────────────────────────────────────────────────────────

/// ZUC keystream generator: the LFSR and the two registers of the nonlinear
/// function, initialized with a key and an IV. The state is wiped on drop.
#[derive(zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct Zuc {
    s: [u32; 16], // LFSR (31-bit stages)
    r1: u32,
    r2: u32,
    started: bool,
}

impl Zuc {
    /// Initialize ZUC with 128-bit key and 128-bit IV.
    pub fn new(key: &[u8; 16], iv: &[u8; 16]) -> Self {
        let mut z = Zuc {
            s: [0u32; 16],
            r1: 0,
            r2: 0,
            started: false,
        };

        // Load LFSR: s[i] = k[i] || d[i] || iv[i] (31 bits: 8+15+8)
        for i in 0..16 {
            z.s[i] = ((key[i] as u32) << 23) | ((D[i] as u32) << 8) | (iv[i] as u32);
        }

        // 32 initialization clocks
        for _ in 0..32 {
            let (x0, x1, x2, x3) = z.bit_reorg();
            let w = z.f(x0, x1, x2, x3);
            z.lfsr_init(w >> 1);
        }

        z
    }

    /// Generate `n` keystream words.
    pub fn generate(&mut self, n: usize) -> Vec<u32> {
        if !self.started {
            // TS 35.222 discards one word after initialization, once per state.
            let (x0, x1, x2, x3) = self.bit_reorg();
            let _ = self.f(x0, x1, x2, x3);
            self.lfsr_keystream();
            self.started = true;
        }

        let mut ks = Vec::with_capacity(n);
        for _ in 0..n {
            let (x0, x1, x2, x3) = self.bit_reorg();
            let w = self.f(x0, x1, x2, x3);
            ks.push(w ^ x3);
            self.lfsr_keystream();
        }
        ks
    }

    /// Bit Reorganization: extract X0..X3 from LFSR stages.
    #[inline]
    fn bit_reorg(&self) -> (u32, u32, u32, u32) {
        let x0 = ((self.s[15] & 0x7FFF8000) << 1) | (self.s[14] & 0xFFFF);
        let x1 = ((self.s[11] & 0xFFFF) << 16) | (self.s[9] >> 15);
        let x2 = ((self.s[7] & 0xFFFF) << 16) | (self.s[5] >> 15);
        let x3 = ((self.s[2] & 0xFFFF) << 16) | (self.s[0] >> 15);
        (x0, x1, x2, x3)
    }

    /// Nonlinear function F.
    fn f(&mut self, x0: u32, x1: u32, x2: u32, x3: u32) -> u32 {
        let w = (x0 ^ self.r1).wrapping_add(self.r2);
        let w1 = self.r1.wrapping_add(x1);
        let w2 = self.r2 ^ x2;

        // Swap halves
        let u = (w1 << 16) | (w2 >> 16);
        let v = (w2 << 16) | (w1 >> 16);

        self.r1 = sbox(l1(u));
        self.r2 = sbox(l2(v));

        let _ = x3; // x3 used by caller for keystream output
        w
    }

    /// LFSR clock during initialization (feedback includes W).
    fn lfsr_init(&mut self, w: u32) {
        let mut f = self.s[0];
        f = mod31(f.wrapping_add(rot31(self.s[0], 8)));
        f = mod31(f.wrapping_add(rot31(self.s[4], 20)));
        f = mod31(f.wrapping_add(rot31(self.s[10], 21)));
        f = mod31(f.wrapping_add(rot31(self.s[13], 17)));
        f = mod31(f.wrapping_add(rot31(self.s[15], 15)));
        f = mod31(f.wrapping_add(w & P));

        for i in 0..15 {
            self.s[i] = self.s[i + 1];
        }
        self.s[15] = f;
    }

    /// LFSR clock during keystream generation.
    fn lfsr_keystream(&mut self) {
        let mut f = self.s[0];
        f = mod31(f.wrapping_add(rot31(self.s[0], 8)));
        f = mod31(f.wrapping_add(rot31(self.s[4], 20)));
        f = mod31(f.wrapping_add(rot31(self.s[10], 21)));
        f = mod31(f.wrapping_add(rot31(self.s[13], 17)));
        f = mod31(f.wrapping_add(rot31(self.s[15], 15)));

        for i in 0..15 {
            self.s[i] = self.s[i + 1];
        }
        self.s[15] = f;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The branchless reduction agrees with the branching one it replaced,
    /// on the boundaries and on pseudo-random inputs.
    #[test]
    fn mod31_matches_the_reference_reduction() {
        fn reference(a: u32) -> u32 {
            let mut r = (a & P) + (a >> 31);
            if r >= P {
                r -= P;
            }
            if r == 0 { P } else { r }
        }
        let mut x = 0x9e37_79b9u32;
        let random = core::iter::repeat_with(move || {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            x
        });
        for a in [0, 1, P - 1, P, P + 1, 2 * P - 1, 2 * P, u32::MAX]
            .into_iter()
            .chain(random.take(100_000))
        {
            assert_eq!(mod31(a), reference(a), "{a:#x}");
        }
    }

    #[test]
    fn split_generate_matches_single_call() {
        let key = [0x23; 16];
        let iv = [0x42; 16];
        let mut one = Zuc::new(&key, &iv);
        let mut split = Zuc::new(&key, &iv);
        let expected = one.generate(8);
        let mut actual = split.generate(3);
        actual.extend(split.generate(5));
        assert_eq!(actual, expected);
    }

    #[test]
    fn test_zuc_test_vector_1() {
        // ZUC 1.6 (TS 35.221): all-zero key and IV
        // Note: ZUC 1.4 produced 0x27BEAD9D; ZUC 1.6 produces 0x27BEDE74
        let key = [0u8; 16];
        let iv = [0u8; 16];
        let mut z = Zuc::new(&key, &iv);
        let ks = z.generate(2);
        assert_eq!(ks[0], 0x27BE_DE74);
        assert_eq!(ks[1], 0x0180_82DA);
    }

    #[test]
    fn test_zuc_test_vector_2() {
        // 3GPP TS 35.221 Test Set 2: all-FF key and IV
        let key = [0xFFu8; 16];
        let iv = [0xFFu8; 16];
        let mut z = Zuc::new(&key, &iv);
        let ks = z.generate(2);
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
        let ks = z.generate(2);
        assert_eq!(ks[0], 0x14F1_C272);
        assert_eq!(ks[1], 0x3279_C419);
    }
}
