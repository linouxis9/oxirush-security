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

//! Arithmetic whose memory accesses and branches do not depend on its
//! operands, and a comparison whose time does not depend on the contents.
//!
//! The S-boxes and the field multiplications of SNOW 3G and ZUC take
//! secret values. Nothing here indexes memory or branches on one: a table
//! is read whole and narrowed down through masks, a small table is a word
//! that is shifted, a linear map and a carry-less product are sums of
//! masked or multiplied words. A shift by a secret amount and a
//! multiplication of secret words remain, which processors with a barrel
//! shifter and a constant-time multiplier, the common ones, run in a time
//! that does not depend on their operands.

use subtle::ConstantTimeEq;

/// Whether two octet strings are equal, in a time that depends on their
/// lengths and not on where they differ.
///
/// For a value derived from a key that is compared with the one a peer
/// sent: RES* with XRES*, HRES* with HXRES*, a SoR or UPU MAC with the
/// expected one. `==` on slices returns at the first octet that differs,
/// and the time it took tells the peer how much of a guess was right.
/// Strings of different lengths are unequal, which is found at once: the
/// lengths are not secret. The comparison is that of the `subtle` crate.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.ct_eq(b).into()
}

/// A word of all ones when the low bit of `bit` is one, of zeros when it is
/// zero, for a selection that depends on a secret bit.
///
/// The compiler is not told that the word is one of the two. Where it knows
/// it, it may turn the masked sum that follows into a conditional move or
/// into a conditional jump: it does so on x86-64 for a sum over constants,
/// and a jump on a secret bit takes a time that depends on it.
#[inline(always)]
pub(crate) fn mask64(bit: u64) -> u64 {
    core::hint::black_box(bit & 1).wrapping_neg()
}

/// A table of 256 octets, kept as 32 words of eight for [`Table::get4`].
pub(crate) struct Table([u64; 32]);

impl Table {
    /// The table of these octets.
    pub(crate) const fn new(octets: &[u8; 256]) -> Self {
        let mut rows = [0u64; 32];
        let mut index = 0;
        while index < 256 {
            rows[index / 8] |= (octets[index] as u64) << (8 * (index % 8));
            index += 1;
        }
        Self(rows)
    }

    /// The octets of the table at four indices, by narrowing the whole
    /// table down for each.
    ///
    /// Each of the five high bits of an index keeps one half of what is
    /// left, through a mask that is all ones or all zeros: sixteen words,
    /// then eight, four, two and one. The three low bits then shift the
    /// octet out of that word. Every word of the table is read whatever the
    /// index.
    #[inline]
    pub(crate) fn get4(&self, indices: [u8; 4]) -> [u8; 4] {
        let rows = &self.0;
        let bit = |k: usize, n: u8| mask64(u64::from(indices[k] >> n));

        // Two words at a time, which a compiler keeps in one vector
        let select = |mask: u64, low: [u64; 2], high: [u64; 2]| {
            [
                low[0] ^ ((low[0] ^ high[0]) & mask),
                low[1] ^ ((low[1] ^ high[1]) & mask),
            ]
        };
        let pair = |i: usize| [rows[2 * i], rows[2 * i + 1]];
        core::array::from_fn(|k| {
            let mask = bit(k, 7);
            let eight: [[u64; 2]; 8] = core::array::from_fn(|i| select(mask, pair(i), pair(i + 8)));
            let mask = bit(k, 6);
            let four: [[u64; 2]; 4] =
                core::array::from_fn(|i| select(mask, eight[i], eight[i + 4]));
            let mask = bit(k, 5);
            let two = [
                select(mask, four[0], four[2]),
                select(mask, four[1], four[3]),
            ];
            let [low, high] = select(bit(k, 4), two[0], two[1]);
            let word = low ^ ((low ^ high) & bit(k, 3));
            (word >> (8 * (indices[k] & 7))) as u8
        })
    }
}

/// The sixteen octets of four words, each with its low octet first: the
/// state of AES whose column `i` is word `i`.
#[inline]
pub(crate) fn columns_to_block(columns: [u32; 4]) -> [u8; 16] {
    let mut block = [0; 16];
    for (octets, column) in block.as_chunks_mut::<4>().0.iter_mut().zip(columns) {
        *octets = column.to_le_bytes();
    }
    block
}

/// The four words of sixteen octets, the reverse of [`columns_to_block`].
#[inline]
pub(crate) fn block_to_columns(block: &[u8; 16]) -> [u32; 4] {
    let (octets, _) = block.as_chunks::<4>();
    core::array::from_fn(|column| u32::from_le_bytes(octets[column]))
}

/// A table of sixteen four-bit values in one word, the value of `index`
/// at bits `4 * index`.
pub(crate) const fn nibbles(values: [u8; 16]) -> u64 {
    let mut word = 0;
    let mut index = 0;
    while index < 16 {
        word |= ((values[index] & 0x0f) as u64) << (4 * index);
        index += 1;
    }
    word
}

/// The value of `index`, 0 to 15, in a table of [`nibbles`]: the word is
/// shifted, and no memory is read.
#[inline]
pub(crate) fn nibble(table: u64, index: u8) -> u8 {
    ((table >> (4 * (index & 0x0f))) & 0x0f) as u8
}

/// Apply a GF(2)-linear map to each of the four octets of `x`: `columns[i]`
/// is the image of the octet that has bit `i` alone.
///
/// Bit `i` of every octet is isolated as a word of zeros and ones, and its
/// product with the column, which is below 256, puts the column in the
/// octets that had the bit, with no carry from one octet to the next.
#[inline]
pub(crate) fn linear_map(x: u32, columns: &[u8; 8]) -> u32 {
    let mut image = 0;
    for (bit, column) in columns.iter().enumerate() {
        image ^= ((x >> bit) & 0x0101_0101) * u32::from(*column);
    }
    image
}

/// The low 64 bits of the carry-less product of `x` and `y`, the product
/// of two polynomials over GF(2).
///
/// Each operand is cut into four words that keep one bit in four. The
/// integer product of two of them adds up to sixteen ones at a position.
/// Their sum spills into the three clear bits above it, and the sixteenth
/// one, which only the highest position can have, carries out of the word:
/// the bit that stays at the position is the bit of the carry-less
/// product. The sixteen products are sorted by the position of their bits
/// modulo four. This is the multiplication of BearSSL's constant-time
/// GHASH.
#[inline]
pub(crate) fn clmul64(x: u64, y: u64) -> u64 {
    const EVERY_FOURTH: u64 = 0x1111_1111_1111_1111;
    let x: [u64; 4] = core::array::from_fn(|i| x & (EVERY_FOURTH << i));
    let y: [u64; 4] = core::array::from_fn(|i| y & (EVERY_FOURTH << i));
    let mut product = 0;
    for position in 0..4 {
        let mut bits = 0;
        for i in 0..4 {
            bits ^= x[i].wrapping_mul(y[(position + 4 - i) % 4]);
        }
        product |= bits & (EVERY_FOURTH << position);
    }
    product
}

/// The carry-less product of `x` and `y` in two words, low then high.
#[inline]
pub(crate) fn clmul128(x: u64, y: u64) -> (u64, u64) {
    // The product of the reversed operands is the reversed product, which
    // has 127 bits: its low word, reversed and moved by one, is the high
    // word of the product.
    let high = clmul64(x.reverse_bits(), y.reverse_bits()).reverse_bits() >> 1;
    (clmul64(x, y), high)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Words that look random, the same at every run.
    fn words() -> impl Iterator<Item = u64> {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        core::iter::repeat_with(move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        })
    }

    #[test]
    fn a_mask_is_all_ones_for_a_one_bit() {
        assert_eq!(
            (mask64(0), mask64(1), mask64(2), mask64(3)),
            (0, u64::MAX, 0, u64::MAX)
        );
    }

    #[test]
    fn a_table_gives_the_octet_of_every_index() {
        let octets: [u8; 256] =
            core::array::from_fn(|index| (index as u8).wrapping_mul(167) ^ 0x5a);
        let table = Table::new(&octets);
        let of = |index: u8| octets[usize::from(index)];
        for index in 0..=u8::MAX {
            // In each of the four places, beside three other indices
            let others = [index.wrapping_mul(3), !index, index ^ 0x80];
            for place in 0..4 {
                let mut indices = [others[0], others[1], others[2], others[0]];
                indices[place] = index;
                assert_eq!(table.get4(indices), indices.map(of));
            }
        }
        for word in words().take(100_000) {
            let indices = (word as u32).to_le_bytes();
            assert_eq!(table.get4(indices), indices.map(of));
        }
        // An octet of all ones and one of zero, at both ends
        let mut ends = [0x33u8; 256];
        (ends[0], ends[255]) = (0xff, 0x00);
        let table = Table::new(&ends);
        assert_eq!(table.get4([0, 255, 255, 0]), [0xff, 0x00, 0x00, 0xff]);
    }

    #[test]
    fn a_block_is_its_four_columns() {
        let columns = [0x0302_0100, 0x0706_0504, 0x0b0a_0908, 0x0f0e_0d0c];
        let block = columns_to_block(columns);
        assert_eq!(block, core::array::from_fn(|index| index as u8));
        assert_eq!(block_to_columns(&block), columns);
    }

    #[test]
    fn a_word_of_nibbles_gives_the_value_of_every_index() {
        let values = [9, 15, 0, 14, 15, 15, 2, 10, 0, 4, 0, 12, 7, 5, 3, 9];
        let table = nibbles(values);
        for (index, value) in values.iter().enumerate() {
            assert_eq!(nibble(table, index as u8), *value);
        }
    }

    #[test]
    fn a_linear_map_is_the_sum_of_the_columns_of_the_set_bits() {
        let columns = [0x01, 0x32, 0x73, 0x75, 0xd9, 0xe8, 0xcd, 0x2d];
        let one = |octet: u8| {
            (0..8)
                .filter(|bit| (octet >> bit) & 1 == 1)
                .fold(0, |image, bit| image ^ columns[bit])
        };
        for octet in 0..=u8::MAX {
            // In each of the four places, beside three other octets
            let others = [octet.wrapping_mul(3), !octet, octet ^ 0x80];
            for place in 0..4 {
                let mut octets = [others[0], others[1], others[2], others[0]];
                octets[place] = octet;
                let image = linear_map(u32::from_le_bytes(octets), &columns);
                assert_eq!(image.to_le_bytes(), octets.map(one));
            }
        }
    }

    /// The carry-less product, one bit of `y` at a time.
    fn clmul_reference(x: u64, y: u64) -> u128 {
        (0..64)
            .filter(|bit| (y >> bit) & 1 == 1)
            .fold(0, |product, bit| product ^ (u128::from(x) << bit))
    }

    #[test]
    fn the_carry_less_product_is_that_of_the_shifted_sums() {
        let all = u64::MAX;
        let edges = [
            0,
            1,
            2,
            3,
            0x8000_0000_0000_0000,
            all,
            all - 1,
            0x1111_1111_1111_1111,
        ];
        let random: Vec<u64> = words().take(2_000).collect();
        let pairs = edges
            .iter()
            .flat_map(|x| edges.iter().map(move |y| (*x, *y)))
            .chain(random.chunks(2).map(|pair| (pair[0], pair[1])));
        for (x, y) in pairs {
            let expected = clmul_reference(x, y);
            assert_eq!(clmul64(x, y), expected as u64, "{x:#x} {y:#x}");
            assert_eq!(
                clmul128(x, y),
                (expected as u64, (expected >> 64) as u64),
                "{x:#x} {y:#x}"
            );
        }
    }

    #[test]
    fn constant_time_eq_agrees_with_equality() {
        let res_star = [0x5a; 16];
        assert!(constant_time_eq(&res_star, &[0x5a; 16]));
        assert!(constant_time_eq(&[], &[]));
        // One bit of difference, in every position.
        for index in 0..res_star.len() {
            for bit in 0..8 {
                let mut other = res_star;
                other[index] ^= 1 << bit;
                assert!(!constant_time_eq(&res_star, &other));
            }
        }
        // A prefix is another string.
        assert!(!constant_time_eq(&res_star, &res_star[..15]));
        assert!(!constant_time_eq(&res_star[..15], &res_star));
        assert!(!constant_time_eq(&[], &[0]));
    }
}
