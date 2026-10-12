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

//! The tables of the vector paths, each sixteen octets that a shuffle
//! instruction indexes with a value below sixteen. They are computed here
//! from the tables and the constants of the scalar code, which are those
//! of the specifications.

use crate::common::snow3g::{SQ_OCTETS, div_alpha_value, mul_alpha_value};
use crate::common::zuc::{P1, P2, P3, S1_CONSTANT, S1_IN, S1_OUT};

/// SQ of SNOW 3G in sixteen rows: row `i` has SQ of `16 i` to `16 i + 15`.
pub(super) const SQ_ROWS: [[u8; 16]; 16] = {
    let mut rows = [[0; 16]; 16];
    let mut index = 0;
    while index < 256 {
        rows[index / 16][index % 16] = SQ_OCTETS[index];
        index += 1;
    }
    rows
};

/// MULα and DIVα of SNOW 3G take an octet to a word and are linear, so the
/// word of an octet is the sum of the words of its four two-bit digits.
/// Table `k` has the four words of digit `k`, each with its low octet
/// first: the octet at `4 d + j` is octet `j` of the word of the digit `d`.
const fn alpha_digits(alpha: bool) -> [[u8; 16]; 4] {
    let mut tables = [[0; 16]; 4];
    let mut digit = 0;
    while digit < 16 {
        let (place, value) = (digit / 4, digit % 4);
        let octet = (value << (2 * place)) as u8;
        let word = if alpha {
            mul_alpha_value(octet)
        } else {
            div_alpha_value(octet)
        };
        let octets = word.to_le_bytes();
        let mut j = 0;
        while j < 4 {
            tables[place][4 * value + j] = octets[j];
            j += 1;
        }
        digit += 1;
    }
    tables
}

pub(super) const MUL_ALPHA: [[u8; 16]; 4] = alpha_digits(true);
pub(super) const DIV_ALPHA: [[u8; 16]; 4] = alpha_digits(false);

/// The octet number within its word, for the four words: what a two-bit
/// digit times four is added to, to index a table of [`MUL_ALPHA`].
pub(super) const OCTET_OF_WORD: [u8; 16] = [0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3, 0, 1, 2, 3];

/// The shuffle that fills each word with its high octet, and with its low
/// one.
pub(super) const HIGH_OCTETS: [u8; 16] = [3, 3, 3, 3, 7, 7, 7, 7, 11, 11, 11, 11, 15, 15, 15, 15];
pub(super) const LOW_OCTETS: [u8; 16] = [0, 0, 0, 0, 4, 4, 4, 4, 8, 8, 8, 8, 12, 12, 12, 12];

/// The shuffles that rotate each word by 8 bits to the right, by 8 to the
/// left and by 16.
pub(super) const ROTATE_RIGHT_8: [u8; 16] = [1, 2, 3, 0, 5, 6, 7, 4, 9, 10, 11, 8, 13, 14, 15, 12];
pub(super) const ROTATE_LEFT_8: [u8; 16] = [3, 0, 1, 2, 7, 4, 5, 6, 11, 8, 9, 10, 15, 12, 13, 14];
pub(super) const ROTATE_16: [u8; 16] = [2, 3, 0, 1, 6, 7, 4, 5, 10, 11, 8, 9, 14, 15, 12, 13];

/// The shuffle that ShiftRows of AES undoes: after it and a round of AES,
/// each column of the state is made of the octets of one word.
pub(super) const INVERSE_SHIFT_ROWS: [u8; 16] = {
    let mut shuffle = [0; 16];
    let mut position = 0;
    while position < 16 {
        let (row, column) = (position % 4, position / 4);
        shuffle[position] = (row + 4 * ((column + 4 - row) % 4)) as u8;
        position += 1;
    }
    shuffle
};

/// A four-bit S-box of ZUC, which the scalar code keeps as a word of
/// sixteen nibbles, as sixteen octets.
const fn nibble_table(word: u64) -> [u8; 16] {
    let mut table = [0; 16];
    let mut index = 0;
    while index < 16 {
        table[index] = ((word >> (4 * index)) & 0x0f) as u8;
        index += 1;
    }
    table
}

pub(super) const ZUC_P1: [u8; 16] = nibble_table(P1);
pub(super) const ZUC_P2: [u8; 16] = nibble_table(P2);

/// The end of S0 of ZUC. With q1 and q2 the nibbles after the first two
/// rounds, S0 is `((q3 << 4) | q2)` rotated left by five bits, where
/// `q3 = q1 ^ P3[q2]`. Shifts and rotations are linear, so that is the sum
/// of a function of q1, [`ZUC_S0_OF_Q1`], and one of q2, [`ZUC_S0_OF_Q2`].
pub(super) const ZUC_S0_OF_Q1: [u8; 16] = {
    let mut table = [0; 16];
    let mut q1 = 0;
    while q1 < 16 {
        table[q1] = ((q1 as u8) << 4).rotate_left(5);
        q1 += 1;
    }
    table
};
pub(super) const ZUC_S0_OF_Q2: [u8; 16] = {
    let p3 = nibble_table(P3);
    let mut table = [0; 16];
    let mut q2 = 0;
    while q2 < 16 {
        table[q2] = (p3[q2] << 4).rotate_left(5) ^ (q2 as u8).rotate_left(5);
        q2 += 1;
    }
    table
};

/// The image of an octet under a linear map that is given by the images of
/// its eight bits.
const fn linear(columns: &[u8; 8], octet: u8) -> u8 {
    let mut image = 0;
    let mut bit = 0;
    while bit < 8 {
        if (octet >> bit) & 1 == 1 {
            image ^= columns[bit];
        }
        bit += 1;
    }
    image
}

/// A linear map on octets as two tables, of the low nibble and of the high
/// one, whose sum is the image. `constant` is added to the first.
const fn linear_tables(columns: &[u8; 8], constant: u8) -> ([u8; 16], [u8; 16]) {
    let (mut low, mut high) = ([0; 16], [0; 16]);
    let mut nibble = 0;
    while nibble < 16 {
        low[nibble] = linear(columns, nibble as u8) ^ constant;
        high[nibble] = linear(columns, (nibble as u8) << 4);
        nibble += 1;
    }
    (low, high)
}

/// S1 of ZUC is `OUT(SR(IN(x))) + S1_CONSTANT` with SR the S-box of AES:
/// the two linear maps, with the constant in the first table of OUT.
pub(super) const ZUC_S1_IN: ([u8; 16], [u8; 16]) = linear_tables(&S1_IN, 0);
pub(super) const ZUC_S1_OUT: ([u8; 16], [u8; 16]) = linear_tables(&S1_OUT, S1_CONSTANT);

/// All ones in the second word.
pub(super) const SECOND_WORD: [u8; 16] =
    [0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0];

/// An index that a shuffle answers with zero, on x86-64 and on AArch64.
const NONE: u8 = 0x80;

/// The shuffle that gives W1L || W2H and W2L || W1H of ZUC from W1 and W2,
/// the first two words: the low half of one becomes the high half, above
/// the high half of the other.
pub(super) const ZUC_HALVES: [u8; 16] = [
    6, 7, 0, 1, 2, 3, 4, 5, NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
];

/// L1 and L2 of ZUC on the first and on the second word. L1 adds to a word
/// its rotations by 2, 10, 18 and 24 bits, and L2 by 8, 14, 22 and 30.
/// With the word rotated by 2 bits for L1 and by 6 for L2, the others are
/// rotations by whole octets: [`ZUC_L_OF_WORD`] is the one of the word
/// itself, by 24 for L1 and by 8 for L2, and [`ZUC_L_OF_BITS`] the three of
/// the word rotated by bits, by 0, 8 and 16 for L1 and by 8, 16 and 24 for
/// L2.
pub(super) const ZUC_L_OF_WORD: [u8; 16] = [
    1, 2, 3, 0, 7, 4, 5, 6, NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
];
pub(super) const ZUC_L_OF_BITS: [[u8; 16]; 3] = [
    [
        0, 1, 2, 3, 7, 4, 5, 6, NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    ],
    [
        3, 0, 1, 2, 6, 7, 4, 5, NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    ],
    [
        2, 3, 0, 1, 5, 6, 7, 4, NONE, NONE, NONE, NONE, NONE, NONE, NONE, NONE,
    ],
];

/// The octets of a word that go through S0 in ZUC, the first and the third
/// from the high one: all ones there.
pub(super) const ZUC_S0_OCTETS: [u8; 16] = [
    0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff, 0, 0xff,
];

/// An octet with its bits in the reverse order is the reverse of its low
/// nibble, as the high nibble, and the reverse of its high nibble: the
/// table of the low nibble, then that of the high one.
pub(super) const REVERSED_BITS: ([u8; 16], [u8; 16]) = {
    let (mut of_low, mut of_high) = ([0; 16], [0; 16]);
    let mut nibble = 0;
    while nibble < 16 {
        let reversed = (nibble as u8).reverse_bits() >> 4;
        of_low[nibble] = reversed << 4;
        of_high[nibble] = reversed;
        nibble += 1;
    }
    (of_low, of_high)
};

/// The shuffle that exchanges the two words of each half.
pub(super) const EXCHANGED_WORDS: [u8; 16] = [4, 5, 6, 7, 0, 1, 2, 3, 12, 13, 14, 15, 8, 9, 10, 11];

/// The shuffles that leave one word, as the low word, and zero elsewhere.
pub(super) const WORD_ALONE: [[u8; 16]; 4] = {
    let mut shuffles = [[NONE; 16]; 4];
    let mut index = 0;
    while index < 16 {
        shuffles[index / 4][index % 4] = index as u8;
        index += 1;
    }
    shuffles
};

/// The shuffle that reverses the octets of each half: eight octets of a
/// message become the word that they are with the high octet first.
pub(super) const REVERSED_HALVES: [u8; 16] = [7, 6, 5, 4, 3, 2, 1, 0, 15, 14, 13, 12, 11, 10, 9, 8];

/// The round constants of the key expansion of AES-128 (FIPS 197 §5.2).
pub(super) const AES_ROUND_CONSTANTS: [u32; 10] =
    [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36];

/// The shuffle that fills every word with the last one, rotated by an
/// octet as RotWord of the key expansion rotates it.
pub(super) const AES_ROTATED_LAST_WORD: [u8; 16] = [
    13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12, 13, 14, 15, 12,
];

/// The shuffles that move the words up by one, by two and by three, with
/// zero in the words that they leave.
pub(super) const WORDS_MOVED_UP: [[u8; 16]; 3] = {
    let mut shuffles = [[NONE; 16]; 3];
    let mut words = 1;
    while words <= 3 {
        let mut index = 4 * words;
        while index < 16 {
            shuffles[words - 1][index] = (index - 4 * words) as u8;
            index += 1;
        }
        words += 1;
    }
    shuffles
};
