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

//! The vector operations of x86-64 with AVX2, on 256-bit registers, that
//! the generators of eight messages are written with.
//!
//! A register is two halves of 128 bits, and a shuffle or an AES round
//! works on each half by itself: a table of sixteen octets is in both
//! halves, and what [`sboxes!`] does to four words it does here to eight.
//! The AES round is the instruction of 128 bits on each half, which every
//! processor with AVX2 and AES has.
//!
//! Every function is compiled for these instructions and is safe: it takes
//! and returns values, never a pointer. Calling one from code that is not
//! compiled for them is what needs `unsafe`, and the parent module does it
//! once it has seen that the processor has them.

use core::arch::x86_64::*;

/// Thirty-two octets, also read as eight 32-bit words with their low octet
/// first.
pub(super) type V = __m256i;

macro_rules! operations {
    ($(
        $(#[$attribute:meta])*
        fn $name:ident $(<const $shift:ident: i32>)? ($($argument:ident: $kind:ty),*) -> $result:ty $body:block
    )*) => {$(
        $(#[$attribute])*
        #[inline]
        #[target_feature(enable = "avx2,aes")]
        pub(super) fn $name $(<const $shift: i32>)? ($($argument: $kind),*) -> $result $body
    )*};
}

operations! {
    fn zero() -> V {
        _mm256_setzero_si256()
    }

    /// Sixteen octets in each half.
    fn from_octets(octets: [u8; 16]) -> V {
        let [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15] =
            octets.map(|octet| octet as i8);
        _mm256_broadcastsi128_si256(_mm_set_epi8(
            o15, o14, o13, o12, o11, o10, o9, o8, o7, o6, o5, o4, o3, o2, o1, o0,
        ))
    }

    fn from_words(words: [u32; 8]) -> V {
        let [w0, w1, w2, w3, w4, w5, w6, w7] = words.map(|word| word as i32);
        _mm256_set_epi32(w7, w6, w5, w4, w3, w2, w1, w0)
    }

    fn to_words(vector: V) -> [u32; 8] {
        [
            _mm256_extract_epi32::<0>(vector) as u32,
            _mm256_extract_epi32::<1>(vector) as u32,
            _mm256_extract_epi32::<2>(vector) as u32,
            _mm256_extract_epi32::<3>(vector) as u32,
            _mm256_extract_epi32::<4>(vector) as u32,
            _mm256_extract_epi32::<5>(vector) as u32,
            _mm256_extract_epi32::<6>(vector) as u32,
            _mm256_extract_epi32::<7>(vector) as u32,
        ]
    }

    fn splat8(octet: u8) -> V {
        _mm256_set1_epi8(octet as i8)
    }

    fn xor(a: V, b: V) -> V {
        _mm256_xor_si256(a, b)
    }

    fn and(a: V, b: V) -> V {
        _mm256_and_si256(a, b)
    }

    fn or(a: V, b: V) -> V {
        _mm256_or_si256(a, b)
    }

    /// Each 16-bit word shifted left. The callers mask what crosses from
    /// one octet into the next.
    fn shl16<const N: i32>(vector: V) -> V {
        _mm256_slli_epi16::<N>(vector)
    }

    /// Each 16-bit word shifted right, with the same caution.
    fn shr16<const N: i32>(vector: V) -> V {
        _mm256_srli_epi16::<N>(vector)
    }

    fn shl32<const N: i32>(vector: V) -> V {
        _mm256_slli_epi32::<N>(vector)
    }

    fn shr32<const N: i32>(vector: V) -> V {
        _mm256_srli_epi32::<N>(vector)
    }

    /// For each octet of `index`, the octet of the same half of `table` at
    /// that index when it is below 16, and zero when it is 0x80. The index
    /// is the operand of an instruction, not an address.
    fn shuffle(table: V, index: V) -> V {
        _mm256_shuffle_epi8(table, index)
    }

    /// All ones in the octets that are equal.
    fn eq8(a: V, b: V) -> V {
        _mm256_cmpeq_epi8(a, b)
    }

    /// The sums of the 32-bit words.
    fn add32(a: V, b: V) -> V {
        _mm256_add_epi32(a, b)
    }

    /// Each octet added to itself.
    fn double8(vector: V) -> V {
        _mm256_add_epi8(vector, vector)
    }

    /// All ones in the octets whose top bit is set.
    fn negative8(vector: V) -> V {
        _mm256_cmpgt_epi8(_mm256_setzero_si256(), vector)
    }

    /// SubBytes, ShiftRows and MixColumns of AES on each half.
    fn aes_round(state: V) -> V {
        let no_key = _mm_setzero_si128();
        let low = _mm_aesenc_si128(_mm256_castsi256_si128(state), no_key);
        let high = _mm_aesenc_si128(_mm256_extracti128_si256::<1>(state), no_key);
        _mm256_set_m128i(high, low)
    }

    /// SubBytes and ShiftRows of AES on each half.
    fn aes_last_round(state: V) -> V {
        let no_key = _mm_setzero_si128();
        let low = _mm_aesenclast_si128(_mm256_castsi256_si128(state), no_key);
        let high = _mm_aesenclast_si128(_mm256_extracti128_si256::<1>(state), no_key);
        _mm256_set_m128i(high, low)
    }
}

sboxes!("avx2,aes");
lanes!("avx2,aes", 8);
