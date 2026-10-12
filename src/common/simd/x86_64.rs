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

//! The vector operations of x86-64 that the generators are written with:
//! SSSE3 and SSE4.1 on 128-bit registers, the AES round and the carry-less
//! multiplication.
//!
//! Every function is compiled for these instructions and is safe: it takes
//! and returns values, never a pointer. Calling one from code that is not
//! compiled for them is what needs `unsafe`, and the parent module does it
//! once it has seen that the processor has them.

use core::arch::x86_64::*;

/// Sixteen octets, also read as four 32-bit words with their low octet
/// first.
pub(super) type V = __m128i;

macro_rules! operations {
    ($(
        $(#[$attribute:meta])*
        fn $name:ident $(<const $shift:ident: i32>)? ($($argument:ident: $kind:ty),*) -> $result:ty $body:block
    )*) => {$(
        $(#[$attribute])*
        #[inline]
        #[target_feature(enable = "ssse3,sse4.1,aes,pclmulqdq")]
        pub(super) fn $name $(<const $shift: i32>)? ($($argument: $kind),*) -> $result $body
    )*};
}

operations! {
    fn zero() -> V {
        _mm_setzero_si128()
    }

    fn from_octets(octets: [u8; 16]) -> V {
        let [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15] =
            octets.map(|octet| octet as i8);
        _mm_set_epi8(o15, o14, o13, o12, o11, o10, o9, o8, o7, o6, o5, o4, o3, o2, o1, o0)
    }

    fn from_words(words: [u32; 4]) -> V {
        let [w0, w1, w2, w3] = words.map(|word| word as i32);
        _mm_set_epi32(w3, w2, w1, w0)
    }

    fn to_words(vector: V) -> [u32; 4] {
        [
            _mm_cvtsi128_si32(vector) as u32,
            _mm_extract_epi32::<1>(vector) as u32,
            _mm_extract_epi32::<2>(vector) as u32,
            _mm_extract_epi32::<3>(vector) as u32,
        ]
    }

    fn splat8(octet: u8) -> V {
        _mm_set1_epi8(octet as i8)
    }

    fn xor(a: V, b: V) -> V {
        _mm_xor_si128(a, b)
    }

    fn and(a: V, b: V) -> V {
        _mm_and_si128(a, b)
    }

    fn or(a: V, b: V) -> V {
        _mm_or_si128(a, b)
    }

    /// Each 16-bit word shifted left. The callers mask what crosses from
    /// one octet into the next.
    fn shl16<const N: i32>(vector: V) -> V {
        _mm_slli_epi16::<N>(vector)
    }

    /// Each 16-bit word shifted right, with the same caution.
    fn shr16<const N: i32>(vector: V) -> V {
        _mm_srli_epi16::<N>(vector)
    }

    fn shl32<const N: i32>(vector: V) -> V {
        _mm_slli_epi32::<N>(vector)
    }

    fn shr32<const N: i32>(vector: V) -> V {
        _mm_srli_epi32::<N>(vector)
    }

    /// For each octet of `index`, the octet of `table` at that index when
    /// it is below 16, and zero when it is 0x80. The index is the operand
    /// of an instruction, not an address.
    fn shuffle(table: V, index: V) -> V {
        _mm_shuffle_epi8(table, index)
    }

    /// All ones in the octets that are equal.
    fn eq8(a: V, b: V) -> V {
        _mm_cmpeq_epi8(a, b)
    }

    /// The sums of the 32-bit words.
    fn add32(a: V, b: V) -> V {
        _mm_add_epi32(a, b)
    }

    /// Each octet added to itself.
    fn double8(vector: V) -> V {
        _mm_add_epi8(vector, vector)
    }

    /// All ones in the octets whose top bit is set.
    fn negative8(vector: V) -> V {
        _mm_cmpgt_epi8(_mm_setzero_si128(), vector)
    }

    /// SubBytes, ShiftRows and MixColumns of AES.
    fn aes_round(state: V) -> V {
        _mm_aesenc_si128(state, _mm_setzero_si128())
    }

    /// SubBytes and ShiftRows of AES.
    fn aes_last_round(state: V) -> V {
        _mm_aesenclast_si128(state, _mm_setzero_si128())
    }

    /// A round of AES and its round key.
    fn aes_round_key(state: V, key: V) -> V {
        _mm_aesenc_si128(state, key)
    }

    /// The last round of AES and its round key.
    fn aes_last_round_key(state: V, key: V) -> V {
        _mm_aesenclast_si128(state, key)
    }

    /// A word in the low half, and zero in the high half.
    fn from_u64(word: u64) -> V {
        _mm_cvtsi64_si128(word as i64)
    }

    /// The low half and the high half of a vector.
    fn from_u64s(low: u64, high: u64) -> V {
        _mm_set_epi64x(high as i64, low as i64)
    }

    /// The low half and the high half.
    fn to_u64s(vector: V) -> (u64, u64) {
        (
            _mm_cvtsi128_si64(vector) as u64,
            _mm_extract_epi64::<1>(vector) as u64,
        )
    }

    /// The carry-less product of the low halves.
    fn clmul_low(a: V, b: V) -> V {
        _mm_clmulepi64_si128::<0x00>(a, b)
    }

    /// The carry-less product of the high half of `a` and the low half of
    /// `b`.
    fn clmul_high_low(a: V, b: V) -> V {
        _mm_clmulepi64_si128::<0x01>(a, b)
    }
}

sboxes!("ssse3,sse4.1,aes,pclmulqdq");
generators!("ssse3,sse4.1,aes,pclmulqdq");
lanes!("ssse3,sse4.1,aes,pclmulqdq", 4);
