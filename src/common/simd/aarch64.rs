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

//! The vector operations of AArch64 that the generators are written with:
//! NEON, the AES round and the polynomial multiplication.
//!
//! Every function is compiled for these instructions and is safe: it takes
//! and returns values, never a pointer. Calling one from code that is not
//! compiled for them is what needs `unsafe`, and the parent module does it
//! once it has seen that the processor has them.

use core::arch::aarch64::*;

/// Sixteen octets, also read as four 32-bit words with their low octet
/// first.
pub(super) type V = uint8x16_t;

/// Whether the processor has the instructions that this module is compiled
/// for: NEON, and `aes`, the AES round with the polynomial multiplication.
/// With the standard library it is asked, when the program runs. Without,
/// it has them when the build says that every processor of its target does
/// (`-C target-feature`, `-C target-cpu`).
pub(super) fn detected() -> bool {
    // The vectors are built from words with their low octet first
    if cfg!(target_endian = "big") {
        return false;
    }
    #[cfg(feature = "std")]
    return std::arch::is_aarch64_feature_detected!("neon")
        && std::arch::is_aarch64_feature_detected!("aes");
    #[cfg(not(feature = "std"))]
    cfg!(all(target_feature = "neon", target_feature = "aes"))
}

macro_rules! operations {
    ($(
        $(#[$attribute:meta])*
        fn $name:ident $(<const $shift:ident: i32>)? ($($argument:ident: $kind:ty),*) -> $result:ty $body:block
    )*) => {$(
        $(#[$attribute])*
        #[inline]
        #[target_feature(enable = "neon,aes")]
        pub(super) fn $name $(<const $shift: i32>)? ($($argument: $kind),*) -> $result $body
    )*};
}

operations! {
    fn zero() -> V {
        vdupq_n_u8(0)
    }

    fn from_octets(octets: [u8; 16]) -> V {
        let [o0, o1, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15] = octets;
        vcombine_u8(
            vcreate_u8(u64::from_le_bytes([o0, o1, o2, o3, o4, o5, o6, o7])),
            vcreate_u8(u64::from_le_bytes([o8, o9, o10, o11, o12, o13, o14, o15])),
        )
    }

    fn from_words(words: [u32; 4]) -> V {
        let [w0, w1, w2, w3] = words.map(u64::from);
        vreinterpretq_u8_u64(vcombine_u64(vcreate_u64(w0 | (w1 << 32)), vcreate_u64(w2 | (w3 << 32))))
    }

    fn to_words(vector: V) -> [u32; 4] {
        let vector = vreinterpretq_u32_u8(vector);
        [
            vgetq_lane_u32::<0>(vector),
            vgetq_lane_u32::<1>(vector),
            vgetq_lane_u32::<2>(vector),
            vgetq_lane_u32::<3>(vector),
        ]
    }

    fn splat8(octet: u8) -> V {
        vdupq_n_u8(octet)
    }

    fn xor(a: V, b: V) -> V {
        veorq_u8(a, b)
    }

    fn and(a: V, b: V) -> V {
        vandq_u8(a, b)
    }

    fn or(a: V, b: V) -> V {
        vorrq_u8(a, b)
    }

    /// Each 16-bit word shifted left. The callers mask what crosses from
    /// one octet into the next.
    fn shl16<const N: i32>(vector: V) -> V {
        vreinterpretq_u8_u16(vshlq_n_u16::<N>(vreinterpretq_u16_u8(vector)))
    }

    /// Each 16-bit word shifted right, with the same caution.
    fn shr16<const N: i32>(vector: V) -> V {
        vreinterpretq_u8_u16(vshrq_n_u16::<N>(vreinterpretq_u16_u8(vector)))
    }

    fn shl32<const N: i32>(vector: V) -> V {
        vreinterpretq_u8_u32(vshlq_n_u32::<N>(vreinterpretq_u32_u8(vector)))
    }

    fn shr32<const N: i32>(vector: V) -> V {
        vreinterpretq_u8_u32(vshrq_n_u32::<N>(vreinterpretq_u32_u8(vector)))
    }

    /// For each octet of `index`, the octet of `table` at that index when
    /// it is below 16, and zero when it is 0x80. The index is the operand
    /// of an instruction, not an address.
    fn shuffle(table: V, index: V) -> V {
        vqtbl1q_u8(table, index)
    }

    /// All ones in the octets that are equal.
    fn eq8(a: V, b: V) -> V {
        vceqq_u8(a, b)
    }

    /// The sums of the 32-bit words.
    fn add32(a: V, b: V) -> V {
        vreinterpretq_u8_u32(vaddq_u32(vreinterpretq_u32_u8(a), vreinterpretq_u32_u8(b)))
    }

    /// Each octet added to itself.
    fn double8(vector: V) -> V {
        vaddq_u8(vector, vector)
    }

    /// All ones in the octets whose top bit is set.
    fn negative8(vector: V) -> V {
        vcltzq_s8(vreinterpretq_s8_u8(vector))
    }

    /// SubBytes, ShiftRows and MixColumns of AES.
    fn aes_round(state: V) -> V {
        vaesmcq_u8(vaeseq_u8(state, vdupq_n_u8(0)))
    }

    /// SubBytes and ShiftRows of AES.
    fn aes_last_round(state: V) -> V {
        vaeseq_u8(state, vdupq_n_u8(0))
    }

    /// The carry-less product of two words, low word then high word.
    fn clmul(x: u64, y: u64) -> (u64, u64) {
        let product = vmull_p64(x, y);
        (product as u64, (product >> 64) as u64)
    }
}

algorithms!("neon,aes");
