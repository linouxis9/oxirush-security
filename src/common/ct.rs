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

//! Table lookups whose memory accesses do not depend on the index, and a
//! comparison whose time does not depend on the contents.

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

/// Word-sized table entries for [`lookup`].
pub(crate) trait Entry: Copy {
    fn to_word(self) -> u32;
    fn from_word(word: u32) -> Self;
}

impl Entry for u8 {
    fn to_word(self) -> u32 {
        u32::from(self)
    }

    fn from_word(word: u32) -> Self {
        word as u8
    }
}

impl Entry for u32 {
    fn to_word(self) -> u32 {
        self
    }

    fn from_word(word: u32) -> Self {
        word
    }
}

/// `table[index]`, read by visiting every entry and keeping the matching
/// one through a mask, so neither the memory accesses nor the branches of
/// the lookup depend on a secret index.
#[inline]
pub(crate) fn lookup<T: Entry>(table: &[T; 256], index: u8) -> T {
    let index = u32::from(index);
    let mut value = 0;
    for (candidate, entry) in (0u32..).zip(table) {
        // All ones when the candidate is the index: only then does the
        // difference minus one wrap to set bit 31.
        let mask = 0u32.wrapping_sub((candidate ^ index).wrapping_sub(1) >> 31);
        value |= entry.to_word() & mask;
    }
    T::from_word(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_reads_every_index() {
        let table: [u32; 256] = core::array::from_fn(|index| ((index as u32) * 0x0101_0101) ^ 0x5a);
        for index in 0..=u8::MAX {
            assert_eq!(lookup(&table, index), table[usize::from(index)]);
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
