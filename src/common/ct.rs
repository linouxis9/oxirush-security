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

//! Table lookups whose memory accesses do not depend on the index.

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
}
