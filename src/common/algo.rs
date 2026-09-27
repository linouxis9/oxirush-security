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

//! Shared NAS algorithm selection for 5GS and EPS.
//!
//! The first capability byte has EA bits and the second has IA bits. Both
//! TS 24.501 and TS 24.301 assign bit 8 to algorithm 0, bit 7 to algorithm 1,
//! bit 6 to algorithm 2, and bit 5 to algorithm 3.

/// Default integrity algorithm preference: algorithm 2 > 1 > 3.
/// Null integrity is excluded from ordinary protected NAS signalling.
const NIA_PREFERENCE: &[u8] = &[2, 1, 3];

/// Default ciphering algorithm preference: algorithm 2 > 1 > 3 > 0.
const NEA_PREFERENCE: &[u8] = &[2, 1, 3, 0];

/// Select the best integrity algorithm supported by the UE.
///
/// `nia_capability` is the IA capability byte.
/// Returns `Some(algorithm_id)` (0x01–0x03), or `None` if no valid algorithm matches.
/// Algorithm 0 (null) is not selected for ordinary protected signalling.
pub fn select_integrity_algo(nia_capability: u8) -> Option<u8> {
    select_integrity_algo_with_preference(nia_capability, NIA_PREFERENCE)
}

/// Select the first integrity algorithm in an operator-configured preference
/// list that the UE supports (TS 33.401 §7.2.4.3.1 and TS 33.501 §6.7.1).
///
/// Algorithm IDs outside 0 through 3 are ignored. Including algorithm 0 in
/// `preference` explicitly permits null integrity for the exceptional
/// unauthenticated emergency/RLOS policy; ordinary signalling should omit it.
pub fn select_integrity_algo_with_preference(nia_capability: u8, preference: &[u8]) -> Option<u8> {
    select_with_preference(nia_capability, preference)
}

/// Select the best ciphering algorithm supported by the UE.
///
/// `nea_capability` is the EA capability byte.
/// Returns `Some(algorithm_id)` (0x00–0x03), or `None` if no bits match.
pub fn select_ciphering_algo(nea_capability: u8) -> Option<u8> {
    select_ciphering_algo_with_preference(nea_capability, NEA_PREFERENCE)
}

/// Select the first ciphering algorithm in an operator-configured preference
/// list that the UE supports. Algorithm IDs outside 0 through 3 are ignored.
pub fn select_ciphering_algo_with_preference(nea_capability: u8, preference: &[u8]) -> Option<u8> {
    select_with_preference(nea_capability, preference)
}

fn select_with_preference(capability: u8, preference: &[u8]) -> Option<u8> {
    preference
        .iter()
        .copied()
        .filter(|algorithm| *algorithm <= 3)
        .find(|algorithm| capability & (0x80 >> algorithm) != 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrity_prefers_nia2() {
        // All algorithms supported → picks NIA2
        assert_eq!(select_integrity_algo(0xF0), Some(0x02));
    }

    #[test]
    fn integrity_nia1_when_no_nia2() {
        assert_eq!(select_integrity_algo(0xD0), Some(0x01)); // NIA0 + NIA1 + NIA3
    }

    #[test]
    fn integrity_nia3_when_only_nia3_nia0() {
        assert_eq!(select_integrity_algo(0x90), Some(0x03)); // NIA0 + NIA3
    }

    #[test]
    fn integrity_rejects_nia0_only() {
        // NIA0 (null) is never selected — returns None
        assert_eq!(select_integrity_algo(0x80), None);
    }

    #[test]
    fn integrity_fallback_nia2() {
        assert_eq!(select_integrity_algo(0x00), None);
    }

    #[test]
    fn ciphering_prefers_nea2() {
        assert_eq!(select_ciphering_algo(0xF0), Some(0x02));
    }

    #[test]
    fn ciphering_nea1_when_no_nea2() {
        assert_eq!(select_ciphering_algo(0xC0), Some(0x01)); // NEA0 + NEA1
    }

    #[test]
    fn ciphering_nea3_when_only_nea3() {
        assert_eq!(select_ciphering_algo(0x10), Some(0x03));
    }

    #[test]
    fn ciphering_fallback_nea0() {
        // Only NEA0 bit set → NEA0 selected
        assert_eq!(select_ciphering_algo(0x80), Some(0x00));
    }

    #[test]
    fn ciphering_no_bits_nea0() {
        assert_eq!(select_ciphering_algo(0x00), None);
    }

    #[test]
    fn operator_order_and_explicit_null_policy_are_honoured() {
        assert_eq!(
            select_integrity_algo_with_preference(0x70, &[3, 1, 2]),
            Some(3)
        );
        assert_eq!(
            select_ciphering_algo_with_preference(0x70, &[1, 3, 2]),
            Some(1)
        );
        assert_eq!(
            select_integrity_algo_with_preference(0x80, &[2, 1, 3]),
            None
        );
        assert_eq!(select_integrity_algo_with_preference(0x80, &[0]), Some(0));
        assert_eq!(
            select_ciphering_algo_with_preference(0x20, &[9, 2]),
            Some(2)
        );
    }
}
