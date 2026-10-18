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

//! Algorithm selection from the capabilities of a UE, for 5GS and EPS.
//!
//! A UE security capability gives one octet to the ciphering algorithms
//! and one to the integrity algorithms. TS 24.501 §9.11.3.54 and TS 24.301
//! §9.9.3.34 both assign bit 8 to algorithm 0, bit 7 to algorithm 1, bit 6
//! to algorithm 2 and bit 5 to algorithm 3, so one function reads the octet
//! of either system.

use crate::common::input::{CipheringAlgorithm, IntegrityAlgorithm};

/// Default integrity algorithm preference: algorithm 2 > 1 > 3.
/// Null integrity is excluded from ordinary protected NAS signalling.
const INTEGRITY_PREFERENCE: &[IntegrityAlgorithm] = &[
    IntegrityAlgorithm::Aes,
    IntegrityAlgorithm::Snow3g,
    IntegrityAlgorithm::Zuc,
];

/// Default ciphering algorithm preference: algorithm 2 > 1 > 3 > 0.
const CIPHERING_PREFERENCE: &[CipheringAlgorithm] = &[
    CipheringAlgorithm::Aes,
    CipheringAlgorithm::Snow3g,
    CipheringAlgorithm::Zuc,
    CipheringAlgorithm::Null,
];

/// Select the integrity algorithm for a UE with the default preference:
/// algorithm 2, then 1, then 3.
///
/// `capability` is the octet of the integrity algorithms: 5G-IA0 to 5G-IA7
/// or EIA0 to EIA7. The null algorithm is not selected, as ordinary
/// signalling must not use it; `None` when the UE supports none of the
/// three others.
///
/// ```
/// use oxirush_security::{IntegrityAlgorithm, select_integrity_algo};
///
/// // A UE security capability of IA1 and IA2, then one of IA0 alone
/// assert_eq!(select_integrity_algo(0x60), Some(IntegrityAlgorithm::NIA2));
/// assert_eq!(select_integrity_algo(0x80), None);
/// ```
pub fn select_integrity_algo(capability: u8) -> Option<IntegrityAlgorithm> {
    select_integrity_algo_with_preference(capability, INTEGRITY_PREFERENCE)
}

/// Select the first integrity algorithm of an operator's preference list
/// that the UE supports (TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1).
///
/// A list with [`IntegrityAlgorithm::Null`] permits null integrity, which
/// is for unauthenticated emergency sessions only; a list for ordinary
/// signalling leaves it out.
pub fn select_integrity_algo_with_preference(
    capability: u8,
    preference: &[IntegrityAlgorithm],
) -> Option<IntegrityAlgorithm> {
    preference
        .iter()
        .copied()
        .find(|algorithm| supported(capability, (*algorithm).into()))
}

/// Select the ciphering algorithm for a UE with the default preference:
/// algorithm 2, then 1, then 3, then the null algorithm.
///
/// `capability` is the octet of the ciphering algorithms: 5G-EA0 to 5G-EA7
/// or EEA0 to EEA7. `None` when the UE supports none of the four.
///
/// ```
/// use oxirush_security::{CipheringAlgorithm, select_ciphering_algo};
///
/// // A UE security capability of EA0, EA1 and EA2, then one of EA0 alone
/// assert_eq!(select_ciphering_algo(0xe0), Some(CipheringAlgorithm::NEA2));
/// assert_eq!(select_ciphering_algo(0x80), Some(CipheringAlgorithm::NEA0));
/// ```
pub fn select_ciphering_algo(capability: u8) -> Option<CipheringAlgorithm> {
    select_ciphering_algo_with_preference(capability, CIPHERING_PREFERENCE)
}

/// Select the first ciphering algorithm of an operator's preference list
/// that the UE supports (TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1).
pub fn select_ciphering_algo_with_preference(
    capability: u8,
    preference: &[CipheringAlgorithm],
) -> Option<CipheringAlgorithm> {
    preference
        .iter()
        .copied()
        .find(|algorithm| supported(capability, (*algorithm).into()))
}

/// Whether the capability octet has the bit of an algorithm: bit 8 for
/// algorithm 0 down to bit 5 for algorithm 3.
fn supported(capability: u8, identifier: u8) -> bool {
    capability & (0x80 >> identifier) != 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use CipheringAlgorithm as Nea;
    use IntegrityAlgorithm as Nia;

    #[test]
    fn integrity_prefers_nia2() {
        // All algorithms supported → picks NIA2
        assert_eq!(select_integrity_algo(0xF0), Some(Nia::NIA2));
    }

    #[test]
    fn integrity_nia1_when_no_nia2() {
        assert_eq!(select_integrity_algo(0xD0), Some(Nia::NIA1)); // NIA0 + NIA1 + NIA3
    }

    #[test]
    fn integrity_nia3_when_only_nia3_nia0() {
        assert_eq!(select_integrity_algo(0x90), Some(Nia::NIA3)); // NIA0 + NIA3
    }

    #[test]
    fn integrity_rejects_nia0_only() {
        // NIA0 (null) is never selected — returns None
        assert_eq!(select_integrity_algo(0x80), None);
    }

    #[test]
    fn integrity_none_without_capability() {
        assert_eq!(select_integrity_algo(0x00), None);
        // The bits of algorithms 4 to 7 select nothing
        assert_eq!(select_integrity_algo(0x0f), None);
    }

    #[test]
    fn ciphering_prefers_nea2() {
        assert_eq!(select_ciphering_algo(0xF0), Some(Nea::NEA2));
    }

    #[test]
    fn ciphering_nea1_when_no_nea2() {
        assert_eq!(select_ciphering_algo(0xC0), Some(Nea::NEA1)); // NEA0 + NEA1
    }

    #[test]
    fn ciphering_nea3_when_only_nea3() {
        assert_eq!(select_ciphering_algo(0x10), Some(Nea::NEA3));
    }

    #[test]
    fn ciphering_fallback_nea0() {
        // Only NEA0 bit set → NEA0 selected
        assert_eq!(select_ciphering_algo(0x80), Some(Nea::NEA0));
    }

    #[test]
    fn ciphering_none_without_capability() {
        assert_eq!(select_ciphering_algo(0x00), None);
        assert_eq!(select_ciphering_algo(0x0f), None);
    }

    #[test]
    fn operator_order_and_explicit_null_policy_are_honoured() {
        assert_eq!(
            select_integrity_algo_with_preference(0x70, &[Nia::Zuc, Nia::Snow3g, Nia::Aes]),
            Some(Nia::Zuc)
        );
        assert_eq!(
            select_ciphering_algo_with_preference(0x70, &[Nea::Snow3g, Nea::Zuc, Nea::Aes]),
            Some(Nea::Snow3g)
        );
        assert_eq!(
            select_integrity_algo_with_preference(0x80, &[Nia::Aes, Nia::Snow3g, Nia::Zuc]),
            None
        );
        assert_eq!(
            select_integrity_algo_with_preference(0x80, &[Nia::Null]),
            Some(Nia::Null)
        );
        assert_eq!(select_ciphering_algo_with_preference(0xf0, &[]), None);
    }
}
