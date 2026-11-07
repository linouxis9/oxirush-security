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

use oxirush_utils::identity::Algorithm;

/// The integrity algorithms that an operator prefers by default: 2, then 1,
/// then 3. The null algorithm is left out: ordinary signalling must not use
/// it.
pub const DEFAULT_INTEGRITY_PREFERENCE: &[Algorithm] =
    &[Algorithm::Aes, Algorithm::Snow3g, Algorithm::Zuc];

/// The ciphering algorithms that an operator prefers by default: 2, then 1,
/// then 3, then the null algorithm.
pub const DEFAULT_CIPHERING_PREFERENCE: &[Algorithm] = &[
    Algorithm::Aes,
    Algorithm::Snow3g,
    Algorithm::Zuc,
    Algorithm::Null,
];

/// The first integrity algorithm of an operator's `preference` that the UE
/// supports (TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1); `None` when it
/// supports none of them.
///
/// `capability` is the octet of the integrity algorithms of a UE security
/// capability: 5G-IA0 to 5G-IA7 or EIA0 to EIA7. A preference with
/// [`Algorithm::Null`] permits null integrity, which is for
/// unauthenticated emergency sessions only.
///
/// ```
/// use oxirush_security::identity::Algorithm;
/// use oxirush_security::{DEFAULT_INTEGRITY_PREFERENCE, select_integrity_algorithm};
///
/// // A UE security capability of IA1 and IA2, then one of IA0 alone
/// assert_eq!(select_integrity_algorithm(0x60, DEFAULT_INTEGRITY_PREFERENCE), Some(Algorithm::Aes));
/// assert_eq!(select_integrity_algorithm(0x80, DEFAULT_INTEGRITY_PREFERENCE), None);
/// ```
pub fn select_integrity_algorithm(capability: u8, preference: &[Algorithm]) -> Option<Algorithm> {
    preference
        .iter()
        .copied()
        .find(|algorithm| supported(capability, (*algorithm).into()))
}

/// The first ciphering algorithm of an operator's `preference` that the UE
/// supports (TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1); `None` when it
/// supports none of them.
///
/// `capability` is the octet of the ciphering algorithms: 5G-EA0 to 5G-EA7
/// or EEA0 to EEA7.
///
/// ```
/// use oxirush_security::identity::Algorithm;
/// use oxirush_security::{DEFAULT_CIPHERING_PREFERENCE, select_ciphering_algorithm};
///
/// // A UE security capability of EA0, EA1 and EA2, then one of EA0 alone
/// assert_eq!(select_ciphering_algorithm(0xe0, DEFAULT_CIPHERING_PREFERENCE), Some(Algorithm::Aes));
/// assert_eq!(select_ciphering_algorithm(0x80, DEFAULT_CIPHERING_PREFERENCE), Some(Algorithm::Null));
/// ```
pub fn select_ciphering_algorithm(capability: u8, preference: &[Algorithm]) -> Option<Algorithm> {
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

    #[test]
    fn integrity_prefers_nia2() {
        // All algorithms supported → picks NIA2
        assert_eq!(
            select_integrity_algorithm(0xF0, DEFAULT_INTEGRITY_PREFERENCE),
            Some(Algorithm::Aes)
        );
    }

    #[test]
    fn integrity_nia1_when_no_nia2() {
        assert_eq!(
            select_integrity_algorithm(0xD0, DEFAULT_INTEGRITY_PREFERENCE),
            Some(Algorithm::Snow3g)
        ); // NIA0 + NIA1 + NIA3
    }

    #[test]
    fn integrity_nia3_when_only_nia3_nia0() {
        assert_eq!(
            select_integrity_algorithm(0x90, DEFAULT_INTEGRITY_PREFERENCE),
            Some(Algorithm::Zuc)
        ); // NIA0 + NIA3
    }

    #[test]
    fn integrity_rejects_nia0_only() {
        // NIA0 (null) is never selected — returns None
        assert_eq!(
            select_integrity_algorithm(0x80, DEFAULT_INTEGRITY_PREFERENCE),
            None
        );
    }

    #[test]
    fn integrity_none_without_capability() {
        assert_eq!(
            select_integrity_algorithm(0x00, DEFAULT_INTEGRITY_PREFERENCE),
            None
        );
        // The bits of algorithms 4 to 7 select nothing
        assert_eq!(
            select_integrity_algorithm(0x0f, DEFAULT_INTEGRITY_PREFERENCE),
            None
        );
    }

    #[test]
    fn ciphering_prefers_nea2() {
        assert_eq!(
            select_ciphering_algorithm(0xF0, DEFAULT_CIPHERING_PREFERENCE),
            Some(Algorithm::Aes)
        );
    }

    #[test]
    fn ciphering_nea1_when_no_nea2() {
        assert_eq!(
            select_ciphering_algorithm(0xC0, DEFAULT_CIPHERING_PREFERENCE),
            Some(Algorithm::Snow3g)
        ); // NEA0 + NEA1
    }

    #[test]
    fn ciphering_nea3_when_only_nea3() {
        assert_eq!(
            select_ciphering_algorithm(0x10, DEFAULT_CIPHERING_PREFERENCE),
            Some(Algorithm::Zuc)
        );
    }

    #[test]
    fn ciphering_fallback_nea0() {
        // Only NEA0 bit set → NEA0 selected
        assert_eq!(
            select_ciphering_algorithm(0x80, DEFAULT_CIPHERING_PREFERENCE),
            Some(Algorithm::Null)
        );
    }

    #[test]
    fn ciphering_none_without_capability() {
        assert_eq!(
            select_ciphering_algorithm(0x00, DEFAULT_CIPHERING_PREFERENCE),
            None
        );
        assert_eq!(
            select_ciphering_algorithm(0x0f, DEFAULT_CIPHERING_PREFERENCE),
            None
        );
    }

    #[test]
    fn operator_order_and_explicit_null_policy_are_honoured() {
        assert_eq!(
            select_integrity_algorithm(0x70, &[Algorithm::Zuc, Algorithm::Snow3g, Algorithm::Aes]),
            Some(Algorithm::Zuc)
        );
        assert_eq!(
            select_ciphering_algorithm(0x70, &[Algorithm::Snow3g, Algorithm::Zuc, Algorithm::Aes]),
            Some(Algorithm::Snow3g)
        );
        assert_eq!(
            select_integrity_algorithm(0x80, &[Algorithm::Aes, Algorithm::Snow3g, Algorithm::Zuc]),
            None
        );
        assert_eq!(
            select_integrity_algorithm(0x80, &[Algorithm::Null]),
            Some(Algorithm::Null)
        );
        assert_eq!(select_ciphering_algorithm(0xf0, &[]), None);
    }
}
