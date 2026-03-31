//! NAS security algorithm selection per 3GPP TS 33.501.
//!
//! UE security capability byte layout (TS 24.501 §9.11.3.54):
//!   byte[0]: 5G-EA bits — bit7=NEA0, bit6=NEA1, bit5=NEA2, bit4=NEA3
//!   byte[1]: 5G-IA bits — bit7=NIA0, bit6=NIA1, bit5=NIA2, bit4=NIA3

/// AMF integrity algorithm preference: NIA2 > NIA1 > NIA3.
/// NIA0 (null) is excluded per TS 33.501 §5.5 — integrity protection is mandatory.
/// Each entry: (bitmask in capability byte, algorithm ID).
const NIA_PREFERENCE: &[(u8, u8)] = &[
    (0x20, 0x02), // NIA2 (AES-CMAC)
    (0x40, 0x01), // NIA1 (SNOW 3G)
    (0x10, 0x03), // NIA3 (ZUC)
];

/// AMF ciphering algorithm preference: NEA2 > NEA1 > NEA3 > NEA0.
const NEA_PREFERENCE: &[(u8, u8)] = &[
    (0x20, 0x02), // NEA2 (AES-CTR)
    (0x40, 0x01), // NEA1 (SNOW 3G)
    (0x10, 0x03), // NEA3 (ZUC)
    (0x80, 0x00), // NEA0 (null)
];

/// Select the best integrity algorithm supported by the UE.
///
/// `nia_capability` is byte[1] of the UE security capability (5G-IA bits).
/// Returns `Some(algorithm_id)` (0x01–0x03), or `None` if no valid algorithm matches.
/// NIA0 (null) is never selected — integrity protection is mandatory.
pub fn select_integrity_algo(nia_capability: u8) -> Option<u8> {
    for &(mask, algo) in NIA_PREFERENCE {
        if nia_capability & mask != 0 {
            return Some(algo);
        }
    }
    None
}

/// Select the best ciphering algorithm supported by the UE.
///
/// `nea_capability` is byte[0] of the UE security capability (5G-EA bits).
/// Returns `Some(algorithm_id)` (0x00–0x03), or `None` if no bits match.
pub fn select_ciphering_algo(nea_capability: u8) -> Option<u8> {
    for &(mask, algo) in NEA_PREFERENCE {
        if nea_capability & mask != 0 {
            return Some(algo);
        }
    }
    None
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
}
