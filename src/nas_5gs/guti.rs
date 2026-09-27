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

//! 5G-GUTI construction and parsing (TS 24.501 §9.11.3.4)

/// Build the 11-byte 5G-GUTI mobile identity value.
///
/// Layout (TS 24.501 §9.11.3.4, Figure 9.11.3.4.1):
/// ```text
///   [0]      0xF2 = bits 8-5 "1111" | spare(0) | type(010 = 5G-GUTI)
///   [1..3]   PLMN (3 bytes)
///   [4]      AMF Region ID (8 bits)
///   [5..6]   AMF Set ID (10 bits) || AMF Pointer (6 bits)
///   [7..10]  5G-TMSI (4 bytes)
/// ```
///
/// # Panics
///
/// Panics if `plmn_bytes` has fewer than three octets, `amf_set_id` exceeds
/// 10 bits, or `amf_pointer` exceeds 6 bits.
pub fn build_guti_bytes(
    plmn_bytes: &[u8],
    amf_region_id: u8,
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
) -> Vec<u8> {
    assert!(plmn_bytes.len() >= 3, "PLMN must contain three octets");
    assert!(amf_set_id <= 0x3FF, "AMF Set ID must be 10 bits");
    assert!(amf_pointer <= 0x3F, "AMF Pointer must be 6 bits");
    let mut g = Vec::with_capacity(11);
    // TS 24.501 Figure 9.11.3.4.1: bits 8-5 are "1111", bit 4 is spare, and
    // bits 3-1 are type 010.
    g.push(0xF2);
    g.extend_from_slice(&plmn_bytes[..3]);
    g.push(amf_region_id);
    g.push((amf_set_id >> 2) as u8);
    g.push(((amf_set_id as u8 & 0x03) << 6) | (amf_pointer & 0x3F));
    g.extend_from_slice(&tmsi.to_be_bytes());
    g
}

/// Parse a 5G-GUTI mobile identity (type 010) and return the 5G-TMSI.
/// Only the type bits of the first octet are checked.
pub fn parse_guti_tmsi(identity: &[u8]) -> Option<u32> {
    if identity.len() < 11 {
        return None;
    }
    if identity[0] & 0x07 != 0x02 {
        return None;
    }
    let tmsi = u32::from_be_bytes(identity[7..11].try_into().ok()?);
    Some(tmsi)
}

/// Parse a 5G-S-TMSI mobile identity (type=0x04) and return the 5G-TMSI.
///
/// Layout (TS 24.501 §9.11.3.4, Figure 9.11.3.4.5):
/// ```text
///   [0]      0xF4 = bits 8-5 "1111" | spare(0) | type(100 = 5G-S-TMSI);
///            only the type bits are checked
///   [1]      AMF Set ID bits [9:2]
///   [2]      AMF Set ID bits [1:0] || AMF Pointer bits [5:0]
///   [3..6]   5G-TMSI (4 bytes)
/// ```
pub fn parse_s_tmsi(identity: &[u8]) -> Option<u32> {
    if identity.len() < 7 {
        return None;
    }
    if identity[0] & 0x07 != 0x04 {
        return None;
    }
    let tmsi = u32::from_be_bytes(identity[3..7].try_into().ok()?);
    Some(tmsi)
}

/// Return the mobile identity type from the first byte (bits 2:0).
pub fn mobile_identity_type(identity: &[u8]) -> u8 {
    if identity.is_empty() {
        0
    } else {
        identity[0] & 0x07
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guti_and_s_tmsi_use_the_ts_24501_identity_octet() {
        let guti = build_guti_bytes(&[0x02, 0xf8, 0x39], 0xca, 0x3ff, 0x3f, 0x1234_5678);
        assert_eq!(guti[0], 0xf2);
        assert_eq!(&guti[5..7], [0xff, 0xff]);
        assert_eq!(parse_guti_tmsi(&guti), Some(0x1234_5678));
        // Receivers check only the type bits.
        let mut legacy = guti.clone();
        legacy[0] = 0x02;
        assert_eq!(parse_guti_tmsi(&legacy), Some(0x1234_5678));
        assert_eq!(parse_s_tmsi(&[0xf4, 0xff, 0xff, 0, 0, 0, 7]), Some(7));
        assert_eq!(parse_s_tmsi(&[0xf2, 0xff, 0xff, 0, 0, 0, 7]), None);
        // TS 24.501 receiver behavior ignores excess contents for these identities.
        let mut long_guti = guti.clone();
        long_guti.extend_from_slice(&[0xaa, 0xbb]);
        assert_eq!(parse_guti_tmsi(&long_guti), Some(0x1234_5678));
        assert_eq!(parse_s_tmsi(&[0xf4, 0xff, 0xff, 0, 0, 0, 7, 0xaa]), Some(7));
        assert_eq!(mobile_identity_type(&guti), 2);
    }
}
