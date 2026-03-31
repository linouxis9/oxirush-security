//! 5G-GUTI construction and parsing (TS 24.501 §9.11.3.4)

/// Build the 11-byte 5G-GUTI mobile identity value.
///
/// Layout (TS 24.501 §9.11.3.4, Figure 9.11.3.4.3):
///   [0]      0xF2 = spare(0xF) | odd/even(0) | type(010 = 5G-GUTI)
///   [1..3]   PLMN (3 bytes)
///   [4]      AMF Region ID (8 bits)
///   [5..6]   AMF Set ID (10 bits) || AMF Pointer (6 bits)
///   [7..10]  5G-TMSI (4 bytes)
pub fn build_guti_bytes(
    plmn_bytes: &[u8],
    amf_region_id: u8,
    amf_set_id: u16,
    amf_pointer: u8,
    tmsi: u32,
) -> Vec<u8> {
    debug_assert!(amf_set_id <= 0x3FF, "AMF Set ID must be 10 bits");
    debug_assert!(amf_pointer <= 0x3F, "AMF Pointer must be 6 bits");
    let mut g = Vec::with_capacity(11);
    g.push(0xF2); // spare=0xF | even | type=0x02 (5G-GUTI)
    g.extend_from_slice(&plmn_bytes[..3]);
    g.push(amf_region_id);
    g.push((amf_set_id >> 2) as u8);
    g.push(((amf_set_id as u8 & 0x03) << 6) | (amf_pointer & 0x3F));
    g.extend_from_slice(&tmsi.to_be_bytes());
    g
}

/// Parse a 5G-GUTI mobile identity (type=0x02) and return the 5G-TMSI.
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
/// Layout (TS 24.501 §9.11.3.4, Figure 9.11.3.4.4):
///   [0]      0xF4 = spare(0xF) | odd/even(0) | type(100 = 5G-S-TMSI)
///   [1]      AMF Set ID bits [9:2]
///   [2]      AMF Set ID bits [1:0] || AMF Pointer bits [5:0]
///   [3..6]   5G-TMSI (4 bytes)
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
