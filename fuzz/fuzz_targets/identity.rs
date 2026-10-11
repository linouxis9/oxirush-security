//! The identities and the digit strings of a peer never panic the functions
//! that read them, and what decodes encodes back to the octets it came from.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::nas_5gs::{
    build_guti_bytes, mobile_identity_type, msin_to_bcd, parse_guti_tmsi, parse_s_tmsi,
};
use oxirush_security::plmn::{
    plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode, try_tbcd_decode,
};

fuzz_target!(|bytes: &[u8]| {
    // A 5G-GUTI or a 5G-S-TMSI mobile identity
    let _ = mobile_identity_type(bytes);
    let _ = parse_s_tmsi(bytes);
    if let Some(tmsi) = parse_guti_tmsi(bytes) {
        // The same fields build a 5G-GUTI with the same 5G-TMSI
        let plmn = [bytes[1], bytes[2], bytes[3]];
        let set = (u16::from(bytes[5]) << 2) | u16::from(bytes[6] >> 6);
        let rebuilt = build_guti_bytes(&plmn, bytes[4], set, bytes[6] & 0x3f, tmsi)
            .expect("the fields of a GUTI are in range");
        assert_eq!(rebuilt[1..], bytes[1..11]);
        assert_eq!(parse_guti_tmsi(&rebuilt), Some(tmsi));
    }

    // A PLMN identity: what decodes encodes to the same three octets
    if let Some((mcc, mnc)) = plmn_from_bytes(bytes) {
        let encoded = plmn_to_bytes(&mcc, &mnc).expect("decoded digits encode");
        assert_eq!(encoded, bytes[..3]);
    }

    // A TBCD string: the characters up to the filler encode to octets that
    // decode to the same characters
    let text = tbcd_decode(bytes);
    let encoded = tbcd_encode(&text).expect("decoded characters encode");
    assert_eq!(tbcd_decode(&encoded), text);

    // A decimal TBCD string, which has only a final filler, is its octets
    if let Some(digits) = try_tbcd_decode(bytes) {
        assert_eq!(tbcd_encode(&digits).as_deref(), Ok(bytes));
        assert_eq!(digits, text);
    }

    // Text from a configuration is refused or encoded, never a panic
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = tbcd_encode(text);
        let _ = msin_to_bcd(text);
        if let Some((mcc, mnc)) = text.split_at_checked(3) {
            let _ = plmn_to_bytes(mcc, mnc);
        }
    }
});
