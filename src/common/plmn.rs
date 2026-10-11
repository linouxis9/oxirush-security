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

//! PLMN and TBCD encoding/decoding utilities per 3GPP TS 24.301 and TS 24.501.

use crate::common::error::SecurityError;

/// Encode an MCC and an MNC as the three octets of a PLMN identity
/// (TS 24.501 §9.11.3.4, TS 24.301 §9.9.3.12).
///
/// An `mcc` that is not three decimal digits, or an `mnc` that is not two
/// or three, is [`SecurityError::InvalidParameter`].
pub fn plmn_to_bytes(mcc: &str, mnc: &str) -> Result<[u8; 3], SecurityError> {
    let digits = |text: &str, value: &mut [u8]| {
        let text = text.as_bytes();
        let decimal = text.len() == value.len() && text.iter().all(u8::is_ascii_digit);
        for (digit, character) in value.iter_mut().zip(text) {
            *digit = character.wrapping_sub(b'0');
        }
        decimal
    };
    let mut mcc_digits = [0u8; 3];
    if !digits(mcc, &mut mcc_digits) {
        return Err(SecurityError::InvalidParameter(
            "MCC must be 3 decimal digits",
        ));
    }
    // A two-digit MNC has the filler 0xF in the place of a third digit
    let mut mnc_digits = [0, 0, 0x0f];
    let mnc_length = if mnc.len() == 2 { 2 } else { 3 };
    if !digits(mnc, &mut mnc_digits[..mnc_length]) {
        return Err(SecurityError::InvalidParameter(
            "MNC must be 2 or 3 decimal digits",
        ));
    }
    Ok([
        (mcc_digits[1] << 4) | mcc_digits[0],
        (mnc_digits[2] << 4) | mcc_digits[2],
        (mnc_digits[1] << 4) | mnc_digits[0],
    ])
}

/// Decode PLMN bytes back to (MCC, MNC) strings.
pub fn plmn_from_bytes(bytes: &[u8]) -> Option<(String, String)> {
    if bytes.len() < 3 {
        return None;
    }
    let mcc0 = bytes[0] & 0x0F;
    let mcc1 = (bytes[0] >> 4) & 0x0F;
    let mcc2 = bytes[1] & 0x0F;
    let mnc_hi = (bytes[1] >> 4) & 0x0F;
    let mnc0 = bytes[2] & 0x0F;
    let mnc1 = (bytes[2] >> 4) & 0x0F;

    if [mcc0, mcc1, mcc2, mnc0, mnc1]
        .iter()
        .any(|digit| *digit > 9)
        || (mnc_hi > 9 && mnc_hi != 0x0f)
    {
        return None;
    }

    let mcc = format!("{mcc0}{mcc1}{mcc2}");
    let mnc = if mnc_hi == 0xF {
        format!("{mnc0}{mnc1}")
    } else {
        format!("{mnc0}{mnc1}{mnc_hi}")
    };
    Some((mcc, mnc))
}

/// Decode a TBCD-STRING (TS 29.002): the low nibble of each octet, then the
/// high nibble, up to the first 0xF filler.
///
/// 0 to 9 decode as digits and 0xA to 0xE as "*", "#", "a", "b" and "c".
/// Use [`try_tbcd_decode`] for a decimal value, such as an IMSI, that must
/// have only a final filler.
pub fn tbcd_decode(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|octet| [octet & 0x0f, octet >> 4])
        .take_while(|&nibble| nibble != 0x0f)
        .map(|nibble| char::from(b"0123456789*#abc"[usize::from(nibble)]))
        .collect()
}

/// Decode decimal TBCD with only a final high-nibble filler permitted.
pub fn try_tbcd_decode(bytes: &[u8]) -> Option<String> {
    let mut digits = String::with_capacity(bytes.len() * 2);
    for (index, byte) in bytes.iter().copied().enumerate() {
        let low = byte & 0x0f;
        let high = byte >> 4;
        if low > 9 {
            return None;
        }
        digits.push(char::from(b'0' + low));
        if high == 0x0f && index + 1 == bytes.len() {
            continue;
        }
        if high > 9 {
            return None;
        }
        digits.push(char::from(b'0' + high));
    }
    Some(digits)
}

/// Encode a TBCD-STRING (TS 29.002), the reverse of [`tbcd_decode`].
///
/// The first character of each pair goes to the low nibble. An odd number
/// of characters leaves the filler 0xF in the high nibble of the last
/// octet.
///
/// A character other than a decimal digit, "*", "#", "a", "b" or "c" is
/// [`SecurityError::InvalidParameter`].
pub fn tbcd_encode(value: &str) -> Result<Vec<u8>, SecurityError> {
    let mut result = Vec::with_capacity(value.len().div_ceil(2));
    for pair in value.as_bytes().chunks(2) {
        let mut octet = 0xf0;
        for (index, character) in pair.iter().enumerate() {
            let nibble = b"0123456789*#abc"
                .iter()
                .position(|known| known == character)
                .ok_or(SecurityError::InvalidParameter(
                    "a TBCD string has digits, *, #, a, b and c only",
                ))? as u8;
            octet = if index == 0 {
                0xf0 | nibble
            } else {
                (nibble << 4) | (octet & 0x0f)
            };
        }
        result.push(octet);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plmn_2digit_mnc_roundtrip() {
        let bytes = plmn_to_bytes("208", "93").unwrap();
        assert_eq!(bytes, [0x02, 0xF8, 0x39]);
        let (mcc, mnc) = plmn_from_bytes(&bytes).unwrap();
        assert_eq!(mcc, "208");
        assert_eq!(mnc, "93");
    }

    #[test]
    fn plmn_3digit_mnc_roundtrip() {
        let bytes = plmn_to_bytes("999", "070").unwrap();
        let (mcc, mnc) = plmn_from_bytes(&bytes).unwrap();
        assert_eq!(mcc, "999");
        assert_eq!(mnc, "070");
    }

    /// TS 24.501 Figure 9.11.3.4.1: MCC digit 2 and MCC digit 1 in the
    /// first octet, MNC digit 3 and MCC digit 3 in the second, MNC digit 2
    /// and MNC digit 1 in the third.
    #[test]
    fn plmn_octets_follow_the_figure_of_ts_24_501() {
        assert_eq!(plmn_to_bytes("123", "456"), Ok([0x21, 0x63, 0x54]));
        assert_eq!(plmn_to_bytes("310", "410"), Ok([0x13, 0x00, 0x14]));
        assert_eq!(plmn_to_bytes("123", "45"), Ok([0x21, 0xf3, 0x54]));
    }

    #[test]
    fn a_plmn_that_is_not_decimal_digits_is_an_error() {
        for (mcc, mnc) in [
            ("20", "93"),
            ("2080", "93"),
            ("2a8", "93"),
            ("208", "9"),
            ("208", "9300"),
            ("208", "9x"),
            ("208", "9\u{e9}"),
            ("208", ""),
            ("", "93"),
            ("20\u{e9}", "93"),
            ("208", "\u{663}\u{663}"),
        ] {
            assert!(
                matches!(
                    plmn_to_bytes(mcc, mnc),
                    Err(SecurityError::InvalidParameter(_))
                ),
                "{mcc}-{mnc}"
            );
        }
    }

    #[test]
    fn plmn_from_bytes_too_short() {
        assert!(plmn_from_bytes(&[0x02, 0xF8]).is_none());
    }

    #[test]
    fn tbcd_decode_even() {
        assert_eq!(tbcd_decode(&[0x21, 0x43]), "1234");
    }

    #[test]
    fn tbcd_decode_odd() {
        assert_eq!(tbcd_decode(&[0x21, 0xF3]), "123");
    }

    /// The TBCD-STRING of TS 29.002 codes 1010 to 1110 as "*", "#", "a",
    /// "b" and "c", and 1111 as the filler that ends the digits.
    #[test]
    fn tbcd_decode_keeps_non_decimal_characters_and_stops_at_the_filler() {
        assert_eq!(tbcd_decode(&[0xa1, 0xcb, 0xed]), "1*#abc");
        assert_eq!(tbcd_decode(&[0x21, 0xf3, 0x54]), "123");
        assert_eq!(tbcd_decode(&[0xf1, 0x32]), "1");
    }

    /// What `tbcd_decode` returns for a peer's octets goes back through
    /// `tbcd_encode`.
    #[test]
    fn tbcd_round_trips_every_character() {
        let octets = [0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe];
        assert_eq!(tbcd_decode(&octets), "0123456789*#abc");
        assert_eq!(tbcd_encode("0123456789*#abc").unwrap(), octets);
    }

    #[test]
    fn tbcd_encode_even() {
        assert_eq!(tbcd_encode("1234"), Ok(vec![0x21, 0x43]));
    }

    #[test]
    fn tbcd_encode_odd() {
        assert_eq!(tbcd_encode("123"), Ok(vec![0x21, 0xF3]));
        assert_eq!(tbcd_encode(""), Ok(vec![]));
    }

    #[test]
    fn tbcd_encode_refuses_other_characters() {
        for value in ["12d4", "12 4", "A", "1\u{e9}"] {
            assert!(
                matches!(tbcd_encode(value), Err(SecurityError::InvalidParameter(_))),
                "{value}"
            );
        }
    }

    #[test]
    fn tbcd_roundtrip() {
        let encoded = tbcd_encode("9876543210").unwrap();
        assert_eq!(tbcd_decode(&encoded), "9876543210");
    }
}
