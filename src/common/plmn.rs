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

//! PLMN and TBCD encoding/decoding utilities per 3GPP TS 24.301 and TS 24.501.

/// Encode MCC/MNC as 3 PLMN octets per 3GPP TS 24.301 §9.9.3.12
/// and TS 24.501 §9.11.3.4.
///
/// MCC must be 3 decimal digits, MNC must be 2 or 3 decimal digits.
///
/// # Panics
///
/// Panics if `mcc` or `mnc` does not have the documented decimal format.
pub fn plmn_to_bytes(mcc: &str, mnc: &str) -> Vec<u8> {
    assert!(
        mcc.len() == 3 && mcc.chars().all(|c| c.is_ascii_digit()),
        "MCC must be 3 ASCII digits"
    );
    assert!(
        (mnc.len() == 2 || mnc.len() == 3) && mnc.chars().all(|c| c.is_ascii_digit()),
        "MNC must be 2 or 3 ASCII digits"
    );
    let mcc: Vec<u8> = mcc.bytes().map(|b| b - b'0').collect();
    let mnc: Vec<u8> = mnc.bytes().map(|b| b - b'0').collect();

    let mut result = vec![0u8; 3];
    result[0] = (mcc[1] << 4) | mcc[0];
    if mnc.len() == 2 {
        result[1] = 0xF0 | mcc[2];
        result[2] = (mnc[1] << 4) | mnc[0];
    } else {
        result[1] = (mnc[2] << 4) | mcc[2];
        result[2] = (mnc[1] << 4) | mnc[0];
    }
    result
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

/// Decode TBCD-encoded bytes to a digit string.
///
/// Low nibble first, then high nibble. 0xF = end padding (skipped).
pub fn tbcd_decode(bytes: &[u8]) -> String {
    let mut s = String::new();
    for &b in bytes {
        let lo = b & 0x0F;
        let hi = (b >> 4) & 0x0F;
        if lo <= 9 {
            s.push((b'0' + lo) as char);
        }
        if hi <= 9 {
            s.push((b'0' + hi) as char);
        }
    }
    s
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

/// Encode a decimal digit string as TBCD bytes.
///
/// Swaps nibble pairs. Odd-length strings are padded with 0xF in the high nibble of the last byte.
///
/// # Panics
///
/// Panics if `value` contains a non-ASCII decimal digit.
pub fn tbcd_encode(value: &str) -> Vec<u8> {
    assert!(
        value.bytes().all(|digit| digit.is_ascii_digit()),
        "TBCD input must be ASCII digits"
    );
    let digits: Vec<u8> = value.bytes().map(|b| b - b'0').collect();
    let mut result = Vec::with_capacity(digits.len().div_ceil(2));
    let mut i = 0;
    while i < digits.len() {
        let lo = digits[i];
        let hi = if i + 1 < digits.len() {
            digits[i + 1]
        } else {
            0xF
        };
        result.push((hi << 4) | lo);
        i += 2;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plmn_2digit_mnc_roundtrip() {
        let bytes = plmn_to_bytes("208", "93");
        assert_eq!(bytes, vec![0x02, 0xF8, 0x39]);
        let (mcc, mnc) = plmn_from_bytes(&bytes).unwrap();
        assert_eq!(mcc, "208");
        assert_eq!(mnc, "93");
    }

    #[test]
    fn plmn_3digit_mnc_roundtrip() {
        let bytes = plmn_to_bytes("999", "070");
        let (mcc, mnc) = plmn_from_bytes(&bytes).unwrap();
        assert_eq!(mcc, "999");
        assert_eq!(mnc, "070");
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

    #[test]
    fn tbcd_encode_even() {
        assert_eq!(tbcd_encode("1234"), vec![0x21, 0x43]);
    }

    #[test]
    fn tbcd_encode_odd() {
        assert_eq!(tbcd_encode("123"), vec![0x21, 0xF3]);
    }

    #[test]
    fn tbcd_roundtrip() {
        let encoded = tbcd_encode("9876543210");
        assert_eq!(tbcd_decode(&encoded), "9876543210");
    }
}
