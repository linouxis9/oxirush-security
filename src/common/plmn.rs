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

//! The PLMN identity and the TBCD strings of TS 24.501 and TS 24.301.

use crate::common::error::SecurityError;
#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};
use core::fmt;

/// A PLMN identity: a Mobile Country Code of three decimal digits and a
/// Mobile Network Code of two or three (TS 23.003 §2.2).
///
/// ```
/// use oxirush_security::Plmn;
///
/// let plmn = Plmn::new("208", "93")?;
/// // The three octets of TS 24.501 §9.11.3.4 and TS 24.301 §9.9.3.12
/// assert_eq!(plmn.to_octets(), [0x02, 0xf8, 0x39]);
/// assert_eq!(Plmn::from_octets(&[0x02, 0xf8, 0x39])?, plmn);
/// assert_eq!((plmn.mcc(), plmn.mnc()), ("208", "93"));
/// assert_eq!(plmn.to_string(), "208-93");
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Plmn {
    /// The digits of the MCC, then those of the MNC, as characters.
    digits: [u8; 6],
    /// The digits of the MNC: two or three.
    mnc_digits: u8,
}

impl Plmn {
    /// The PLMN of an MCC and an MNC.
    ///
    /// An `mcc` that is not three decimal digits, or an `mnc` that is
    /// not two or three, is [`SecurityError::InvalidParameter`].
    pub fn new(mcc: &str, mnc: &str) -> Result<Self, SecurityError> {
        let decimal = |text: &str| text.bytes().all(|character| character.is_ascii_digit());
        if mcc.len() != 3 || !decimal(mcc) {
            return Err(SecurityError::InvalidParameter(
                "MCC must be 3 decimal digits",
            ));
        }
        if !(2..=3).contains(&mnc.len()) || !decimal(mnc) {
            return Err(SecurityError::InvalidParameter(
                "MNC must be 2 or 3 decimal digits",
            ));
        }
        let mut digits = [b'0'; 6];
        digits[..3].copy_from_slice(mcc.as_bytes());
        digits[3..3 + mnc.len()].copy_from_slice(mnc.as_bytes());
        Ok(Self {
            digits,
            mnc_digits: mnc.len() as u8,
        })
    }

    /// The PLMN of the three octets of a NAS message (TS 24.501 §9.11.3.4,
    /// TS 24.301 §9.9.3.12).
    ///
    /// A digit above 9, or a third MNC digit that is neither a digit nor
    /// the filler 0xF, is [`SecurityError::InvalidParameter`].
    pub fn from_octets(octets: &[u8; 3]) -> Result<Self, SecurityError> {
        let [mcc_1, mcc_2] = [octets[0] & 0x0f, octets[0] >> 4];
        let [mcc_3, mnc_3] = [octets[1] & 0x0f, octets[1] >> 4];
        let [mnc_1, mnc_2] = [octets[2] & 0x0f, octets[2] >> 4];
        let five = [mcc_1, mcc_2, mcc_3, mnc_1, mnc_2];
        if five.iter().any(|digit| *digit > 9) || (mnc_3 > 9 && mnc_3 != 0x0f) {
            return Err(SecurityError::InvalidParameter(
                "a PLMN identity has decimal digits, and the filler in the third MNC digit alone",
            ));
        }
        let mut digits = [b'0'; 6];
        for (character, digit) in digits.iter_mut().zip(five) {
            *character = b'0' + digit;
        }
        let mnc_digits = if mnc_3 == 0x0f { 2 } else { 3 };
        if mnc_digits == 3 {
            digits[5] = b'0' + mnc_3;
        }
        Ok(Self { digits, mnc_digits })
    }

    /// The three octets of a NAS message. A two-digit MNC has the filler
    /// 0xF in the place of its third digit.
    pub fn to_octets(self) -> [u8; 3] {
        let digit = |index: usize| self.digits[index] - b'0';
        let mnc_3 = if self.mnc_digits == 3 { digit(5) } else { 0x0f };
        [
            (digit(1) << 4) | digit(0),
            (mnc_3 << 4) | digit(2),
            (digit(4) << 4) | digit(3),
        ]
    }

    /// The Mobile Country Code, three digits.
    pub fn mcc(&self) -> &str {
        core::str::from_utf8(&self.digits[..3]).expect("decimal digits")
    }

    /// The Mobile Network Code, two or three digits.
    pub fn mnc(&self) -> &str {
        let digits = &self.digits[3..3 + usize::from(self.mnc_digits)];
        core::str::from_utf8(digits).expect("decimal digits")
    }
}

/// The MCC, a hyphen and the MNC: `208-93`.
impl fmt::Display for Plmn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}-{}", self.mcc(), self.mnc())
    }
}

impl fmt::Debug for Plmn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Plmn({self})")
    }
}

/// The characters of a TBCD-STRING, by the value of their four bits.
#[cfg(feature = "alloc")]
const TBCD_CHARACTERS: &[u8; 15] = b"0123456789*#abc";

/// Decode a TBCD-STRING (TS 29.002): the low four bits of each octet, then
/// the high four.
///
/// 0 to 9 are digits, and 0xA to 0xE are "*", "#", "a", "b" and "c". The
/// filler 0xF is the high four bits of the last octet of a string with an
/// odd number of characters: anywhere else it is
/// [`SecurityError::InvalidParameter`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn tbcd_decode(octets: &[u8]) -> Result<String, SecurityError> {
    let mut characters = String::with_capacity(2 * octets.len());
    for (index, octet) in octets.iter().enumerate() {
        let (low, high) = (octet & 0x0f, octet >> 4);
        let last = index + 1 == octets.len();
        if low == 0x0f || (high == 0x0f && !last) {
            return Err(SecurityError::InvalidParameter(
                "a TBCD string has its filler at its end alone",
            ));
        }
        characters.push(char::from(TBCD_CHARACTERS[usize::from(low)]));
        if high != 0x0f {
            characters.push(char::from(TBCD_CHARACTERS[usize::from(high)]));
        }
    }
    Ok(characters)
}

/// Decode a TBCD-STRING of decimal digits, such as an MSIN: `None` for a
/// character that is not a digit and for a filler that is not at the end.
#[cfg(feature = "suci")]
pub(crate) fn decimal_tbcd_decode(octets: &[u8]) -> Option<String> {
    let digits = tbcd_decode(octets).ok()?;
    digits
        .bytes()
        .all(|character| character.is_ascii_digit())
        .then_some(digits)
}

/// Encode a TBCD-STRING (TS 29.002), the reverse of [`tbcd_decode`].
///
/// The first character of each pair goes to the low four bits. An odd
/// number of characters leaves the filler 0xF in the high four bits of the
/// last octet.
///
/// A character other than a decimal digit, "*", "#", "a", "b" or "c" is
/// [`SecurityError::InvalidParameter`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn tbcd_encode(value: &str) -> Result<Vec<u8>, SecurityError> {
    let mut result = Vec::with_capacity(value.len().div_ceil(2));
    for pair in value.as_bytes().chunks(2) {
        let mut octet = 0xf0;
        for (index, character) in pair.iter().enumerate() {
            let nibble = TBCD_CHARACTERS
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
    fn a_plmn_is_its_three_octets() {
        // TS 24.501 Figure 9.11.3.4.1: MCC digit 2 | MCC digit 1, MNC digit
        // 3 | MCC digit 3, MNC digit 2 | MNC digit 1
        for (mcc, mnc, octets) in [
            ("208", "93", [0x02, 0xf8, 0x39]),
            ("310", "410", [0x13, 0x00, 0x14]),
            ("123", "456", [0x21, 0x63, 0x54]),
            ("001", "01", [0x00, 0xf1, 0x10]),
        ] {
            let plmn = Plmn::new(mcc, mnc).unwrap();
            assert_eq!(plmn.to_octets(), octets, "{mcc} {mnc}");
            assert_eq!(Plmn::from_octets(&octets), Ok(plmn));
            assert_eq!((plmn.mcc(), plmn.mnc()), (mcc, mnc));
        }
        let plmn = Plmn::new("208", "93").unwrap();
        assert_eq!(plmn.to_string(), "208-93");
        assert_eq!(format!("{plmn:?}"), "Plmn(208-93)");
        // A two-digit MNC is not the three-digit one with a zero
        assert_ne!(Plmn::new("208", "093").unwrap(), plmn);
    }

    #[test]
    fn a_plmn_that_is_not_decimal_digits_is_an_error() {
        let mcc = Err(SecurityError::InvalidParameter(
            "MCC must be 3 decimal digits",
        ));
        let mnc = Err(SecurityError::InvalidParameter(
            "MNC must be 2 or 3 decimal digits",
        ));
        assert_eq!(Plmn::new("20", "93"), mcc);
        assert_eq!(Plmn::new("2080", "93"), mcc);
        assert_eq!(Plmn::new("2o8", "93"), mcc);
        assert_eq!(Plmn::new("２08", "93"), mcc);
        assert_eq!(Plmn::new("208", "9"), mnc);
        assert_eq!(Plmn::new("208", "9345"), mnc);
        assert_eq!(Plmn::new("208", "9x"), mnc);
        assert_eq!(Plmn::new("208", ""), mnc);
    }

    #[test]
    fn octets_that_are_not_a_plmn_are_refused() {
        for octets in [
            [0xff, 0xff, 0xff],
            [0x0a, 0xf8, 0x39],
            [0xa2, 0xf8, 0x39],
            [0x02, 0xfa, 0x39],
            [0x02, 0xa8, 0x39],
            [0x02, 0xf8, 0x3f],
            [0x02, 0xf8, 0xf9],
        ] {
            assert!(Plmn::from_octets(&octets).is_err(), "{octets:02x?}");
        }
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tbcd_is_two_characters_to_an_octet() {
        assert_eq!(tbcd_decode(&[0x21, 0x43, 0x65]).unwrap(), "123456");
        assert_eq!(tbcd_decode(&[0x21, 0x43, 0xf5]).unwrap(), "12345");
        assert_eq!(tbcd_decode(&[]).unwrap(), "");
        assert_eq!(tbcd_encode("123456").unwrap(), [0x21, 0x43, 0x65]);
        assert_eq!(tbcd_encode("12345").unwrap(), [0x21, 0x43, 0xf5]);
        assert_eq!(tbcd_encode("").unwrap(), []);
        // Every character, and back
        let all = "0123456789*#abc";
        assert_eq!(tbcd_decode(&tbcd_encode(all).unwrap()).unwrap(), all);
        assert_eq!(tbcd_decode(&[0xba, 0xdc, 0xfe]).unwrap(), "*#abc");
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn a_filler_that_is_not_at_the_end_is_refused() {
        let error = Err(SecurityError::InvalidParameter(
            "a TBCD string has its filler at its end alone",
        ));
        // In the middle, which once ended the string without a word
        assert_eq!(tbcd_decode(&[0x21, 0xf3, 0x54]), error);
        assert_eq!(tbcd_decode(&[0x21, 0x3f, 0x54]), error);
        // In the low four bits of the last octet
        assert_eq!(tbcd_decode(&[0x21, 0x4f]), error);
        assert_eq!(tbcd_decode(&[0xff]), error);
    }

    /// An MSIN has decimal digits alone.
    #[cfg(feature = "suci")]
    #[test]
    fn a_string_of_decimal_digits_has_no_other_character() {
        assert_eq!(decimal_tbcd_decode(&[0x21, 0xf3]).as_deref(), Some("123"));
        assert_eq!(decimal_tbcd_decode(&[0x21, 0xa3]), None);
        assert_eq!(decimal_tbcd_decode(&[0x21, 0xf3, 0x54]), None);
    }

    #[cfg(feature = "alloc")]
    #[test]
    fn tbcd_encode_refuses_other_characters() {
        for text in ["12x", "d", "1 2", "１"] {
            assert_eq!(
                tbcd_encode(text),
                Err(SecurityError::InvalidParameter(
                    "a TBCD string has digits, *, #, a, b and c only"
                )),
                "{text:?}"
            );
        }
    }
}
