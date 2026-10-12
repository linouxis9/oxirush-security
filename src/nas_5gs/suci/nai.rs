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

//! The NAI format of a SUCI (TS 23.003 §28.7.3, §28.15.5 and §28.16.5),
//! and the NAI of a SUPI that is a network specific identifier, a GCI or a
//! GLI (§28.7.2, §28.15.2 and §28.16.2).
//!
//! This is the `nai` feature. It brings the Unicode normalization of
//! RFC 7542 usernames and the IDNA rules of RFC 5891 realms, and with them
//! most of the crates that the crate depends on.

use super::ecies::{MAC_LEN, PROFILE_A_PUBLIC_KEY_LEN, PROFILE_B_PUBLIC_KEY_LEN};
use super::{Home, NaiError, ProtectionScheme, RoutingIndicator, Suci, SuciError};
use crate::nas_5gs::supi::SupiType;
use alloc::{borrow::ToOwned, format, string::String, vec::Vec};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use unicode_normalization::UnicodeNormalization;

/// The longest realm, in octets: the longest domain name (RFC 1035
/// §2.3.4).
const LONGEST_REALM: usize = 253;
/// The longest username of a SUPI, in octets, which is also the longest
/// plaintext of a profile.
pub(super) const LONGEST_USERNAME: usize = 253;
/// The longest output of a scheme of the operator, in octets: 3000 and
/// the size of the input (TS 33.501 Annex C.1).
const LONGEST_PROPRIETARY_OUTPUT: usize = 3000 + LONGEST_USERNAME;
/// The longest SUCI in the NAI format that is looked at, in octets: the
/// fields before the scheme output, the longest scheme output in
/// hexadecimal digits, `@` and the longest realm.
pub(super) const LONGEST_SUCI_NAI: usize = 64 + 2 * LONGEST_PROPRIETARY_OUTPUT + 1 + LONGEST_REALM;

/// The number that the NAI format writes for a SUPI type (TS 23.003
/// §2.2B). The SUPI format of NAS has GCI and GLI the other way round.
fn type_number(kind: SupiType) -> u8 {
    match kind {
        SupiType::Imsi => 0,
        SupiType::NetworkSpecific => 1,
        SupiType::Gli => 2,
        SupiType::Gci => 3,
    }
}

/// The realm of RFC 7542 §2.2, which is also a domain name of RFC 5891.
/// Its length is checked first: nothing else looks at a longer one.
pub(super) fn checked_realm(value: &str) -> Result<&str, NaiError> {
    if value.is_empty() || value.len() > LONGEST_REALM {
        return Err(NaiError::Realm);
    }
    if value.nfc().ne(value.chars()) {
        return Err(NaiError::Realm);
    }
    let abnf_matches = value.split('.').count() >= 2
        && value.split('.').all(|label| {
            let is_rtext =
                |character: char| character.is_ascii_alphanumeric() || !character.is_ascii();
            !label.is_empty()
                && label
                    .chars()
                    .all(|character| is_rtext(character) || character == '-')
                && label.chars().next().is_some_and(is_rtext)
                && label.chars().last().is_some_and(is_rtext)
        });
    let Ok(ascii) = idna::domain_to_ascii_strict(value) else {
        return Err(NaiError::Realm);
    };
    let valid = if !abnf_matches || value.is_ascii() {
        abnf_matches
    } else {
        let (canonical_unicode, status) = idna::domain_to_unicode(&ascii);
        status.is_ok() && canonical_unicode == value
    };
    if valid {
        Ok(value)
    } else {
        Err(NaiError::Realm)
    }
}

/// The username of RFC 7542 §2.2.
fn valid_nai_username(value: &str, allow_anonymous: bool) -> bool {
    if value.is_empty() {
        return allow_anonymous;
    }
    if value.len() > LONGEST_USERNAME || value.nfc().ne(value.chars()) {
        return false;
    }
    value.split('.').all(|atom| {
        !atom.is_empty()
            && atom.chars().all(|character| {
                if character.is_ascii() {
                    character.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~".contains(character)
                } else {
                    !character.is_control()
                }
            })
    })
}

/// The realm of a SUCI whose SUPI is an IMSI: the home network domain of
/// TS 23.003 §28.2, with the NID of an SNPN or without it.
fn valid_imsi_realm(value: &str) -> bool {
    let labels: Vec<&str> = value.split('.').collect();
    let (nid, mnc, mcc, suffix) = match labels.as_slice() {
        ["5gc", nid, mnc, mcc, rest @ ..] if nid.starts_with("nid") => {
            (Some(*nid), *mnc, *mcc, rest)
        }
        ["5gc", mnc, mcc, rest @ ..] => (None, *mnc, *mcc, rest),
        _ => return false,
    };
    let decimal_suffix = |label: &str, prefix: &str| {
        label.strip_prefix(prefix).is_some_and(|digits| {
            digits.len() == 3 && digits.bytes().all(|byte| byte.is_ascii_digit())
        })
    };
    if suffix != ["3gppnetwork", "org"]
        || !decimal_suffix(mnc, "mnc")
        || !decimal_suffix(mcc, "mcc")
    {
        return false;
    }
    nid.is_none_or(|label| {
        label.strip_prefix("nid").is_some_and(|digits| {
            digits.len() == 11
                && digits.bytes().all(|byte| byte.is_ascii_hexdigit())
                && matches!(digits.as_bytes()[0], b'0'..=b'2')
        })
    })
}

/// A GLI: up to 200 characters of base64 for up to 150 octets
/// (TS 23.003 §28.16.4).
fn valid_gli(value: &str) -> bool {
    if value.is_empty() || value.len() > 200 {
        return false;
    }
    let Ok(decoded) = BASE64_STANDARD.decode(value) else {
        return false;
    };
    decoded.len() <= 150 && BASE64_STANDARD.encode(decoded) == value
}

/// Whether `value` is what a SUPI of this type has before the `@` of its
/// NAI, or the MSIN of an IMSI: the scheme output of the null scheme, and
/// the plaintext of a profile.
pub(super) fn valid_identity(kind: SupiType, value: &str) -> bool {
    match kind {
        SupiType::Imsi => {
            (1..=10).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
        }
        SupiType::NetworkSpecific => valid_nai_username(value, true),
        SupiType::Gli => valid_gli(value),
        SupiType::Gci => valid_nai_username(value, false),
    }
}

/// The realm of a SUCI in the NAI format whose SUPI is an IMSI of
/// `plmn`: `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`, the MNC with three
/// digits (TS 23.003 §28.7.3).
pub(super) fn imsi_realm(plmn: crate::Plmn) -> String {
    format!(
        "5gc.mnc{:0>3}.mcc{}.3gppnetwork.org",
        plmn.mnc(),
        plmn.mcc()
    )
}

/// The decimal number of a field after its name, of at most three digits.
fn number(field: &'static str, text: &str) -> Result<u8, NaiError> {
    let digits = text.strip_prefix(field).ok_or(NaiError::Field(field))?;
    if digits.is_empty() || digits.len() > 3 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NaiError::Field(field));
    }
    digits.parse().map_err(|_| NaiError::Field(field))
}

/// The octets that a field writes in hexadecimal digits after its name: at
/// most `longest`, and exactly `exact` when that is given.
fn octets(
    field: &'static str,
    text: Option<&&str>,
    longest: usize,
    exact: Option<usize>,
) -> Result<Vec<u8>, NaiError> {
    let digits = text
        .and_then(|text| text.strip_prefix(field))
        .ok_or(NaiError::Field(field))?;
    if digits.len() > 2 * longest || exact.is_some_and(|octets| digits.len() != 2 * octets) {
        return Err(NaiError::Field(field));
    }
    hex::decode(digits).map_err(|_| NaiError::Field(field))
}

/// Read a SUCI in the NAI format: `username@realm`, the username in one
/// of the three forms of TS 23.003 §28.7.3.
pub(super) fn parse(input: &str) -> Result<Suci, SuciError> {
    // The length first: what follows looks at no more than this
    if input.len() > LONGEST_SUCI_NAI {
        return Err(NaiError::TooLong.into());
    }
    let (username, realm) = input.rsplit_once('@').ok_or(NaiError::NoRealm)?;
    let realm = checked_realm(realm)?;

    // The scheme output of the null scheme, the last field, may have dots
    let mut fields = username.splitn(4, '.');
    let mut field = |name: &'static str| fields.next().ok_or(NaiError::Field(name));
    let supi_type = match number("type", field("type")?)? {
        0 => SupiType::Imsi,
        1 => SupiType::NetworkSpecific,
        2 => SupiType::Gli,
        3 => SupiType::Gci,
        other => return Err(SuciError::SupiType(other)),
    };
    let routing_indicator = field("rid")?
        .strip_prefix("rid")
        .ok_or(NaiError::Field("rid"))?;
    let routing_indicator = RoutingIndicator::new(routing_indicator)?;
    let scheme = match number("schid", field("schid")?)? {
        identifier @ 0..=15 => ProtectionScheme::try_from(identifier)?,
        _ => return Err(NaiError::Field("schid").into()),
    };
    let rest = field(match scheme {
        ProtectionScheme::Null => "userid",
        _ => "hnkey",
    })?;

    let (key_id, output) = match scheme {
        ProtectionScheme::Null => {
            let clear = rest
                .strip_prefix("userid")
                .ok_or(NaiError::Field("userid"))?;
            (0, clear.as_bytes().to_vec())
        }
        ProtectionScheme::ProfileA | ProtectionScheme::ProfileB => {
            let fields: Vec<&str> = rest.split('.').collect();
            if fields.len() > 4 {
                return Err(NaiError::Field("mac").into());
            }
            let key_id = number("hnkey", fields[0])?;
            let public_key_len = if scheme == ProtectionScheme::ProfileA {
                PROFILE_A_PUBLIC_KEY_LEN
            } else {
                PROFILE_B_PUBLIC_KEY_LEN
            };
            let mut output = octets(
                "ecckey",
                fields.get(1),
                public_key_len,
                Some(public_key_len),
            )?;
            let ciphertext = octets("cip", fields.get(2), LONGEST_USERNAME, None)?;
            if ciphertext.is_empty() {
                return Err(NaiError::Field("cip").into());
            }
            output.extend_from_slice(&ciphertext);
            output.extend_from_slice(&octets("mac", fields.get(3), MAC_LEN, Some(MAC_LEN))?);
            (key_id, output)
        }
        ProtectionScheme::Proprietary(_) => {
            let (key_id, output) = rest.split_once('.').ok_or(NaiError::Field("out"))?;
            let key_id = number("hnkey", key_id)?;
            (
                key_id,
                octets("out", Some(&output), LONGEST_PROPRIETARY_OUTPUT, None)?,
            )
        }
    };
    let home = Home::Realm(realm.to_owned());
    Suci::checked(supi_type, home, routing_indicator, scheme, key_id, output)
}

/// What the realm of a SUCI has to be for its SUPI type, once it is a
/// realm: that of an IMSI is the home network domain of its PLMN.
pub(super) fn check(suci: &Suci) -> Result<(), SuciError> {
    match &suci.home {
        Home::Realm(realm) if suci.supi_type == SupiType::Imsi && !valid_imsi_realm(realm) => {
            Err(NaiError::ImsiRealm.into())
        }
        _ => Ok(()),
    }
}

/// Write a SUCI in the NAI format.
pub(super) fn encode(suci: &Suci) -> String {
    let realm = match &suci.home {
        Home::Plmn(plmn) => imsi_realm(*plmn),
        Home::Realm(realm) => realm.clone(),
    };
    let fields = format!(
        "type{}.rid{}.schid{}",
        type_number(suci.supi_type),
        suci.routing_indicator.as_str(),
        suci.scheme.identifier(),
    );
    let key_id = suci.key_id;
    let output = match suci.scheme_output() {
        super::SchemeOutput::Clear(clear) => format!("userid{clear}"),
        super::SchemeOutput::Ecies {
            ephemeral_public_key,
            ciphertext,
            mac_tag,
        } => format!(
            "hnkey{key_id}.ecckey{}.cip{}.mac{}",
            hex::encode(ephemeral_public_key),
            hex::encode(ciphertext),
            hex::encode(mac_tag),
        ),
        super::SchemeOutput::Proprietary(output) => {
            format!("hnkey{key_id}.out{}", hex::encode(output))
        }
    };
    format!("{fields}.{output}@{realm}")
}

/// The username and the realm of the NAI of a SUPI that is concealed: a
/// network specific identifier, a GCI or a GLI.
pub(super) fn username_and_realm(kind: SupiType, nai: &str) -> Result<(&str, &str), SuciError> {
    let (username, realm) = nai.rsplit_once('@').ok_or(NaiError::NoRealm)?;
    let realm = checked_realm(realm)?;
    if !valid_identity(kind, username) {
        return Err(NaiError::Username.into());
    }
    Ok((username, realm))
}

#[cfg(test)]
mod tests {
    use super::super::test_keys::*;
    use super::super::{HomeNetwork, Protection, SchemeOutput};
    use super::*;
    use crate::nas_5gs::supi::Supi;

    fn nas(format: u8, nai: &str) -> Vec<u8> {
        let mut identity = vec![(format << 4) | 0x01];
        identity.extend_from_slice(nai.as_bytes());
        identity
    }

    fn refused(nai: &str) -> SuciError {
        Suci::from_nai(nai).unwrap_err()
    }

    /// The examples of TS 23.003 §28.7.3, §28.15.5 and §28.16.5.
    #[test]
    fn a_suci_of_the_null_scheme_is_read_in_both_forms() {
        let wire = "type1.rid678.schid0.useriduser17@example.com";
        let suci = Suci::from_nai(wire).unwrap();
        assert_eq!(suci.supi_type(), SupiType::NetworkSpecific);
        assert_eq!(suci.home_network(), HomeNetwork::Realm("example.com"));
        assert_eq!(suci.routing_indicator(), "678");
        assert_eq!(suci.protection_scheme(), ProtectionScheme::Null);
        assert_eq!(suci.home_network_public_key_id(), 0);
        assert_eq!(suci.scheme_output(), SchemeOutput::Clear("user17"));
        assert_eq!(suci.to_nai(), wire);
        assert_eq!(suci.to_string(), "suci-1-example.com-678-0-0-user17");
        let supi = suci.deconceal(None).unwrap();
        assert_eq!(supi, Supi::network_specific("user17@example.com").unwrap());
        assert_eq!(supi.to_string(), "nai-user17@example.com");

        // In a mobile identity, the SUPI format 1 and the text
        assert_eq!(suci.to_nas().unwrap(), nas(1, wire));
        assert_eq!(Suci::from_nas(&nas(1, wire)), Ok(suci));

        // The SUPI format 2 of NAS is a GCI, whose SUPI type is 3, and the
        // SUPI format 3 a GLI, whose SUPI type is 2
        let gci = "type3.rid0.schid0.userid00-00-5E-00-53-00@operator.com";
        let suci = Suci::from_nas(&nas(2, gci)).unwrap();
        assert_eq!(suci.supi_type(), SupiType::Gci);
        assert_eq!(suci.to_nas().unwrap(), nas(2, gci));
        assert_eq!(
            suci.deconceal(None).unwrap().to_string(),
            "gci-00-00-5E-00-53-00@operator.com"
        );
        let gli = "type2.rid0.schid0.useridQUJDRA==@operator.com";
        let suci = Suci::from_nas(&nas(3, gli)).unwrap();
        assert_eq!(suci.supi_type(), SupiType::Gli);
        assert_eq!(suci.to_nas().unwrap(), nas(3, gli));
        assert_eq!(
            suci.deconceal(None).unwrap().to_string(),
            "gli-QUJDRA==@operator.com"
        );
        for (format, nai) in [(1, gci), (2, gli), (3, gci), (2, wire)] {
            assert_eq!(
                Suci::from_nas(&nas(format, nai)),
                Err(SuciError::SupiTypeMismatch)
            );
        }
        // A GCI and a GLI have the routing indicator 0 and the null scheme
        assert_eq!(
            refused("type3.rid1.schid0.userid00-00-5E-00-53-00@operator.com"),
            SuciError::RoutingIndicator
        );
        assert_eq!(
            refused("type3.rid0.schid12.hnkey1.outaa@operator.com"),
            SuciError::NullSchemeRequired
        );
        // An anonymous SUCI, whose username is empty
        let anonymous = Suci::from_nai("type1.rid678.schid0.userid@example.com").unwrap();
        assert_eq!(
            anonymous.deconceal(None).unwrap().identity(),
            "@example.com"
        );
    }

    /// m5: each mistake has an error of its own.
    #[test]
    fn a_text_that_is_no_suci_is_refused_with_its_reason() {
        for (nai, error) in [
            ("type1.rid678.schid0.useriduser17", NaiError::NoRealm),
            ("type1.rid678.schid0.useriduser17@example", NaiError::Realm),
            ("type1.rid678.schid0.useriduser17@", NaiError::Realm),
            ("@example.com", NaiError::Field("type")),
            ("user17@example.com", NaiError::Field("type")),
            (
                "typex.rid678.schid0.useridu@example.com",
                NaiError::Field("type"),
            ),
            ("type1@example.com", NaiError::Field("rid")),
            (
                "type1.schid0.rid1.useridu@example.com",
                NaiError::Field("rid"),
            ),
            ("type1.rid678@example.com", NaiError::Field("schid")),
            (
                "type1.rid678.schid16.useridu@example.com",
                NaiError::Field("schid"),
            ),
            ("type1.rid678.schid0@example.com", NaiError::Field("userid")),
            (
                "type1.rid678.schid0.user17@example.com",
                NaiError::Field("userid"),
            ),
            ("type1.rid678.schid1@example.com", NaiError::Field("hnkey")),
            (
                "type1.rid678.schid1.hnkey@example.com",
                NaiError::Field("hnkey"),
            ),
            (
                "type1.rid678.schid1.hnkey1000.ecckey@example.com",
                NaiError::Field("hnkey"),
            ),
            (
                "type1.rid678.schid1.hnkey27@example.com",
                NaiError::Field("ecckey"),
            ),
            (
                "type1.rid678.schid12.hnkey27@example.com",
                NaiError::Field("out"),
            ),
            (
                "type1.rid678.schid12.hnkey27.outnot-hex@example.com",
                NaiError::Field("out"),
            ),
            (
                "type1.rid678.schid12.hnkey27.outabc@example.com",
                NaiError::Field("out"),
            ),
        ] {
            assert_eq!(refused(nai), SuciError::Nai(error), "{nai}");
        }
        // The fields of a profile, each missing or of another length
        let key = "42".repeat(32);
        let profile = |ecckey: &str, cip: &str, mac: &str| {
            format!("type1.rid678.schid1.hnkey27.{ecckey}.{cip}.{mac}@example.com")
        };
        let whole = profile(&format!("ecckey{key}"), "cipaabb", "mac0011223344556677");
        assert!(Suci::from_nai(&whole).is_ok());
        for (nai, field) in [
            (
                profile(
                    &format!("ecckey{}", &key[2..]),
                    "cipaabb",
                    "mac0011223344556677",
                ),
                "ecckey",
            ),
            (
                profile(&format!("key{key}"), "cipaabb", "mac0011223344556677"),
                "ecckey",
            ),
            (
                profile(&format!("ecckey{key}"), "cip", "mac0011223344556677"),
                "cip",
            ),
            (
                profile(&format!("ecckey{key}"), "cipaab", "mac0011223344556677"),
                "cip",
            ),
            (
                profile(&format!("ecckey{key}"), "cipaabb", "mac00112233445566"),
                "mac",
            ),
            (
                profile(
                    &format!("ecckey{key}"),
                    "cipaabb",
                    "mac0011223344556677.more",
                ),
                "mac",
            ),
            (whole.replace(".mac0011223344556677", ""), "mac"),
        ] {
            assert_eq!(
                refused(&nai),
                SuciError::Nai(NaiError::Field(field)),
                "{nai}"
            );
        }
        // What is not of the NAI itself
        assert_eq!(
            refused("type7.rid678.schid0.useridu@example.com"),
            SuciError::SupiType(7)
        );
        assert_eq!(
            refused("type1.rid12345.schid0.useridu@example.com"),
            SuciError::RoutingIndicator
        );
        assert_eq!(
            refused("type1.rid678.schid3.hnkey27.out00@example.com"),
            SuciError::UnknownScheme(3)
        );
        assert_eq!(
            refused("type1.rid678.schid0.userida b@example.com"),
            SuciError::SchemeOutput
        );
        // A SUPI without a realm, and one that is an IMSI
        let conceal = |supi: &Supi<'_>| Suci::conceal_nai(supi, "678", Protection::Null);
        assert!(Supi::network_specific("bob").is_err());
        assert_eq!(
            conceal(&Supi::network_specific("bob@example").unwrap()),
            Err(SuciError::Nai(NaiError::Realm))
        );
        assert_eq!(
            conceal(&Supi::network_specific("a b@example.com").unwrap()),
            Err(SuciError::Nai(NaiError::Username))
        );
        assert_eq!(
            conceal(&Supi::imsi("208930000000001").unwrap()),
            Err(SuciError::Identity)
        );
        // A text of a mobile identity that is not UTF-8
        assert_eq!(
            Suci::from_nas(&[0x11, b't', 0xff, b'@', b'a', b'.', b'b']),
            Err(SuciError::Nai(NaiError::Encoding))
        );
    }

    /// m3: the length is looked at first, and the realm before its
    /// labels.
    #[test]
    fn a_text_that_is_too_long_is_refused_before_it_is_read() {
        let huge = format!(
            "type1.rid0.schid0.userid{}@example.com",
            "a".repeat(64 * 1024)
        );
        assert_eq!(refused(&huge), SuciError::Nai(NaiError::TooLong));
        assert_eq!(
            Suci::from_nas(&nas(1, &huge)),
            Err(SuciError::Nai(NaiError::TooLong))
        );
        let long_realm = format!("type1.rid0.schid0.useridu@{}.com", "a".repeat(250));
        assert_eq!(refused(&long_realm), SuciError::Nai(NaiError::Realm));
        let realm = format!("{0}.{0}.{0}.{1}.com", "a".repeat(63), "a".repeat(57));
        assert_eq!(realm.len(), 253);
        assert!(Suci::from_nai(&format!("type1.rid0.schid0.useridu@{realm}")).is_ok());
        // A username of more than 253 octets, in clear and as ciphertext
        let long_username = format!("type1.rid0.schid0.userid{}@example.com", "a".repeat(254));
        assert_eq!(refused(&long_username), SuciError::SchemeOutput);
        let long_ciphertext = format!(
            "type1.rid0.schid1.hnkey1.ecckey{}.cip{}.mac0011223344556677@example.com",
            "42".repeat(32),
            "aa".repeat(254)
        );
        assert_eq!(
            refused(&long_ciphertext),
            SuciError::Nai(NaiError::Field("cip"))
        );
    }

    /// The home network public key identifier is 1 to 254 with a scheme
    /// that has a key, in this form as in a mobile identity.
    #[test]
    fn a_key_identifier_is_the_same_in_both_forms() {
        for valid in [1, 27, 254] {
            let nai = format!("type1.rid678.schid12.hnkey{valid}.out00abff@example.com");
            let suci = Suci::from_nai(&nai).unwrap();
            assert_eq!(suci.home_network_public_key_id(), valid);
            assert_eq!(
                suci.scheme_output(),
                SchemeOutput::Proprietary(&[0x00, 0xab, 0xff])
            );
            assert_eq!(suci.to_nai(), nai);
        }
        for invalid in [0, 255] {
            let nai = format!("type1.rid678.schid12.hnkey{invalid}.out00abff@example.com");
            assert_eq!(refused(&nai), SuciError::KeyIdentifier(invalid));
        }
        // Hexadecimal digits of either case are read, and written small
        let upper = Suci::from_nai("type1.rid678.schid12.hnkey27.out00ABFF@example.com").unwrap();
        assert_eq!(
            upper.to_nai(),
            "type1.rid678.schid12.hnkey27.out00abff@example.com"
        );
    }

    #[test]
    fn the_grammar_of_rfc_7542_is_strict() {
        for realm in [
            ".",
            "a..b",
            "-bad.example",
            "bad-.example",
            "example",
            "ｅxample.com",
            "a．b.example",
        ] {
            assert_eq!(
                refused(&format!("type1.rid678.schid0.useridu@{realm}")),
                SuciError::Nai(NaiError::Realm),
                "realm {realm:?}"
            );
        }
        for wire in [
            "type1.rid678.schid0.userida b@example.com",
            "type1.rid678.schid0.userida@b@example.com",
            "type1.rid678.schid0.userida..b@example.com",
        ] {
            assert_eq!(refused(wire), SuciError::SchemeOutput, "{wire}");
        }
        let conceal = |nai: &str| {
            Suci::conceal_nai(
                &Supi::network_specific(nai).unwrap(),
                "678",
                Protection::Null,
            )
        };
        // A space, a second @, and a username that is not normalized
        for nai in ["a b@example.com", "a@b@example.com", "e\u{301}@example.com"] {
            assert_eq!(
                conceal(nai),
                Err(SuciError::Nai(NaiError::Username)),
                "{nai}"
            );
        }
        for username in ["user\u{a0}name", "user\u{2003}name", "élodie"] {
            let nai = format!("{username}@example.com");
            let supi = conceal(&nai).unwrap().deconceal(None).unwrap();
            assert_eq!(supi.identity(), nai);
        }
        for username in ["user\u{85}name", "user\u{7f}name"] {
            assert!(conceal(&format!("{username}@example.com")).is_err());
        }
        for realm in ["bücher.example", "xn--bcher-kva.example"] {
            let nai = format!("alice@{realm}");
            let supi = conceal(&nai).unwrap().deconceal(None).unwrap();
            assert_eq!(supi.identity(), nai);
        }
        assert_eq!(
            refused("type1.rid678.schid0.useridélodie@bu\u{0308}cher.example"),
            SuciError::Nai(NaiError::Realm)
        );
    }

    /// TS 23.003 §28.7.3: the SUCI of an IMSI in the NAI format, whose
    /// realm is the home network domain. It is read and written, and its
    /// IMSI is not known from it.
    #[test]
    fn an_imsi_in_the_nai_format_keeps_its_realm() {
        for nai in [
            "type0.rid678.schid0.userid0999999999@5gc.mnc015.mcc234.3gppnetwork.org",
            "type0.rid678.schid0.userid0999999999@5gc.nid000007ed9d5.mnc015.mcc234.3gppnetwork.org",
        ] {
            let suci = Suci::from_nai(nai).unwrap();
            assert_eq!(suci.supi_type(), SupiType::Imsi);
            assert_eq!(suci.to_nai(), nai);
            assert_eq!(suci.deconceal(None), Err(SuciError::MncLengthUnknown));
            assert_eq!(suci.to_nas(), Err(SuciError::MncLengthUnknown));
        }
        for (nai, error) in [
            (
                "type0.rid678.schid0.userid@5gc.mnc015.mcc234.3gppnetwork.org",
                SuciError::SchemeOutput,
            ),
            (
                "type0.rid678.schid0.useridabc@5gc.mnc015.mcc234.3gppnetwork.org",
                SuciError::SchemeOutput,
            ),
            (
                "type0.rid678.schid0.userid01234567890@5gc.mnc015.mcc234.3gppnetwork.org",
                SuciError::SchemeOutput,
            ),
            (
                "type0.rid678.schid0.userid0123@example.com",
                SuciError::Nai(NaiError::ImsiRealm),
            ),
            (
                "type3.rid0.schid0.userid@operator.com",
                SuciError::SchemeOutput,
            ),
            (
                "type2.rid0.schid0.userid***@operator.com",
                SuciError::SchemeOutput,
            ),
        ] {
            assert_eq!(refused(nai), error, "{nai}");
        }
        // The IMSI of a mobile identity is written with the realm of its
        // PLMN, the MNC with three digits (the example of §28.7.3)
        let suci = Suci::conceal_imsi(
            crate::Plmn::new("234", "15").unwrap(),
            "0999999999",
            "678",
            Protection::Null,
        )
        .unwrap();
        assert_eq!(
            suci.to_nai(),
            "type0.rid678.schid0.userid0999999999@5gc.mnc015.mcc234.3gppnetwork.org"
        );
    }

    /// TS 33.501 Annex C.4.3.2 and C.4.4.2: the scheme outputs of the
    /// network specific identifier verylongusername1@3gpp.com.
    #[test]
    fn the_profiles_de_conceal_the_data_of_annex_c4() {
        for (scheme, private, ecckey, cip, mac) in [
            (
                1,
                private_a(),
                "977d8b2fdaa7b64aa700d04227d5b440630ea4ec50f9082273a26bb678c92222",
                "8e358a1582adb15322c10e515141d2039a",
                "12e1d7783a97f1ac",
            ),
            (
                2,
                private_b(),
                "03759bb22c563d9f4a6b3c1419e543fc2f39d6823f02a9d71162b39399218b244b",
                "be22d8b9f856a52ed381cd7eaf4cf2d525",
                "3cddc61a0a7882eb",
            ),
        ] {
            let nai = format!(
                "type1.rid678.schid{scheme}.hnkey27.ecckey{ecckey}.cip{cip}.mac{mac}@3gpp.com"
            );
            let suci = Suci::from_nai(&nai).unwrap();
            assert_eq!(suci.to_nai(), nai);
            assert_eq!(suci.home_network_public_key_id(), 27);
            assert_eq!(
                suci.deconceal(Some(&private)).unwrap().identity(),
                "verylongusername1@3gpp.com"
            );
            assert_eq!(Suci::from_nas(&suci.to_nas().unwrap()), Ok(suci));
        }
    }

    #[test]
    fn a_username_is_concealed_as_its_octets() {
        let supi = Supi::network_specific("user17@example.com").unwrap();
        for (public, private) in [(public_a(), private_a()), (public_b(), private_b())] {
            let protection = Protection::Ecies {
                key_id: 27,
                key: &public,
            };
            let suci = Suci::conceal_nai(&supi, "678", protection).unwrap();
            let SchemeOutput::Ecies { ciphertext, .. } = suci.scheme_output() else {
                panic!("the scheme output of a profile");
            };
            assert_eq!(ciphertext.len(), "user17".len());
            assert_eq!(
                suci.deconceal(Some(&private)),
                Ok(supi.clone().into_owned())
            );
            // A username that is not there cannot be concealed
            let anonymous = Supi::network_specific("@example.com").unwrap();
            assert_eq!(
                Suci::conceal_nai(&anonymous, "678", protection),
                Err(SuciError::Nai(NaiError::Username))
            );
        }
        // A GCI and a GLI have the null scheme alone
        let gci = Supi::gci("00-00-5E-00-53-00@operator.com").unwrap();
        let protection = Protection::Ecies {
            key_id: 1,
            key: &public_a(),
        };
        assert_eq!(
            Suci::conceal_nai(&gci, "0", protection),
            Err(SuciError::NullSchemeRequired)
        );
        assert_eq!(
            Suci::conceal_nai(&gci, "0", Protection::Null)
                .unwrap()
                .to_nai(),
            "type3.rid0.schid0.userid00-00-5E-00-53-00@operator.com"
        );
    }

    /// TS 33.501 Annex C.4.2.2: with the null scheme, the scheme output is
    /// the username of the NAI.
    #[test]
    fn annex_c4_null_scheme_nai_vector() {
        let supi = Supi::network_specific("verylongusername1@3gpp.com").unwrap();
        let suci = Suci::conceal_nai(&supi, "0", Protection::Null).unwrap();
        assert_eq!(
            suci.to_nai(),
            "type1.rid0.schid0.useridverylongusername1@3gpp.com"
        );
    }
}
