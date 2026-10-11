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

//! SUCI and SUPI in the NAI format (TS 23.003 §28.7.3, §28.15.5 and
//! §28.16.5): network specific identifiers, GCI and GLI.
//!
//! This is the `nai` feature. It brings the Unicode normalization of
//! RFC 7542 usernames and the IDNA rules of RFC 5891 realms, and with them
//! most of the crates that the crate depends on.

use super::{
    PROFILE_A_MAC_LEN, PROFILE_A_PUB_KEY_LEN, PROFILE_B_MAC_LEN, PROFILE_B_PUB_KEY_LEN,
    suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a, suci_scheme_output_b,
};
use crate::error::SecurityError;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use unicode_normalization::UnicodeNormalization;

/// SUPI type used by the textual NAI form in TS 23.003 clause 2.2B.
///
/// These values are the textual `type` field. TS 24.501 uses the opposite
/// ordering for GCI and GLI in its separate three-bit NAS SUPI-format field.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SupiType {
    /// IMSI.
    Imsi = 0,
    /// Network specific identifier.
    NetworkSpecific = 1,
    /// Global Line Identifier (GLI).
    Gli = 2,
    /// Global Cable Identifier (GCI).
    Gci = 3,
}

impl SupiType {
    fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Imsi),
            1 => Some(Self::NetworkSpecific),
            2 => Some(Self::Gli),
            3 => Some(Self::Gci),
            _ => None,
        }
    }
}

/// Typed protection-scheme output of a textual NAI SUCI.
#[non_exhaustive]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuciSchemeOutput {
    /// Clear UTF-8 username used by the null scheme.
    Null(Vec<u8>),
    /// Profile-A bytes: ephemeral public key, ciphertext, and MAC tag.
    ProfileA(Vec<u8>),
    /// Profile-B bytes: compressed ephemeral public key, ciphertext, and MAC tag.
    ProfileB(Vec<u8>),
    /// Operator-defined hexadecimal output for a scheme identifier in `0xC..=0xF`.
    Proprietary {
        /// Protection scheme identifier, `0xC` to `0xF`.
        scheme_id: u8,
        /// Scheme output, in the hexadecimal digits of the `out` field.
        output: String,
    },
}

/// Parsed TS 23.003 clause 28.7.3 SUCI in NAI form.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaiSuci {
    /// SUPI type, the `type` field.
    pub supi_type: SupiType,
    /// Routing indicator, the one to four decimal digits of the `rid` field.
    pub routing_indicator: String,
    /// Home network public key identifier, the `hnkey` field: `None` with
    /// the null scheme, which has no such field, and 1 to 255 otherwise.
    pub home_network_public_key_id: Option<u8>,
    /// Protection scheme and its output.
    pub scheme_output: SuciSchemeOutput,
    /// Realm, the part after the last `@`.
    pub realm: String,
}

/// Protection choice for constructing a network-specific-identifier SUCI.
#[non_exhaustive]
pub enum NaiProtectionScheme<'a> {
    /// Null scheme: the username stays in clear.
    Null,
    /// Profile A, ECIES over X25519.
    ProfileA {
        /// Home network public key identifier, 1 to 255.
        home_network_public_key_id: u8,
        /// X25519 home network public key.
        home_network_public_key: &'a [u8; 32],
    },
    /// Profile B, ECIES over P-256.
    ProfileB {
        /// Home network public key identifier, 1 to 255.
        home_network_public_key_id: u8,
        /// P-256 home network public key in SEC1 encoding, compressed or
        /// uncompressed.
        home_network_public_key: &'a [u8],
    },
}

fn invalid_nai() -> SecurityError {
    SecurityError::InvalidParameter("malformed SUCI NAI")
}

fn valid_routing_indicator(value: &str) -> bool {
    (1..=4).contains(&value.len()) && value.bytes().all(|byte| byte.is_ascii_digit())
}

/// Validate the RFC 7542 realm ABNF and RFC 5891 FQDN requirement.
fn valid_realm(value: &str) -> bool {
    if value.nfc().ne(value.chars()) {
        return false;
    }
    let labels: Vec<&str> = value.split('.').collect();
    let abnf_matches = labels.len() >= 2
        && labels.iter().all(|label| {
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
        return false;
    };
    if !abnf_matches || value.is_ascii() {
        return abnf_matches;
    }
    let (canonical_unicode, status) = idna::domain_to_unicode(&ascii);
    status.is_ok() && canonical_unicode == value
}

fn valid_nai_username(value: &str, allow_anonymous: bool) -> bool {
    if value.is_empty() {
        return allow_anonymous;
    }
    if value.nfc().ne(value.chars()) {
        return false;
    }
    value.split('.').all(|atom| {
        !atom.is_empty()
            && atom.chars().all(|character| {
                if character.is_ascii() {
                    character.is_ascii_alphanumeric()
                        || matches!(
                            character,
                            '!' | '#'
                                | '$'
                                | '%'
                                | '&'
                                | '\''
                                | '*'
                                | '+'
                                | '-'
                                | '/'
                                | '='
                                | '?'
                                | '^'
                                | '_'
                                | '`'
                                | '{'
                                | '|'
                                | '}'
                                | '~'
                        )
                } else {
                    !character.is_control()
                }
            })
    })
}

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

fn valid_gli(value: &str) -> bool {
    if value.is_empty() || value.len() > 200 {
        return false;
    }
    let Ok(decoded) = BASE64_STANDARD.decode(value) else {
        return false;
    };
    decoded.len() <= 150 && BASE64_STANDARD.encode(decoded) == value
}

fn valid_null_scheme_output(supi_type: SupiType, value: &str) -> bool {
    match supi_type {
        SupiType::Imsi => {
            !value.is_empty()
                && value.len() <= 10
                && value.bytes().all(|byte| byte.is_ascii_digit())
        }
        SupiType::NetworkSpecific => valid_nai_username(value, true),
        SupiType::Gli => valid_gli(value),
        SupiType::Gci => valid_nai_username(value, false),
    }
}

fn parse_decimal_field(field: &str, prefix: &str) -> Result<u8, SecurityError> {
    let digits = field.strip_prefix(prefix).ok_or_else(invalid_nai)?;
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(invalid_nai());
    }
    digits.parse().map_err(|_| invalid_nai())
}

fn validate_nai_suci(value: &NaiSuci) -> Result<(), SecurityError> {
    if !valid_routing_indicator(&value.routing_indicator)
        || !valid_realm(&value.realm)
        || (value.supi_type == SupiType::Imsi && !valid_imsi_realm(&value.realm))
    {
        return Err(invalid_nai());
    }
    if matches!(value.supi_type, SupiType::Gli | SupiType::Gci) && value.routing_indicator != "0" {
        return Err(SecurityError::InvalidParameter(
            "GCI/GLI routing indicator must be zero",
        ));
    }
    match &value.scheme_output {
        SuciSchemeOutput::Null(output) => {
            let username = std::str::from_utf8(output).map_err(|_| invalid_nai())?;
            if value.home_network_public_key_id.is_some()
                || !valid_null_scheme_output(value.supi_type, username)
            {
                return Err(invalid_nai());
            }
        }
        SuciSchemeOutput::ProfileA(output) => {
            if !matches!(value.supi_type, SupiType::Imsi | SupiType::NetworkSpecific)
                || value.home_network_public_key_id == Some(0)
                || value.home_network_public_key_id.is_none()
                || output.len() < PROFILE_A_PUB_KEY_LEN + PROFILE_A_MAC_LEN + 1
            {
                return Err(invalid_nai());
            }
        }
        SuciSchemeOutput::ProfileB(output) => {
            if !matches!(value.supi_type, SupiType::Imsi | SupiType::NetworkSpecific)
                || value.home_network_public_key_id == Some(0)
                || value.home_network_public_key_id.is_none()
                || output.len() < PROFILE_B_PUB_KEY_LEN + PROFILE_B_MAC_LEN + 1
            {
                return Err(invalid_nai());
            }
        }
        SuciSchemeOutput::Proprietary { scheme_id, output } => {
            if !(0x0c..=0x0f).contains(scheme_id)
                || !output.bytes().all(|byte| byte.is_ascii_hexdigit())
                || !matches!(value.supi_type, SupiType::Imsi | SupiType::NetworkSpecific)
                || value.home_network_public_key_id == Some(0)
                || value.home_network_public_key_id.is_none()
            {
                return Err(invalid_nai());
            }
        }
    }
    Ok(())
}

/// Parse the TS 23.003 clause 28.7.3/28.15.5/28.16.5 textual SUCI form.
pub fn parse_nai_suci(input: &str) -> Result<NaiSuci, SecurityError> {
    let (username, realm) = input.rsplit_once('@').ok_or_else(invalid_nai)?;
    if !valid_realm(realm) {
        return Err(invalid_nai());
    }
    let fields: Vec<&str> = username.split('.').collect();
    if fields.len() < 4 {
        return Err(invalid_nai());
    }
    let supi_type =
        SupiType::from_u8(parse_decimal_field(fields[0], "type")?).ok_or_else(invalid_nai)?;
    let routing_indicator = fields[1]
        .strip_prefix("rid")
        .filter(|value| valid_routing_indicator(value))
        .ok_or_else(invalid_nai)?
        .to_owned();
    let scheme_id = parse_decimal_field(fields[2], "schid")?;
    if scheme_id > 15 {
        return Err(invalid_nai());
    }

    let (home_network_public_key_id, scheme_output) = match scheme_id {
        0 => {
            let prefix = format!("{}.{}.{}.userid", fields[0], fields[1], fields[2]);
            let output = username.strip_prefix(&prefix).ok_or_else(invalid_nai)?;
            (None, SuciSchemeOutput::Null(output.as_bytes().to_vec()))
        }
        1 | 2 => {
            if fields.len() != 7 {
                return Err(invalid_nai());
            }
            let key_id = parse_decimal_field(fields[3], "hnkey")?;
            if key_id == 0 {
                return Err(invalid_nai());
            }
            let ephemeral = hex::decode(fields[4].strip_prefix("ecckey").ok_or_else(invalid_nai)?)
                .map_err(|_| invalid_nai())?;
            let ciphertext = hex::decode(fields[5].strip_prefix("cip").ok_or_else(invalid_nai)?)
                .map_err(|_| invalid_nai())?;
            let mac = hex::decode(fields[6].strip_prefix("mac").ok_or_else(invalid_nai)?)
                .map_err(|_| invalid_nai())?;
            let expected_ephemeral = if scheme_id == 1 {
                PROFILE_A_PUB_KEY_LEN
            } else {
                PROFILE_B_PUB_KEY_LEN
            };
            if ephemeral.len() != expected_ephemeral || ciphertext.is_empty() || mac.len() != 8 {
                return Err(invalid_nai());
            }
            let mut output = Vec::with_capacity(ephemeral.len() + ciphertext.len() + mac.len());
            output.extend_from_slice(&ephemeral);
            output.extend_from_slice(&ciphertext);
            output.extend_from_slice(&mac);
            let output = if scheme_id == 1 {
                SuciSchemeOutput::ProfileA(output)
            } else {
                SuciSchemeOutput::ProfileB(output)
            };
            (Some(key_id), output)
        }
        3..=11 => return Err(invalid_nai()),
        scheme_id => {
            if fields.len() < 5 {
                return Err(invalid_nai());
            }
            let key_id = parse_decimal_field(fields[3], "hnkey")?;
            if key_id == 0 {
                return Err(invalid_nai());
            }
            let prefix = format!(
                "{}.{}.{}.{}.out",
                fields[0], fields[1], fields[2], fields[3]
            );
            let output = username
                .strip_prefix(&prefix)
                .ok_or_else(invalid_nai)?
                .to_owned();
            (
                Some(key_id),
                SuciSchemeOutput::Proprietary { scheme_id, output },
            )
        }
    };
    let parsed = NaiSuci {
        supi_type,
        routing_indicator,
        home_network_public_key_id,
        scheme_output,
        realm: realm.to_owned(),
    };
    validate_nai_suci(&parsed)?;
    Ok(parsed)
}

/// Encode a typed SUCI into the TS 23.003 NAI representation.
pub fn encode_nai_suci(suci: &NaiSuci) -> Result<String, SecurityError> {
    validate_nai_suci(suci)?;
    let prefix = format!("type{}.rid{}", suci.supi_type as u8, suci.routing_indicator);
    let username = match &suci.scheme_output {
        SuciSchemeOutput::Null(output) => format!(
            "{prefix}.schid0.userid{}",
            std::str::from_utf8(output).map_err(|_| invalid_nai())?
        ),
        SuciSchemeOutput::ProfileA(output) => {
            let key_id = suci.home_network_public_key_id.ok_or_else(invalid_nai)?;
            let cipher_end = output.len() - PROFILE_A_MAC_LEN;
            format!(
                "{prefix}.schid1.hnkey{key_id}.ecckey{}.cip{}.mac{}",
                hex::encode(&output[..PROFILE_A_PUB_KEY_LEN]),
                hex::encode(&output[PROFILE_A_PUB_KEY_LEN..cipher_end]),
                hex::encode(&output[cipher_end..]),
            )
        }
        SuciSchemeOutput::ProfileB(output) => {
            let key_id = suci.home_network_public_key_id.ok_or_else(invalid_nai)?;
            let cipher_end = output.len() - PROFILE_B_MAC_LEN;
            format!(
                "{prefix}.schid2.hnkey{key_id}.ecckey{}.cip{}.mac{}",
                hex::encode(&output[..PROFILE_B_PUB_KEY_LEN]),
                hex::encode(&output[PROFILE_B_PUB_KEY_LEN..cipher_end]),
                hex::encode(&output[cipher_end..]),
            )
        }
        SuciSchemeOutput::Proprietary { scheme_id, output } => {
            let key_id = suci.home_network_public_key_id.ok_or_else(invalid_nai)?;
            format!("{prefix}.schid{scheme_id}.hnkey{key_id}.out{output}")
        }
    };
    Ok(format!("{username}@{}", suci.realm))
}

/// Construct a network-specific-identifier SUCI from a `username@realm` SUPI.
pub fn conceal_network_specific_supi(
    supi: &str,
    routing_indicator: &str,
    protection: NaiProtectionScheme<'_>,
) -> Result<NaiSuci, SecurityError> {
    let (username, realm) = supi.rsplit_once('@').ok_or_else(invalid_nai)?;
    if !valid_realm(realm)
        || !valid_nai_username(username, false)
        || !valid_routing_indicator(routing_indicator)
    {
        return Err(invalid_nai());
    }
    let (key_id, output) = match protection {
        NaiProtectionScheme::Null => (None, SuciSchemeOutput::Null(username.as_bytes().to_vec())),
        NaiProtectionScheme::ProfileA {
            home_network_public_key_id,
            home_network_public_key,
        } => {
            if username.is_empty() || home_network_public_key_id == 0 {
                return Err(invalid_nai());
            }
            (
                Some(home_network_public_key_id),
                SuciSchemeOutput::ProfileA(suci_scheme_output_a(
                    username.as_bytes(),
                    home_network_public_key,
                )?),
            )
        }
        NaiProtectionScheme::ProfileB {
            home_network_public_key_id,
            home_network_public_key,
        } => {
            if username.is_empty() || home_network_public_key_id == 0 {
                return Err(invalid_nai());
            }
            (
                Some(home_network_public_key_id),
                SuciSchemeOutput::ProfileB(suci_scheme_output_b(
                    username.as_bytes(),
                    home_network_public_key,
                )?),
            )
        }
    };
    let suci = NaiSuci {
        supi_type: SupiType::NetworkSpecific,
        routing_indicator: routing_indicator.to_owned(),
        home_network_public_key_id: key_id,
        scheme_output: output,
        realm: realm.to_owned(),
    };
    validate_nai_suci(&suci)?;
    Ok(suci)
}

/// Deconceal a non-IMSI NAI SUCI into its `username@realm` SUPI.
pub fn deconceal_nai_suci(
    suci: &NaiSuci,
    home_network_private_key: Option<&[u8]>,
) -> Result<String, SecurityError> {
    validate_nai_suci(suci)?;
    if suci.supi_type == SupiType::Imsi {
        return Err(SecurityError::InvalidParameter(
            "IMSI NAI deconcealment needs the IMSI home-network prefix",
        ));
    }
    let username = match &suci.scheme_output {
        SuciSchemeOutput::Null(output) => output.clone(),
        SuciSchemeOutput::ProfileA(output) => {
            let key: &[u8; 32] = home_network_private_key
                .ok_or(SecurityError::InvalidParameter(
                    "missing home-network private key",
                ))?
                .try_into()
                .map_err(|_| SecurityError::InvalidKeyLength {
                    expected: 32,
                    got: home_network_private_key.map_or(0, <[u8]>::len),
                })?;
            suci_decrypt_a(output, key)?
        }
        SuciSchemeOutput::ProfileB(output) => suci_decrypt_b(
            output,
            home_network_private_key.ok_or(SecurityError::InvalidParameter(
                "missing home-network private key",
            ))?,
        )?,
        SuciSchemeOutput::Proprietary { .. } => {
            return Err(SecurityError::InvalidParameter(
                "operator-defined SUCI cannot be deconcealed generically",
            ));
        }
    };
    let username = String::from_utf8(username).map_err(|_| invalid_nai())?;
    if !valid_null_scheme_output(suci.supi_type, &username) {
        return Err(invalid_nai());
    }
    Ok(format!("{username}@{}", suci.realm))
}

/// Deconceal a network-specific-identifier SUCI.
pub fn deconceal_network_specific_suci(
    suci: &NaiSuci,
    home_network_private_key: Option<&[u8]>,
) -> Result<String, SecurityError> {
    if suci.supi_type != SupiType::NetworkSpecific {
        return Err(SecurityError::InvalidParameter(
            "SUCI is not a network-specific identifier",
        ));
    }
    deconceal_nai_suci(suci, home_network_private_key)
}

/// Deconceal the NAI that a NAS SUCI carries after its first octet.
/// `nas_supi_format` is the SUPI format of that octet: 1 for a network
/// specific identifier, 2 for a GCI and 3 for a GLI (TS 24.501 §9.11.3.4).
pub(super) fn nas_nai_suci_to_supi(
    nas_supi_format: u8,
    nai: &[u8],
    home_network_private_key: Option<&[u8]>,
) -> Option<String> {
    let expected_textual_type = match nas_supi_format {
        1 => SupiType::NetworkSpecific,
        // TS 24.501 NAS values 2/3 are GCI/GLI, while TS 23.003's
        // textual type values 2/3 are GLI/GCI.
        2 => SupiType::Gci,
        3 => SupiType::Gli,
        _ => return None,
    };
    let parsed = parse_nai_suci(std::str::from_utf8(nai).ok()?).ok()?;
    if parsed.supi_type != expected_textual_type {
        return None;
    }
    deconceal_nai_suci(&parsed, home_network_private_key).ok()
}

#[cfg(test)]
mod tests {
    use super::super::suci_to_supi;
    use super::super::test_keys::*;
    use super::*;

    #[test]
    fn nai_null_scheme_real_wire_and_gci_gli_mapping() {
        let wire = "type1.rid678.schid0.useriduser17@example.com";
        let parsed = parse_nai_suci(wire).unwrap();
        assert_eq!(parsed.supi_type, SupiType::NetworkSpecific);
        assert_eq!(encode_nai_suci(&parsed).unwrap(), wire);
        assert_eq!(
            deconceal_network_specific_suci(&parsed, None).unwrap(),
            "user17@example.com"
        );

        let mut nas = vec![0x11];
        nas.extend_from_slice(wire.as_bytes());
        assert_eq!(
            suci_to_supi(&nas, None).as_deref(),
            Some("user17@example.com")
        );

        // NAS format 2 means GCI, whose TS 23.003 textual type is 3.
        let gci = "type3.rid0.schid0.userid00-00-5E-00-53-00@operator.com";
        let mut nas = vec![0x21];
        nas.extend_from_slice(gci.as_bytes());
        assert_eq!(
            suci_to_supi(&nas, None).as_deref(),
            Some("00-00-5E-00-53-00@operator.com")
        );
        // NAS format 3 means GLI, whose textual type is 2.
        let gli = "type2.rid0.schid0.useridQUJDRA==@operator.com";
        let mut nas = vec![0x31];
        nas.extend_from_slice(gli.as_bytes());
        assert_eq!(
            suci_to_supi(&nas, None).as_deref(),
            Some("QUJDRA==@operator.com")
        );
        assert!(parse_nai_suci("type3.rid1.schid0.userid00-00-5E-00-53-00@operator.com").is_err());
    }

    #[test]
    fn nai_proprietary_scheme_range_and_hex_output_are_strict() {
        for valid in [
            "type1.rid678.schid12.hnkey27.out00aBff@example.com",
            "type1.rid678.schid12.hnkey255.out00aBff@example.com",
        ] {
            let parsed = parse_nai_suci(valid).unwrap();
            assert_eq!(encode_nai_suci(&parsed).unwrap(), valid);
        }

        assert!(parse_nai_suci("type1.rid678.schid3.hnkey27.out00aBff@example.com").is_err());
        assert!(parse_nai_suci("type1.rid678.schid12.hnkey27.outnot-hex@example.com").is_err());
        assert!(
            encode_nai_suci(&NaiSuci {
                supi_type: SupiType::NetworkSpecific,
                routing_indicator: "678".into(),
                home_network_public_key_id: Some(27),
                scheme_output: SuciSchemeOutput::Proprietary {
                    scheme_id: 15,
                    output: "xyz".into(),
                },
                realm: "example.com".into(),
            })
            .is_err()
        );
    }

    #[test]
    fn nai_rfc7542_username_and_realm_grammar_is_strict() {
        for realm in [
            ".",
            "a..b",
            "-bad.example",
            "bad-.example",
            "example",
            "ｅxample.com",
            "a．b.example",
        ] {
            assert!(
                encode_nai_suci(&NaiSuci {
                    supi_type: SupiType::NetworkSpecific,
                    routing_indicator: "678".into(),
                    home_network_public_key_id: Some(27),
                    scheme_output: SuciSchemeOutput::Proprietary {
                        scheme_id: 12,
                        output: "aabb".into(),
                    },
                    realm: realm.into(),
                })
                .is_err(),
                "realm {realm:?}"
            );
        }
        for wire in [
            "type1.rid678.schid0.userida b@example.com",
            "type1.rid678.schid0.userida@b@example.com",
            "type1.rid678.schid0.userida..b@example.com",
        ] {
            assert!(parse_nai_suci(wire).is_err(), "{wire}");
        }
        assert!(
            conceal_network_specific_supi("a b@example.com", "678", NaiProtectionScheme::Null)
                .is_err()
        );
        assert!(
            conceal_network_specific_supi("a@b@example.com", "678", NaiProtectionScheme::Null)
                .is_err()
        );
        assert!(
            conceal_network_specific_supi("e\u{301}@example.com", "678", NaiProtectionScheme::Null)
                .is_err()
        );

        for username in ["user\u{a0}name", "user\u{2003}name"] {
            let supi = format!("{username}@example.com");
            let concealed =
                conceal_network_specific_supi(&supi, "678", NaiProtectionScheme::Null).unwrap();
            assert_eq!(
                deconceal_network_specific_suci(&concealed, None).unwrap(),
                supi
            );
        }
        for username in ["user\u{85}name", "user\u{7f}name"] {
            assert!(
                conceal_network_specific_supi(
                    &format!("{username}@example.com"),
                    "678",
                    NaiProtectionScheme::Null,
                )
                .is_err()
            );
        }

        let unicode =
            conceal_network_specific_supi("élodie@example.com", "678", NaiProtectionScheme::Null)
                .unwrap();
        assert_eq!(
            deconceal_network_specific_suci(&unicode, None).unwrap(),
            "élodie@example.com"
        );
        for realm in ["bücher.example", "xn--bcher-kva.example"] {
            let nai = format!("alice@{realm}");
            let concealed =
                conceal_network_specific_supi(&nai, "678", NaiProtectionScheme::Null).unwrap();
            assert_eq!(
                deconceal_network_specific_suci(&concealed, None).unwrap(),
                nai
            );
        }
        assert!(parse_nai_suci("type1.rid678.schid0.useridélodie@bu\u{0308}cher.example").is_err());
        for imsi in [
            "type0.rid678.schid0.userid0999999999@5gc.mnc015.mcc234.3gppnetwork.org",
            "type0.rid678.schid0.userid0999999999@5gc.nid000007ed9d5.mnc015.mcc234.3gppnetwork.org",
        ] {
            assert_eq!(
                encode_nai_suci(&parse_nai_suci(imsi).unwrap()).unwrap(),
                imsi
            );
        }
        for wire in [
            "type0.rid678.schid0.userid@5gc.mnc015.mcc234.3gppnetwork.org",
            "type0.rid678.schid0.useridabc@5gc.mnc015.mcc234.3gppnetwork.org",
            "type0.rid678.schid0.userid01234567890@5gc.mnc015.mcc234.3gppnetwork.org",
            "type0.rid678.schid0.userid0123@example.com",
            "type3.rid0.schid0.userid@operator.com",
            "type2.rid0.schid0.userid***@operator.com",
        ] {
            assert!(parse_nai_suci(wire).is_err(), "{wire}");
        }
    }

    #[test]
    fn nai_profiles_decrypt_official_annex_c_vectors() {
        let private_a = hex::decode(PROFILE_A_PRIV).unwrap();
        let output_a = hex::decode(concat!(
            "977d8b2fdaa7b64aa700d04227d5b440630ea4ec50f9082273a26bb678c92222",
            "8e358a1582adb15322c10e515141d2039a",
            "12e1d7783a97f1ac"
        ))
        .unwrap();
        let suci_a = NaiSuci {
            supi_type: SupiType::NetworkSpecific,
            routing_indicator: "678".into(),
            home_network_public_key_id: Some(27),
            scheme_output: SuciSchemeOutput::ProfileA(output_a),
            realm: "3gpp.com".into(),
        };
        assert_eq!(
            deconceal_network_specific_suci(&suci_a, Some(&private_a)).unwrap(),
            "verylongusername1@3gpp.com"
        );
        assert_eq!(
            parse_nai_suci(&encode_nai_suci(&suci_a).unwrap()).unwrap(),
            suci_a
        );

        let private_b = hex::decode(PROFILE_B_PRIV).unwrap();
        let output_b = hex::decode(concat!(
            "03759bb22c563d9f4a6b3c1419e543fc2f39d6823f02a9d71162b39399218b244b",
            "be22d8b9f856a52ed381cd7eaf4cf2d525",
            "3cddc61a0a7882eb"
        ))
        .unwrap();
        let suci_b = NaiSuci {
            supi_type: SupiType::NetworkSpecific,
            routing_indicator: "678".into(),
            home_network_public_key_id: Some(27),
            scheme_output: SuciSchemeOutput::ProfileB(output_b),
            realm: "3gpp.com".into(),
        };
        assert_eq!(
            deconceal_network_specific_suci(&suci_b, Some(&private_b)).unwrap(),
            "verylongusername1@3gpp.com"
        );
        assert_eq!(
            parse_nai_suci(&encode_nai_suci(&suci_b).unwrap()).unwrap(),
            suci_b
        );
    }

    #[test]
    fn nai_constructor_uses_utf8_username_as_ecies_plaintext() {
        let public: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let private = hex::decode(PROFILE_A_PRIV).unwrap();
        let suci = conceal_network_specific_supi(
            "user17@example.com",
            "678",
            NaiProtectionScheme::ProfileA {
                home_network_public_key_id: 27,
                home_network_public_key: &public,
            },
        )
        .unwrap();
        assert_eq!(
            deconceal_network_specific_suci(&suci, Some(&private)).unwrap(),
            "user17@example.com"
        );
    }

    /// TS 33.501 Annex C.4.2.2: with the null scheme, the scheme output is
    /// the username of the NAI.
    #[test]
    fn annex_c4_null_scheme_nai_vector() {
        let suci = conceal_network_specific_supi(
            "verylongusername1@3gpp.com",
            "0",
            NaiProtectionScheme::Null,
        )
        .unwrap();
        assert!(
            encode_nai_suci(&suci)
                .unwrap()
                .ends_with(".schid0.useridverylongusername1@3gpp.com")
        );
    }
}
