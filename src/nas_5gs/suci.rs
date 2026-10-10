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

//! SUCI concealment per 3GPP TS 33.501 Annex C.4.
//!
//! Implements:
//! - Null scheme (scheme_id=0): MSIN in BCD cleartext
//! - Profile A (scheme_id=1): X25519 ECIES — AES-128-CTR + HMAC-SHA-256
//! - Profile B (scheme_id=2): P-256 ECIES — AES-128-CTR + HMAC-SHA-256

use crate::error::SecurityError;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64_STANDARD};
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

// Profile A (X25519)
const PROFILE_A_ENC_KEY_LEN: usize = 16;
const PROFILE_A_MAC_KEY_LEN: usize = 32;
const PROFILE_A_ICB_LEN: usize = 16;
const PROFILE_A_MAC_LEN: usize = 8;
const PROFILE_A_PUB_KEY_LEN: usize = 32;

// Profile B (P-256, compressed ephemeral pub key)
const PROFILE_B_ENC_KEY_LEN: usize = 16;
const PROFILE_B_MAC_KEY_LEN: usize = 32;
const PROFILE_B_ICB_LEN: usize = 16;
const PROFILE_B_MAC_LEN: usize = 8;
const PROFILE_B_PUB_KEY_LEN: usize = 33; // compressed

/// SUPI type used by the textual NAI form in TS 23.003 clause 2.2B.
///
/// These values are the textual `type` field. TS 24.501 uses the opposite
/// ordering for GCI and GLI in its separate three-bit NAS SUPI-format field.
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

/// ANSI X9.63 KDF using SHA-256.
/// Returns `enc_key_len + mac_key_len` bytes of key material (where enc_key_len should include the ICB length if an ICB is needed),
/// wiped on drop like the hash state.
fn ansi_x963_kdf(
    shared_key: &[u8],
    public_key: &[u8],
    enc_key_len: usize,
    mac_key_len: usize,
) -> Zeroizing<Vec<u8>> {
    use crate::common::sha256::Sha256;
    let total = enc_key_len + mac_key_len;
    let hash_len = 32usize;
    let rounds = total.div_ceil(hash_len);
    // Exact capacity: the vector never reallocates and leaves no copy behind.
    let mut kdf_key = Zeroizing::new(Vec::with_capacity(rounds * hash_len));
    for i in 0u32..rounds as u32 {
        let counter = (i + 1).to_be_bytes();
        let mut h = Sha256::new();
        h.update(shared_key);
        h.update(&counter);
        h.update(public_key);
        let mut digest = h.finalize();
        kdf_key.extend_from_slice(&digest);
        digest.zeroize();
    }
    kdf_key
}

/// AES-128-CTR encryption with the ICB as the first counter block, incremented
/// as one 128-bit big-endian integer. The keystream and counter blocks are
/// wiped.
fn aes128_ctr(key: &[u8; 16], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut counter = Zeroizing::new(*icb);
    for chunk in data.chunks(16) {
        let mut block = aes::Block::clone_from_slice(counter.as_ref());
        aes.encrypt_block(&mut block);
        for (d, k) in chunk.iter().zip(block.iter()) {
            out.push(d ^ k);
        }
        block.as_mut_slice().zeroize();
        let mut carry = 1u16;
        for octet in counter.iter_mut().rev() {
            let sum = u16::from(*octet) + carry;
            *octet = sum as u8;
            carry = sum >> 8;
        }
    }
    out
}

/// HMAC-SHA-256 truncated to 8 bytes.
fn hmac_sha256_8(key: &[u8], data: &[u8]) -> [u8; 8] {
    crate::common::sha256::hmac_sha256(key, data)[..8]
        .try_into()
        .expect("SHA-256 output is 32 bytes, 8-byte prefix always valid")
}

/// MSIN decimal string → packed BCD bytes (low nibble first, right-padded with 0xF if odd length).
///
/// # Panics
///
/// Panics if `msin` contains a non-ASCII decimal digit.
pub fn msin_to_bcd(msin: &str) -> Vec<u8> {
    assert!(
        msin.as_bytes().iter().all(|b| b.is_ascii_digit()),
        "MSIN must be ASCII digits"
    );
    let bytes = msin.as_bytes();
    let len = bytes.len().div_ceil(2);
    let mut out = Vec::with_capacity(len);
    let mut i = 0;
    while i < bytes.len() {
        let lo = bytes[i] - b'0';
        let hi = if i + 1 < bytes.len() {
            bytes[i + 1] - b'0'
        } else {
            0xF
        };
        out.push(lo | (hi << 4));
        i += 2;
    }
    out
}

/// Build the scheme output bytes for SUCI Profile A (X25519 ECIES).
///
/// `hn_pub_key`: 32-byte X25519 home network public key.
/// Returns: `ephemeral_pub (32) || ciphertext (len(msin_bcd)) || mac (8)`
///
/// An empty `msin_bcd` is an error, as a scheme output without ciphertext is
/// one for [`suci_decrypt_a`].
pub fn suci_scheme_output_a(
    msin_bcd: &[u8],
    hn_pub_key: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    if msin_bcd.is_empty() {
        return Err(SecurityError::Ecies(
            "Profile A scheme input is empty".into(),
        ));
    }
    let hn_pub = PublicKey::from(*hn_pub_key);
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&hn_pub);
    if !shared.was_contributory() {
        return Err(SecurityError::Ecies(
            "invalid X25519 home network public key".into(),
        ));
    }

    let eph_pub_bytes = eph_pub.as_bytes();
    let kdf = ansi_x963_kdf(
        shared.as_bytes(),
        eph_pub_bytes,
        PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN,
        PROFILE_A_MAC_KEY_LEN,
    );
    let enc_key: &[u8; PROFILE_A_ENC_KEY_LEN] = kdf[0..PROFILE_A_ENC_KEY_LEN]
        .try_into()
        .expect("KDF output is at least ENC_KEY_LEN bytes");
    let icb: &[u8; PROFILE_A_ICB_LEN] = kdf
        [PROFILE_A_ENC_KEY_LEN..PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN]
        .try_into()
        .expect("KDF output is at least ENC_KEY_LEN + ICB_LEN bytes");
    let mac_key = &kdf[kdf.len() - PROFILE_A_MAC_KEY_LEN..];

    let ciphertext = aes128_ctr(enc_key, icb, msin_bcd);
    let mac = hmac_sha256_8(mac_key, &ciphertext);

    let mut out = Vec::with_capacity(PROFILE_A_PUB_KEY_LEN + msin_bcd.len() + PROFILE_A_MAC_LEN);
    out.extend_from_slice(eph_pub_bytes);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Build the scheme output bytes for SUCI Profile B (P-256 ECIES, compressed ephemeral key).
///
/// `hn_pub_key`: P-256 public key in SEC1 encoding (33-byte compressed or 65-byte uncompressed).
/// Returns: `compressed_eph_pub (33) || ciphertext (len(msin_bcd)) || mac (8)`
///
/// An empty `msin_bcd` is an error, as a scheme output without ciphertext is
/// one for [`suci_decrypt_b`], and so is a key in another SEC1 encoding.
pub fn suci_scheme_output_b(msin_bcd: &[u8], hn_pub_key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    if msin_bcd.is_empty() {
        return Err(SecurityError::Ecies(
            "Profile B scheme input is empty".into(),
        ));
    }
    // SEC1 has other encodings, which p256 would decode: the x-only one of
    // tag 0x05 among them.
    if !matches!(
        (hn_pub_key.first(), hn_pub_key.len()),
        (Some(0x02 | 0x03), 33) | (Some(0x04), 65)
    ) {
        return Err(SecurityError::Ecies(
            "Profile B home network public key must be compressed or uncompressed".into(),
        ));
    }
    let hn_pub = PublicKey::from_sec1_bytes(hn_pub_key)
        .map_err(|e| SecurityError::Ecies(format!("invalid P-256 public key: {e}")))?;
    let eph_secret = EphemeralSecret::random(&mut OsRng);
    let eph_pub = eph_secret.public_key();

    // Compressed ephemeral public key (33 bytes)
    let eph_pub_enc = eph_pub.to_encoded_point(true);
    let eph_pub_bytes = eph_pub_enc.as_bytes();

    let shared = eph_secret.diffie_hellman(&hn_pub);
    let shared_bytes = shared.raw_secret_bytes();

    let kdf = ansi_x963_kdf(
        shared_bytes.as_slice(),
        eph_pub_bytes,
        PROFILE_B_ENC_KEY_LEN + PROFILE_B_ICB_LEN,
        PROFILE_B_MAC_KEY_LEN,
    );
    let enc_key: &[u8; PROFILE_B_ENC_KEY_LEN] = kdf[0..PROFILE_B_ENC_KEY_LEN]
        .try_into()
        .expect("KDF output is at least ENC_KEY_LEN bytes");
    let icb: &[u8; PROFILE_B_ICB_LEN] = kdf
        [PROFILE_B_ENC_KEY_LEN..PROFILE_B_ENC_KEY_LEN + PROFILE_B_ICB_LEN]
        .try_into()
        .expect("KDF output is at least ENC_KEY_LEN + ICB_LEN bytes");
    let mac_key = &kdf[kdf.len() - PROFILE_B_MAC_KEY_LEN..];

    let ciphertext = aes128_ctr(enc_key, icb, msin_bcd);
    let mac = hmac_sha256_8(mac_key, &ciphertext);

    let mut out = Vec::with_capacity(PROFILE_B_PUB_KEY_LEN + msin_bcd.len() + PROFILE_B_MAC_LEN);
    out.extend_from_slice(eph_pub_bytes);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&mac);
    Ok(out)
}

/// Conceal MSIN using the specified SUCI protection scheme.
///
/// Dispatches to null scheme, Profile A, or Profile B based on `scheme_id`.
/// - `scheme_id=0`: null scheme — returns raw `msin_bcd`.
/// - `scheme_id=1`: Profile A (X25519) — `hn_pub_key` must be 32 bytes.
/// - `scheme_id=2`: Profile B (P-256) — `hn_pub_key` in SEC1 encoding.
///
/// Returns the scheme output bytes (for non-null: `ephemeral_pub || ciphertext || mac`).
/// Profile A and Profile B return an error for an empty `msin_bcd`; the null
/// scheme returns it as it is.
pub fn suci_conceal(
    msin_bcd: &[u8],
    scheme_id: u8,
    hn_pub_key: &[u8],
) -> Result<Vec<u8>, SecurityError> {
    match scheme_id {
        0x00 => Ok(msin_bcd.to_vec()),
        0x01 => {
            let key: &[u8; 32] =
                hn_pub_key
                    .try_into()
                    .map_err(|_| SecurityError::InvalidKeyLength {
                        expected: 32,
                        got: hn_pub_key.len(),
                    })?;
            suci_scheme_output_a(msin_bcd, key)
        }
        0x02 => suci_scheme_output_b(msin_bcd, hn_pub_key),
        _ => Err(SecurityError::Ecies(format!(
            "unsupported protection scheme: {scheme_id}"
        ))),
    }
}

// ── SUCI decryption (network-side) ──────────────────────────────────────────

/// Decrypt a Profile A (X25519 ECIES) scheme output.
///
/// `scheme_output`: `ephemeral_pub (32) || ciphertext || mac (8)`
/// `hn_priv_key`: 32-byte X25519 home network private key.
/// Returns the decrypted MSIN in BCD.
pub fn suci_decrypt_a(
    scheme_output: &[u8],
    hn_priv_key: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    use x25519_dalek::{PublicKey, StaticSecret};

    if scheme_output.len() < PROFILE_A_PUB_KEY_LEN + PROFILE_A_MAC_LEN + 1 {
        return Err(SecurityError::Ecies(
            "Profile A scheme output too short".into(),
        ));
    }
    let priv_key = StaticSecret::from(*hn_priv_key);
    let eph_pub = PublicKey::from(
        <[u8; 32]>::try_from(&scheme_output[0..32])
            .map_err(|_| SecurityError::Ecies("invalid ephemeral public key".into()))?,
    );
    let shared = priv_key.diffie_hellman(&eph_pub);
    if !shared.was_contributory() {
        return Err(SecurityError::Ecies(
            "invalid X25519 ephemeral public key".into(),
        ));
    }

    let kdf = ansi_x963_kdf(
        shared.as_bytes(),
        &scheme_output[0..32],
        PROFILE_A_ENC_KEY_LEN + PROFILE_A_ICB_LEN,
        PROFILE_A_MAC_KEY_LEN,
    );
    let enc_key: &[u8; 16] = kdf[0..16].try_into().expect("KDF output >= 16");
    let icb: &[u8; 16] = kdf[16..32].try_into().expect("KDF output >= 32");
    let mac_key = &kdf[32..];

    let ciphertext = &scheme_output[32..scheme_output.len() - 8];
    let mac_received = &scheme_output[scheme_output.len() - 8..];
    let mac_computed = hmac_sha256_8(mac_key, ciphertext);
    if mac_received.ct_eq(&mac_computed).unwrap_u8() != 1 {
        return Err(SecurityError::MacMismatch);
    }
    Ok(aes128_ctr(enc_key, icb, ciphertext))
}

/// Decrypt a Profile B (P-256 ECIES) scheme output.
///
/// `scheme_output`: `ephemeral_pub (33 compressed) || ciphertext || mac (8)`
/// `hn_priv_key`: 32-byte P-256 home network private key.
/// Returns the decrypted MSIN in BCD.
///
/// Profile B always applies point compression (TS 33.501 Annex C.3.4.2), so
/// SharedInfo1 of the KDF is the 33-byte compressed ephemeral public key.
/// Uncompressed ephemeral keys are rejected (TS 33.514 §4.2.1.3).
pub fn suci_decrypt_b(scheme_output: &[u8], hn_priv_key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use p256::{PublicKey, SecretKey};

    let priv_bytes: &[u8; 32] =
        hn_priv_key
            .try_into()
            .map_err(|_| SecurityError::InvalidKeyLength {
                expected: 32,
                got: hn_priv_key.len(),
            })?;
    let priv_key = SecretKey::from_bytes(priv_bytes.into())
        .map_err(|e| SecurityError::Ecies(format!("invalid P-256 private key: {e}")))?;

    if !matches!(scheme_output.first(), Some(0x02 | 0x03)) {
        return Err(SecurityError::Ecies(
            "Profile B ephemeral public key must be compressed".into(),
        ));
    }
    if scheme_output.len() < PROFILE_B_PUB_KEY_LEN + PROFILE_B_MAC_LEN + 1 {
        return Err(SecurityError::Ecies(
            "Profile B scheme output too short".into(),
        ));
    }
    // The compressed point is also SharedInfo1 of the KDF.
    let eph_pub_bytes = &scheme_output[0..PROFILE_B_PUB_KEY_LEN];
    let eph_pub = PublicKey::from_sec1_bytes(eph_pub_bytes)
        .map_err(|e| SecurityError::Ecies(format!("invalid ephemeral P-256 key: {e}")))?;

    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        priv_key.to_nonzero_scalar(),
        eph_pub.as_affine(),
    );
    let shared_bytes = shared.raw_secret_bytes();

    let kdf = ansi_x963_kdf(
        shared_bytes.as_slice(),
        eph_pub_bytes,
        PROFILE_B_ENC_KEY_LEN + PROFILE_B_ICB_LEN,
        PROFILE_B_MAC_KEY_LEN,
    );
    let enc_key: &[u8; 16] = kdf[0..16].try_into().expect("KDF output >= 16");
    let icb: &[u8; 16] = kdf[16..32].try_into().expect("KDF output >= 32");
    let mac_key = &kdf[32..];

    let ciphertext = &scheme_output[PROFILE_B_PUB_KEY_LEN..scheme_output.len() - 8];
    let mac_received = &scheme_output[scheme_output.len() - 8..];
    let mac_computed = hmac_sha256_8(mac_key, ciphertext);
    if mac_received.ct_eq(&mac_computed).unwrap_u8() != 1 {
        return Err(SecurityError::MacMismatch);
    }
    Ok(aes128_ctr(enc_key, icb, ciphertext))
}

// ── SUCI → SUPI decoding (network-side) ─────────────────────────────────────

fn decode_routing_indicator(bytes: &[u8]) -> Option<String> {
    if bytes.len() != 2 {
        return None;
    }
    let mut digits = String::new();
    let mut filler = false;
    for nibble in [
        bytes[0] & 0x0f,
        bytes[0] >> 4,
        bytes[1] & 0x0f,
        bytes[1] >> 4,
    ] {
        match nibble {
            0..=9 if !filler => digits.push(char::from(b'0' + nibble)),
            0x0f => filler = true,
            _ => return None,
        }
    }
    (!digits.is_empty()).then_some(digits)
}

/// Decode a SUCI to SUPI, supporting all protection schemes.
///
/// - Null scheme (0x00): MSIN decoded directly from BCD.
/// - Profile A (0x01): X25519 ECIES decryption with `hn_priv_key`.
/// - Profile B (0x02): P-256 ECIES decryption with `hn_priv_key`.
///
/// `hn_priv_key`: home network private key bytes (32 bytes for both profiles).
/// Pass `None` if only null-scheme SUCI is expected.
///
/// Returns `imsi-<MCC><MNC><MSIN>` for a SUCI in the IMSI format. For a SUCI
/// in a NAI format (network specific identifier, GCI or GLI) it returns the
/// `username@realm` SUPI as it is, without the `nai-`, `gci-` or `gli-`
/// prefix of the SBI representation (TS 29.571). Returns `None` for a SUCI
/// that is malformed or cannot be deconcealed.
pub fn suci_to_supi(suci: &[u8], hn_priv_key: Option<&[u8]>) -> Option<String> {
    if suci.len() < 2 || suci[0] & 0x07 != 0x01 {
        return None;
    }
    let nas_supi_format = (suci[0] >> 4) & 0x07;
    if matches!(nas_supi_format, 1..=3) {
        let expected_textual_type = match nas_supi_format {
            1 => SupiType::NetworkSpecific,
            // TS 24.501 NAS values 2/3 are GCI/GLI, while TS 23.003's
            // textual type values 2/3 are GLI/GCI.
            2 => SupiType::Gci,
            3 => SupiType::Gli,
            _ => unreachable!(),
        };
        let nai = std::str::from_utf8(&suci[1..]).ok()?;
        let parsed = parse_nai_suci(nai).ok()?;
        if parsed.supi_type != expected_textual_type {
            return None;
        }
        return deconceal_nai_suci(&parsed, hn_priv_key).ok();
    }
    // TS 24.501 says unassigned SUPI-format values 4..=7 are interpreted as IMSI.
    if suci.len() < 9 {
        return None;
    }
    let protection_scheme = suci[6] & 0x0F;
    if (protection_scheme == 0 && suci[7] != 0)
        || (protection_scheme != 0 && !(1..=254).contains(&suci[7]))
    {
        return None;
    }
    let (mcc, mnc) = crate::plmn::plmn_from_bytes(&suci[1..4])?;
    decode_routing_indicator(&suci[4..6])?;
    if mcc.len() != 3 || !mcc.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    if !(2..=3).contains(&mnc.len()) || !mnc.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }

    let msin = match protection_scheme {
        0x00 => crate::plmn::try_tbcd_decode(&suci[8..])?,
        0x01 => {
            let priv_key = hn_priv_key?;
            let priv_key: &[u8; 32] = priv_key.try_into().ok()?;
            let msin_bcd = suci_decrypt_a(&suci[8..], priv_key).ok()?;
            crate::plmn::try_tbcd_decode(&msin_bcd)?
        }
        0x02 => {
            let priv_key = hn_priv_key?;
            let msin_bcd = suci_decrypt_b(&suci[8..], priv_key).ok()?;
            crate::plmn::try_tbcd_decode(&msin_bcd)?
        }
        _ => return None,
    };
    if mcc.len() + mnc.len() + msin.len() > 15 {
        return None;
    }

    Some(format!("imsi-{mcc}{mnc}{msin}"))
}

/// Convert an IMSI-format binary NAS SUCI to textual
/// `suci-0-MCC-MNC-RI-SchemeID-KeyID-Output` form.
/// Null-scheme MSIN is TBCD-decoded; protected output is hex-encoded.
pub fn suci_to_string(suci: &[u8]) -> Option<String> {
    if suci.len() < 9 || suci[0] & 0x07 != 0x01 {
        return None;
    }
    let nas_supi_format = (suci[0] >> 4) & 0x07;
    if matches!(nas_supi_format, 1..=3) {
        return None;
    }
    let (mcc, mnc) = crate::plmn::plmn_from_bytes(&suci[1..4])?;
    let ri = decode_routing_indicator(&suci[4..6])?;
    let scheme_id = suci[6] & 0x0F;
    let key_id = suci[7];
    if (scheme_id == 0 && key_id != 0) || (scheme_id != 0 && !(1..=254).contains(&key_id)) {
        return None;
    }
    let scheme_output = if scheme_id == 0 {
        let msin = crate::plmn::try_tbcd_decode(&suci[8..])?;
        if mcc.len() + mnc.len() + msin.len() > 15 {
            return None;
        }
        msin
    } else {
        hex::encode(&suci[8..])
    };
    Some(format!(
        "suci-0-{mcc}-{mnc}-{ri}-{scheme_id}-{key_id}-{scheme_output}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Keys shared across tests — TS 33.501-f60 Annex C.4 / PacketRusher test suite.
    const PROFILE_A_PRIV: &str = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    const PROFILE_A_PUB: &str = "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
    const PROFILE_B_PRIV: &str = "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA";
    const PROFILE_B_PUB: &str = "0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4";

    // ── msin_to_bcd ─────────────────────────────────────────────────────────

    #[test]
    fn test_msin_to_bcd_even() {
        // "00007487" — 8 digits → 4 bytes; lo nibble first within each byte
        // byte0: lo=0,hi=0=0x00  byte1: lo=0,hi=0=0x00  byte2: lo=7,hi=4=0x47  byte3: lo=8,hi=7=0x78
        assert_eq!(msin_to_bcd("00007487"), vec![0x00, 0x00, 0x47, 0x78]);
    }

    #[test]
    fn test_msin_to_bcd_odd() {
        // "001002086" — 9 digits → 5 bytes (last nibble padded with 0xF)
        assert_eq!(msin_to_bcd("001002086"), vec![0x00, 0x01, 0x20, 0x80, 0xF6]);
    }

    #[test]
    fn test_msin_to_bcd_ten_digits() {
        // "0123456789" — 10 digits → 5 bytes
        assert_eq!(
            msin_to_bcd("0123456789"),
            vec![0x10, 0x32, 0x54, 0x76, 0x98]
        );
    }

    #[test]
    fn test_msin_to_bcd_all_zeros() {
        assert_eq!(
            msin_to_bcd("0000000001"),
            vec![0x00, 0x00, 0x00, 0x00, 0x10]
        );
    }

    // ── Profile A round-trip ─────────────────────────────────────────────────

    #[test]
    fn test_profile_a_round_trip() {
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let priv_bytes: [u8; 32] = hex::decode(PROFILE_A_PRIV).unwrap().try_into().unwrap();
        let msin_bcd = msin_to_bcd("0000000001");
        let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
        assert_eq!(
            suci_decrypt_a(&scheme_output, &priv_bytes).unwrap(),
            msin_bcd
        );
    }

    // ── Profile A known vector (PacketRusher TestToSupi case 1) ─────────────
    //
    // SUCI: suci-0-208-93-0-1-1-<scheme_output>
    // Expected SUPI: imsi-20893001002086  (MSIN = "001002086")
    #[test]
    fn test_profile_a_known_vector() {
        let priv_bytes: [u8; 32] = hex::decode(PROFILE_A_PRIV).unwrap().try_into().unwrap();
        let scheme_output = hex::decode(
            "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d\
             cb02352410\
             cddd9e730ef3fa87",
        )
        .unwrap();
        let plaintext = suci_decrypt_a(&scheme_output, &priv_bytes).unwrap();
        assert_eq!(plaintext, msin_to_bcd("001002086"));
    }

    // ── Profile B round-trip ─────────────────────────────────────────────────

    #[test]
    fn test_profile_b_round_trip() {
        let pub_bytes = hex::decode(PROFILE_B_PUB).unwrap();
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let msin_bcd = msin_to_bcd("0000000001");
        let scheme_output = suci_scheme_output_b(&msin_bcd, &pub_bytes).unwrap();
        assert_eq!(
            suci_decrypt_b(&scheme_output, &priv_bytes).unwrap(),
            msin_bcd
        );
    }

    // ── Profile B known vector — compressed eph key (TestToSupi case 2) ──────
    //
    // SUCI: suci-0-208-93-0-2-2-<scheme_output>
    // Expected SUPI: imsi-20893001002086  (MSIN = "001002086")
    #[test]
    fn test_profile_b_known_vector_compressed_msin9() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let scheme_output = hex::decode(
            "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1\
             46a33fc271\
             6ac7dae96aa30a4d",
        )
        .unwrap();
        let plaintext = suci_decrypt_b(&scheme_output, &priv_bytes).unwrap();
        assert_eq!(plaintext, msin_to_bcd("001002086"));
    }

    // ── Profile B known vector — compressed eph key (TestToSupi case 4) ──────
    //
    // SUCI: suci-0-001-01-0-2-2-<scheme_output>
    // Expected SUPI: imsi-001010123456789  (MSIN = "0123456789")
    #[test]
    fn test_profile_b_known_vector_compressed_msin10() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let scheme_output = hex::decode(
            "03a7b1db2a9db9d44112b59d03d8243dc6089fd91d2ecb78f5d16298634682e94\
             373888b22bdc9293d1681922e17",
        )
        .unwrap();
        // 33 eph + 5 ct + 8 mac = 46 bytes
        let plaintext = suci_decrypt_b(&scheme_output, &priv_bytes).unwrap();
        assert_eq!(plaintext, msin_to_bcd("0123456789"));
    }

    // TS 33.514 §4.2.1.3 requires rejection of an uncompressed ephemeral
    // point even with a valid ciphertext and MAC.
    #[test]
    fn test_profile_b_rejects_known_vector_uncompressed_eph() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let scheme_output = hex::decode(
            "049AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1\
             D1F44EA1C87AA7478B954537BDE79951E748A43294A4F4CF86EAFF1789C9C81F\
             46A33FC2716AC7DAE96AA30A4D",
        )
        .unwrap();
        // 65 eph (uncompressed) + 5 ct + 8 mac = 78 bytes
        assert!(suci_decrypt_b(&scheme_output, &priv_bytes).is_err());
    }

    #[test]
    fn profile_b_private_key_of_another_length_is_an_invalid_key_length() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        for got in [0, 31, 33] {
            let mut key = priv_bytes.clone();
            key.resize(got, 0);
            assert!(matches!(
                suci_decrypt_b(&[0x02; 47], &key),
                Err(SecurityError::InvalidKeyLength { expected: 32, got: length }) if length == got
            ));
        }
    }

    // The counter is the whole block: a carry out of its low 32 bits goes
    // into the octets before them, as in NIST SP 800-38A Appendix B.1.
    #[test]
    fn aes_ctr_counter_carries_over_the_whole_block() {
        let key = [0x2b; 16];
        let block = |counter: [u8; 16]| {
            let mut block = aes::Block::clone_from_slice(&counter);
            Aes128::new(&key.into()).encrypt_block(&mut block);
            block
        };
        let mut icb = [0u8; 16];
        icb[10..].copy_from_slice(&[0x12, 0xff, 0xff, 0xff, 0xff, 0xff]);
        let mut next = [0u8; 16];
        next[10] = 0x13;
        let keystream = aes128_ctr(&key, &icb, &[0u8; 32]);
        assert_eq!(keystream[..16], block(icb)[..]);
        assert_eq!(keystream[16..], block(next)[..]);
        // All ones wraps to zero.
        let keystream = aes128_ctr(&key, &[0xff; 16], &[0u8; 32]);
        assert_eq!(keystream[16..], block([0; 16])[..]);
    }

    // ── Profile B round-trip — multiple MSINs (mirrors TestSupiToSuciToSupi) ─

    #[test]
    fn test_profile_b_round_trip_various_msins() {
        let pub_bytes = hex::decode(PROFILE_B_PUB).unwrap();
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        for msin in &[
            "0010020862",
            "00007487",
            "001002086",
            "0123456789",
            "0000000001",
        ] {
            let msin_bcd = msin_to_bcd(msin);
            let scheme_output = suci_scheme_output_b(&msin_bcd, &pub_bytes).unwrap();
            assert_eq!(
                suci_decrypt_b(&scheme_output, &priv_bytes).unwrap(),
                msin_bcd,
                "msin={msin}"
            );
        }
    }

    // ── Profile A round-trip — multiple MSINs ────────────────────────────────

    #[test]
    fn test_profile_a_round_trip_various_msins() {
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let priv_bytes: [u8; 32] = hex::decode(PROFILE_A_PRIV).unwrap().try_into().unwrap();
        for msin in &[
            "0010020862",
            "00007487",
            "001002086",
            "0123456789",
            "0000000001",
        ] {
            let msin_bcd = msin_to_bcd(msin);
            let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
            assert_eq!(
                suci_decrypt_a(&scheme_output, &priv_bytes).unwrap(),
                msin_bcd,
                "msin={msin}"
            );
        }
    }

    // ── suci_to_supi with Profile A ─────────────────────────────────────────

    #[test]
    fn test_suci_to_supi_profile_a_known_vector() {
        let priv_bytes = hex::decode(PROFILE_A_PRIV).unwrap();
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        // Build a full SUCI binary: type=SUCI(0x01), PLMN=208/93, RI=0000, scheme=1, key_id=1
        let msin_bcd = msin_to_bcd("001002086");
        let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01]; // SUPI format=IMSI, identity type=SUCI
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93")); // PLMN
        suci.extend_from_slice(&[0x00, 0x00]); // routing indicator
        suci.push(0x01); // scheme_id = Profile A
        suci.push(0x01); // key_id
        suci.extend_from_slice(&scheme_output);
        let result = suci_to_supi(&suci, Some(&priv_bytes));
        assert_eq!(result, Some("imsi-20893001002086".to_string()));
        assert!(suci_to_string(&suci).is_some());
        for invalid_key_id in [0, u8::MAX] {
            suci[7] = invalid_key_id;
            assert_eq!(suci_to_supi(&suci, Some(&priv_bytes)), None);
            assert_eq!(suci_to_string(&suci), None);
        }
    }

    #[test]
    fn test_suci_to_supi_profile_b_known_vector() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let pub_bytes = hex::decode(PROFILE_B_PUB).unwrap();
        let msin_bcd = msin_to_bcd("001002086");
        let scheme_output = suci_scheme_output_b(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01];
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93"));
        suci.extend_from_slice(&[0x00, 0x00]);
        suci.push(0x02); // scheme_id = Profile B
        suci.push(0x02); // key_id
        suci.extend_from_slice(&scheme_output);
        let result = suci_to_supi(&suci, Some(&priv_bytes));
        assert_eq!(result, Some("imsi-20893001002086".to_string()));
    }

    #[test]
    fn test_suci_to_supi_null_scheme() {
        // Null scheme: MSIN in cleartext BCD
        let mut suci = vec![0x01];
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93"));
        suci.extend_from_slice(&[0x00, 0x00]);
        suci.push(0x00); // null scheme
        suci.push(0x00); // key_id
        suci.extend_from_slice(&msin_to_bcd("0000000001"));
        let result = suci_to_supi(&suci, None);
        assert_eq!(result, Some("imsi-208930000000001".to_string()));
    }

    #[test]
    fn binary_suci_receiver_applies_spare_and_supi_format_fallbacks() {
        // TS 24.501 §9.11.3.4: bits 8 and 4 of octet 1 and bits 8..5 of the
        // protection-scheme octet are spare, and SUPI formats 4..=7 are
        // interpreted as IMSI by the receiver.
        let canonical = [0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00];
        let expected_supi = suci_to_supi(&canonical, None);
        let expected_string = suci_to_string(&canonical);
        assert!(expected_supi.is_some());
        assert!(expected_string.is_some());

        for received in [
            [0x81, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x09, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x41, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0xf0, 0x00, 0x00],
        ] {
            assert_eq!(suci_to_supi(&received, None), expected_supi);
            assert_eq!(suci_to_string(&received), expected_string);
        }
    }

    #[test]
    fn test_suci_to_supi_no_key_for_profile_a() {
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let msin_bcd = msin_to_bcd("001002086");
        let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01];
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93"));
        suci.extend_from_slice(&[0x00, 0x00]);
        suci.push(0x01);
        suci.push(0x01);
        suci.extend_from_slice(&scheme_output);
        // No private key provided — should return None
        assert_eq!(suci_to_supi(&suci, None), None);
    }

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

    /// Checks one TS 33.501 Annex C.4 ECIES data set step by step on the UE
    /// side: key agreement output, KDF split into encryption key, ICB, and
    /// MAC key, counter-mode ciphertext, and MAC tag.
    #[allow(clippy::too_many_arguments)]
    fn check_annex_c4_ecies_steps(
        shared_key: &[u8],
        ephemeral_public_key: &[u8],
        enc_key: &str,
        icb: Option<&str>,
        mac_key: &str,
        plaintext: &str,
        ciphertext: &str,
        mac_tag: &str,
    ) {
        let kdf = ansi_x963_kdf(shared_key, ephemeral_public_key, 32, 32);
        assert_eq!(hex::encode(&kdf[..16]), enc_key.to_lowercase());
        if let Some(icb) = icb {
            assert_eq!(hex::encode(&kdf[16..32]), icb.to_lowercase());
        }
        assert_eq!(hex::encode(&kdf[32..]), mac_key.to_lowercase());
        let computed = aes128_ctr(
            kdf[..16].try_into().unwrap(),
            kdf[16..32].try_into().unwrap(),
            &hex::decode(plaintext).unwrap(),
        );
        assert_eq!(hex::encode(&computed), ciphertext.to_lowercase());
        assert_eq!(
            hex::encode(hmac_sha256_8(&kdf[32..], &computed)),
            mac_tag.to_lowercase()
        );
    }

    #[test]
    fn annex_c4_null_scheme_vectors() {
        // C.4.2.1: MSIN 001002086 of IMSI 274012001002086.
        assert_eq!(hex::encode(msin_to_bcd("001002086")), "00012080f6");
        assert_eq!(
            hex::encode(suci_conceal(&msin_to_bcd("001002086"), 0, &[]).unwrap()),
            "00012080f6"
        );
        // C.4.2.2: the scheme output is the username of the NAI.
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

    #[test]
    fn annex_c4_profile_a_intermediate_values() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let home_network_public_key =
            PublicKey::from(<[u8; 32]>::try_from(hex::decode(PROFILE_A_PUB).unwrap()).unwrap());
        for (
            ephemeral_private_key,
            ephemeral_public_key,
            shared_key,
            enc_key,
            icb,
            mac_key,
            plaintext,
            ciphertext,
            mac_tag,
        ) in [
            // C.4.3.1, IMSI-based SUPI.
            (
                "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256",
                "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d",
                "028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a",
                "2ba342cabd2b3b1e5e4e890da11b65f6",
                Some("e2622cb0cdd08204e721c8ea9b95a7c6"),
                "d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2",
                "00012080f6",
                "cb02352410",
                "cddd9e730ef3fa87",
            ),
            // C.4.3.2, network specific identifier-based SUPI; the
            // 17-octet plaintext spans two counter blocks.
            (
                "BE9EFF3E9F22A4B42A3D236E7A6C500B3F2E7E0C7449988BA800D664BF4FCD97",
                "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222",
                "511C1DF473BB88317F923501F8BA944FD3B667D25699DCB552DBCEF60BBDC56D",
                "FE77B87D87F40428EDD71BCA69D79059",
                None,
                "D87B69F4FE8CD6B211264EA5E69F682F151A82252684CDB15A047E6EF0595028",
                "766572796C6F6E67757365726E616D6531",
                "8E358A1582ADB15322C10E515141D2039A",
                "12E1D7783A97F1AC",
            ),
        ] {
            let secret = StaticSecret::from(
                <[u8; 32]>::try_from(hex::decode(ephemeral_private_key).unwrap()).unwrap(),
            );
            let public = PublicKey::from(&secret);
            assert_eq!(
                hex::encode(public.as_bytes()),
                ephemeral_public_key.to_lowercase()
            );
            let shared = secret.diffie_hellman(&home_network_public_key);
            assert_eq!(hex::encode(shared.as_bytes()), shared_key.to_lowercase());
            check_annex_c4_ecies_steps(
                shared.as_bytes(),
                public.as_bytes(),
                enc_key,
                icb,
                mac_key,
                plaintext,
                ciphertext,
                mac_tag,
            );
        }
    }

    #[test]
    fn annex_c4_profile_b_intermediate_values() {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        use p256::{PublicKey, SecretKey};

        let home_network_public_key =
            PublicKey::from_sec1_bytes(&hex::decode(PROFILE_B_PUB).unwrap()).unwrap();
        for (
            ephemeral_private_key,
            ephemeral_public_key,
            shared_key,
            enc_key,
            icb,
            mac_key,
            plaintext,
            ciphertext,
            mac_tag,
        ) in [
            // C.4.4.1, IMSI-based SUPI.
            (
                "99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529",
                "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
                "6C7E6518980025B982FBB2FF746E3C2E85A196D252099A7AD23EA7B4C0959CAE",
                "8A65C3AED80295C12BD55087E965702A",
                Some("EF285B4061C3BAEE858AB6EC68487DAE"),
                "A5EBAC0BC48D9CF7AE5CE39CD840AC6C761AEC04078FAB954D634F923E901C64",
                "00012080F6",
                "46A33FC271",
                "6AC7DAE96AA30A4D",
            ),
            // C.4.4.2, network specific identifier-based SUPI.
            (
                "90A5898BD29FFA3F261E00E980067C70A2B1B992A21F5B4FEF6D4DF69FE804AD",
                "03759BB22C563D9F4A6B3C1419E543FC2F39D6823F02A9D71162B39399218B244B",
                "BC3529ED79541CF8C007CE9806330F4A5FF15064D7CF4B16943EF8F007597872",
                "84F9A78995D39E6968047547ECC12C4F",
                None,
                "39D5517E965F8E1252B61345ED45226C5F1A8C69F03D6C91437591F0B8E48FA0",
                "766572796C6F6E67757365726E616D6531",
                "BE22D8B9F856A52ED381CD7EAF4CF2D525",
                "3CDDC61A0A7882EB",
            ),
        ] {
            let secret =
                SecretKey::from_slice(&hex::decode(ephemeral_private_key).unwrap()).unwrap();
            // Profile B applies point compression to the ephemeral public
            // key, and that octet string is SharedInfo1 of the KDF.
            let public = secret.public_key().to_encoded_point(true);
            assert_eq!(
                hex::encode(public.as_bytes()),
                ephemeral_public_key.to_lowercase()
            );
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                secret.to_nonzero_scalar(),
                home_network_public_key.as_affine(),
            );
            assert_eq!(
                hex::encode(shared.raw_secret_bytes()),
                shared_key.to_lowercase()
            );
            check_annex_c4_ecies_steps(
                shared.raw_secret_bytes(),
                public.as_bytes(),
                enc_key,
                icb,
                mac_key,
                plaintext,
                ciphertext,
                mac_tag,
            );
        }
    }
}
