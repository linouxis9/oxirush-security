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

//! SUCI concealment per 3GPP TS 33.501 Annex C.
//!
//! Implements:
//! - Null scheme (scheme_id=0): MSIN in BCD cleartext
//! - Profile A (scheme_id=1): X25519 ECIES — AES-128-CTR + HMAC-SHA-256
//! - Profile B (scheme_id=2): P-256 ECIES — AES-128-CTR + HMAC-SHA-256
//!
//! This module is the `suci` feature. The SUCI and SUPI of the NAI format
//! are the `nai` feature beside it.

use crate::error::SecurityError;
use aes::Aes128Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "nai")]
mod nai;
#[cfg(feature = "nai")]
#[cfg_attr(docsrs, doc(cfg(feature = "nai")))]
pub use nai::{
    NaiProtectionScheme, NaiSuci, SuciSchemeOutput, SupiType, conceal_network_specific_supi,
    deconceal_nai_suci, deconceal_network_specific_suci, encode_nai_suci, parse_nai_suci,
};

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

fn random_source_failed() -> SecurityError {
    SecurityError::Ecies("the system random number generator failed".into())
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
    use crate::common::sha256::sha256;
    let total = enc_key_len + mac_key_len;
    let hash_len = 32usize;
    let rounds = total.div_ceil(hash_len);
    // Exact capacity: the vector never reallocates and leaves no copy behind.
    let mut kdf_key = Zeroizing::new(Vec::with_capacity(rounds * hash_len));
    for i in 0u32..rounds as u32 {
        let counter = (i + 1).to_be_bytes();
        let digest = sha256(&[shared_key, &counter, public_key]);
        kdf_key.extend_from_slice(digest.as_ref());
    }
    kdf_key
}

/// AES-128-CTR encryption with the ICB as the first counter block, incremented
/// as one 128-bit big-endian integer. The keystream and counter blocks are
/// wiped.
fn aes128_ctr(key: &[u8; 16], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes128Enc::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut counter = Zeroizing::new(*icb);
    for chunk in data.chunks(16) {
        let mut block = aes::Block::from(*counter);
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

/// Encode the decimal digits of an MSIN as packed BCD: the first digit of
/// each pair in the low nibble, and the filler 0xF after an odd number of
/// digits.
///
/// A character that is not a decimal digit is
/// [`SecurityError::InvalidParameter`].
pub fn msin_to_bcd(msin: &str) -> Result<Vec<u8>, SecurityError> {
    if !msin.bytes().all(|character| character.is_ascii_digit()) {
        return Err(SecurityError::InvalidParameter(
            "MSIN must be decimal digits",
        ));
    }
    crate::plmn::tbcd_encode(msin)
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
    use x25519_dalek::{PublicKey, StaticSecret};

    if msin_bcd.is_empty() {
        return Err(SecurityError::Ecies(
            "Profile A scheme input is empty".into(),
        ));
    }
    let hn_pub = PublicKey::from(*hn_pub_key);
    // A fresh secret for this one concealment. It is drawn here, and not
    // by `EphemeralSecret::random`, so that a failure of the system's
    // random number generator is an error and not a panic.
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(seed.as_mut()).map_err(|_| random_source_failed())?;
    let eph_secret = StaticSecret::from(*seed);
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
    use p256::elliptic_curve::Generate;
    use p256::elliptic_curve::sec1::ToSec1Point;

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
    let eph_secret = EphemeralSecret::try_generate().map_err(|_| random_source_failed())?;
    let eph_pub = eph_secret.public_key();

    // Compressed ephemeral public key (33 bytes)
    let eph_pub_enc = eph_pub.to_sec1_point(true);
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
/// that is malformed or cannot be deconcealed, and for a SUCI in a NAI
/// format when the crate is built without its `nai` feature.
pub fn suci_to_supi(suci: &[u8], hn_priv_key: Option<&[u8]>) -> Option<String> {
    if suci.len() < 2 || suci[0] & 0x07 != 0x01 {
        return None;
    }
    let nas_supi_format = (suci[0] >> 4) & 0x07;
    if matches!(nas_supi_format, 1..=3) {
        #[cfg(feature = "nai")]
        return nai::nas_nai_suci_to_supi(nas_supi_format, &suci[1..], hn_priv_key);
        #[cfg(not(feature = "nai"))]
        return None;
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
        suci[8..]
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect()
    };
    Some(format!(
        "suci-0-{mcc}-{mnc}-{ri}-{scheme_id}-{key_id}-{scheme_output}"
    ))
}

#[cfg(test)]
mod test_keys {
    //! The home network keys of TS 33.501 Annex C.4.
    pub(super) const PROFILE_A_PRIV: &str =
        "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    pub(super) const PROFILE_A_PUB: &str =
        "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
    pub(super) const PROFILE_B_PRIV: &str =
        "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA";
    pub(super) const PROFILE_B_PUB: &str = "0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4";
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;

    // ── msin_to_bcd ─────────────────────────────────────────────────────────

    #[test]
    fn test_msin_to_bcd_even() {
        // "00007487" — 8 digits → 4 bytes; lo nibble first within each byte
        // byte0: lo=0,hi=0=0x00  byte1: lo=0,hi=0=0x00  byte2: lo=7,hi=4=0x47  byte3: lo=8,hi=7=0x78
        assert_eq!(
            msin_to_bcd("00007487").unwrap(),
            vec![0x00, 0x00, 0x47, 0x78]
        );
    }

    #[test]
    fn test_msin_to_bcd_odd() {
        // "001002086" — 9 digits → 5 bytes (last nibble padded with 0xF)
        assert_eq!(
            msin_to_bcd("001002086").unwrap(),
            vec![0x00, 0x01, 0x20, 0x80, 0xF6]
        );
    }

    #[test]
    fn test_msin_to_bcd_ten_digits() {
        // "0123456789" — 10 digits → 5 bytes
        assert_eq!(
            msin_to_bcd("0123456789").unwrap(),
            vec![0x10, 0x32, 0x54, 0x76, 0x98]
        );
    }

    #[test]
    fn test_msin_to_bcd_all_zeros() {
        assert_eq!(
            msin_to_bcd("0000000001").unwrap(),
            vec![0x00, 0x00, 0x00, 0x00, 0x10]
        );
    }

    // ── Profile A round-trip ─────────────────────────────────────────────────

    #[test]
    fn test_profile_a_round_trip() {
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let priv_bytes: [u8; 32] = hex::decode(PROFILE_A_PRIV).unwrap().try_into().unwrap();
        let msin_bcd = msin_to_bcd("0000000001").unwrap();
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
        assert_eq!(plaintext, msin_to_bcd("001002086").unwrap());
    }

    // ── Profile B round-trip ─────────────────────────────────────────────────

    #[test]
    fn test_profile_b_round_trip() {
        let pub_bytes = hex::decode(PROFILE_B_PUB).unwrap();
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let msin_bcd = msin_to_bcd("0000000001").unwrap();
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
        assert_eq!(plaintext, msin_to_bcd("001002086").unwrap());
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
        assert_eq!(plaintext, msin_to_bcd("0123456789").unwrap());
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
            let mut block = aes::Block::from(counter);
            Aes128Enc::new(&key.into()).encrypt_block(&mut block);
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
            let msin_bcd = msin_to_bcd(msin).unwrap();
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
            let msin_bcd = msin_to_bcd(msin).unwrap();
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
        let msin_bcd = msin_to_bcd("001002086").unwrap();
        let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01]; // SUPI format=IMSI, identity type=SUCI
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93").unwrap()); // PLMN
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
        let msin_bcd = msin_to_bcd("001002086").unwrap();
        let scheme_output = suci_scheme_output_b(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01];
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93").unwrap());
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
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93").unwrap());
        suci.extend_from_slice(&[0x00, 0x00]);
        suci.push(0x00); // null scheme
        suci.push(0x00); // key_id
        suci.extend_from_slice(&msin_to_bcd("0000000001").unwrap());
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

    /// A SUCI in the NAI format needs the `nai` feature.
    #[cfg(not(feature = "nai"))]
    #[test]
    fn a_nai_suci_is_not_decoded_without_the_nai_feature() {
        let mut suci = vec![0x11];
        suci.extend_from_slice(b"type1.rid0.schid0.useriduser17@example.com");
        assert_eq!(suci_to_supi(&suci, None), None);
    }

    #[test]
    fn test_suci_to_supi_no_key_for_profile_a() {
        let pub_bytes: [u8; 32] = hex::decode(PROFILE_A_PUB).unwrap().try_into().unwrap();
        let msin_bcd = msin_to_bcd("001002086").unwrap();
        let scheme_output = suci_scheme_output_a(&msin_bcd, &pub_bytes).unwrap();
        let mut suci = vec![0x01];
        suci.extend_from_slice(&crate::plmn::plmn_to_bytes("208", "93").unwrap());
        suci.extend_from_slice(&[0x00, 0x00]);
        suci.push(0x01);
        suci.push(0x01);
        suci.extend_from_slice(&scheme_output);
        // No private key provided — should return None
        assert_eq!(suci_to_supi(&suci, None), None);
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
        assert_eq!(hex::encode(msin_to_bcd("001002086").unwrap()), "00012080f6");
        assert_eq!(
            hex::encode(suci_conceal(&msin_to_bcd("001002086").unwrap(), 0, &[]).unwrap()),
            "00012080f6"
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
        use p256::elliptic_curve::sec1::ToSec1Point;
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
            let public = secret.public_key().to_sec1_point(true);
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
