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

use crate::error::SecurityError;
use aes::Aes128;
use aes::cipher::{BlockEncrypt, KeyInit};
use hmac::{Hmac, Mac};
/// SUCI concealment per 3GPP TS 33.501 Annex C.4
///
/// Implements:
/// - Null scheme (scheme_id=0): MSIN in BCD cleartext
/// - Profile A (scheme_id=1): X25519 ECIES — AES-128-CTR + HMAC-SHA-256
/// - Profile B (scheme_id=2): P-256 ECIES — AES-128-CTR + HMAC-SHA-256
use sha2::Sha256;
use subtle::ConstantTimeEq;

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

/// ANSI X9.63 KDF using SHA-256.
/// Returns `enc_key_len + mac_key_len` bytes of key material (where enc_key_len should include the ICB length if an ICB is needed).
fn ansi_x963_kdf(
    shared_key: &[u8],
    public_key: &[u8],
    enc_key_len: usize,
    mac_key_len: usize,
) -> Vec<u8> {
    use sha2::Digest;
    let total = enc_key_len + mac_key_len;
    let hash_len = 32usize;
    let rounds = total.div_ceil(hash_len);
    let mut kdf_key = Vec::with_capacity(rounds * hash_len);
    for i in 0u32..rounds as u32 {
        let counter = (i + 1).to_be_bytes();
        let mut h = Sha256::new();
        h.update(shared_key);
        h.update(counter);
        h.update(public_key);
        kdf_key.extend_from_slice(&h.finalize());
    }
    kdf_key
}

/// AES-128-CTR encryption with a 32-bit big-endian counter in the ICB.
fn aes128_ctr(key: &[u8; 16], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes128::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut counter = *icb;
    for chunk in data.chunks(16) {
        let mut block = aes::Block::clone_from_slice(&counter);
        aes.encrypt_block(&mut block);
        for (d, k) in chunk.iter().zip(block.iter()) {
            out.push(d ^ k);
        }
        let low = u32::from_be_bytes(counter[12..16].try_into().expect("four counter octets"));
        counter[12..16].copy_from_slice(&low.wrapping_add(1).to_be_bytes());
    }
    out
}

/// HMAC-SHA-256 truncated to 8 bytes.
fn hmac_sha256_8(key: &[u8], data: &[u8]) -> [u8; 8] {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .expect("HMAC-SHA-256 accepts any key size per RFC 2104");
    mac.update(data);
    let full = mac.finalize().into_bytes();
    full[..8]
        .try_into()
        .expect("SHA-256 output is 32 bytes, 8-byte prefix always valid")
}

/// MSIN decimal string → packed BCD bytes (low nibble first, right-padded with 0xF if odd length).
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
pub fn suci_scheme_output_a(
    msin_bcd: &[u8],
    hn_pub_key: &[u8; 32],
) -> Result<Vec<u8>, SecurityError> {
    use rand_core::OsRng;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let hn_pub = PublicKey::from(*hn_pub_key);
    let eph_secret = EphemeralSecret::random_from_rng(OsRng);
    let eph_pub = PublicKey::from(&eph_secret);
    let shared = eph_secret.diffie_hellman(&hn_pub);
    if shared.as_bytes().iter().all(|&byte| byte == 0) {
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
pub fn suci_scheme_output_b(msin_bcd: &[u8], hn_pub_key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use p256::PublicKey;
    use p256::ecdh::EphemeralSecret;
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use rand_core::OsRng;

    let hn_pub = PublicKey::from_sec1_bytes(hn_pub_key)
        .map_err(|e| SecurityError::Ecies(format!("invalid P-256 public key: {}", e)))?;
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
            "unsupported protection scheme: {}",
            scheme_id
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
    if shared.as_bytes().iter().all(|&byte| byte == 0) {
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
/// `scheme_output`: `ephemeral_pub (33 compressed or 65 uncompressed) || ciphertext || mac (8)`
/// `hn_priv_key`: 32-byte P-256 home network private key.
/// Returns the decrypted MSIN in BCD.
///
/// Per TS 33.501 Annex C.4.2, the KDF always uses the compressed ephemeral
/// public key (33 bytes), even when the transmitted form is uncompressed.
pub fn suci_decrypt_b(scheme_output: &[u8], hn_priv_key: &[u8]) -> Result<Vec<u8>, SecurityError> {
    use p256::elliptic_curve::sec1::ToEncodedPoint;
    use p256::{PublicKey, SecretKey};

    #[allow(clippy::unnecessary_fallible_conversions)] // &[u8] → &[u8; 32] IS fallible
    let priv_key = SecretKey::from_bytes(
        hn_priv_key
            .try_into()
            .map_err(|_| SecurityError::Ecies("P-256 private key must be 32 bytes".into()))?,
    )
    .map_err(|e| SecurityError::Ecies(format!("invalid P-256 private key: {}", e)))?;

    // Detect compressed (0x02/0x03, 33 B) vs uncompressed (0x04, 65 B)
    let eph_pub_len = if scheme_output.first() == Some(&0x04) {
        65
    } else {
        33
    };
    if scheme_output.len() < eph_pub_len + PROFILE_B_MAC_LEN + 1 {
        return Err(SecurityError::Ecies(
            "Profile B scheme output too short".into(),
        ));
    }
    let eph_pub_bytes = &scheme_output[0..eph_pub_len];
    let eph_pub = PublicKey::from_sec1_bytes(eph_pub_bytes)
        .map_err(|e| SecurityError::Ecies(format!("invalid ephemeral P-256 key: {}", e)))?;

    // Always use compressed form as KDF input
    let compressed = eph_pub.to_encoded_point(true);
    let kdf_pub_bytes = compressed.as_bytes();

    let shared = p256::elliptic_curve::ecdh::diffie_hellman(
        priv_key.to_nonzero_scalar(),
        eph_pub.as_affine(),
    );
    let shared_bytes = shared.raw_secret_bytes();

    let kdf = ansi_x963_kdf(
        shared_bytes.as_slice(),
        kdf_pub_bytes,
        PROFILE_B_ENC_KEY_LEN + PROFILE_B_ICB_LEN,
        PROFILE_B_MAC_KEY_LEN,
    );
    let enc_key: &[u8; 16] = kdf[0..16].try_into().expect("KDF output >= 16");
    let icb: &[u8; 16] = kdf[16..32].try_into().expect("KDF output >= 32");
    let mac_key = &kdf[32..];

    let ciphertext = &scheme_output[eph_pub_len..scheme_output.len() - 8];
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
/// Returns SUPI string of the form "imsi-<MCC><MNC><MSIN>" on success.
pub fn suci_to_supi(suci: &[u8], hn_priv_key: Option<&[u8]>) -> Option<String> {
    if suci.len() < 9 || suci[0] & 0x0f != 0x01 || suci[6] & 0xf0 != 0 {
        return None;
    }
    let supi_format = (suci[0] >> 4) & 0x0F;
    if supi_format != 0 {
        return None; // Only IMSI SUPI format supported
    }
    let protection_scheme = suci[6] & 0x0F;
    if protection_scheme == 0 && suci[7] != 0 {
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

    Some(format!("imsi-{}{}{}", mcc, mnc, msin))
}

/// Convert an IMSI-format binary NAS SUCI to textual
/// `suci-0-MCC-MNC-RI-SchemeID-KeyID-Output` form.
/// Null-scheme MSIN is TBCD-decoded; protected output is hex-encoded.
pub fn suci_to_string(suci: &[u8]) -> Option<String> {
    if suci.len() < 9 || suci[0] != 0x01 || suci[6] & 0xf0 != 0 {
        return None;
    }
    let (mcc, mnc) = crate::plmn::plmn_from_bytes(&suci[1..4])?;
    let ri = decode_routing_indicator(&suci[4..6])?;
    let scheme_id = suci[6] & 0x0F;
    let key_id = suci[7];
    if scheme_id == 0 && key_id != 0 {
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
        "suci-0-{}-{}-{}-{}-{}-{}",
        mcc, mnc, ri, scheme_id, key_id, scheme_output
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

    // ── Profile B known vector — uncompressed eph key (TestToSupi case 5) ────
    //
    // SUCI: suci-0-001-01-0-2-2-<scheme_output>
    // Expected SUPI: imsi-00101001002086  (MSIN = "001002086")
    #[test]
    fn test_profile_b_known_vector_uncompressed_eph() {
        let priv_bytes = hex::decode(PROFILE_B_PRIV).unwrap();
        let scheme_output = hex::decode(
            "049AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1\
             D1F44EA1C87AA7478B954537BDE79951E748A43294A4F4CF86EAFF1789C9C81F\
             46A33FC2716AC7DAE96AA30A4D",
        )
        .unwrap();
        // 65 eph (uncompressed) + 5 ct + 8 mac = 78 bytes
        let plaintext = suci_decrypt_b(&scheme_output, &priv_bytes).unwrap();
        assert_eq!(plaintext, msin_to_bcd("001002086"));
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
                "msin={}",
                msin
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
                "msin={}",
                msin
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
}
