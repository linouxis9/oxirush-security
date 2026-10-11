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

//! The ciphering algorithms of 5GS and EPS (TS 33.501 Annex D.2,
//! TS 33.401 Annex B.1).
//!
//! - NEA0, EEA0: null ciphering.
//! - 128-NEA1, 128-EEA1: SNOW 3G (TS 33.401 Annex B.1.2, TS 35.215 and TS 35.216).
//! - 128-NEA2, 128-EEA2: AES-128-CTR (TS 33.401 Annex B.1.3).
//! - 128-NEA3, 128-EEA3: ZUC (TS 33.401 Annex B.1.4, TS 35.221).
//!
//! These functions take what the algorithms take: any 32-bit COUNT and a
//! five-bit [`Bearer`]. They cipher or decipher in place, which is one
//! operation. [`nea_cipher`], [`nea1_cipher`], [`nea2_cipher`] and
//! [`nea3_cipher`] process whole octets and cannot fail. The `*_bits`
//! forms process the first bits of the data and leave the unused low-order
//! bits of the last octet as they are; they return an error for a length
//! that the data does not have.
//!
//! For a NAS message use
//! [`nas_5gs::nas_cipher`](crate::nas_5gs::nas_cipher) or
//! [`nas_eps::nas_cipher`](crate::nas_eps::nas_cipher), which take a NAS
//! COUNT.
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, octets_of};
use crate::snow3g::Snow3G;
use crate::zuc::Zuc;
use aes::Aes128Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use zeroize::{Zeroize, Zeroizing};

/// Cipher or decipher octets in place with `algorithm`.
///
/// The null algorithm leaves the data as it is.
pub fn nea_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    algorithm: CipheringAlgorithm,
) {
    match algorithm {
        CipheringAlgorithm::Null => {}
        CipheringAlgorithm::Snow3g => nea1_cipher(key, count, bearer, direction, data),
        CipheringAlgorithm::Aes => nea2_cipher(key, count, bearer, direction, data),
        CipheringAlgorithm::Zuc => nea3_cipher(key, count, bearer, direction, data),
    }
}

/// Cipher or decipher, as [`nea_cipher`] does, the first `bit_length`
/// most-significant bits of `data`. Unused low-order bits of the partial
/// final octet are unchanged.
///
/// A `bit_length` above the length of `data` in bits is
/// [`SecurityError::BitLengthExceedsData`], with the null algorithm too,
/// and the data is then unchanged.
pub fn nea_cipher_bits(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    bit_length: u64,
    algorithm: CipheringAlgorithm,
) -> Result<(), SecurityError> {
    cipher_bits(data, bit_length, |octets| {
        nea_cipher(key, count, bearer, direction, octets, algorithm)
    })
}

/// Apply a whole-octet cipher to the octets that hold the first
/// `bit_length` bits, then give the unused bits of the last octet back.
fn cipher_bits(
    data: &mut [u8],
    bit_length: u64,
    apply: impl FnOnce(&mut [u8]),
) -> Result<(), SecurityError> {
    let octets = octets_of(bit_length, data.len())?;
    let Some(last) = octets.checked_sub(1) else {
        return Ok(());
    };
    let used = (bit_length % 8) as u32;
    let unused_mask = if used == 0 { 0 } else { 0xffu8 >> used };
    let retained = data[last] & unused_mask;
    apply(&mut data[..octets]);
    data[last] = (data[last] & !unused_mask) | retained;
    Ok(())
}

/// XOR a keystream of 32-bit words, most significant octet first, into the
/// data. The copy of the last word is wiped.
fn xor_keystream(data: &mut [u8], mut next_word: impl FnMut() -> u32) {
    let mut word = Zeroizing::new(0u32);
    let (words, rest) = data.as_chunks_mut::<4>();
    for octets in words {
        *word = next_word();
        *octets = (u32::from_be_bytes(*octets) ^ *word).to_be_bytes();
    }
    if !rest.is_empty() {
        *word = next_word();
        for (octet, key_octet) in rest.iter_mut().zip(word.to_be_bytes()) {
            *octet ^= key_octet;
        }
    }
}

// ── NEA1: 128-EEA1 (SNOW 3G keystream) ────────────────────────────────────────

/// Cipher or decipher octets with 128-NEA1 / 128-EEA1 (TS 33.401
/// Annex B.1.2, TS 35.215 §3).
///
/// IV construction (UEA2/UIA2 specification §3.4):
/// ```text
/// IV[0] = (BEARER << 27) | (DIRECTION << 26)
/// IV[1] = COUNT
/// IV[2] = (BEARER << 27) | (DIRECTION << 26)
/// IV[3] = COUNT
/// ```
pub fn nea1_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let bearer_dir = (u32::from(bearer.get()) << 27) | (u32::from(u8::from(direction)) << 26);

    // The key words are loaded last word first (UEA2 §3.4).
    let (words, _) = key.as_chunks::<4>();
    let k = Zeroizing::new([
        u32::from_be_bytes(words[3]),
        u32::from_be_bytes(words[2]),
        u32::from_be_bytes(words[1]),
        u32::from_be_bytes(words[0]),
    ]);
    let iv = [bearer_dir, count, bearer_dir, count];

    let mut snow = Snow3G::new(*k, iv);
    xor_keystream(data, || snow.next_word());
}

/// Cipher or decipher the first `bit_length` bits with 128-NEA1 /
/// 128-EEA1.
///
/// A `bit_length` above the length of `data` in bits is
/// [`SecurityError::BitLengthExceedsData`].
pub fn nea1_cipher_bits(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    bit_length: u64,
) -> Result<(), SecurityError> {
    cipher_bits(data, bit_length, |octets| {
        nea1_cipher(key, count, bearer, direction, octets)
    })
}

// ── NEA2: 128-EEA2 (AES-128-CTR) ──────────────────────────────────────────────

/// Cipher or decipher octets with 128-NEA2 / 128-EEA2 (TS 33.401
/// Annex B.1.3).
///
/// Counter block layout (128 bits):
/// ```text
///   Bytes [0..3]:  COUNT (big-endian)
///   Byte  [4]:     (BEARER << 3) | (DIRECTION << 2)
///   Bytes [5..7]:  0x000000
///   Bytes [8..15]: block counter (big-endian u64, starts at 0)
/// ```
pub fn nea2_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let cipher = Aes128Enc::new(key.into());

    // The upper eight octets of a counter block are fixed
    let mut fixed = [0u8; 8];
    fixed[0..4].copy_from_slice(&count.to_be_bytes());
    fixed[4] = (bearer.get() << 3) | (u8::from(direction) << 2);

    // The counter blocks of a group are encrypted in one call, which the AES
    // instructions of a processor run side by side
    let mut keystream = [aes::Block::default(); CTR_GROUP];
    let mut counter = 0u64;
    for group in data.chunks_mut(16 * CTR_GROUP) {
        let blocks = &mut keystream[..group.len().div_ceil(16)];
        for block in blocks.iter_mut() {
            block[..8].copy_from_slice(&fixed);
            block[8..].copy_from_slice(&counter.to_be_bytes());
            counter += 1;
        }
        cipher.encrypt_blocks(blocks);
        for (octets, block) in group.chunks_mut(16).zip(blocks.iter()) {
            for (octet, key_octet) in octets.iter_mut().zip(block) {
                *octet ^= key_octet;
            }
        }
    }

    // A group overwrites the blocks of the one before it: the array holds
    // keystream in as many blocks as the longest group had
    let written = CTR_GROUP.min(data.len().div_ceil(16));
    for block in &mut keystream[..written] {
        block.as_mut_slice().zeroize();
    }
}

/// The number of counter blocks that [`nea2_cipher`] encrypts in one call.
const CTR_GROUP: usize = 8;

/// Cipher or decipher the first `bit_length` bits with 128-NEA2 /
/// 128-EEA2.
///
/// A `bit_length` above the length of `data` in bits is
/// [`SecurityError::BitLengthExceedsData`].
pub fn nea2_cipher_bits(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    bit_length: u64,
) -> Result<(), SecurityError> {
    cipher_bits(data, bit_length, |octets| {
        nea2_cipher(key, count, bearer, direction, octets)
    })
}

// ── NEA3: 128-EEA3 (ZUC keystream) ────────────────────────────────────────────

/// Cipher or decipher octets with 128-NEA3 / 128-EEA3 (TS 33.401
/// Annex B.1.4, TS 35.221 §3).
///
/// IV construction for ZUC:
/// ```text
///   Bytes [0..3]:  COUNT (big-endian)
///   Byte  [4]:     (BEARER << 3) | (DIRECTION << 2)
///   Bytes [5..7]:  0x000000
///   Bytes [8..11]: COUNT (big-endian, same as [0..3])
///   Byte  [12]:    (BEARER << 3) | (DIRECTION << 2)
///   Bytes [13..15]: 0x000000
/// ```
pub fn nea3_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = (bearer.get() << 3) | (u8::from(direction) << 2);
    // The upper half repeats the lower one
    iv.copy_within(0..8, 8);

    let mut zuc = Zuc::new(key, &iv);
    xor_keystream(data, || zuc.next_word());
}

/// Cipher or decipher the first `bit_length` bits with 128-NEA3 /
/// 128-EEA3.
///
/// A `bit_length` above the length of `data` in bits is
/// [`SecurityError::BitLengthExceedsData`].
pub fn nea3_cipher_bits(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    bit_length: u64,
) -> Result<(), SecurityError> {
    cipher_bits(data, bit_length, |octets| {
        nea3_cipher(key, count, bearer, direction, octets)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bearer(value: u8) -> Bearer {
        Bearer::new(value).unwrap()
    }

    fn direction(bit: u8) -> Direction {
        Direction::try_from(bit).unwrap()
    }

    const ALGORITHMS: [CipheringAlgorithm; 4] = [
        CipheringAlgorithm::Null,
        CipheringAlgorithm::Snow3g,
        CipheringAlgorithm::Aes,
        CipheringAlgorithm::Zuc,
    ];

    /// Ciphering twice gives the plaintext back, at every length around the
    /// 4-octet words of SNOW 3G and ZUC and the 16-octet blocks of AES.
    #[test]
    fn ciphering_twice_deciphers() {
        let key = [0x01u8; 16];
        let plaintext: Vec<u8> = (0..70u8).map(|octet| octet.wrapping_mul(13)).collect();
        for algorithm in ALGORITHMS {
            for length in 0..=plaintext.len() {
                let mut data = plaintext[..length].to_vec();
                nea_cipher(&key, 42, bearer(1), Direction::Uplink, &mut data, algorithm);
                if algorithm != CipheringAlgorithm::Null && length >= 8 {
                    assert_ne!(data, plaintext[..length]);
                }
                nea_cipher(&key, 42, bearer(1), Direction::Uplink, &mut data, algorithm);
                assert_eq!(data, plaintext[..length]);
            }
        }
    }

    #[test]
    fn test_nea0_noop() {
        let key = [0u8; 16];
        let original = b"untouched";
        let mut data = original.to_vec();
        nea_cipher(
            &key,
            0,
            Bearer::ZERO,
            Direction::Uplink,
            &mut data,
            CipheringAlgorithm::Null,
        );
        assert_eq!(&data[..], &original[..]);
    }

    /// `nea_cipher` is the function of each algorithm.
    #[test]
    fn nea_cipher_is_each_algorithm() {
        let key = [0x5a; 16];
        let plaintext = [0x3c; 37];
        let (count, bearer, direction) = (7, Bearer::MAX, Direction::Downlink);
        let with = |cipher: fn(&[u8; 16], u32, Bearer, Direction, &mut [u8])| {
            let mut data = plaintext;
            cipher(&key, count, bearer, direction, &mut data);
            data
        };
        let dispatched = |algorithm| {
            let mut data = plaintext;
            nea_cipher(&key, count, bearer, direction, &mut data, algorithm);
            data
        };
        assert_eq!(dispatched(CipheringAlgorithm::Snow3g), with(nea1_cipher));
        assert_eq!(dispatched(CipheringAlgorithm::Aes), with(nea2_cipher));
        assert_eq!(dispatched(CipheringAlgorithm::Zuc), with(nea3_cipher));
        assert_ne!(with(nea1_cipher), with(nea2_cipher));
        assert_ne!(with(nea2_cipher), with(nea3_cipher));
    }

    /// A length in bits ciphers those bits and leaves the others of the
    /// last octet, and every octet after it, as they are.
    #[test]
    fn a_bit_length_leaves_the_other_bits_unchanged() {
        let key = [0x5a; 16];
        let original = [0xa5, 0x5a, 0xc3];

        for algorithm in ALGORITHMS {
            let mut whole = original;
            nea_cipher(
                &key,
                7,
                Bearer::MAX,
                Direction::Downlink,
                &mut whole,
                algorithm,
            );
            let mut data = original;
            nea_cipher_bits(
                &key,
                7,
                Bearer::MAX,
                Direction::Downlink,
                &mut data,
                13,
                algorithm,
            )
            .unwrap();
            assert_eq!(data[0], whole[0]);
            assert_eq!(data[1] & 0xf8, whole[1] & 0xf8);
            assert_eq!(data[1] & 0x07, original[1] & 0x07);
            assert_eq!(data[2], original[2]);
            nea_cipher_bits(
                &key,
                7,
                Bearer::MAX,
                Direction::Downlink,
                &mut data,
                13,
                algorithm,
            )
            .unwrap();
            assert_eq!(data, original);
        }
    }

    #[test]
    fn a_bit_length_longer_than_the_data_is_an_error() {
        let key = [0x5a; 16];
        let original = [0xa5, 0x5a];
        let refused = Err(SecurityError::BitLengthExceedsData {
            bits: 17,
            octets: 2,
        });
        let (bearer, direction) = (Bearer::MAX, Direction::Downlink);

        for algorithm in ALGORITHMS {
            let mut data = original;
            assert_eq!(
                nea_cipher_bits(&key, 7, bearer, direction, &mut data, 17, algorithm),
                refused
            );
            assert_eq!(data, original);
            assert!(nea_cipher_bits(&key, 7, bearer, direction, &mut data, 16, algorithm).is_ok());
            assert!(nea_cipher_bits(&key, 7, bearer, direction, &mut [], 0, algorithm).is_ok());
        }
        let mut data = original;
        assert_eq!(
            nea1_cipher_bits(&key, 7, bearer, direction, &mut data, 17),
            refused
        );
        assert_eq!(
            nea2_cipher_bits(&key, 7, bearer, direction, &mut data, 17),
            refused
        );
        assert_eq!(
            nea3_cipher_bits(&key, 7, bearer, direction, &mut data, 17),
            refused
        );
        assert!(nea3_cipher_bits(&key, 7, bearer, direction, &mut data, u64::MAX).is_err());
        assert_eq!(data, original);
    }

    // ── NEA1 test vectors from 3GPP TS 35.215 / free5gc ────────────────────────
    //
    // The bit-length entry point covers the non-byte-aligned official vectors.

    fn nea1_test(
        key: [u8; 16],
        count: u32,
        bearer_value: u8,
        dir: u8,
        bit_length: u32,
        plaintext: &[u8],
        expected: &[u8],
    ) {
        let byte_len = (bit_length as usize).div_ceil(8);
        let pt = &plaintext[..byte_len];
        let ex = &expected[..byte_len];
        let mut data = pt.to_vec();
        let (bearer, dir) = (bearer(bearer_value), direction(dir));
        nea1_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, ex);
        // Decrypt (same op)
        nea1_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, pt);
    }

    #[test]
    fn test_nea1_tc1() {
        // Length = 798 bits → 99 full bytes tested
        nea1_test(
            [
                0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81,
                0xff, 0x48,
            ],
            0x72a4f20f,
            0x0c,
            1,
            798,
            &[
                0x7e, 0xc6, 0x12, 0x72, 0x74, 0x3b, 0xf1, 0x61, 0x47, 0x26, 0x44, 0x6a, 0x6c, 0x38,
                0xce, 0xd1, 0x66, 0xf6, 0xca, 0x76, 0xeb, 0x54, 0x30, 0x04, 0x42, 0x86, 0x34, 0x6c,
                0xef, 0x13, 0x0f, 0x92, 0x92, 0x2b, 0x03, 0x45, 0x0d, 0x3a, 0x99, 0x75, 0xe5, 0xbd,
                0x2e, 0xa0, 0xeb, 0x55, 0xad, 0x8e, 0x1b, 0x19, 0x9e, 0x3e, 0xc4, 0x31, 0x60, 0x20,
                0xe9, 0xa1, 0xb2, 0x85, 0xe7, 0x62, 0x79, 0x53, 0x59, 0xb7, 0xbd, 0xfd, 0x39, 0xbe,
                0xf4, 0xb2, 0x48, 0x45, 0x83, 0xd5, 0xaf, 0xe0, 0x82, 0xae, 0xe6, 0x38, 0xbf, 0x5f,
                0xd5, 0xa6, 0x06, 0x19, 0x39, 0x01, 0xa0, 0x8f, 0x4a, 0xb4, 0x1a, 0xab, 0x9b, 0x13,
                0x48, 0x80,
            ],
            &[
                0x8c, 0xeb, 0xa6, 0x29, 0x43, 0xdc, 0xed, 0x3a, 0x09, 0x90, 0xb0, 0x6e, 0xa1, 0xb0,
                0xa2, 0xc4, 0xfb, 0x3c, 0xed, 0xc7, 0x1b, 0x36, 0x9f, 0x42, 0xba, 0x64, 0xc1, 0xeb,
                0x66, 0x65, 0xe7, 0x2a, 0xa1, 0xc9, 0xbb, 0x0d, 0xea, 0xa2, 0x0f, 0xe8, 0x60, 0x58,
                0xb8, 0xba, 0xee, 0x2c, 0x2e, 0x7f, 0x0b, 0xec, 0xce, 0x48, 0xb5, 0x29, 0x32, 0xa5,
                0x3c, 0x9d, 0x5f, 0x93, 0x1a, 0x3a, 0x7c, 0x53, 0x22, 0x59, 0xaf, 0x43, 0x25, 0xe2,
                0xa6, 0x5e, 0x30, 0x84, 0xad, 0x5f, 0x6a, 0x51, 0x3b, 0x7b, 0xdd, 0xc1, 0xb6, 0x5f,
                0x0a, 0xa0, 0xd9, 0x7a, 0x05, 0x3d, 0xb5, 0x5a, 0x88, 0xc4, 0xc4, 0xf9, 0x60, 0x5e,
                0x41, 0x40,
            ],
        );
    }

    #[test]
    fn test_nea1_tc2() {
        // Length = 510 bits → 63 full bytes tested
        nea1_test(
            [
                0xef, 0xa8, 0xb2, 0x22, 0x9e, 0x72, 0x0c, 0x2a, 0x7c, 0x36, 0xea, 0x55, 0xe9, 0x60,
                0x56, 0x95,
            ],
            0xe28bcf7b,
            0x18,
            0,
            510,
            &[
                0x10, 0x11, 0x12, 0x31, 0xe0, 0x60, 0x25, 0x3a, 0x43, 0xfd, 0x3f, 0x57, 0xe3, 0x76,
                0x07, 0xab, 0x28, 0x27, 0xb5, 0x99, 0xb6, 0xb1, 0xbb, 0xda, 0x37, 0xa8, 0xab, 0xcc,
                0x5a, 0x8c, 0x55, 0x0d, 0x1b, 0xfb, 0x2f, 0x49, 0x46, 0x24, 0xfb, 0x50, 0x36, 0x7f,
                0xa3, 0x6c, 0xe3, 0xbc, 0x68, 0xf1, 0x1c, 0xf9, 0x3b, 0x15, 0x10, 0x37, 0x6b, 0x02,
                0x13, 0x0f, 0x81, 0x2a, 0x9f, 0xa1, 0x69, 0xd8,
            ],
            &[
                0xe0, 0xda, 0x15, 0xca, 0x8e, 0x25, 0x54, 0xf5, 0xe5, 0x6c, 0x94, 0x68, 0xdc, 0x6c,
                0x7c, 0x12, 0x9c, 0x56, 0x8a, 0xa5, 0x03, 0x23, 0x17, 0xe0, 0x4e, 0x07, 0x29, 0x64,
                0x6c, 0xab, 0xef, 0xa6, 0x89, 0x86, 0x4c, 0x41, 0x0f, 0x24, 0xf9, 0x19, 0xe6, 0x1e,
                0x3d, 0xfd, 0xfa, 0xd7, 0x7e, 0x56, 0x0d, 0xb0, 0xa9, 0xcd, 0x36, 0xc3, 0x4a, 0xe4,
                0x18, 0x14, 0x90, 0xb2, 0x9f, 0x5f, 0xa2, 0xfc,
            ],
        );
    }

    #[test]
    fn test_nea1_tc3() {
        // Length = 120 bits → 15 full bytes tested
        nea1_test(
            [
                0x5a, 0xcb, 0x1d, 0x64, 0x4c, 0x0d, 0x51, 0x20, 0x4e, 0xa5, 0xf1, 0x45, 0x10, 0x10,
                0xd8, 0x52,
            ],
            0xfa556b26,
            0x03,
            1,
            120,
            &[
                0xad, 0x9c, 0x44, 0x1f, 0x89, 0x0b, 0x38, 0xc4, 0x57, 0xa4, 0x9d, 0x42, 0x14, 0x07,
                0xe8, 0x00,
            ],
            &[
                0xba, 0x0f, 0x31, 0x30, 0x03, 0x34, 0xc5, 0x6b, 0x52, 0xa7, 0x49, 0x7c, 0xba, 0xc0,
                0x46, 0x00,
            ],
        );
    }

    #[test]
    fn test_nea1_tc4() {
        // Length = 253 bits → 31 full bytes tested
        nea1_test(
            [
                0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8,
                0xc6, 0xd1,
            ],
            0x398a59b4,
            0x05,
            1,
            253,
            &[
                0x98, 0x1b, 0xa6, 0x82, 0x4c, 0x1b, 0xfb, 0x1a, 0xb4, 0x85, 0x47, 0x20, 0x29, 0xb7,
                0x1d, 0x80, 0x8c, 0xe3, 0x3e, 0x2c, 0xc3, 0xc0, 0xb5, 0xfc, 0x1f, 0x3d, 0xe8, 0xa6,
                0xdc, 0x66, 0xb1, 0xf0,
            ],
            &[
                0x98, 0x9b, 0x71, 0x9c, 0xdc, 0x33, 0xce, 0xb7, 0xcf, 0x27, 0x6a, 0x52, 0x82, 0x7c,
                0xef, 0x94, 0xa5, 0x6c, 0x40, 0xc0, 0xab, 0x9d, 0x81, 0xf7, 0xa2, 0xa9, 0xba, 0xc6,
                0x0e, 0x11, 0xc4, 0xb0,
            ],
        );
    }

    #[test]
    fn test_nea1_tc5() {
        // Length = 837 bits → 104 full bytes tested
        nea1_test(
            [
                0x60, 0x90, 0xea, 0xe0, 0x4c, 0x83, 0x70, 0x6e, 0xec, 0xbf, 0x65, 0x2b, 0xe8, 0xe3,
                0x65, 0x66,
            ],
            0x72a4f20f,
            0x09,
            0,
            837,
            &[
                0x40, 0x98, 0x1b, 0xa6, 0x82, 0x4c, 0x1b, 0xfb, 0x42, 0x86, 0xb2, 0x99, 0x78, 0x3d,
                0xaf, 0x44, 0x2c, 0x09, 0x9f, 0x7a, 0xb0, 0xf5, 0x8d, 0x5c, 0x8e, 0x46, 0xb1, 0x04,
                0xf0, 0x8f, 0x01, 0xb4, 0x1a, 0xb4, 0x85, 0x47, 0x20, 0x29, 0xb7, 0x1d, 0x36, 0xbd,
                0x1a, 0x3d, 0x90, 0xdc, 0x3a, 0x41, 0xb4, 0x6d, 0x51, 0x67, 0x2a, 0xc4, 0xc9, 0x66,
                0x3a, 0x2b, 0xe0, 0x63, 0xda, 0x4b, 0xc8, 0xd2, 0x80, 0x8c, 0xe3, 0x3e, 0x2c, 0xcc,
                0xbf, 0xc6, 0x34, 0xe1, 0xb2, 0x59, 0x06, 0x08, 0x76, 0xa0, 0xfb, 0xb5, 0xa4, 0x37,
                0xeb, 0xcc, 0x8d, 0x31, 0xc1, 0x9e, 0x44, 0x54, 0x31, 0x87, 0x45, 0xe3, 0x98, 0x76,
                0x45, 0x98, 0x7a, 0x98, 0x6f, 0x2c, 0xb0,
            ],
            &[
                0x58, 0x92, 0xbb, 0xa8, 0x8b, 0xbb, 0xca, 0xae, 0xae, 0x76, 0x9a, 0xa0, 0x6b, 0x68,
                0x3d, 0x3a, 0x17, 0xcc, 0x04, 0xa3, 0x69, 0x88, 0x16, 0x97, 0x43, 0x5e, 0x44, 0xfe,
                0xd5, 0xff, 0x9a, 0xf5, 0x7b, 0x9e, 0x89, 0x0d, 0x4d, 0x5c, 0x64, 0x70, 0x98, 0x85,
                0xd4, 0x8a, 0xe4, 0x06, 0x90, 0xec, 0x04, 0x3b, 0xaa, 0xe9, 0x70, 0x57, 0x96, 0xe4,
                0xa9, 0xff, 0x5a, 0x4b, 0x8d, 0x8b, 0x36, 0xd7, 0xf3, 0xfe, 0x57, 0xcc, 0x6c, 0xfd,
                0x6c, 0xd0, 0x05, 0xcd, 0x38, 0x52, 0xa8, 0x5e, 0x94, 0xce, 0x6b, 0xcd, 0x90, 0xd0,
                0xd0, 0x78, 0x39, 0xce, 0x09, 0x73, 0x35, 0x44, 0xca, 0x8e, 0x35, 0x08, 0x43, 0x24,
                0x85, 0x50, 0x92, 0x2a, 0xc1, 0x28, 0x18,
            ],
        );
    }

    #[test]
    fn test_nea1_tc6() {
        // Length = 224 bits → 28 full bytes (byte-aligned)
        nea1_test(
            [
                0xaa, 0x3f, 0xc7, 0x8b, 0x4c, 0x1b, 0xb6, 0x1a, 0xf0, 0xa3, 0x7f, 0xa5, 0xf6, 0x23,
                0xab, 0xfc,
            ],
            0x02,
            0x01,
            0,
            224,
            &[
                0xbe, 0x40, 0x61, 0x94, 0xd3, 0x0b, 0xd7, 0x5e, 0x90, 0xea, 0xe3, 0xd7, 0x57, 0x71,
                0xae, 0x7b, 0x3a, 0x02, 0x62, 0x29, 0xe7, 0x0d, 0xd4, 0x30, 0x51, 0xe3, 0xa7, 0x1c,
            ],
            &[
                0x7e, 0x00, 0x67, 0x01, 0x00, 0x08, 0x2e, 0x05, 0x01, 0xc1, 0xff, 0xff, 0x91, 0xa1,
                0x12, 0x05, 0x81, 0x25, 0x09, 0x08, 0x69, 0x6e, 0x74, 0x65, 0x72, 0x6e, 0x65, 0x74,
            ],
        );
    }

    // ── NEA2 test vectors ───────────────────────────────────────────────────────

    fn nea2_test(
        key: [u8; 16],
        count: u32,
        bearer_value: u8,
        dir: u8,
        bit_length: u32,
        plaintext: &[u8],
        expected: &[u8],
    ) {
        let byte_len = (bit_length as usize).div_ceil(8);
        let plaintext = &plaintext[..byte_len];
        let expected = &expected[..byte_len];
        let mut data = plaintext.to_vec();
        let (bearer, dir) = (bearer(bearer_value), direction(dir));
        nea2_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, expected);
        // Decrypt (same op)
        nea2_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, plaintext);
    }

    #[test]
    fn test_nea2_tc1() {
        nea2_test(
            [
                0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8,
                0xc6, 0xd1,
            ],
            0x398a59b4,
            0x15,
            1,
            253,
            &[
                0x98, 0x1b, 0xa6, 0x82, 0x4c, 0x1b, 0xfb, 0x1a, 0xb4, 0x85, 0x47, 0x20, 0x29, 0xb7,
                0x1d, 0x80, 0x8c, 0xe3, 0x3e, 0x2c, 0xc3, 0xc0, 0xb5, 0xfc, 0x1f, 0x3d, 0xe8, 0xa6,
                0xdc, 0x66, 0xb1, 0xf0,
            ],
            &[
                0xe9, 0xfe, 0xd8, 0xa6, 0x3d, 0x15, 0x53, 0x04, 0xd7, 0x1d, 0xf2, 0x0b, 0xf3, 0xe8,
                0x22, 0x14, 0xb2, 0x0e, 0xd7, 0xda, 0xd2, 0xf2, 0x33, 0xdc, 0x3c, 0x22, 0xd7, 0xbd,
                0xee, 0xed, 0x8e, 0x78,
            ],
        );
    }

    #[test]
    fn test_nea2_tc2() {
        nea2_test(
            [
                0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc4, 0x40, 0xe0, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x05,
                0xff, 0x48,
            ],
            0xc675a64b,
            0x0c,
            1,
            798,
            &[
                0x7e, 0xc6, 0x12, 0x72, 0x74, 0x3b, 0xf1, 0x61, 0x47, 0x26, 0x44, 0x6a, 0x6c, 0x38,
                0xce, 0xd1, 0x66, 0xf6, 0xca, 0x76, 0xeb, 0x54, 0x30, 0x04, 0x42, 0x86, 0x34, 0x6c,
                0xef, 0x13, 0x0f, 0x92, 0x92, 0x2b, 0x03, 0x45, 0x0d, 0x3a, 0x99, 0x75, 0xe5, 0xbd,
                0x2e, 0xa0, 0xeb, 0x55, 0xad, 0x8e, 0x1b, 0x19, 0x9e, 0x3e, 0xc4, 0x31, 0x60, 0x20,
                0xe9, 0xa1, 0xb2, 0x85, 0xe7, 0x62, 0x79, 0x53, 0x59, 0xb7, 0xbd, 0xfd, 0x39, 0xbe,
                0xf4, 0xb2, 0x48, 0x45, 0x83, 0xd5, 0xaf, 0xe0, 0x82, 0xae, 0xe6, 0x38, 0xbf, 0x5f,
                0xd5, 0xa6, 0x06, 0x19, 0x39, 0x01, 0xa0, 0x8f, 0x4a, 0xb4, 0x1a, 0xab, 0x9b, 0x13,
                0x48, 0x80,
            ],
            &[
                0x59, 0x61, 0x60, 0x53, 0x53, 0xc6, 0x4b, 0xdc, 0xa1, 0x5b, 0x19, 0x5e, 0x28, 0x85,
                0x53, 0xa9, 0x10, 0x63, 0x25, 0x06, 0xd6, 0x20, 0x0a, 0xa7, 0x90, 0xc4, 0xc8, 0x06,
                0xc9, 0x99, 0x04, 0xcf, 0x24, 0x45, 0xcc, 0x50, 0xbb, 0x1c, 0xf1, 0x68, 0xa4, 0x96,
                0x73, 0x73, 0x4e, 0x08, 0x1b, 0x57, 0xe3, 0x24, 0xce, 0x52, 0x59, 0xc0, 0xe7, 0x8d,
                0x4c, 0xd9, 0x7b, 0x87, 0x09, 0x76, 0x50, 0x3c, 0x09, 0x43, 0xf2, 0xcb, 0x5a, 0xe8,
                0xf0, 0x52, 0xc7, 0xb7, 0xd3, 0x92, 0x23, 0x95, 0x87, 0xb8, 0x95, 0x60, 0x86, 0xbc,
                0xab, 0x18, 0x83, 0x60, 0x42, 0xe2, 0xe6, 0xce, 0x42, 0x43, 0x2a, 0x17, 0x10, 0x5c,
                0x53, 0xd0,
            ],
        );
    }

    #[test]
    fn test_nea2_tc3() {
        nea2_test(
            [
                0x0a, 0x8b, 0x6b, 0xd8, 0xd9, 0xb0, 0x8b, 0x08, 0xd6, 0x4e, 0x32, 0xd1, 0x81, 0x77,
                0x77, 0xfb,
            ],
            0x544d49cd,
            0x04,
            0,
            310,
            &[
                0xfd, 0x40, 0xa4, 0x1d, 0x37, 0x0a, 0x1f, 0x65, 0x74, 0x50, 0x95, 0x68, 0x7d, 0x47,
                0xba, 0x1d, 0x36, 0xd2, 0x34, 0x9e, 0x23, 0xf6, 0x44, 0x39, 0x2c, 0x8e, 0xa9, 0xc4,
                0x9d, 0x40, 0xc1, 0x32, 0x71, 0xaf, 0xf2, 0x64, 0xd0, 0xf2, 0x48,
            ],
            &[
                0x75, 0x75, 0x0d, 0x37, 0xb4, 0xbb, 0xa2, 0xa4, 0xde, 0xdb, 0x34, 0x23, 0x5b, 0xd6,
                0x8c, 0x66, 0x45, 0xac, 0xda, 0xac, 0xa4, 0x81, 0x38, 0xa3, 0xb0, 0xc4, 0x71, 0xe2,
                0xa7, 0x04, 0x1a, 0x57, 0x64, 0x23, 0xd2, 0x92, 0x72, 0x87, 0xf0,
            ],
        );
    }

    // ── NEA3 test vectors from 3GPP TS 35.223 / free5gc ────────────────────────
    //
    // The bit-length entry point covers the non-byte-aligned official vectors.

    fn nea3_test(
        key: [u8; 16],
        count: u32,
        bearer_value: u8,
        dir: u8,
        bit_length: u32,
        plaintext: &[u8],
        expected: &[u8],
    ) {
        let byte_len = (bit_length as usize).div_ceil(8);
        let pt = &plaintext[..byte_len];
        let ex = &expected[..byte_len];
        let mut data = pt.to_vec();
        let (bearer, dir) = (bearer(bearer_value), direction(dir));
        nea3_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, ex);
        // Decrypt (same op)
        nea3_cipher_bits(&key, count, bearer, dir, &mut data, bit_length.into()).unwrap();
        assert_eq!(&data, pt);
    }

    #[test]
    fn test_nea3_tc1() {
        // Length = 193 bits → 24 full bytes tested
        nea3_test(
            [
                0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0,
                0x0a, 0x29,
            ],
            0x66035492,
            0x0f,
            0,
            193,
            &[
                0x6c, 0xf6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xab, 0x0c, 0x97, 0x52, 0xfa, 0x6f, 0x90,
                0x25, 0xfe, 0x0b, 0xd6, 0x75, 0xd9, 0x00, 0x58, 0x75, 0xb2, 0x00, 0x00, 0x00, 0x00,
            ],
            &[
                0xa6, 0xc8, 0x5f, 0xc6, 0x6a, 0xfb, 0x85, 0x33, 0xaa, 0xfc, 0x25, 0x18, 0xdf, 0xe7,
                0x84, 0x94, 0x0e, 0xe1, 0xe4, 0xb0, 0x30, 0x23, 0x8c, 0xc8, 0x00, 0x00, 0x00, 0x00,
            ],
        );
    }

    #[test]
    fn test_nea3_tc2() {
        // Length = 800 bits → 100 full bytes tested
        nea3_test(
            [
                0xe5, 0xbd, 0x3e, 0xa0, 0xeb, 0x55, 0xad, 0xe8, 0x66, 0xc6, 0xac, 0x58, 0xbd, 0x54,
                0x30, 0x2a,
            ],
            0x056823,
            0x18,
            1,
            800,
            &[
                0x14, 0xa8, 0xef, 0x69, 0x3d, 0x67, 0x85, 0x07, 0xbb, 0xe7, 0x27, 0x0a, 0x7f, 0x67,
                0xff, 0x50, 0x06, 0xc3, 0x52, 0x5b, 0x98, 0x07, 0xe4, 0x67, 0xc4, 0xe5, 0x60, 0x00,
                0xba, 0x33, 0x8f, 0x5d, 0x42, 0x95, 0x59, 0x03, 0x67, 0x51, 0x82, 0x22, 0x46, 0xc8,
                0x0d, 0x3b, 0x38, 0xf0, 0x7f, 0x4b, 0xe2, 0xd8, 0xff, 0x58, 0x05, 0xf5, 0x13, 0x22,
                0x29, 0xbd, 0xe9, 0x3b, 0xbb, 0xdc, 0xaf, 0x38, 0x2b, 0xf1, 0xee, 0x97, 0x2f, 0xbf,
                0x99, 0x77, 0xba, 0xda, 0x89, 0x45, 0x84, 0x7a, 0x2a, 0x6c, 0x9a, 0xd3, 0x4a, 0x66,
                0x75, 0x54, 0xe0, 0x4d, 0x1f, 0x7f, 0xa2, 0xc3, 0x32, 0x41, 0xbd, 0x8f, 0x01, 0xba,
                0x22, 0x0d,
            ],
            &[
                0x13, 0x1d, 0x43, 0xe0, 0xde, 0xa1, 0xbe, 0x5c, 0x5a, 0x1b, 0xfd, 0x97, 0x1d, 0x85,
                0x2c, 0xbf, 0x71, 0x2d, 0x7b, 0x4f, 0x57, 0x96, 0x1f, 0xea, 0x32, 0x08, 0xaf, 0xa8,
                0xbc, 0xa4, 0x33, 0xf4, 0x56, 0xad, 0x09, 0xc7, 0x41, 0x7e, 0x58, 0xbc, 0x69, 0xcf,
                0x88, 0x66, 0xd1, 0x35, 0x3f, 0x74, 0x86, 0x5e, 0x80, 0x78, 0x1d, 0x20, 0x2d, 0xfb,
                0x3e, 0xcf, 0xf7, 0xfc, 0xbc, 0x3b, 0x19, 0x0f, 0xe8, 0x2a, 0x20, 0x4e, 0xd0, 0xe3,
                0x50, 0xfc, 0x0f, 0x6f, 0x26, 0x13, 0xb2, 0xf2, 0xbc, 0xa6, 0xdf, 0x5a, 0x47, 0x3a,
                0x57, 0xa4, 0xa0, 0x0d, 0x98, 0x5e, 0xba, 0xd8, 0x80, 0xd6, 0xf2, 0x38, 0x64, 0xa0,
                0x7b, 0x01,
            ],
        );
    }
}
