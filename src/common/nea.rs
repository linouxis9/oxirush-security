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
//! operation. A program calls them through a
//! [`CipheringContext`](crate::CipheringContext), or for a NAS message
//! through [`nas_5gs::nas_cipher`](crate::nas_5gs::nas_cipher) and
//! [`nas_eps::nas_cipher`](crate::nas_eps::nas_cipher), which take a NAS
//! COUNT.
use crate::common::aes128::{Aes128, RoundKeys};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, Direction, octets_of};
use crate::common::keys::CipheringKey;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::{AesSchedule, Instructions};
use crate::common::snow3g::Snow3G;
use crate::common::wipe;
use crate::common::zuc::Zuc;
use oxirush_utils::identity::Algorithm;
use zeroize::{Zeroize, Zeroizing};

/// Cipher or decipher octets in place with `algorithm`.
///
/// The null algorithm leaves the data as it is.
pub fn nea_cipher(
    key: &impl CipheringKey,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    algorithm: Algorithm,
) {
    cipher_message(key.key_octets(), count, bearer, direction, data, algorithm);
}

/// Cipher or decipher one message in place with the octets of a key, and
/// clear what the work left: each algorithm in a frame of its own, as deep
/// as it goes and no deeper.
pub(crate) fn cipher_message(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    algorithm: Algorithm,
) {
    if data.is_empty() {
        return;
    }
    match algorithm {
        Algorithm::Null => {}
        Algorithm::Snow3g => {
            wipe::message(|| nea1_cipher(key, count, bearer, direction, data));
        }
        Algorithm::Aes => {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if let Some(instructions) = Instructions::detect() {
                return wipe::aes(|| {
                    nea2_instructions(instructions, key, None, count, bearer, direction, data);
                });
            }
            wipe::portable(|| nea2_portable(key, count, bearer, direction, data));
        }
        Algorithm::Zuc => {
            wipe::message(|| nea3_cipher(key, count, bearer, direction, data));
        }
    }
}

/// Cipher or decipher octets in place with the octets of a key, for a
/// caller that clears after its own work.
#[cfg(feature = "batch")]
pub(crate) fn cipher_octets(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    algorithm: Algorithm,
) {
    match algorithm {
        Algorithm::Null => {}
        Algorithm::Snow3g => nea1_cipher(key, count, bearer, direction, data),
        Algorithm::Aes => nea2_cipher(key, count, bearer, direction, data),
        Algorithm::Zuc => nea3_cipher(key, count, bearer, direction, data),
    }
}

/// Cipher or decipher, as [`nea_cipher`] does, the first `bit_length`
/// most-significant bits of `data`. Unused low-order bits of the partial
/// final octet are unchanged.
///
/// A `bit_length` above the length of `data` in bits is
/// [`SecurityError::BitLengthExceedsData`], with the null algorithm too,
/// and the data is then unchanged.
#[cfg(any(test, oxirush_security_hooks))]
pub fn nea_cipher_bits(
    key: &impl CipheringKey,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
    bit_length: u64,
    algorithm: Algorithm,
) -> Result<(), SecurityError> {
    let key = key.key_octets();
    cipher_bits(data, bit_length, |octets| {
        cipher_message(key, count, bearer, direction, octets, algorithm);
    })
}

/// Apply a whole-octet cipher to the octets that hold the first
/// `bit_length` bits, then give the unused bits of the last octet back.
pub(crate) fn cipher_bits(
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
/// data. `fill` gives the next words of the keystream, which are taken
/// [`KEYSTREAM_WORDS`] at a time. The copy of the keystream is wiped.
fn xor_keystream(data: &mut [u8], mut fill: impl FnMut(&mut [u32])) {
    let mut keystream = [0u32; KEYSTREAM_WORDS];
    for part in data.chunks_mut(4 * KEYSTREAM_WORDS) {
        let words = &mut keystream[..part.len().div_ceil(4)];
        fill(words);
        let (whole, rest) = part.as_chunks_mut::<4>();
        for (octets, word) in whole.iter_mut().zip(words.iter()) {
            *octets = (u32::from_be_bytes(*octets) ^ word).to_be_bytes();
        }
        if let Some(word) = words.get(whole.len()) {
            for (octet, key_octet) in rest.iter_mut().zip(word.to_be_bytes()) {
                *octet ^= key_octet;
            }
        }
    }
    // A part overwrites the words of the one before it: the array holds
    // keystream in as many words as the longest part had
    keystream[..data.len().div_ceil(4).min(KEYSTREAM_WORDS)].zeroize();
}

/// The number of keystream words that [`xor_keystream`] asks for at a time:
/// a multiple of three, the number that SNOW 3G makes at once.
const KEYSTREAM_WORDS: usize = 48;

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
pub(crate) fn nea1_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let (k, iv) = eea1_key_and_iv(key, count, bearer, direction);
    let mut snow = Snow3G::start(*k, iv);
    xor_keystream(data, |words| snow.words(words));
}

/// The key words and the IV of SNOW 3G for 128-EEA1.
pub(crate) fn eea1_key_and_iv(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
) -> (Zeroizing<[u32; 4]>, [u32; 4]) {
    let bearer_dir = (u32::from(bearer.get()) << 27) | (u32::from(u8::from(direction)) << 26);

    // The key words are loaded last word first (UEA2 §3.4).
    let (words, _) = key.as_chunks::<4>();
    let k = Zeroizing::new([
        u32::from_be_bytes(words[3]),
        u32::from_be_bytes(words[2]),
        u32::from_be_bytes(words[1]),
        u32::from_be_bytes(words[0]),
    ]);
    (k, [bearer_dir, count, bearer_dir, count])
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
#[cfg(any(test, feature = "batch"))]
pub(crate) fn nea2_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return nea2_instructions(instructions, key, None, count, bearer, direction, data);
    }
    nea2_portable(key, count, bearer, direction, data);
}

/// 128-EEA2 on the AES instructions, with the round keys of the key when
/// a context has them. Without them, they go from their expansion to the
/// counter mode without a keyed state between the two, which a message
/// alone does not need.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn nea2_instructions(
    instructions: Instructions,
    key: &[u8; 16],
    schedule: Option<&AesSchedule>,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }
    let prefix = u64::from_le_bytes(ctr_prefix(count, bearer, direction));
    match schedule {
        Some(schedule) => instructions.aes_ctr(schedule, prefix, data),
        None => instructions.aes_ctr(&instructions.aes_schedules([key])[0], prefix, data),
    }
}

/// 128-EEA2 with the `aes` crate, for a processor without the AES
/// instructions.
pub(crate) fn nea2_portable(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    Aes128::new(key).ctr(ctr_prefix(count, bearer, direction), data);
}

/// 128-EEA2 of octets, of which there are some, with a key and its round
/// keys, for a caller that clears after its own work.
#[cfg(feature = "batch")]
pub(crate) fn nea2_cipher_keyed(
    key: &[u8; 16],
    round_keys: RoundKeys<'_>,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some((instructions, schedule)) = round_keys.schedule() {
        let schedule = Some(schedule);
        return nea2_instructions(instructions, key, schedule, count, bearer, direction, data);
    }
    let _ = round_keys;
    nea2_portable(key, count, bearer, direction, data);
}

/// 128-EEA2 of one message with a key and its round keys, and what the
/// work left cleared.
pub(crate) fn nea2_message_keyed(
    key: &[u8; 16],
    round_keys: RoundKeys<'_>,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some((instructions, schedule)) = round_keys.schedule() {
        let schedule = Some(schedule);
        return wipe::aes_keyed(|| {
            nea2_instructions(instructions, key, schedule, count, bearer, direction, data);
        });
    }
    let _ = round_keys;
    wipe::portable(|| nea2_portable(key, count, bearer, direction, data));
}

/// The upper eight octets of the counter blocks of a message, which are
/// fixed: COUNT, BEARER and DIRECTION.
pub(crate) fn ctr_prefix(count: u32, bearer: Bearer, direction: Direction) -> [u8; 8] {
    let mut prefix = [0u8; 8];
    prefix[0..4].copy_from_slice(&count.to_be_bytes());
    prefix[4] = (bearer.get() << 3) | (u8::from(direction) << 2);
    prefix
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
pub(crate) fn nea3_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    data: &mut [u8],
) {
    if data.is_empty() {
        return;
    }

    let mut zuc = Zuc::start(key, &eea3_iv(count, bearer, direction));
    xor_keystream(data, |words| zuc.words(words));
}

/// The IV of ZUC for 128-EEA3.
pub(crate) fn eea3_iv(count: u32, bearer: Bearer, direction: Direction) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = (bearer.get() << 3) | (u8::from(direction) << 2);
    // The upper half repeats the lower one
    iv.copy_within(0..8, 8);
    iv
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One algorithm over the first bits of the data, by its number.
    fn algorithm_bits(
        algorithm: Algorithm,
    ) -> impl Fn(&[u8; 16], u32, Bearer, Direction, &mut [u8], u64) -> Result<(), SecurityError>
    {
        move |key, count, bearer, direction, data, bit_length| {
            nea_cipher_bits(key, count, bearer, direction, data, bit_length, algorithm)
        }
    }

    fn nea1_cipher_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &mut [u8],
        bit_length: u64,
    ) -> Result<(), SecurityError> {
        algorithm_bits(Algorithm::Snow3g)(key, count, bearer, direction, data, bit_length)
    }

    fn nea2_cipher_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &mut [u8],
        bit_length: u64,
    ) -> Result<(), SecurityError> {
        algorithm_bits(Algorithm::Aes)(key, count, bearer, direction, data, bit_length)
    }

    fn nea3_cipher_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &mut [u8],
        bit_length: u64,
    ) -> Result<(), SecurityError> {
        algorithm_bits(Algorithm::Zuc)(key, count, bearer, direction, data, bit_length)
    }

    fn bearer(value: u8) -> Bearer {
        Bearer::new(value).unwrap()
    }

    const ALGORITHMS: [Algorithm; 4] = [
        Algorithm::Null,
        Algorithm::Snow3g,
        Algorithm::Aes,
        Algorithm::Zuc,
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
                if algorithm != Algorithm::Null && length >= 8 {
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
            Algorithm::Null,
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
        assert_eq!(dispatched(Algorithm::Snow3g), with(nea1_cipher));
        assert_eq!(dispatched(Algorithm::Aes), with(nea2_cipher));
        assert_eq!(dispatched(Algorithm::Zuc), with(nea3_cipher));
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
}
