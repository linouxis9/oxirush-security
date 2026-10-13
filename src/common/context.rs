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

//! A key with its algorithm, kept from a message to the next.
//!
//! A UE, an AMF or an MME protects many messages with the same NAS keys.
//! [`IntegrityContext`] and [`CipheringContext`] hold a key with its
//! algorithm and with what the algorithm computes from the key alone, so
//! that a message does not pay for it again:
//!
//! - 128-EIA2: the round keys of AES and the two subkeys of CMAC;
//! - 128-EEA2: the round keys of AES;
//! - SNOW 3G and ZUC: nothing. Their initialization mixes the key with
//!   COUNT, BEARER and DIRECTION from its first step, so no part of it is
//!   that of the key alone, and a context saves no time with them.
//!
//! A context serves both directions and every bearer, which have the same
//! key: COUNT, BEARER and DIRECTION are inputs of each call. It is wiped
//! when it is dropped. Its values are those of
//! [`nia_mac`](crate::nia_mac) and of [`nea_cipher`](crate::nea_cipher).
//!
//! The round keys are kept on a processor with the AES instructions, where
//! they are 176 octets: an [`IntegrityContext`] is 240 octets and a
//! [`CipheringContext`] 208, whatever their algorithm, against 16 for a
//! key. Elsewhere the `aes` crate expands the key for each message, and a
//! context keeps the subkeys of CMAC alone. A program with very many
//! security contexts keeps contexts for those of AES, where they save
//! time, and keys for the others.

use crate::common::aes128::{Expanded, RoundKeys, Schedule, expand, no_round_keys};
use crate::common::batch::{CipherJob, MacJob};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm};
use crate::common::keys::{CipheringKey, IntegrityKey};
use crate::common::nea::{
    cipher_bits, cipher_message, cipher_octets, nea2_cipher_keyed, nea2_message_keyed,
};
use crate::common::nia::{
    BitString, CmacBlocks, cmac, cmac_message, cmac_subkeys, mac_message, mac_of_bits,
};
use crate::common::wipe;
use core::fmt;
use zeroize::Zeroizing;

/// An integrity key with its algorithm, for the messages of one security
/// context.
///
/// `count` is a `u32` or a [`NasCount`](crate::NasCount), and `bearer` a
/// [`Bearer`] or the [`NasConnection`](crate::nas_5gs::NasConnection) of
/// a 5GS NAS message; an EPS NAS message has [`Bearer::ZERO`].
///
/// ```
/// use oxirush_security::nas_5gs::{KNasInt, NasConnection};
/// use oxirush_security::{Direction, IntegrityAlgorithm, IntegrityContext, NasCount, nia_mac};
///
/// let key = KNasInt::new(&[0x2b; 16]);
/// let context = IntegrityContext::new(&key, IntegrityAlgorithm::NIA2);
///
/// let (count, message) = (NasCount::new(7)?, [0x07, 0x7e, 0x00, 0x43]);
/// let mac = context.mac(count, NasConnection::ThreeGpp, Direction::Uplink, &message);
/// assert_eq!(
///     mac,
///     nia_mac(
///         &key,
///         count.get(),
///         NasConnection::ThreeGpp.into(),
///         Direction::Uplink,
///         &message,
///         IntegrityAlgorithm::NIA2,
///     )
/// );
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone)]
pub struct IntegrityContext {
    algorithm: IntegrityAlgorithm,
    key: Zeroizing<[u8; 16]>,
    /// For 128-EIA2, the round keys of AES and the subkeys K1 and K2 of
    /// CMAC; none and zeros for another algorithm.
    expanded: Expanded,
    schedule: Schedule,
    subkeys: Zeroizing<[u128; 2]>,
}

impl IntegrityContext {
    /// The context of a key and its algorithm.
    pub fn new(key: &impl IntegrityKey, algorithm: IntegrityAlgorithm) -> Self {
        let key = key.key_octets();
        wipe::portable(|| {
            let key = Zeroizing::new(*key);
            let ((mut expanded, mut schedule), mut subkeys) =
                (no_round_keys(), Zeroizing::new([0; 2]));
            if algorithm == IntegrityAlgorithm::Aes {
                (expanded, schedule) = expand(&key);
                *subkeys = cmac_subkeys(&key, RoundKeys::of(&expanded, &schedule));
            }
            Self {
                algorithm,
                key,
                expanded,
                schedule,
                subkeys,
            }
        })
    }

    /// Its algorithm.
    pub fn algorithm(&self) -> IntegrityAlgorithm {
        self.algorithm
    }

    /// The 32-bit MAC of a message of whole octets. The null algorithm
    /// gives zero.
    pub fn mac(
        &self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        message: &[u8],
    ) -> u32 {
        let message = BitString::whole(message);
        self.mac_message(count.into(), bearer.into(), direction, message)
    }

    /// The MAC of the first `bit_length` bits of `message`.
    ///
    /// A `bit_length` above the length of `message` in bits is
    /// [`SecurityError::BitLengthExceedsData`].
    pub fn mac_bits(
        &self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        message: &[u8],
        bit_length: u64,
    ) -> Result<u32, SecurityError> {
        let (count, bearer, bits) = (
            count.into(),
            bearer.into(),
            BitString::new(message, bit_length)?,
        );
        Ok(self.mac_message(count, bearer, direction, bits))
    }

    /// The message as a job of [`nia_mac_batch`](crate::nia_mac_batch),
    /// which computes its MAC with those of other messages.
    pub fn job<'a>(
        &'a self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        message: &'a [u8],
    ) -> MacJob<'a> {
        let bits = BitString::whole(message);
        MacJob::of_context(self, count.into(), bearer.into(), direction, bits)
    }

    /// The first `bit_length` bits of `message` as a job of
    /// [`nia_mac_batch`](crate::nia_mac_batch).
    ///
    /// A `bit_length` above the length of `message` in bits is
    /// [`SecurityError::BitLengthExceedsData`].
    pub fn job_bits<'a>(
        &'a self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        message: &'a [u8],
        bit_length: u64,
    ) -> Result<MacJob<'a>, SecurityError> {
        let bits = BitString::new(message, bit_length)?;
        Ok(MacJob::of_context(
            self,
            count.into(),
            bearer.into(),
            direction,
            bits,
        ))
    }

    /// The octets of the key.
    pub(crate) fn key(&self) -> &[u8; 16] {
        &self.key
    }

    fn round_keys(&self) -> RoundKeys<'_> {
        RoundKeys::of(&self.expanded, &self.schedule)
    }

    /// The round keys on the AES instructions and the subkeys of CMAC,
    /// when the context has them.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn cmac_key(&self) -> Option<crate::common::nia::CmacKey<'_>> {
        let (_, schedule) = self.round_keys().schedule()?;
        Some(crate::common::nia::CmacKey::Keyed(schedule, &self.subkeys))
    }

    /// The MAC of the first bits of one message, which are known to be
    /// there, and what the work left cleared.
    fn mac_message(
        &self,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: BitString<'_>,
    ) -> u32 {
        match self.algorithm {
            IntegrityAlgorithm::Aes => {
                let blocks = CmacBlocks::new(count, bearer, direction, message);
                cmac_message(&self.key, self.round_keys(), &self.subkeys, &blocks)
            }
            algorithm => mac_message(&self.key, count, bearer, direction, message, algorithm),
        }
    }

    /// The MAC of the first bits of a message, for a caller that clears
    /// after its own work.
    pub(crate) fn mac_of(
        &self,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: BitString<'_>,
    ) -> u32 {
        match self.algorithm {
            IntegrityAlgorithm::Aes => {
                let blocks = CmacBlocks::new(count, bearer, direction, message);
                cmac(&self.key, self.round_keys(), &self.subkeys, &blocks)
            }
            algorithm => mac_of_bits(&self.key, count, bearer, direction, message, algorithm),
        }
    }
}

/// The algorithm, and nothing of the key.
impl fmt::Debug for IntegrityContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IntegrityContext")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

/// A ciphering key with its algorithm, for the messages of one security
/// context.
///
/// `count` is a `u32` or a [`NasCount`](crate::NasCount), and `bearer` a
/// [`Bearer`] or the [`NasConnection`](crate::nas_5gs::NasConnection) of
/// a 5GS NAS message; an EPS NAS message has [`Bearer::ZERO`].
///
/// ```
/// use oxirush_security::nas_eps::KNasEnc;
/// use oxirush_security::{Bearer, CipheringAlgorithm, CipheringContext, Direction, NasCount};
///
/// let key = KNasEnc::new(&[0x2b; 16]);
/// let context = CipheringContext::new(&key, CipheringAlgorithm::EEA2);
///
/// let mut message = *b"an EPS NAS message";
/// let count = NasCount::new(7)?;
/// context.cipher(count, Bearer::ZERO, Direction::Downlink, &mut message);
/// assert_ne!(&message, b"an EPS NAS message");
/// // To decipher is the same operation
/// context.cipher(count, Bearer::ZERO, Direction::Downlink, &mut message);
/// assert_eq!(&message, b"an EPS NAS message");
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone)]
pub struct CipheringContext {
    algorithm: CipheringAlgorithm,
    key: Zeroizing<[u8; 16]>,
    /// For 128-EEA2, the round keys of AES; none for another algorithm.
    expanded: Expanded,
    schedule: Schedule,
}

impl CipheringContext {
    /// The context of a key and its algorithm.
    pub fn new(key: &impl CipheringKey, algorithm: CipheringAlgorithm) -> Self {
        let key = key.key_octets();
        wipe::portable(|| {
            let key = Zeroizing::new(*key);
            let (expanded, schedule) = match algorithm {
                CipheringAlgorithm::Aes => expand(&key),
                _ => no_round_keys(),
            };
            Self {
                algorithm,
                key,
                expanded,
                schedule,
            }
        })
    }

    /// Its algorithm.
    pub fn algorithm(&self) -> CipheringAlgorithm {
        self.algorithm
    }

    /// Cipher or decipher octets in place, which is one operation. The
    /// null algorithm leaves them as they are.
    pub fn cipher(
        &self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        data: &mut [u8],
    ) {
        self.cipher_message(count.into(), bearer.into(), direction, data);
    }

    /// Cipher or decipher the first `bit_length` bits of `data`. The
    /// unused low-order bits of the last octet stay as they are.
    ///
    /// A `bit_length` above the length of `data` in bits is
    /// [`SecurityError::BitLengthExceedsData`], and the data is then
    /// unchanged.
    pub fn cipher_bits(
        &self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        data: &mut [u8],
        bit_length: u64,
    ) -> Result<(), SecurityError> {
        let (count, bearer) = (count.into(), bearer.into());
        cipher_bits(data, bit_length, |octets| {
            self.cipher_message(count, bearer, direction, octets);
        })
    }

    /// The message as a job of
    /// [`nea_cipher_batch`](crate::nea_cipher_batch), which ciphers it
    /// with other messages.
    pub fn job<'a>(
        &'a self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        data: &'a mut [u8],
    ) -> CipherJob<'a> {
        CipherJob::of_context(self, count.into(), bearer.into(), direction, data)
    }

    /// The first `bit_length` bits of `data` as a job of
    /// [`nea_cipher_batch`](crate::nea_cipher_batch).
    ///
    /// A `bit_length` above the length of `data` in bits is
    /// [`SecurityError::BitLengthExceedsData`].
    pub fn job_bits<'a>(
        &'a self,
        count: impl Into<u32>,
        bearer: impl Into<Bearer>,
        direction: Direction,
        data: &'a mut [u8],
        bit_length: u64,
    ) -> Result<CipherJob<'a>, SecurityError> {
        let job = CipherJob::of_context(self, count.into(), bearer.into(), direction, data);
        job.with_bits(bit_length)
    }

    /// The octets of the key.
    pub(crate) fn key(&self) -> &[u8; 16] {
        &self.key
    }

    /// Cipher the whole octets of one message, and clear what the work
    /// left.
    fn cipher_message(&self, count: u32, bearer: Bearer, direction: Direction, data: &mut [u8]) {
        match self.algorithm {
            CipheringAlgorithm::Aes if data.is_empty() => {}
            CipheringAlgorithm::Aes => {
                let round_keys = RoundKeys::of(&self.expanded, &self.schedule);
                nea2_message_keyed(&self.key, round_keys, count, bearer, direction, data);
            }
            algorithm => cipher_message(&self.key, count, bearer, direction, data, algorithm),
        }
    }

    /// The round keys on the AES instructions, when the context has them.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn schedule(&self) -> Option<&crate::common::simd::AesSchedule> {
        let (_, schedule) = RoundKeys::of(&self.expanded, &self.schedule).schedule()?;
        Some(schedule)
    }

    /// Cipher whole octets, for a caller that clears after its own work.
    pub(crate) fn cipher_whole(
        &self,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &mut [u8],
    ) {
        match self.algorithm {
            CipheringAlgorithm::Aes if data.is_empty() => {}
            CipheringAlgorithm::Aes => {
                let round_keys = RoundKeys::of(&self.expanded, &self.schedule);
                nea2_cipher_keyed(&self.key, round_keys, count, bearer, direction, data)
            }
            algorithm => cipher_octets(&self.key, count, bearer, direction, data, algorithm),
        }
    }
}

/// The algorithm, and nothing of the key.
impl fmt::Debug for CipheringContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CipheringContext")
            .field("algorithm", &self.algorithm)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::batch::{nea_cipher_batch, nia_mac_batch};
    use crate::common::nea::{nea_cipher, nea_cipher_bits};
    use crate::common::nia::{nia_mac, nia_mac_bits};
    use crate::nas_5gs::NasConnection;
    use crate::{NasCount, nas_eps};

    /// Octets that look random, the same at every run.
    fn octets(seed: u32, length: usize) -> Vec<u8> {
        let mut state = seed.wrapping_mul(0x9e37_79b9) | 1;
        (0..length)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 17;
                state ^= state << 5;
                (state >> 24) as u8
            })
            .collect()
    }

    const LENGTHS: [usize; 16] = [
        0, 1, 2, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1500,
    ];

    /// Run a comparison on every code that the processor has: the vector
    /// instructions, those of 128 bits alone, and none.
    fn on_every_code(work: impl Fn()) {
        work();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            crate::common::simd::narrow(&work);
            crate::common::simd::scalar(&work);
        }
    }

    #[test]
    fn an_integrity_context_gives_the_macs_of_the_function() {
        on_every_code(|| {
            for identifier in 0..=3 {
                let algorithm = IntegrityAlgorithm::try_from(identifier).unwrap();
                let key: [u8; 16] = octets(identifier.into(), 16).try_into().unwrap();
                let context = IntegrityContext::new(&key, algorithm);
                assert_eq!(context.algorithm(), algorithm);
                for (index, length) in LENGTHS.into_iter().enumerate() {
                    let message = octets(length as u32 + 7, length);
                    let count = 0xfedc_ba00 + index as u32;
                    let bearer = Bearer::new(index as u8 * 2).unwrap();
                    for direction in [Direction::Uplink, Direction::Downlink] {
                        assert_eq!(
                            context.mac(count, bearer, direction, &message),
                            nia_mac(&key, count, bearer, direction, &message, algorithm),
                            "{algorithm} of {length} octets"
                        );
                        for bits in (8 * length as u64).saturating_sub(9)..=8 * length as u64 {
                            assert_eq!(
                                context.mac_bits(count, bearer, direction, &message, bits),
                                nia_mac_bits(
                                    &key, count, bearer, direction, &message, bits, algorithm
                                ),
                                "{algorithm} of {bits} bits"
                            );
                        }
                    }
                }
                let bits = 8 * 4 + 1;
                assert_eq!(
                    context.mac_bits(0u32, Bearer::ZERO, Direction::Uplink, &[0; 4], bits),
                    Err(SecurityError::BitLengthExceedsData { bits, octets: 4 })
                );
            }
        });
    }

    #[test]
    fn a_ciphering_context_ciphers_as_the_function_does() {
        on_every_code(|| {
            for identifier in 0..=3 {
                let algorithm = CipheringAlgorithm::try_from(identifier).unwrap();
                let key: [u8; 16] = octets(identifier.into(), 16).try_into().unwrap();
                let context = CipheringContext::new(&key, algorithm);
                assert_eq!(context.algorithm(), algorithm);
                for (index, length) in LENGTHS.into_iter().enumerate() {
                    let plain = octets(length as u32 + 11, length);
                    let count = 0x0123_4500 + index as u32;
                    let bearer = Bearer::new(31 - index as u8).unwrap();
                    for direction in [Direction::Uplink, Direction::Downlink] {
                        let mut expected = plain.clone();
                        nea_cipher(&key, count, bearer, direction, &mut expected, algorithm);
                        let mut data = plain.clone();
                        context.cipher(count, bearer, direction, &mut data);
                        assert_eq!(data, expected, "{algorithm} of {length} octets");
                        // To decipher is the same operation
                        context.cipher(count, bearer, direction, &mut data);
                        assert_eq!(data, plain);

                        for bits in (8 * length as u64).saturating_sub(9)..=8 * length as u64 {
                            let mut expected = plain.clone();
                            nea_cipher_bits(
                                &key,
                                count,
                                bearer,
                                direction,
                                &mut expected,
                                bits,
                                algorithm,
                            )
                            .unwrap();
                            let mut data = plain.clone();
                            context
                                .cipher_bits(count, bearer, direction, &mut data, bits)
                                .unwrap();
                            assert_eq!(data, expected, "{algorithm} of {bits} bits");
                        }
                    }
                }
                let mut data = [0x5a; 4];
                assert_eq!(
                    context.cipher_bits(0u32, Bearer::ZERO, Direction::Uplink, &mut data, 33),
                    Err(SecurityError::BitLengthExceedsData {
                        bits: 33,
                        octets: 4
                    })
                );
                assert_eq!(data, [0x5a; 4]);
            }
        });
    }

    /// The jobs of contexts and those of keys, of every algorithm, in one
    /// batch: each has the value of its message alone.
    #[test]
    fn the_jobs_of_contexts_are_computed_in_a_batch() {
        on_every_code(|| {
            let keys: Vec<[u8; 16]> = (0..24).map(|index| [index as u8 + 1; 16]).collect();
            let messages: Vec<Vec<u8>> = (0..24)
                .map(|index| octets(index, 3 * index as usize))
                .collect();
            let integrity = |index: usize| IntegrityAlgorithm::try_from(index as u8 % 4).unwrap();
            let ciphering = |index: usize| CipheringAlgorithm::try_from(index as u8 % 4).unwrap();
            let (bearer, direction) = (Bearer::new(3).unwrap(), Direction::Downlink);

            let contexts: Vec<IntegrityContext> = (0..24)
                .map(|index| IntegrityContext::new(&keys[index], integrity(index)))
                .collect();
            let mut jobs: Vec<MacJob<'_>> = (0..24)
                .map(|index| {
                    let (count, message) = (index as u32, &messages[index][..]);
                    // Every third message has the octets of its key, and
                    // every fifth the first bits of its message
                    if index % 3 == 0 {
                        MacJob::new(
                            &keys[index],
                            count,
                            bearer,
                            direction,
                            message,
                            integrity(index),
                        )
                    } else if index % 5 == 0 {
                        let bits = 8 * message.len() as u64 - 3;
                        contexts[index]
                            .job_bits(count, bearer, direction, message, bits)
                            .unwrap()
                    } else {
                        contexts[index].job(count, bearer, direction, message)
                    }
                })
                .collect();
            nia_mac_batch(&mut jobs);
            for (index, job) in jobs.iter().enumerate() {
                let message = &messages[index];
                let bits = match index {
                    index if index % 3 != 0 && index % 5 == 0 => 8 * message.len() as u64 - 3,
                    _ => 8 * message.len() as u64,
                };
                let algorithm = integrity(index);
                let expected = nia_mac_bits(
                    &keys[index],
                    index as u32,
                    bearer,
                    direction,
                    message,
                    bits,
                    algorithm,
                );
                assert_eq!(job.mac(), expected.ok(), "message {index}, {algorithm}");
            }

            let contexts: Vec<CipheringContext> = (0..24)
                .map(|index| CipheringContext::new(&keys[index], ciphering(index)))
                .collect();
            let mut data = messages.clone();
            let mut jobs: Vec<CipherJob<'_>> = data
                .iter_mut()
                .enumerate()
                .map(|(index, data)| {
                    let count = index as u32;
                    if index % 3 == 0 {
                        CipherJob::new(
                            &keys[index],
                            count,
                            bearer,
                            direction,
                            data,
                            ciphering(index),
                        )
                    } else if index % 5 == 0 {
                        let bits = 8 * data.len() as u64 - 3;
                        contexts[index]
                            .job_bits(count, bearer, direction, data, bits)
                            .unwrap()
                    } else {
                        contexts[index].job(count, bearer, direction, data)
                    }
                })
                .collect();
            nea_cipher_batch(&mut jobs);
            for (index, data) in data.iter().enumerate() {
                let mut expected = messages[index].clone();
                let bits = match index {
                    index if index % 3 != 0 && index % 5 == 0 => 8 * expected.len() as u64 - 3,
                    _ => 8 * expected.len() as u64,
                };
                let algorithm = ciphering(index);
                nea_cipher_bits(
                    &keys[index],
                    index as u32,
                    bearer,
                    direction,
                    &mut expected,
                    bits,
                    algorithm,
                )
                .unwrap();
                assert_eq!(data, &expected, "message {index}, {algorithm}");
            }
            let mut short = [0u8; 2];
            assert!(
                contexts[1]
                    .job_bits(0u32, bearer, direction, &mut short, 17)
                    .is_err()
            );
        });
    }

    /// A NAS COUNT and a NAS connection are taken as they are, and the
    /// keys of both systems.
    #[test]
    fn a_context_takes_the_inputs_of_nas() {
        let message = *b"\x07a 5GS NAS message";
        let count = NasCount::new(0x01_0207).unwrap();
        let key = crate::nas_5gs::KNasInt::new(&[0x2b; 16]);
        let context = IntegrityContext::new(&key, IntegrityAlgorithm::NIA2);
        for connection in [NasConnection::ThreeGpp, NasConnection::Non3Gpp] {
            assert_eq!(
                context.mac(count, connection, Direction::Uplink, &message),
                crate::nas_5gs::nas_mac(
                    &key,
                    count,
                    connection,
                    Direction::Uplink,
                    &message,
                    IntegrityAlgorithm::NIA2
                )
            );
        }
        let key = nas_eps::KNasEnc::new(&[0x2b; 16]);
        let context = CipheringContext::new(&key, CipheringAlgorithm::EEA2);
        let (mut data, mut expected) = (message, message);
        context.cipher(count, Bearer::ZERO, Direction::Downlink, &mut data);
        nas_eps::nas_cipher(
            &key,
            count,
            Direction::Downlink,
            &mut expected,
            CipheringAlgorithm::EEA2,
        );
        assert_eq!(data, expected);
    }

    #[test]
    fn a_context_shows_its_algorithm_alone() {
        let key = [0x42; 16];
        let integrity = IntegrityContext::new(&key, IntegrityAlgorithm::NIA2);
        assert_eq!(
            format!("{integrity:?}"),
            "IntegrityContext { algorithm: Aes, .. }"
        );
        let ciphering = CipheringContext::new(&key, CipheringAlgorithm::NEA1);
        assert_eq!(
            format!("{ciphering:?}"),
            "CipheringContext { algorithm: Snow3g, .. }"
        );
        // A context is shared between the threads of a server, and a copy
        // of it is a context of its own
        fn shared<T: Send + Sync + Clone>() {}
        // The round keys that a context keeps are those of the AES
        // instructions, and never the larger ones of the `aes` crate
        assert!(size_of::<IntegrityContext>() <= 240);
        assert!(size_of::<CipheringContext>() <= 208);
        shared::<IntegrityContext>();
        shared::<CipheringContext>();
    }
}
