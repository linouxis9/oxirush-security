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

//! Several messages at once, each with its own key, COUNT, BEARER and
//! DIRECTION, as an AMF, an MME or a load generator has them.
//!
//! [`nea_cipher_batch`] and [`nia_mac_batch`] give every message what
//! [`nea_cipher`](crate::nea_cipher) and [`nia_mac`](crate::nia_mac) give
//! it alone. A message is a job: [`CipherJob`] or [`MacJob`], which holds
//! its key with its COUNT, its BEARER, its DIRECTION and its algorithm, so
//! that none of them goes to another message. The jobs of a batch need not
//! have the same algorithm or the same length.
//!
//! For a NAS message, [`nas_5gs::cipher_job`](crate::nas_5gs::cipher_job),
//! [`nas_5gs::mac_job`](crate::nas_5gs::mac_job) and their counterparts of
//! [`nas_eps`](crate::nas_eps) make the job from a NAS COUNT. A keyed
//! context makes the job of a message with
//! [`CipheringContext::job`](crate::CipheringContext::job) or
//! [`IntegrityContext::job`](crate::IntegrityContext::job), and the batch
//! then has what the context has computed from the key.
//!
//! # What runs side by side
//!
//! - 128-EEA1, 128-EIA1, 128-EEA3 and 128-EIA3: SNOW 3G or ZUC generators
//!   are clocked together, one in each 32-bit word of a vector. There are
//!   four of them on an x86-64 processor with SSSE3, SSE4.1, AES-NI and
//!   PCLMULQDQ or an AArch64 one with AES, and eight for more than four
//!   messages on an x86-64 processor that has AVX2 as well. A generator
//!   that has given its message its keystream takes the next message of
//!   the batch.
//! - 128-EIA2: on the same processors, the key expansions of eight
//!   messages run together, and so do their CBC-MAC chains, a block of each
//!   message at a time.
//! - 128-EEA2: one message after the other. The counter blocks of one
//!   message are encrypted eight at a time, which leaves nothing for a
//!   second message to add.
//!
//! Elsewhere, and for a batch of one message, the functions call those of
//! one message. The values are the same in every case.
//!
//! What a generator or a chain does at a step depends on the lengths of
//! the messages: the time of a message does not depend on the octets or
//! the key of another.

use crate::common::context::{CipheringContext, IntegrityContext};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, octets_of};
use crate::common::keys::{CipheringKey, IntegrityKey};
use crate::common::nea::cipher_octets;
use crate::common::nia::{BitString, mac_of_bits};

/// A message to cipher or to decipher in a batch: its key, the COUNT, the
/// BEARER and the DIRECTION of the algorithm, its octets and its algorithm.
pub struct CipherJob<'a> {
    algorithm: CipheringAlgorithm,
    key: &'a [u8; 16],
    /// The context that the job comes from, if it comes from one.
    context: Option<&'a CipheringContext>,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    /// The octets that hold the bits of the message.
    data: &'a mut [u8],
    /// The bits of the last octet that are not of the message, as they
    /// were, and their place.
    retained: u8,
    unused: u8,
}

impl<'a> CipherJob<'a> {
    /// The message `data`, in whole octets, with what
    /// [`nea_cipher`](crate::nea_cipher) takes.
    pub fn new(
        key: &'a impl CipheringKey,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &'a mut [u8],
        algorithm: CipheringAlgorithm,
    ) -> Self {
        Self {
            algorithm,
            key: key.key_octets(),
            context: None,
            count,
            bearer,
            direction,
            data,
            retained: 0,
            unused: 0,
        }
    }

    /// The message `data`, in whole octets, with the key and the
    /// algorithm of a context.
    pub(crate) fn of_context(
        context: &'a CipheringContext,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &'a mut [u8],
    ) -> Self {
        Self {
            algorithm: context.algorithm(),
            key: context.key(),
            context: Some(context),
            count,
            bearer,
            direction,
            data,
            retained: 0,
            unused: 0,
        }
    }

    /// The first `bit_length` bits of `data`, with what
    /// [`nea_cipher_bits`](crate::nea_cipher_bits) takes. The unused
    /// low-order bits of the last octet stay as they are.
    ///
    /// A `bit_length` that `data` does not have is
    /// [`SecurityError::BitLengthExceedsData`].
    pub fn bits(
        key: &'a impl CipheringKey,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: &'a mut [u8],
        bit_length: u64,
        algorithm: CipheringAlgorithm,
    ) -> Result<Self, SecurityError> {
        Self::new(key, count, bearer, direction, data, algorithm).with_bits(bit_length)
    }

    /// The job of the first `bit_length` bits of its data.
    pub(crate) fn with_bits(mut self, bit_length: u64) -> Result<Self, SecurityError> {
        let octets = octets_of(bit_length, self.data.len())?;
        self.data = &mut self.data[..octets];
        let used = (bit_length % 8) as u32;
        self.unused = if used == 0 { 0 } else { 0xff >> used };
        self.retained = self.data.last().map_or(0, |last| last & self.unused);
        Ok(self)
    }

    /// The message through the function of one message.
    fn alone(&mut self) {
        let (count, bearer, direction) = (self.count, self.bearer, self.direction);
        match self.context {
            Some(context) => context.cipher_whole(count, bearer, direction, self.data),
            None => cipher_octets(
                self.key,
                count,
                bearer,
                direction,
                self.data,
                self.algorithm,
            ),
        }
    }

    /// Put back the bits of the last octet that are not of the message.
    fn restore(&mut self) {
        if let Some(last) = self.data.last_mut() {
            *last = (*last & !self.unused) | self.retained;
        }
    }
}

/// Cipher or decipher each message of `jobs` in place, which is one
/// operation. Each call ciphers every job once more.
pub fn nea_cipher_batch(jobs: &mut [CipherJob<'_>]) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let generators = lanes::cipher(jobs);
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let generators = false;

    for job in jobs {
        let done = match job.algorithm {
            CipheringAlgorithm::Null => true,
            CipheringAlgorithm::Snow3g | CipheringAlgorithm::Zuc => generators,
            // The counter blocks of a message are encrypted eight at a
            // time: there is nothing that a second message would add
            CipheringAlgorithm::Aes => false,
        };
        if !done {
            job.alone();
        }
        job.restore();
    }
}

/// A message whose MAC is computed in a batch: its key, the COUNT, the
/// BEARER and the DIRECTION of the algorithm, its octets and its algorithm.
pub struct MacJob<'a> {
    algorithm: IntegrityAlgorithm,
    key: &'a [u8; 16],
    /// The context that the job comes from, if it comes from one.
    context: Option<&'a IntegrityContext>,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'a>,
    mac: Option<u32>,
}

impl<'a> MacJob<'a> {
    /// The message `message`, in whole octets, with what
    /// [`nia_mac`](crate::nia_mac) takes.
    pub fn new(
        key: &'a impl IntegrityKey,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &'a [u8],
        algorithm: IntegrityAlgorithm,
    ) -> Self {
        Self {
            algorithm,
            key: key.key_octets(),
            context: None,
            count,
            bearer,
            direction,
            message: BitString::whole(message),
            mac: None,
        }
    }

    /// The first bits of a message with the key and the algorithm of a
    /// context.
    pub(crate) fn of_context(
        context: &'a IntegrityContext,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: BitString<'a>,
    ) -> Self {
        Self {
            algorithm: context.algorithm(),
            key: context.key(),
            context: Some(context),
            count,
            bearer,
            direction,
            message,
            mac: None,
        }
    }

    /// The first `bit_length` bits of `message`, with what
    /// [`nia_mac_bits`](crate::nia_mac_bits) takes.
    ///
    /// A `bit_length` that `message` does not have is
    /// [`SecurityError::BitLengthExceedsData`].
    pub fn bits(
        key: &'a impl IntegrityKey,
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &'a [u8],
        bit_length: u64,
        algorithm: IntegrityAlgorithm,
    ) -> Result<Self, SecurityError> {
        let mut job = Self::new(key, count, bearer, direction, message, algorithm);
        job.message = BitString::new(message, bit_length)?;
        Ok(job)
    }

    /// AES-CMAC with the key of the job, and its round keys on the AES
    /// instructions, when the job comes from a context that has them.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    fn keyed(&self) -> Option<crate::common::nia::CmacKey<'a>> {
        let cmac = self.context.and_then(IntegrityContext::cmac)?;
        Some(crate::common::nia::CmacKey::Keyed(cmac, cmac.schedule()?.1))
    }

    /// The MAC, once [`nia_mac_batch`] has computed it: `None` before.
    pub fn mac(&self) -> Option<u32> {
        self.mac
    }

    /// The MAC through the function of one message.
    fn alone(&mut self) {
        let (count, bearer, direction) = (self.count, self.bearer, self.direction);
        self.mac = Some(match self.context {
            Some(context) => context.mac_of(count, bearer, direction, self.message),
            None => mac_of_bits(
                self.key,
                count,
                bearer,
                direction,
                self.message,
                self.algorithm,
            ),
        });
    }
}

/// Compute the MAC of each message of `jobs`, which [`MacJob::mac`] then
/// returns.
pub fn nia_mac_batch(jobs: &mut [MacJob<'_>]) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    let (generators, aes) = (lanes::mac(jobs), lanes::mac_aes(jobs));
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    let (generators, aes) = (false, false);

    for job in jobs {
        let done = match job.algorithm {
            IntegrityAlgorithm::Null => false,
            IntegrityAlgorithm::Snow3g | IntegrityAlgorithm::Zuc => generators,
            IntegrityAlgorithm::Aes => aes,
        };
        if !done {
            job.alone();
        }
    }
}

/// The messages of a batch as the vector and the AES instructions take
/// them.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod lanes {
    use super::{CipherJob, MacJob};
    use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm};
    use crate::common::nea::{eea1_key_and_iv, eea3_iv};
    use crate::common::nia::{
        BitString, CmacBlocks, CmacKey, EIA1_WORDS, Eia3, cmac_lanes, cmac_lanes_keyed,
        eia1_evaluate, eia1_key_and_iv, eia3_iv,
    };
    use crate::common::simd::lanes::Stream;
    use crate::common::simd::{Instructions, snow3g_lanes, zuc_lanes};
    use crate::common::{snow3g, zuc};
    use zeroize::Zeroizing;

    /// How many messages of 128-EIA2 are taken together: the AES
    /// instructions of a processor run the rounds of as many blocks side
    /// by side.
    const AES_GROUP: usize = 8;

    /// The key of a place of a group that has no message.
    const NO_KEY: [u8; 16] = [0; 16];

    /// Compute the MACs of the messages of AES, eight at a time. `false`
    /// on a processor without the instructions, where nothing is done.
    pub(super) fn mac_aes(jobs: &mut [MacJob<'_>]) -> bool {
        let Some(instructions) = Instructions::detect() else {
            return false;
        };
        let mut jobs = jobs
            .iter_mut()
            .filter(|job| job.algorithm == IntegrityAlgorithm::Aes);
        loop {
            let mut group: [Option<&mut MacJob<'_>>; AES_GROUP] = [const { None }; AES_GROUP];
            let mut count = 0;
            for (place, job) in group.iter_mut().zip(&mut jobs) {
                *place = Some(job);
                count += 1;
            }
            // As many chains side by side as there are messages
            match count {
                0 => break,
                1 => mac_aes_group::<1>(instructions, &mut group),
                2 => mac_aes_group::<2>(instructions, &mut group),
                3 | 4 => mac_aes_group::<4>(instructions, &mut group),
                _ => mac_aes_group::<AES_GROUP>(instructions, &mut group),
            }
        }
        true
    }

    /// 128-EIA2 of the first `N` places of `group`.
    fn mac_aes_group<'j, const N: usize>(
        instructions: Instructions,
        group: &mut [Option<&mut MacJob<'j>>; AES_GROUP],
    ) {
        let job = |place: usize| group.get(place).and_then(|job| job.as_deref());
        let blocks: [CmacBlocks<'_>; N] = core::array::from_fn(|place| match job(place) {
            Some(job) => CmacBlocks::new(job.count, job.bearer, job.direction, job.message),
            None => CmacBlocks::new(0, Bearer::ZERO, Direction::Uplink, BitString::whole(&[])),
        });
        // The round keys and the subkeys of a context, or the octets of
        // the key
        let macs = if group.iter().flatten().any(|job| job.keyed().is_some()) {
            let key = |job: &MacJob<'j>| job.keyed().unwrap_or(CmacKey::Octets(job.key));
            let keys =
                core::array::from_fn(|place| job(place).map_or(CmacKey::Octets(&NO_KEY), key));
            cmac_lanes_keyed(instructions, keys, &blocks)
        } else {
            let keys = core::array::from_fn(|place| job(place).map_or(&NO_KEY, |job| job.key));
            cmac_lanes(instructions, keys, &blocks)
        };
        for (job, mac) in group.iter_mut().flatten().zip(macs) {
            job.mac = Some(mac);
        }
    }

    /// Cipher the messages of SNOW 3G and of ZUC. `false` on a processor
    /// without the instructions, where nothing is done.
    pub(super) fn cipher(jobs: &mut [CipherJob<'_>]) -> bool {
        let of = |algorithm| move |job: &&mut CipherJob<'_>| job.algorithm == algorithm;
        let count = |algorithm| jobs.iter().filter(|job| job.algorithm == algorithm).count();
        let (of_snow3g, of_zuc) = (
            count(CipheringAlgorithm::Snow3g),
            count(CipheringAlgorithm::Zuc),
        );
        let streams = jobs.iter_mut().filter(of(CipheringAlgorithm::Snow3g));
        if !snow3g_lanes(of_snow3g, streams.map(CipherStream::snow3g)) {
            return false;
        }
        let streams = jobs.iter_mut().filter(of(CipheringAlgorithm::Zuc));
        zuc_lanes(of_zuc, streams.map(CipherStream::zuc))
    }

    /// Compute the MACs of the messages of SNOW 3G and of ZUC. `false` on
    /// a processor without the instructions, where nothing is done.
    pub(super) fn mac(jobs: &mut [MacJob<'_>]) -> bool {
        let of = |algorithm| move |job: &&mut MacJob<'_>| job.algorithm == algorithm;
        let count = |algorithm| jobs.iter().filter(|job| job.algorithm == algorithm).count();
        let (of_snow3g, of_zuc) = (
            count(IntegrityAlgorithm::Snow3g),
            count(IntegrityAlgorithm::Zuc),
        );
        let streams = jobs.iter_mut().filter(of(IntegrityAlgorithm::Snow3g));
        if !snow3g_lanes(of_snow3g, streams.map(Eia1Stream::new)) {
            return false;
        }
        let streams = jobs.iter_mut().filter(of(IntegrityAlgorithm::Zuc));
        zuc_lanes(of_zuc, streams.map(Eia3Stream::new))
    }

    /// A message that its keystream ciphers.
    struct CipherStream<'j, 'a> {
        job: &'j mut CipherJob<'a>,
        stages: Zeroizing<[u32; 16]>,
        /// The octets that are ciphered.
        done: usize,
    }

    impl<'j, 'a> CipherStream<'j, 'a> {
        fn snow3g(job: &'j mut CipherJob<'a>) -> Self {
            let (k, iv) = eea1_key_and_iv(job.key, job.count, job.bearer, job.direction);
            Self {
                stages: Zeroizing::new(snow3g::load(&k, &iv)),
                job,
                done: 0,
            }
        }

        fn zuc(job: &'j mut CipherJob<'a>) -> Self {
            let iv = eea3_iv(job.count, job.bearer, job.direction);
            Self {
                stages: Zeroizing::new(zuc::load(job.key, &iv)),
                job,
                done: 0,
            }
        }
    }

    impl Stream for CipherStream<'_, '_> {
        fn stages(&self) -> [u32; 16] {
            *self.stages
        }

        fn words(&self) -> usize {
            self.job.data.len().div_ceil(4)
        }

        fn take(&mut self, words: &[u32]) {
            let data = &mut self.job.data[self.done..];
            let (whole, rest) = data.as_chunks_mut::<4>();
            for (octets, word) in whole.iter_mut().zip(words) {
                *octets = (u32::from_be_bytes(*octets) ^ word).to_be_bytes();
            }
            // The last word, of a message that does not end with a word
            if let Some(word) = words.get(whole.len()) {
                for (octet, key_octet) in rest.iter_mut().zip(word.to_be_bytes()) {
                    *octet ^= key_octet;
                }
            }
            self.done += (4 * words.len()).min(data.len());
        }

        fn alone(self) {
            self.job.alone();
        }
    }

    /// A message of 128-EIA1, whose MAC takes five keystream words.
    struct Eia1Stream<'j, 'a> {
        job: &'j mut MacJob<'a>,
        stages: Zeroizing<[u32; 16]>,
        words: Zeroizing<[u32; EIA1_WORDS]>,
        taken: usize,
    }

    impl<'j, 'a> Eia1Stream<'j, 'a> {
        fn new(job: &'j mut MacJob<'a>) -> Self {
            let (k, iv) = eia1_key_and_iv(job.key, job.count, job.bearer, job.direction);
            Self {
                stages: Zeroizing::new(snow3g::load(&k, &iv)),
                job,
                words: Zeroizing::new([0; EIA1_WORDS]),
                taken: 0,
            }
        }
    }

    impl Stream for Eia1Stream<'_, '_> {
        fn stages(&self) -> [u32; 16] {
            *self.stages
        }

        fn words(&self) -> usize {
            EIA1_WORDS
        }

        fn take(&mut self, words: &[u32]) {
            self.words[self.taken..self.taken + words.len()].copy_from_slice(words);
            self.taken += words.len();
            if self.taken == EIA1_WORDS {
                self.job.mac = Some(eia1_evaluate(&self.words, self.job.message));
            }
        }

        fn alone(self) {
            self.job.alone();
        }
    }

    /// A message of 128-EIA3, whose MAC takes its keystream as it comes.
    struct Eia3Stream<'j, 'a> {
        job: &'j mut MacJob<'a>,
        stages: Zeroizing<[u32; 16]>,
        mac: Eia3<'a>,
        left: usize,
    }

    impl<'j, 'a> Eia3Stream<'j, 'a> {
        fn new(job: &'j mut MacJob<'a>) -> Self {
            let iv = eia3_iv(job.count, job.bearer, job.direction);
            let mac = Eia3::new(job.message);
            Self {
                stages: Zeroizing::new(zuc::load(job.key, &iv)),
                left: mac.words(),
                mac,
                job,
            }
        }
    }

    impl Stream for Eia3Stream<'_, '_> {
        fn stages(&self) -> [u32; 16] {
            *self.stages
        }

        fn words(&self) -> usize {
            self.mac.words()
        }

        fn take(&mut self, words: &[u32]) {
            self.mac.take(words);
            self.left -= words.len();
            if self.left == 0 {
                self.job.mac = Some(self.mac.mac());
            }
        }

        fn alone(self) {
            self.job.alone();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::nea::{nea_cipher, nea_cipher_bits};
    use crate::common::nia::nia_mac_bits;
    use crate::{nas_5gs, nas_eps};

    /// Numbers that look random, the same at every run.
    fn random(seed: u64) -> impl FnMut() -> u64 {
        let mut state = seed;
        move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        }
    }

    /// A message of a batch, and what the functions of one message take.
    struct Message {
        key: [u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        data: Vec<u8>,
        /// The length in bits, for a message that is not whole octets.
        bits: Option<u64>,
        algorithm: u8,
    }

    /// The lengths that matter to generators that give four octets at a
    /// time, to blocks of eight and of sixteen octets, and to the clocks
    /// that are run together.
    const LENGTHS: [usize; 24] = [
        0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 24, 31, 32, 33, 63, 64, 65, 127, 128, 129, 300, 1500,
    ];

    fn messages(next: &mut impl FnMut() -> u64, count: usize) -> Vec<Message> {
        (0..count)
            .map(|_| {
                let length = LENGTHS[next() as usize % LENGTHS.len()];
                let bits = next()
                    .is_multiple_of(3)
                    .then(|| next() % (8 * length as u64 + 1));
                Message {
                    key: core::array::from_fn(|_| next() as u8),
                    count: next() as u32,
                    bearer: Bearer::new((next() % 32) as u8).unwrap(),
                    direction: Direction::try_from((next() % 2) as u8).unwrap(),
                    data: (0..length).map(|_| next() as u8).collect(),
                    bits,
                    algorithm: (next() % 4) as u8,
                }
            })
            .collect()
    }

    /// Batches of no message, of one, of fewer than the generators that
    /// run side by side, of as many and of more, with the algorithms and
    /// the lengths mixed.
    const BATCHES: [usize; 14] = [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 33, 40];

    /// Run `test` with all that the processor has, then with its vectors
    /// of 128 bits alone, then without vector instructions.
    fn on_every_path(test: impl Fn()) {
        test();
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            crate::common::simd::narrow(&test);
            crate::common::simd::scalar(&test);
        }
    }

    #[test]
    fn a_batch_ciphers_each_message_as_the_function_of_one_message_does() {
        on_every_path(ciphers_as_one_message);
    }

    fn ciphers_as_one_message() {
        let mut next = random(0x243f_6a88_85a3_08d3);
        for round in 0..40 {
            for size in BATCHES {
                let mut messages = messages(&mut next, size);
                let expected: Vec<Vec<u8>> = messages
                    .iter()
                    .map(|message| {
                        let algorithm = CipheringAlgorithm::try_from(message.algorithm).unwrap();
                        let mut data = message.data.clone();
                        let (key, count) = (&message.key, message.count);
                        let (bearer, direction) = (message.bearer, message.direction);
                        match message.bits {
                            Some(bits) => {
                                nea_cipher_bits(
                                    key, count, bearer, direction, &mut data, bits, algorithm,
                                )
                                .unwrap();
                            }
                            None => nea_cipher(key, count, bearer, direction, &mut data, algorithm),
                        }
                        data
                    })
                    .collect();

                let mut jobs: Vec<CipherJob<'_>> = messages
                    .iter_mut()
                    .map(|message| {
                        let algorithm = CipheringAlgorithm::try_from(message.algorithm).unwrap();
                        let (key, count) = (&message.key, message.count);
                        let (bearer, direction) = (message.bearer, message.direction);
                        let data = &mut message.data[..];
                        match message.bits {
                            Some(bits) => CipherJob::bits(
                                key, count, bearer, direction, data, bits, algorithm,
                            )
                            .unwrap(),
                            None => CipherJob::new(key, count, bearer, direction, data, algorithm),
                        }
                    })
                    .collect();
                nea_cipher_batch(&mut jobs);
                for (index, (message, expected)) in messages.iter().zip(&expected).enumerate() {
                    assert_eq!(
                        &message.data,
                        expected,
                        "round {round}, message {index} of {size}: algorithm {}, {} octets, {:?} bits",
                        message.algorithm,
                        expected.len(),
                        message.bits
                    );
                }
            }
        }
    }

    #[test]
    fn a_batch_gives_each_message_the_mac_of_the_function_of_one_message() {
        on_every_path(macs_as_one_message);
    }

    fn macs_as_one_message() {
        let mut next = random(0x1319_8a2e_0370_7344);
        for round in 0..40 {
            for size in BATCHES {
                let messages = messages(&mut next, size);
                let mut jobs: Vec<MacJob<'_>> = messages
                    .iter()
                    .map(|message| {
                        let algorithm = IntegrityAlgorithm::try_from(message.algorithm).unwrap();
                        let (key, count) = (&message.key, message.count);
                        let (bearer, direction) = (message.bearer, message.direction);
                        match message.bits {
                            Some(bits) => MacJob::bits(
                                key,
                                count,
                                bearer,
                                direction,
                                &message.data,
                                bits,
                                algorithm,
                            )
                            .unwrap(),
                            None => {
                                MacJob::new(key, count, bearer, direction, &message.data, algorithm)
                            }
                        }
                    })
                    .collect();
                assert!(jobs.iter().all(|job| job.mac().is_none()));
                nia_mac_batch(&mut jobs);
                for (index, (message, job)) in messages.iter().zip(&jobs).enumerate() {
                    let algorithm = IntegrityAlgorithm::try_from(message.algorithm).unwrap();
                    let bits = message.bits.unwrap_or(8 * message.data.len() as u64);
                    let expected = nia_mac_bits(
                        &message.key,
                        message.count,
                        message.bearer,
                        message.direction,
                        &message.data,
                        bits,
                        algorithm,
                    )
                    .unwrap();
                    assert_eq!(
                        job.mac(),
                        Some(expected),
                        "round {round}, message {index} of {size}: algorithm {}, {} octets, {:?} bits",
                        message.algorithm,
                        message.data.len(),
                        message.bits
                    );
                }
            }
        }
    }

    /// Messages of one length and one algorithm, which keep the four
    /// generators at work together from the first clock to the last.
    #[test]
    fn a_batch_of_equal_messages_is_the_messages_one_by_one() {
        on_every_path(equal_messages_one_by_one);
    }

    fn equal_messages_one_by_one() {
        let mut next = random(0xa409_3822_299f_31d0);
        for algorithm in 1..=3 {
            for length in [1, 4, 64, 65, 1500] {
                for size in [2, 4, 5, 8, 13, 16, 19] {
                    let mut messages = messages(&mut next, size);
                    for message in &mut messages {
                        message.data = (0..length).map(|_| next() as u8).collect();
                    }
                    let cipher = CipheringAlgorithm::try_from(algorithm).unwrap();
                    let integrity = IntegrityAlgorithm::try_from(algorithm).unwrap();

                    let mut macs: Vec<MacJob<'_>> = messages
                        .iter()
                        .map(|m| {
                            MacJob::new(&m.key, m.count, m.bearer, m.direction, &m.data, integrity)
                        })
                        .collect();
                    nia_mac_batch(&mut macs);
                    for (message, job) in messages.iter().zip(&macs) {
                        let (key, count) = (&message.key, message.count);
                        let (bearer, direction) = (message.bearer, message.direction);
                        let expected =
                            crate::nia_mac(key, count, bearer, direction, &message.data, integrity);
                        assert_eq!(job.mac(), Some(expected), "{integrity:?}, {length} octets");
                    }
                    drop(macs);

                    let mut ciphered: Vec<Vec<u8>> = messages
                        .iter()
                        .map(|message| message.data.clone())
                        .collect();
                    let mut jobs: Vec<CipherJob<'_>> = messages
                        .iter()
                        .zip(&mut ciphered)
                        .map(|(m, data)| {
                            CipherJob::new(&m.key, m.count, m.bearer, m.direction, data, cipher)
                        })
                        .collect();
                    nea_cipher_batch(&mut jobs);
                    // A second call deciphers
                    nea_cipher_batch(&mut jobs);
                    assert!(
                        messages
                            .iter()
                            .zip(&ciphered)
                            .all(|(m, data)| m.data == *data)
                    );
                }
            }
        }
    }

    /// Eight generators side by side, four, and the scalar code, where
    /// the batch functions call those of one message, give the same.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    #[test]
    fn a_batch_is_the_same_on_every_path() {
        use crate::common::simd::{narrow, scalar};
        let mut next = random(0x082e_fa98_ec4e_6c89);
        for size in BATCHES.into_iter().cycle().take(20 * BATCHES.len()) {
            let messages = messages(&mut next, size);
            let run = || {
                let mut data: Vec<Vec<u8>> = messages.iter().map(|m| m.data.clone()).collect();
                let mut ciphers: Vec<CipherJob<'_>> = messages
                    .iter()
                    .zip(&mut data)
                    .map(|(m, data)| {
                        let algorithm = CipheringAlgorithm::try_from(m.algorithm).unwrap();
                        CipherJob::new(&m.key, m.count, m.bearer, m.direction, data, algorithm)
                    })
                    .collect();
                nea_cipher_batch(&mut ciphers);
                drop(ciphers);
                let mut macs: Vec<MacJob<'_>> = messages
                    .iter()
                    .map(|m| {
                        let algorithm = IntegrityAlgorithm::try_from(m.algorithm).unwrap();
                        MacJob::new(&m.key, m.count, m.bearer, m.direction, &m.data, algorithm)
                    })
                    .collect();
                nia_mac_batch(&mut macs);
                let macs: Vec<Option<u32>> = macs.iter().map(MacJob::mac).collect();
                (data, macs)
            };
            let expected = scalar(run);
            assert_eq!(narrow(run), expected, "{size} messages, four generators");
            assert_eq!(run(), expected, "{size} messages");
        }
    }

    #[test]
    fn a_length_in_bits_that_the_message_does_not_have_is_refused() {
        let key = [0; 16];
        let (bearer, uplink) = (Bearer::ZERO, Direction::Uplink);
        let mut data = [0u8; 2];
        let cipher = CipheringAlgorithm::Snow3g;
        assert!(CipherJob::bits(&key, 0, bearer, uplink, &mut data, 16, cipher).is_ok());
        assert_eq!(
            CipherJob::bits(&key, 0, bearer, uplink, &mut data, 17, cipher).err(),
            Some(SecurityError::BitLengthExceedsData {
                bits: 17,
                octets: 2
            })
        );
        let integrity = IntegrityAlgorithm::Zuc;
        assert!(MacJob::bits(&key, 0, bearer, uplink, &data, 16, integrity).is_ok());
        assert_eq!(
            MacJob::bits(&key, 0, bearer, uplink, &data, 17, integrity).err(),
            Some(SecurityError::BitLengthExceedsData {
                bits: 17,
                octets: 2
            })
        );
    }

    /// The jobs of NAS messages are those of the NAS COUNT, of the NAS
    /// connection in 5GS and of BEARER 0 in EPS.
    #[test]
    fn the_jobs_of_nas_messages_give_what_the_nas_functions_give() {
        let count = crate::NasCount::new(0x01_0203).unwrap();
        let uplink = Direction::Uplink;
        for algorithm in 0..=3 {
            let cipher = CipheringAlgorithm::try_from(algorithm).unwrap();
            let integrity = IntegrityAlgorithm::try_from(algorithm).unwrap();
            let enc = nas_5gs::KNasEnc::new([0x11; 16]);
            let int = nas_5gs::KNasInt::new([0x22; 16]);
            for connection in [
                nas_5gs::NasConnection::ThreeGpp,
                nas_5gs::NasConnection::Non3Gpp,
            ] {
                let mut expected = *b"a 5GS NAS message";
                nas_5gs::nas_cipher(&enc, count, connection, uplink, &mut expected, cipher);
                let mac = nas_5gs::nas_mac(&int, count, connection, uplink, &expected, integrity);

                let mut data = [*b"a 5GS NAS message"; 5];
                let mut jobs: Vec<_> = data
                    .iter_mut()
                    .map(|data| nas_5gs::cipher_job(&enc, count, connection, uplink, data, cipher))
                    .collect();
                nea_cipher_batch(&mut jobs);
                assert_eq!(data, [expected; 5]);
                let mut jobs: Vec<_> = data
                    .iter()
                    .map(|data| nas_5gs::mac_job(&int, count, connection, uplink, data, integrity))
                    .collect();
                nia_mac_batch(&mut jobs);
                assert!(jobs.iter().all(|job| job.mac() == Some(mac)));
            }

            let enc = nas_eps::KNasEnc::new([0x11; 16]);
            let int = nas_eps::KNasInt::new([0x22; 16]);
            let mut expected = *b"an EPS NAS message";
            nas_eps::nas_cipher(&enc, count, uplink, &mut expected, cipher);
            let mac = nas_eps::nas_mac(&int, count, uplink, &expected, integrity);
            let mut data = [*b"an EPS NAS message"; 5];
            let mut jobs: Vec<_> = data
                .iter_mut()
                .map(|data| nas_eps::cipher_job(&enc, count, uplink, data, cipher))
                .collect();
            nea_cipher_batch(&mut jobs);
            assert_eq!(data, [expected; 5]);
            let mut jobs: Vec<_> = data
                .iter()
                .map(|data| nas_eps::mac_job(&int, count, uplink, data, integrity))
                .collect();
            nia_mac_batch(&mut jobs);
            assert!(jobs.iter().all(|job| job.mac() == Some(mac)));
        }
    }
}
