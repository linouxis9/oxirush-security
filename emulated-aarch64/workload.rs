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

//! What the emulated AArch64 program and its host both compute, through
//! the public functions of the crate and without an allocator: each case
//! gives a number, the digest of all that it computed.
//!
//! The cases reach every function of the vector code: the SNOW 3G and ZUC
//! generators of one message and of four, the key expansion of AES, its
//! counter mode and its CBC-MAC for one message and for several, with the
//! key of each message or with the round keys of a context, and the
//! carry-less products of 128-EIA1 and 128-EIA3.

use oxirush_security::nas_5gs::{KNasEnc, KNasInt};
use oxirush_security::{
    Bearer, CipherJob, CipheringAlgorithm, CipheringContext, Direction, Implementation,
    IntegrityAlgorithm, IntegrityContext, MacJob, Snow3G, Zuc, implementation, nea_cipher,
    nea_cipher_batch, nea_cipher_bits, nia_mac, nia_mac_batch, nia_mac_bits,
};

/// The cases, by their names.
pub const CASES: [&str; 8] = [
    "the implementation that runs",
    "known answers of the six algorithms (3GPP test sets)",
    "SNOW 3G keystream, 200 keys",
    "ZUC keystream, 200 keys",
    "128-EEA1, 128-EEA2 and 128-EEA3 at 170 lengths, in octets and in bits",
    "128-EIA1, 128-EIA2 and 128-EIA3 at 170 lengths, in octets and in bits",
    "batches of 1 to 9 messages of mixed algorithms and lengths",
    "keyed contexts at 170 lengths, alone and in batches",
];

/// What case 0 gives for each implementation.
pub const fn number_of(implementation: Implementation) -> u64 {
    match implementation {
        Implementation::Scalar => 1,
        Implementation::Vector128 => 2,
        Implementation::Vector256 => 3,
        _ => 0,
    }
}

/// The number of case `case`. Case 1 gives zero when every answer is the
/// known one, and otherwise the number of the first that is not.
pub fn run(case: u64) -> u64 {
    match case {
        0 => number_of(implementation()),
        1 => known_answers(),
        2 => snow3g_keystream(),
        3 => zuc_keystream(),
        4 => ciphers(),
        5 => macs(),
        6 => batches(),
        7 => contexts(),
        _ => 0,
    }
}

/// Numbers that look random, the same at every run.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn octets<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.next() as u8)
    }

    fn bearer(&mut self) -> Bearer {
        Bearer::new((self.next() % 32) as u8).unwrap_or(Bearer::ZERO)
    }

    fn direction(&mut self) -> Direction {
        match self.next() % 2 {
            0 => Direction::Uplink,
            _ => Direction::Downlink,
        }
    }
}

/// A digest of octets (FNV-1a, 64 bits).
struct Digest(u64);

impl Digest {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }

    fn octets(&mut self, octets: &[u8]) {
        for octet in octets {
            self.0 = (self.0 ^ u64::from(*octet)).wrapping_mul(0x0000_0100_0000_01b3);
        }
    }

    fn word(&mut self, word: u32) {
        self.octets(&word.to_be_bytes());
    }
}

const CIPHERING: [CipheringAlgorithm; 3] = [
    CipheringAlgorithm::Snow3g,
    CipheringAlgorithm::Aes,
    CipheringAlgorithm::Zuc,
];
const INTEGRITY: [IntegrityAlgorithm; 3] = [
    IntegrityAlgorithm::Snow3g,
    IntegrityAlgorithm::Aes,
    IntegrityAlgorithm::Zuc,
];

/// The lengths of the messages: every one up to 160 octets, and some
/// around the sizes of the blocks and of a packet.
fn lengths() -> impl Iterator<Item = usize> {
    (0..=160).chain([255, 256, 257, 511, 512, 513, 1023, 1500, 2999])
}

const LONGEST: usize = 2999;

fn snow3g_keystream() -> u64 {
    let (mut random, mut digest) = (Random(0x9e37_79b9_7f4a_7c15), Digest::new());
    for _ in 0..200 {
        let (key, iv): ([u8; 16], [u8; 16]) = (random.octets(), random.octets());
        let mut generator = Snow3G::from_bytes(&key, &iv);
        // In pieces of every length, so that words are left over
        for _ in 0..12 {
            let mut words = [0u32; 9];
            let piece = &mut words[..(random.next() % 10) as usize];
            generator.fill(piece);
            piece.iter().for_each(|word| digest.word(*word));
            digest.word(generator.next_word());
        }
    }
    digest.0
}

fn zuc_keystream() -> u64 {
    let (mut random, mut digest) = (Random(0xd1b5_4a32_d192_ed03), Digest::new());
    for _ in 0..200 {
        let (key, iv): ([u8; 16], [u8; 16]) = (random.octets(), random.octets());
        let mut generator = Zuc::new(&key, &iv);
        for _ in 0..12 {
            let mut words = [0u32; 9];
            let piece = &mut words[..(random.next() % 10) as usize];
            generator.fill(piece);
            piece.iter().for_each(|word| digest.word(*word));
            digest.word(generator.next_word());
        }
    }
    digest.0
}

fn ciphers() -> u64 {
    let (mut random, mut digest) = (Random(0x2545_f491_4f6c_dd1d), Digest::new());
    for length in lengths() {
        let key = KNasEnc::new(random.octets());
        let (count, bearer, direction) =
            (random.next() as u32, random.bearer(), random.direction());
        let message: [u8; LONGEST] = random.octets();
        let bits = (8 * length as u64).saturating_sub(random.next() % 8);
        for algorithm in CIPHERING {
            let mut data = message;
            nea_cipher(
                &key,
                count,
                bearer,
                direction,
                &mut data[..length],
                algorithm,
            );
            digest.octets(&data[..length]);

            let mut data = message;
            let ciphered = &mut data[..length];
            if nea_cipher_bits(&key, count, bearer, direction, ciphered, bits, algorithm).is_err() {
                return u64::MAX;
            }
            digest.octets(&data[..length]);
        }
    }
    digest.0
}

fn macs() -> u64 {
    let (mut random, mut digest) = (Random(0x6a09_e667_f3bc_c908), Digest::new());
    for length in lengths() {
        let key = KNasInt::new(random.octets());
        let (count, bearer, direction) =
            (random.next() as u32, random.bearer(), random.direction());
        let message: [u8; LONGEST] = random.octets();
        let message = &message[..length];
        let bits = (8 * length as u64).saturating_sub(random.next() % 8);
        for algorithm in INTEGRITY {
            digest.word(nia_mac(&key, count, bearer, direction, message, algorithm));
            match nia_mac_bits(&key, count, bearer, direction, message, bits, algorithm) {
                Ok(mac) => digest.word(mac),
                Err(_) => return u64::MAX,
            }
        }
    }
    digest.0
}

/// The most messages of a batch, and the longest of them.
const BATCH: usize = 9;
const IN_BATCH: usize = 300;

fn batches() -> u64 {
    batches_of(0x510e_527f_ade6_82d1, false)
}

/// The messages of each length through a keyed context, then the batches
/// with a context for every other message: the digests are those of the
/// functions that take a key, which the host compares too.
fn contexts() -> u64 {
    let (mut random, mut digest) = (Random(0xbb67_ae85_84ca_a73b), Digest::new());
    for length in lengths() {
        let key: [u8; 16] = random.octets();
        let (count, bearer, direction) =
            (random.next() as u32, random.bearer(), random.direction());
        let message: [u8; LONGEST] = random.octets();
        let bits = (8 * length as u64).saturating_sub(random.next() % 8);
        for (ciphering, integrity) in CIPHERING.into_iter().zip(INTEGRITY) {
            let context = IntegrityContext::new(&KNasInt::new(key), integrity);
            let mac = context.mac(count, bearer, direction, &message[..length]);
            digest.word(mac);
            match context.mac_bits(count, bearer, direction, &message[..length], bits) {
                Ok(mac) => digest.word(mac),
                Err(_) => return u64::MAX,
            }
            // The functions that take the key give the same
            let key = KNasInt::new(key);
            if nia_mac(
                &key,
                count,
                bearer,
                direction,
                &message[..length],
                integrity,
            ) != mac
            {
                return u64::MAX - 1;
            }

            let enc = KNasEnc::new(*key.as_octets());
            let context = CipheringContext::new(&enc, ciphering);
            let mut data = message;
            context.cipher(count, bearer, direction, &mut data[..length]);
            digest.octets(&data[..length]);
            let mut expected = message;
            nea_cipher(
                &enc,
                count,
                bearer,
                direction,
                &mut expected[..length],
                ciphering,
            );
            if data[..length] != expected[..length] {
                return u64::MAX - 2;
            }
            let mut data = message;
            let ciphered = &mut data[..length];
            if context
                .cipher_bits(count, bearer, direction, ciphered, bits)
                .is_err()
            {
                return u64::MAX;
            }
            digest.octets(&data[..length]);
        }
    }
    digest.octets(&batches_of(0x3c6e_f372_fe94_f82b, true).to_be_bytes());
    // Without the contexts, the batches of the same messages give the same
    if batches_of(0x3c6e_f372_fe94_f82b, true) != batches_of(0x3c6e_f372_fe94_f82b, false) {
        return u64::MAX - 3;
    }
    digest.0
}

/// Batches of messages that `seed` gives. With `keyed`, every other
/// message comes from a keyed context.
fn batches_of(seed: u64, keyed: bool) -> u64 {
    let (mut random, mut digest) = (Random(seed), Digest::new());
    for round in 0..60 {
        let size = 1 + round % BATCH;
        let keys: [[u8; 16]; BATCH] = core::array::from_fn(|_| random.octets());
        let counts: [u32; BATCH] = core::array::from_fn(|_| random.next() as u32);
        let bearers: [Bearer; BATCH] = core::array::from_fn(|_| random.bearer());
        let directions: [Direction; BATCH] = core::array::from_fn(|_| random.direction());
        // One algorithm for all in two rounds of three, so that four
        // generators or eight chains are at work together
        let algorithms: [usize; BATCH] = core::array::from_fn(|_| match round % 3 {
            0 => (random.next() % 3) as usize,
            _ => round / 3 % 3,
        });
        let lengths: [usize; BATCH] =
            core::array::from_fn(|_| (random.next() % (IN_BATCH as u64 + 1)) as usize);
        let mut data: [[u8; IN_BATCH]; BATCH] = core::array::from_fn(|_| random.octets());
        let of_context = |index: usize| keyed && index % 2 == 1;

        let integrity_keys = keys.map(KNasInt::new);
        let integrity_contexts: [IntegrityContext; BATCH] = core::array::from_fn(|index| {
            IntegrityContext::new(&integrity_keys[index], INTEGRITY[algorithms[index]])
        });
        let mut messages = data.iter().zip(lengths).enumerate();
        let mut jobs: [MacJob<'_>; BATCH] = core::array::from_fn(|_| {
            let (index, (data, length)) = messages.next().unwrap_or((0, (&data[0], 0)));
            let (key, algorithm) = (&integrity_keys[index], INTEGRITY[algorithms[index]]);
            let (count, bearer, direction) = (counts[index], bearers[index], directions[index]);
            match of_context(index) {
                true => integrity_contexts[index].job(count, bearer, direction, &data[..length]),
                false => MacJob::new(key, count, bearer, direction, &data[..length], algorithm),
            }
        });
        nia_mac_batch(&mut jobs[..size]);
        for job in &jobs[..size] {
            digest.word(job.mac().unwrap_or(0));
        }

        let ciphering_keys = keys.map(KNasEnc::new);
        let ciphering_contexts: [CipheringContext; BATCH] = core::array::from_fn(|index| {
            CipheringContext::new(&ciphering_keys[index], CIPHERING[algorithms[index]])
        });
        let mut messages = data.iter_mut().zip(lengths).enumerate();
        let mut jobs: [Option<CipherJob<'_>>; BATCH] = core::array::from_fn(|_| {
            let (index, (data, length)) = messages.next()?;
            let (key, algorithm) = (&ciphering_keys[index], CIPHERING[algorithms[index]]);
            let (count, bearer, direction) = (counts[index], bearers[index], directions[index]);
            let data = &mut data[..length];
            Some(match of_context(index) {
                true => ciphering_contexts[index].job(count, bearer, direction, data),
                false => CipherJob::new(key, count, bearer, direction, data, algorithm),
            })
        });
        // The jobs of the batch, side by side in one slice
        let mut batch: [CipherJob<'_>; BATCH] = jobs.each_mut().map(|job| match job.take() {
            Some(job) => job,
            None => CipherJob::new(
                &ciphering_keys[0],
                0,
                Bearer::ZERO,
                Direction::Uplink,
                &mut [],
                CIPHERING[0],
            ),
        });
        nea_cipher_batch(&mut batch[..size]);
        for (data, length) in data.iter().zip(lengths).take(size) {
            digest.octets(&data[..length]);
        }
    }
    digest.0
}

/// A test set of a ciphering algorithm: the key, COUNT, BEARER, DIRECTION,
/// the length in bits, the plaintext and the ciphertext.
type CipherSet = (
    CipheringAlgorithm,
    [u8; 16],
    u32,
    u8,
    Direction,
    u64,
    &'static [u8],
    &'static [u8],
);

/// A test set of an integrity algorithm, with the message and the MAC.
type MacSet = (
    IntegrityAlgorithm,
    [u8; 16],
    u32,
    u8,
    Direction,
    u64,
    &'static [u8],
    u32,
);

/// 128-EEA1 test set 1 and 128-EEA2 test set 1 of TS 33.401 Annex C.1, and
/// 128-EEA3 test set 1 of the ZUC test data.
const CIPHER_SETS: [CipherSet; 3] = [
    (
        CipheringAlgorithm::Snow3g,
        [
            0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81,
            0xff, 0x48,
        ],
        0x72a4_f20f,
        0x0c,
        Direction::Downlink,
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
    ),
    (
        CipheringAlgorithm::Aes,
        [
            0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8,
            0xc6, 0xd1,
        ],
        0x398a_59b4,
        0x15,
        Direction::Downlink,
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
    ),
    (
        CipheringAlgorithm::Zuc,
        [
            0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0,
            0x0a, 0x29,
        ],
        0x6603_5492,
        0x0f,
        Direction::Uplink,
        193,
        &[
            0x6c, 0xf6, 0x53, 0x40, 0x73, 0x55, 0x52, 0xab, 0x0c, 0x97, 0x52, 0xfa, 0x6f, 0x90,
            0x25, 0xfe, 0x0b, 0xd6, 0x75, 0xd9, 0x00, 0x58, 0x75, 0xb2, 0x00,
        ],
        &[
            0xa6, 0xc8, 0x5f, 0xc6, 0x6a, 0xfb, 0x85, 0x33, 0xaa, 0xfc, 0x25, 0x18, 0xdf, 0xe7,
            0x84, 0x94, 0x0e, 0xe1, 0xe4, 0xb0, 0x30, 0x23, 0x8c, 0xc8, 0x00,
        ],
    ),
];

/// 128-EIA1 test set 1 and 128-EIA2 test set 2 of TS 33.401 Annex C.2, and
/// 128-EIA3 test set 2 of the ZUC test data.
const MAC_SETS: [MacSet; 3] = [
    (
        IntegrityAlgorithm::Snow3g,
        [
            0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81,
            0xff, 0x48,
        ],
        0x38a6_f056,
        0x1f,
        Direction::Uplink,
        88,
        &[
            0x33, 0x32, 0x34, 0x62, 0x63, 0x39, 0x38, 0x61, 0x37, 0x34, 0x79,
        ],
        0x731f_1165,
    ),
    (
        IntegrityAlgorithm::Aes,
        [
            0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8,
            0xc6, 0xd1,
        ],
        0x398a_59b4,
        0x1a,
        Direction::Downlink,
        64,
        &[0x48, 0x45, 0x83, 0xd5, 0xaf, 0xe0, 0x82, 0xae],
        0xb937_87e6,
    ),
    (
        IntegrityAlgorithm::Zuc,
        [
            0x47, 0x05, 0x41, 0x25, 0x56, 0x1e, 0xb2, 0xdd, 0xa9, 0x40, 0x59, 0xda, 0x05, 0x09,
            0x78, 0x50,
        ],
        0x561e_b2dd,
        0x14,
        Direction::Uplink,
        90,
        &[0; 12],
        0x6719_a088,
    ),
];

fn known_answers() -> u64 {
    let mut number = 0;
    for (algorithm, key, count, bearer, direction, bits, plaintext, ciphertext) in CIPHER_SETS {
        number += 1;
        let Ok(bearer) = Bearer::new(bearer) else {
            return number;
        };
        let mut data = [0u8; 100];
        let data = &mut data[..plaintext.len()];
        data.copy_from_slice(plaintext);
        let key = KNasEnc::new(key);
        let ciphered = nea_cipher_bits(&key, count, bearer, direction, data, bits, algorithm);
        if ciphered.is_err() || data != ciphertext {
            return number;
        }
    }
    for (algorithm, key, count, bearer, direction, bits, message, mac) in MAC_SETS {
        number += 1;
        let Ok(bearer) = Bearer::new(bearer) else {
            return number;
        };
        let key = KNasInt::new(key);
        if nia_mac_bits(&key, count, bearer, direction, message, bits, algorithm) != Ok(mac) {
            return number;
        }
    }
    0
}
