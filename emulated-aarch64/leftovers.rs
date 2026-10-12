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

//! The operations whose leftovers the host looks for on the emulated
//! AArch64 processor: what each of them leaves on the stack and in the
//! registers when it has returned.
//!
//! The guest program prepares an operation in one call and runs it in the
//! next, so that the host paints the stack between the two. What an
//! operation takes lives in the memory of the program and not on its
//! stack: the keys are statics, and the contexts, the generators and the
//! messages are in a [`Prepared`] that the guest keeps.

use core::mem::ManuallyDrop;
use oxirush_security::nas_5gs::{KAmf, KNasEnc, KNasInt, derive_knas_int};
use oxirush_security::{
    Bearer, CipherJob, CipheringAlgorithm, CipheringContext, Direction, IntegrityAlgorithm,
    IntegrityContext, MacJob, Snow3G, Zuc, constant_time_eq, nea_cipher, nea_cipher_batch, nia_mac,
    nia_mac_batch,
};

/// The key of the examples of FIPS 197, whose round keys are known.
pub const KEY: [u8; 16] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
];
pub const IV: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
pub const COUNT: u32 = 0x1234;
pub const BEARER: u8 = 1;
/// What a message has before it is ciphered: not zeros, which would make
/// of the ciphered message the keystream that the host looks for.
pub const PLAIN: u8 = 0x5a;
/// The messages of a batch, and the longest message.
pub const MESSAGES: usize = 9;
pub const LONGEST: usize = 1500;

/// The key of message `index` of a batch.
pub const fn key_of(index: usize) -> [u8; 16] {
    let mut key = KEY;
    key[0] ^= index as u8;
    key[15] ^= (index as u8) << 4;
    key
}

/// KAMF, from which a NAS key is derived.
pub const KAMF: [u8; 32] = {
    let mut key = [0u8; 32];
    let mut at = 0;
    while at < 32 {
        key[at] = 0x33 ^ (at as u8).wrapping_mul(7);
        at += 1;
    }
    key
};

static ENC: KNasEnc = KNasEnc::new(&KEY);
static INT: KNasInt = KNasInt::new(&KEY);
static K_AMF: KAmf = KAmf::new(&KAMF);
static ENCS: [KNasEnc; MESSAGES] = [
    KNasEnc::new(&key_of(0)),
    KNasEnc::new(&key_of(1)),
    KNasEnc::new(&key_of(2)),
    KNasEnc::new(&key_of(3)),
    KNasEnc::new(&key_of(4)),
    KNasEnc::new(&key_of(5)),
    KNasEnc::new(&key_of(6)),
    KNasEnc::new(&key_of(7)),
    KNasEnc::new(&key_of(8)),
];
static INTS: [KNasInt; MESSAGES] = [
    KNasInt::new(&key_of(0)),
    KNasInt::new(&key_of(1)),
    KNasInt::new(&key_of(2)),
    KNasInt::new(&key_of(3)),
    KNasInt::new(&key_of(4)),
    KNasInt::new(&key_of(5)),
    KNasInt::new(&key_of(6)),
    KNasInt::new(&key_of(7)),
    KNasInt::new(&key_of(8)),
];

pub const CIPHERING: [CipheringAlgorithm; 3] = [
    CipheringAlgorithm::Snow3g,
    CipheringAlgorithm::Aes,
    CipheringAlgorithm::Zuc,
];
pub const INTEGRITY: [IntegrityAlgorithm; 3] = [
    IntegrityAlgorithm::Snow3g,
    IntegrityAlgorithm::Aes,
    IntegrityAlgorithm::Zuc,
];

/// What an operation is, for the host to know which values to look for.
#[derive(Clone, Copy, PartialEq)]
pub enum Kind {
    /// An algorithm with [`KEY`]: 0, 1 or 2 for SNOW 3G, AES or ZUC.
    Ciphering(usize),
    Integrity(usize),
    /// Messages with the keys of [`key_of`], of every algorithm.
    Batch,
    /// A generator with [`KEY`] and [`IV`]: SNOW 3G, or ZUC.
    Generator(bool),
    /// A derivation from [`KAMF`].
    Derivation,
    /// A comparison of [`KEY`] with itself.
    Comparison,
}

/// The operations: their names, and what they are.
pub const CASES: [(&str, Kind); 22] = [
    ("nea_cipher 128-EEA1, 64 octets", Kind::Ciphering(0)),
    ("nea_cipher 128-EEA2, 64 octets", Kind::Ciphering(1)),
    ("nea_cipher 128-EEA3, 64 octets", Kind::Ciphering(2)),
    ("nea_cipher 128-EEA1, 1500 octets", Kind::Ciphering(0)),
    ("nea_cipher 128-EEA2, 1500 octets", Kind::Ciphering(1)),
    ("nea_cipher 128-EEA3, 1500 octets", Kind::Ciphering(2)),
    ("nia_mac 128-EIA1, 1500 octets", Kind::Integrity(0)),
    ("nia_mac 128-EIA2, 1500 octets", Kind::Integrity(1)),
    ("nia_mac 128-EIA3, 1500 octets", Kind::Integrity(2)),
    ("CipheringContext::new 128-EEA2", Kind::Ciphering(1)),
    (
        "CipheringContext::cipher 128-EEA2, 1500 octets",
        Kind::Ciphering(1),
    ),
    ("IntegrityContext::new 128-EIA2", Kind::Integrity(1)),
    (
        "IntegrityContext::mac 128-EIA2, 1500 octets",
        Kind::Integrity(1),
    ),
    (
        "nea_cipher_batch of the three algorithms, 9 x 300 octets",
        Kind::Batch,
    ),
    (
        "nia_mac_batch of the three algorithms, 9 x 300 octets",
        Kind::Batch,
    ),
    (
        "nia_mac_batch of 128-EIA2, 8 x 300 octets, from contexts",
        Kind::Batch,
    ),
    ("Snow3G::from_bytes", Kind::Generator(true)),
    ("Snow3G::fill", Kind::Generator(true)),
    ("Zuc::new", Kind::Generator(false)),
    ("Zuc::fill", Kind::Generator(false)),
    ("nas_5gs::derive_knas_int", Kind::Derivation),
    ("constant_time_eq", Kind::Comparison),
];

/// What the operations take, and where their values go: in the memory of
/// the program, off its stack.
pub struct Prepared {
    ciphering: Option<CipheringContext>,
    integrity: Option<IntegrityContext>,
    integrity_of: [Option<IntegrityContext>; MESSAGES],
    snow3g: Option<Snow3G>,
    zuc: Option<Zuc>,
    data: [[u8; LONGEST]; MESSAGES],
    keystream: [u32; 40],
    /// Where the value of the last operation is, when it is a key, a
    /// context or a generator: its first address and the one after its
    /// last. The value is the program's, and is no leftover.
    pub owned: [u64; 2],
}

impl Default for Prepared {
    fn default() -> Self {
        Self::new()
    }
}

impl Prepared {
    pub const fn new() -> Self {
        Self {
            ciphering: None,
            integrity: None,
            integrity_of: [const { None }; MESSAGES],
            snow3g: None,
            zuc: None,
            data: [[PLAIN; LONGEST]; MESSAGES],
            keystream: [0; 40],
            owned: [0; 2],
        }
    }

    /// Make what operation `case` takes.
    pub fn prepare(&mut self, case: usize) {
        let (aes, cmac) = (CipheringAlgorithm::Aes, IntegrityAlgorithm::Aes);
        match case {
            10 => self.ciphering = Some(CipheringContext::new(&ENC, aes)),
            12 => self.integrity = Some(IntegrityContext::new(&INT, cmac)),
            15 => {
                for (context, key) in self.integrity_of.iter_mut().zip(&INTS) {
                    *context = Some(IntegrityContext::new(key, cmac));
                }
            }
            17 => self.snow3g = Some(Snow3G::from_bytes(&KEY, &IV)),
            19 => self.zuc = Some(Zuc::new(&KEY, &IV)),
            _ => {}
        }
    }

    /// Say where the value of an operation is. It stays where the
    /// operation returned it, in the frame of [`run`](Self::run), and is
    /// not dropped: a move or a drop would be the program's doing.
    fn keep<T>(&mut self, value: &ManuallyDrop<T>) -> u64 {
        let from = core::ptr::from_ref(value) as u64;
        self.owned = [from, from + size_of::<T>() as u64];
        0
    }

    /// Run operation `case`, and nothing after it.
    #[inline(never)]
    pub fn run(&mut self, case: usize) -> u64 {
        let bearer = Bearer::new(BEARER).unwrap_or(Bearer::ZERO);
        let downlink = Direction::Downlink;
        self.owned = [0; 2];
        match case {
            0..=5 => {
                let data = &mut self.data[0][..if case < 3 { 64 } else { LONGEST }];
                nea_cipher(&ENC, COUNT, bearer, downlink, data, CIPHERING[case % 3]);
                0
            }
            6..=8 => {
                let (data, algorithm) = (&self.data[0], INTEGRITY[case % 3]);
                nia_mac(&INT, COUNT, bearer, downlink, data, algorithm).into()
            }
            9 => {
                let context = CipheringContext::new(&ENC, CipheringAlgorithm::Aes);
                self.keep(&ManuallyDrop::new(context))
            }
            10 => match &self.ciphering {
                Some(context) => {
                    context.cipher(COUNT, bearer, downlink, &mut self.data[0]);
                    0
                }
                None => u64::MAX,
            },
            11 => {
                let context = IntegrityContext::new(&INT, IntegrityAlgorithm::Aes);
                self.keep(&ManuallyDrop::new(context))
            }
            12 => match &self.integrity {
                Some(context) => context.mac(COUNT, bearer, downlink, &self.data[0]).into(),
                None => u64::MAX,
            },
            13 => {
                let mut index = 0;
                let mut jobs = self.data.each_mut().map(|data| {
                    let (key, algorithm) = (&ENCS[index], CIPHERING[index % 3]);
                    index += 1;
                    CipherJob::new(key, COUNT, bearer, downlink, &mut data[..300], algorithm)
                });
                nea_cipher_batch(&mut jobs);
                0
            }
            14 | 15 => {
                let from_contexts = case == 15;
                let contexts = &self.integrity_of;
                if from_contexts && contexts.iter().any(Option::is_none) {
                    return u64::MAX;
                }
                let mut index = 0;
                let mut jobs = self.data.each_ref().map(|data| {
                    let (at, data) = (index, &data[..300]);
                    index += 1;
                    match &contexts[at] {
                        Some(context) if from_contexts => {
                            context.job(COUNT, bearer, downlink, data)
                        }
                        _ => {
                            let algorithm = INTEGRITY[at % 3];
                            MacJob::new(&INTS[at], COUNT, bearer, downlink, data, algorithm)
                        }
                    }
                });
                // Eight chains of AES side by side, or nine messages
                let jobs = &mut jobs[..if from_contexts { 8 } else { MESSAGES }];
                nia_mac_batch(jobs);
                jobs.iter().filter_map(MacJob::mac).map(u64::from).sum()
            }
            16 => self.keep(&ManuallyDrop::new(Snow3G::from_bytes(&KEY, &IV))),
            17 => match &mut self.snow3g {
                Some(generator) => {
                    generator.fill(&mut self.keystream);
                    0
                }
                None => u64::MAX,
            },
            18 => self.keep(&ManuallyDrop::new(Zuc::new(&KEY, &IV))),
            19 => match &mut self.zuc {
                Some(generator) => {
                    generator.fill(&mut self.keystream);
                    0
                }
                None => u64::MAX,
            },
            20 => {
                let key = derive_knas_int(&K_AMF, IntegrityAlgorithm::Aes);
                self.keep(&ManuallyDrop::new(key))
            }
            21 => constant_time_eq(&KEY, ENC.as_octets()).into(),
            _ => u64::MAX,
        }
    }
}
