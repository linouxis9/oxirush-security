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

//! The operations that are scanned, each with the values that it must not
//! leave.

use crate::values::{
    Secret, aes_secrets, cmac_secrets, eea3_iv, hmac_secrets, keystream_secrets, reversed, s,
    secret, zuc_stages,
};
use oxirush_security::kdf::{extract_128, kdf};
use oxirush_security::nas_5gs::{self, NasConnection, Supi};
use oxirush_security::{
    AccessKeyCount, Autn, Bearer, CipherJob, CipheringAlgorithm, CipheringContext, Ck, Direction,
    Ik, IntegrityAlgorithm, IntegrityContext, MacJob, NasCount, Plmn, Rand, Snow3G, Zuc,
    constant_time_eq, nas_eps, nea_cipher, nea_cipher_batch, nea_cipher_bits, nia_mac,
    nia_mac_batch, nia_mac_bits,
};
use std::hint::black_box;
use std::mem::ManuallyDrop;
use std::sync::Arc;

/// An operation to scan.
pub struct Case {
    pub name: String,
    pub secrets: Vec<Secret>,
    /// Whether the operation has a form for each kind of instructions. A
    /// derivation and a SUCI have one form.
    pub forms: usize,
    pub run: Arc<dyn Fn() + Send + Sync>,
}

/// A value on the heap for as long as the program runs: an operation gets
/// a reference to it, and no copy of it is on a stack.
fn kept<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// A value that is not dropped: what a function allocated for its
/// operation is not freed after it, and the value of an operation is not
/// wiped, either of which would write on the stack that the scan reads.
fn spare<T>(value: T) -> ManuallyDrop<T> {
    ManuallyDrop::new(value)
}

/// What an operation needs, made on the heap by a function of its own: the
/// copies that making it left on the stack are below the caller, where
/// [`here`](crate::here) paints over them.
#[inline(never)]
fn prepared<T>(make: impl FnOnce() -> T) -> ManuallyDrop<Box<T>> {
    ManuallyDrop::new(Box::new(make()))
}

fn octets<const N: usize>(hexadecimal: &str) -> [u8; N] {
    hex::decode(hexadecimal)
        .expect("hexadecimal digits")
        .try_into()
        .expect("the length of the value")
}

/// The key of the examples of FIPS 197, whose round keys are known.
const KEY: &str = "2b7e151628aed2a6abf7158809cf4f3c";
const COUNT: u32 = 0x1234;
const CIPHERING: [(&str, CipheringAlgorithm); 3] = [
    ("128-EEA1", CipheringAlgorithm::EEA1),
    ("128-EEA2", CipheringAlgorithm::EEA2),
    ("128-EEA3", CipheringAlgorithm::EEA3),
];
const INTEGRITY: [(&str, IntegrityAlgorithm); 3] = [
    ("128-EIA1", IntegrityAlgorithm::EIA1),
    ("128-EIA2", IntegrityAlgorithm::EIA2),
    ("128-EIA3", IntegrityAlgorithm::EIA3),
];

struct Cases(Vec<Case>);

impl Cases {
    fn add(
        &mut self,
        name: impl Into<String>,
        forms: usize,
        secrets: Vec<Secret>,
        run: impl Fn() + Send + Sync + 'static,
    ) {
        self.0.push(Case {
            name: name.into(),
            secrets,
            forms,
            run: Arc::new(run),
        });
    }
}

pub fn all() -> Vec<Case> {
    let mut cases = Cases(Vec::new());
    algorithms(&mut cases);
    contexts(&mut cases);
    batches(&mut cases);
    generators(&mut cases);
    derivations(&mut cases);
    comparisons(&mut cases);
    suci(&mut cases);
    cases.0
}

/// What a ciphering algorithm handles with the key: what is expanded from
/// it, and the keystream of the message.
fn ciphering_secrets(key: &[u8; 16], algorithm: CipheringAlgorithm, bearer: u8) -> Vec<Secret> {
    let key_of_algorithm = nas_eps::KNasEnc::new(key);
    let mut keystream = vec![0u8; 64];
    let (bearer_input, downlink) = (Bearer::new(bearer).expect("five bits"), Direction::Downlink);
    nea_cipher(
        &key_of_algorithm,
        COUNT,
        bearer_input,
        downlink,
        &mut keystream,
        algorithm,
    );
    let mut secrets = aes_secrets(key);
    secrets.push(reversed(key));
    secrets.extend(zuc_stages(key, &eea3_iv(COUNT, bearer, 1)));
    secrets.extend(keystream_secrets(&keystream));
    secrets
}

/// What an integrity algorithm handles with the key: what is expanded
/// from it, the subkeys of CMAC, and the keystream words of the two MACs
/// that have some.
fn integrity_secrets(key: &[u8; 16], bearer: u8) -> Vec<Secret> {
    let words =
        |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|word| word.to_le_bytes()).collect() };
    let mut secrets = aes_secrets(key);
    secrets.push(reversed(key));
    secrets.extend(cmac_secrets(key));

    // 128-EIA1: z1 to z5 of SNOW 3G with the IV of the MAC, of which P and
    // Q are two words each (TS 35.215 §4.4)
    let fresh = u32::from(bearer) << 27;
    let iv = [fresh ^ (1 << 15), COUNT ^ (1 << 31), fresh, COUNT];
    let word = |at: usize| u32::from_be_bytes(key[at..at + 4].try_into().expect("four octets"));
    let mut z = [0u32; 5];
    Snow3G::new(&[word(12), word(8), word(4), word(0)], &iv).fill(&mut z);
    secrets.push(secret("128-EIA1 z1 to z4", &words(&z[..4])));
    secrets.push(secret("128-EIA1 P", &words(&[z[1], z[0]])));
    secrets.push(secret("128-EIA1 Q", &words(&[z[3], z[2]])));

    // 128-EIA3: the keystream of ZUC with the IV of the MAC (TS 35.221 §4.2)
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&COUNT.to_be_bytes());
    iv[4] = bearer << 3;
    iv.copy_within(0..8, 8);
    iv[8] ^= 0x80;
    iv[14] ^= 0x80;
    let mut z = [0u32; 8];
    Zuc::new(key, &iv).fill(&mut z);
    secrets.push(secret("128-EIA3 keystream words 0 to 3", &words(&z[..4])));
    secrets.push(secret("128-EIA3 keystream words 4 to 7", &words(&z[4..])));
    secrets.extend(zuc_stages(key, &iv));
    secrets
}

fn algorithms(cases: &mut Cases) {
    let octets_of_key: [u8; 16] = octets(KEY);
    assert_eq!(
        hex::encode(crate::values::round_keys(&octets_of_key)[10]),
        "d014f9a8c9ee2589e13f0cc8b6630ca6",
        "the last round key of FIPS 197 Appendix A.1"
    );
    let enc = kept(nas_5gs::KNasEnc::new(&octets_of_key));
    let int = kept(nas_5gs::KNasInt::new(&octets_of_key));
    let eps_enc = kept(nas_eps::KNasEnc::new(&octets_of_key));
    let eps_int = kept(nas_eps::KNasInt::new(&octets_of_key));
    let count = NasCount::new(COUNT).expect("24 bits");
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);
    let bearer = Bearer::from(access);

    for (name, algorithm) in CIPHERING {
        let secrets = ciphering_secrets(&octets_of_key, algorithm, 1);
        for length in [64usize, 1500] {
            cases.add(
                format!("nea_cipher {name}, {length} octets"),
                3,
                secrets.clone(),
                move || {
                    let mut data = spare(vec![0u8; length]);
                    let key = black_box(enc);
                    crate::here();
                    nea_cipher(
                        key,
                        COUNT,
                        bearer,
                        downlink,
                        black_box(&mut data),
                        algorithm,
                    );
                },
            );
        }
        cases.add(
            format!("nea_cipher_bits {name}, 11997 bits"),
            3,
            secrets.clone(),
            move || {
                let mut data = spare(vec![0u8; 1500]);
                let (key, data) = (black_box(enc), black_box(&mut data));
                crate::here();
                let value = spare(nea_cipher_bits(
                    key, COUNT, bearer, downlink, data, 11997, algorithm,
                ));
                crate::owned(&value);
            },
        );
        cases.add(
            format!("nas_5gs::nas_cipher {name}, 64 octets"),
            3,
            secrets.clone(),
            move || {
                let mut data = spare(vec![0u8; 64]);
                let (key, data) = (black_box(enc), black_box(&mut data));
                crate::here();
                nas_5gs::nas_cipher(key, count, access, downlink, data, algorithm);
            },
        );
        cases.add(
            format!("nas_eps::nas_cipher {name}, 64 octets"),
            3,
            ciphering_secrets(&octets_of_key, algorithm, 0),
            move || {
                let mut data = spare(vec![0u8; 64]);
                let (key, data) = (black_box(eps_enc), black_box(&mut data));
                crate::here();
                nas_eps::nas_cipher(key, count, downlink, data, algorithm);
            },
        );
    }

    for (name, algorithm) in INTEGRITY {
        let secrets = integrity_secrets(&octets_of_key, 1);
        for length in [61usize, 1500] {
            cases.add(
                format!("nia_mac {name}, {length} octets"),
                3,
                secrets.clone(),
                move || {
                    let data = spare(vec![0x5au8; length]);
                    let (key, data) = (black_box(int), black_box(&data));
                    crate::here();
                    let value = spare(nia_mac(key, COUNT, bearer, downlink, data, algorithm));
                    crate::owned(&value);
                },
            );
        }
        cases.add(
            format!("nia_mac_bits {name}, 11997 bits"),
            3,
            secrets.clone(),
            move || {
                let data = spare(vec![0x5au8; 1500]);
                let (key, data) = (black_box(int), black_box(&data));
                crate::here();
                let value = spare(nia_mac_bits(
                    key, COUNT, bearer, downlink, data, 11997, algorithm,
                ));
                crate::owned(&value);
            },
        );
        cases.add(
            format!("nas_5gs::nas_mac {name}, 61 octets"),
            3,
            secrets.clone(),
            move || {
                let data = spare(vec![0x5au8; 61]);
                let (key, data) = (black_box(int), black_box(&data));
                crate::here();
                let value = spare(nas_5gs::nas_mac(
                    key, count, access, downlink, data, algorithm,
                ));
                crate::owned(&value);
            },
        );
        cases.add(
            format!("nas_5gs::nas_container_mac {name}"),
            3,
            aes_secrets(&octets_of_key),
            move || {
                let key = black_box(int);
                crate::here();
                let value = spare(nas_5gs::nas_container_mac(
                    key,
                    &[0x22, 0x15, 0x22],
                    algorithm,
                ));
                crate::owned(&value);
            },
        );
        let eps_secrets = integrity_secrets(&octets_of_key, 0);
        cases.add(
            format!("nas_eps::nas_mac {name}, 61 octets"),
            3,
            eps_secrets.clone(),
            move || {
                let data = spare(vec![0x5au8; 61]);
                let (key, data) = (black_box(eps_int), black_box(&data));
                crate::here();
                let value = spare(nas_eps::nas_mac(key, count, downlink, data, algorithm));
                crate::owned(&value);
            },
        );
        cases.add(
            format!("nas_eps::service_request_short_mac {name}"),
            3,
            aes_secrets(&octets_of_key),
            move || {
                let key = black_box(eps_int);
                let uplink = Direction::Uplink;
                crate::here();
                let value = spare(nas_eps::service_request_short_mac(
                    key, count, uplink, 0x34, algorithm,
                ));
                crate::owned(&value);
            },
        );
        cases.add(
            format!("nas_eps::re_establishment_nas_mac {name}"),
            3,
            aes_secrets(&octets_of_key),
            move || {
                let key = black_box(eps_int);
                crate::here();
                let value = spare(nas_eps::re_establishment_nas_mac(
                    key,
                    count,
                    0x0123_4567,
                    algorithm,
                ));
                crate::owned(&value);
            },
        );
    }
}

fn contexts(cases: &mut Cases) {
    let octets_of_key: [u8; 16] = octets(KEY);
    let enc = kept(nas_5gs::KNasEnc::new(&octets_of_key));
    let int = kept(nas_5gs::KNasInt::new(&octets_of_key));
    let (bearer, downlink) = (Bearer::from(NasConnection::ThreeGpp), Direction::Downlink);

    for (name, algorithm) in CIPHERING {
        let secrets = ciphering_secrets(&octets_of_key, algorithm, 1);
        cases.add(
            format!("CipheringContext::new {name}"),
            3,
            aes_secrets(&octets_of_key),
            move || {
                crate::here();
                let value = spare(CipheringContext::new(black_box(enc), algorithm));
                crate::owned(&value);
            },
        );
        for length in [64usize, 1500] {
            cases.add(
                format!("CipheringContext::cipher {name}, {length} octets"),
                3,
                secrets.clone(),
                move || {
                    // The context is made in the form of the code that
                    // the operation runs in, and is wiped when it is
                    // dropped
                    let context = prepared(|| CipheringContext::new(enc, algorithm));
                    let mut data = spare(vec![0u8; length]);
                    crate::here();
                    black_box(&context).cipher(COUNT, bearer, downlink, black_box(&mut data));
                },
            );
        }
        cases.add(
            format!("CipheringContext::cipher_bits {name}, 11997 bits"),
            3,
            secrets.clone(),
            move || {
                let context = prepared(|| CipheringContext::new(enc, algorithm));
                let mut data = spare(vec![0u8; 1500]);
                let data = black_box(&mut data);
                crate::here();
                let value =
                    spare(black_box(&context).cipher_bits(COUNT, bearer, downlink, data, 11997));
                crate::owned(&value);
            },
        );
    }
    for (name, algorithm) in INTEGRITY {
        let secrets = integrity_secrets(&octets_of_key, 1);
        let mut of_key = aes_secrets(&octets_of_key);
        of_key.extend(cmac_secrets(&octets_of_key));
        cases.add(
            format!("IntegrityContext::new {name}"),
            3,
            of_key,
            move || {
                crate::here();
                let value = spare(IntegrityContext::new(black_box(int), algorithm));
                crate::owned(&value);
            },
        );
        for length in [61usize, 1500] {
            cases.add(
                format!("IntegrityContext::mac {name}, {length} octets"),
                3,
                secrets.clone(),
                move || {
                    let context = prepared(|| IntegrityContext::new(int, algorithm));
                    let data = spare(vec![0x5au8; length]);
                    crate::here();
                    let value =
                        spare(black_box(&context).mac(COUNT, bearer, downlink, black_box(&data)));
                    crate::owned(&value);
                },
            );
        }
        cases.add(
            format!("IntegrityContext::mac_bits {name}, 11997 bits"),
            3,
            secrets.clone(),
            move || {
                let context = prepared(|| IntegrityContext::new(int, algorithm));
                let data = spare(vec![0x5au8; 1500]);
                let data = black_box(&data);
                crate::here();
                let value =
                    spare(black_box(&context).mac_bits(COUNT, bearer, downlink, data, 11997));
                crate::owned(&value);
            },
        );
    }
}

/// Messages that each have a key of their own: every one of an algorithm,
/// then of the three in turn, from keys and from contexts. Sixteen fill
/// the generators and the chains that run side by side; one, two and three
/// take those of fewer messages.
fn batches(cases: &mut Cases) {
    const MESSAGES: usize = 16;
    const SIZES: [(usize, usize); 5] = [(16, 64), (16, 1500), (1, 64), (2, 64), (3, 64)];
    let keys: Vec<[u8; 16]> = (0..MESSAGES)
        .map(|index| {
            let mut key: [u8; 16] = octets(KEY);
            key[0] ^= index as u8;
            key[15] ^= (index as u8) << 4;
            key
        })
        .collect();
    let enc = kept(keys.iter().map(nas_5gs::KNasEnc::new).collect::<Vec<_>>());
    let int = kept(keys.iter().map(nas_5gs::KNasInt::new).collect::<Vec<_>>());
    let (bearer, downlink) = (Bearer::from(NasConnection::ThreeGpp), Direction::Downlink);

    // Every message of one algorithm, then the three in turn
    let mut kinds: Vec<(String, Option<usize>)> = Vec::new();
    for (at, (name, _)) in CIPHERING.iter().enumerate() {
        kinds.push((format!("of {name}"), Some(at)));
    }
    kinds.push(("of the three algorithms".into(), None));

    for (kind, one) in kinds {
        let algorithm_of = Arc::new(move |index: usize| one.unwrap_or(index % 3));
        // The keys of the first messages with what is expanded from them,
        // and the keystream of the first message of each algorithm
        let mut secrets = Vec::new();
        for (index, key) in keys.iter().enumerate().take(4) {
            let algorithm = CIPHERING[algorithm_of(index)].1;
            let mut of_message = ciphering_secrets(key, algorithm, 1);
            if index > 0 {
                of_message.truncate(7);
            }
            secrets.extend(of_message);
        }
        for (form, contexts) in [("keys", false), ("contexts", true)] {
            for (messages, length) in SIZES {
                let of = algorithm_of.clone();
                cases.add(
                    format!("nea_cipher_batch {kind}, {messages} x {length} octets, from {form}"),
                    3,
                    secrets.clone(),
                    move || {
                        let mut data = spare(vec![vec![0u8; length]; messages]);
                        let contexts = prepared(|| -> Vec<CipheringContext> {
                            (0..messages)
                                .filter(|_| contexts)
                                .map(|index| {
                                    CipheringContext::new(&enc[index], CIPHERING[of(index)].1)
                                })
                                .collect()
                        });
                        let jobs: Vec<CipherJob<'_>> = data
                            .iter_mut()
                            .enumerate()
                            .map(|(index, data)| match contexts.get(index) {
                                Some(context) => context.job(COUNT, bearer, downlink, data),
                                None => {
                                    let algorithm = CIPHERING[of(index)].1;
                                    CipherJob::new(
                                        &enc[index],
                                        COUNT,
                                        bearer,
                                        downlink,
                                        data,
                                        algorithm,
                                    )
                                }
                            })
                            .collect();
                        let mut jobs = spare(jobs);
                        crate::here();
                        nea_cipher_batch(black_box(&mut jobs));
                    },
                );
            }
        }

        let mut secrets = Vec::new();
        for key in keys.iter().take(4) {
            secrets.extend(integrity_secrets(key, 1));
        }
        for (form, contexts) in [("keys", false), ("contexts", true)] {
            for (messages, length) in SIZES {
                let of = algorithm_of.clone();
                let kind = kind.replace("EEA", "EIA");
                let length = length - 3;
                cases.add(
                    format!("nia_mac_batch {kind}, {messages} x {length} octets, from {form}"),
                    3,
                    secrets.clone(),
                    move || {
                        let data = spare(vec![vec![0x5au8; length]; messages]);
                        let contexts = prepared(|| -> Vec<IntegrityContext> {
                            (0..messages)
                                .filter(|_| contexts)
                                .map(|index| {
                                    IntegrityContext::new(&int[index], INTEGRITY[of(index)].1)
                                })
                                .collect()
                        });
                        let jobs: Vec<MacJob<'_>> = data
                            .iter()
                            .enumerate()
                            .map(|(index, data)| match contexts.get(index) {
                                Some(context) => context.job(COUNT, bearer, downlink, data),
                                None => {
                                    let algorithm = INTEGRITY[of(index)].1;
                                    MacJob::new(
                                        &int[index],
                                        COUNT,
                                        bearer,
                                        downlink,
                                        data,
                                        algorithm,
                                    )
                                }
                            })
                            .collect();
                        let mut jobs = spare(jobs);
                        crate::here();
                        nia_mac_batch(black_box(&mut jobs));
                    },
                );
            }
        }
    }
}

/// The two keystream generators, which a program may use by themselves.
fn generators(cases: &mut Cases) {
    let key: &'static [u8; 16] = kept(octets(KEY));
    let iv: &'static [u8; 16] = kept(octets("000102030405060708090a0b0c0d0e0f"));
    let words =
        |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|word| word.to_le_bytes()).collect() };

    let mut expected = [0u32; 40];
    Snow3G::from_bytes(key, iv).fill(&mut expected);
    let big_endian: Vec<u8> = key
        .chunks(4)
        .flat_map(|word| word.iter().rev().copied().collect::<Vec<u8>>())
        .collect();
    let secrets = vec![
        secret("the key", key),
        secret("the key, as words", &big_endian),
        secret("keystream words 0 to 3", &words(&expected[..4])),
        secret("keystream words 36 to 39", &words(&expected[36..])),
    ];
    cases.add("Snow3G::from_bytes", 3, secrets.clone(), move || {
        crate::here();
        let value = spare(Snow3G::from_bytes(black_box(key), black_box(iv)));
        crate::owned(&value);
    });
    let word = |of: &[u8; 16], at: usize| {
        u32::from_be_bytes(of[at..at + 4].try_into().expect("four octets"))
    };
    let key_words: &'static [u32; 4] = kept(core::array::from_fn(|at| word(key, 4 * at)));
    let iv_words: &'static [u32; 4] = kept(core::array::from_fn(|at| word(iv, 4 * at)));
    cases.add("Snow3G::new", 3, secrets.clone(), move || {
        crate::here();
        let value = spare(Snow3G::new(black_box(key_words), iv_words));
        crate::owned(&value);
    });
    cases.add("Snow3G::fill", 3, secrets.clone(), move || {
        let mut generator = prepared(|| Snow3G::from_bytes(black_box(key), black_box(iv)));
        let mut keystream = spare(vec![0u32; 40]);
        crate::here();
        generator.fill(black_box(&mut keystream));
    });
    cases.add("Snow3G::next_word", 3, secrets, move || {
        let mut generator = prepared(|| Snow3G::from_bytes(black_box(key), black_box(iv)));
        let mut keystream = spare(vec![0u32; 4]);
        crate::here();
        for word in keystream.iter_mut() {
            *word = generator.next_word();
        }
    });

    Zuc::new(key, iv).fill(&mut expected);
    let mut secrets = vec![
        secret("the key", key),
        secret("keystream words 0 to 3", &words(&expected[..4])),
        secret("keystream words 36 to 39", &words(&expected[36..])),
    ];
    secrets.extend(zuc_stages(key, iv));
    cases.add("Zuc::new", 3, secrets.clone(), move || {
        crate::here();
        let value = spare(Zuc::new(black_box(key), black_box(iv)));
        crate::owned(&value);
    });
    cases.add("Zuc::fill", 3, secrets.clone(), move || {
        let mut generator = prepared(|| Zuc::new(black_box(key), black_box(iv)));
        let mut keystream = spare(vec![0u32; 40]);
        crate::here();
        generator.fill(black_box(&mut keystream));
    });
    cases.add("Zuc::next_word", 3, secrets, move || {
        let mut generator = prepared(|| Zuc::new(black_box(key), black_box(iv)));
        let mut keystream = spare(vec![0u32; 4]);
        crate::here();
        for word in keystream.iter_mut() {
            *word = generator.next_word();
        }
    });
}

/// A derivation, with the key of its HMAC and the string S that it hashes
/// when the scan knows it: the key, its two padded blocks, and then the
/// inner hash and the 256 bits of the result.
fn derivation(
    cases: &mut Cases,
    name: &str,
    key: &[u8],
    s: Option<Vec<u8>>,
    run: impl Fn() + Send + Sync + 'static,
) {
    let mut secrets = hmac_secrets(
        "the key of the derivation",
        key,
        s.as_deref().unwrap_or(&[]),
    );
    if s.is_none() {
        secrets.truncate(3);
    }
    cases.add(name, 1, secrets, run);
}

fn derivations(cases: &mut Cases) {
    let ck = kept(Ck::new(&octets("b40ba9a3c58b2a05bbf0d987b21bf8cb")));
    let ik = kept(Ik::new(&octets("f769bcd751044604127672711c6d3441")));
    let rand = kept(Rand::new(&octets("23553cbe9637a89d218ae64dae47bf35")));
    let autn = kept(Autn::new(&octets("55f328b43577b9b94a9ffac354dfafb3")));
    let ck_ik: Vec<u8> = [&ck.as_octets()[..], ik.as_octets()].concat();
    let sn: &'static [u8] = b"5G:mnc093.mcc208.3gppnetwork.org";
    let res: &'static [u8] = kept(octets::<8>("a54211d5e3ba50bf"));
    let supi = kept(Supi::imsi("208930000000001").expect("an IMSI"));
    let count = NasCount::new(0x01_0203).expect("24 bits");
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);

    // The keys of the 5GS hierarchy, each distinct
    let key = |first: u8| -> [u8; 32] { core::array::from_fn(|at| first ^ (at as u8 * 7)) };
    let kausf = kept(nas_5gs::KAusf::new(&key(0x11)));
    let kseaf = kept(nas_5gs::KSeaf::new(&key(0x22)));
    let kamf = kept(nas_5gs::KAmf::new(&key(0x33)));
    let kgnb = kept(nas_5gs::KGnb::new(&key(0x44)));
    let nh = kept(nas_5gs::Nh::new(&key(0x55)));
    let kn3iwf = kept(nas_5gs::KN3iwf::new(&key(0x66)));
    let kasme = kept(nas_eps::KAsme::new(&key(0x77)));
    let kenb = kept(nas_eps::KEnb::new(&key(0x88)));
    let eps_nh = kept(nas_eps::Nh::new(&key(0x99)));

    let s_kausf = s(0x6a, &[sn, &autn.as_octets()[..6]]);
    derivation(
        cases,
        "nas_5gs::derive_kausf",
        &ck_ik,
        Some(s_kausf),
        move || {
            crate::here();
            let value = spare(nas_5gs::derive_kausf(
                black_box(ck),
                black_box(ik),
                sn,
                autn,
            ));
            crate::owned(&value);
        },
    );
    let s_res = s(0x6b, &[sn, rand.as_octets(), res]);
    derivation(
        cases,
        "nas_5gs::compute_res_star",
        &ck_ik,
        Some(s_res.clone()),
        move || {
            crate::here();
            let value = spare(nas_5gs::compute_res_star(
                black_box(ck),
                black_box(ik),
                sn,
                rand,
                res,
            ));
            crate::owned(&value);
        },
    );
    derivation(
        cases,
        "nas_5gs::compute_xres_star",
        &ck_ik,
        Some(s_res),
        move || {
            crate::here();
            let value = spare(nas_5gs::compute_xres_star(
                black_box(ck),
                black_box(ik),
                sn,
                rand,
                res,
            ));
            crate::owned(&value);
        },
    );
    let s_kseaf = s(0x6c, &[sn]);
    derivation(
        cases,
        "nas_5gs::derive_kseaf",
        kausf.as_octets(),
        Some(s_kseaf),
        move || {
            crate::here();
            let value = spare(nas_5gs::derive_kseaf(black_box(kausf), sn));
            crate::owned(&value);
        },
    );
    let s_kamf = s(0x6d, &[b"208930000000001", &[0, 0]]);
    derivation(
        cases,
        "nas_5gs::derive_kamf",
        kseaf.as_octets(),
        Some(s_kamf),
        move || {
            crate::here();
            let value = spare(nas_5gs::derive_kamf(black_box(kseaf), supi, &[0, 0]));
            crate::owned(&value);
        },
    );
    let s_knas = s(0x69, &[&[0x01], &[0x02]]);
    derivation(
        cases,
        "nas_5gs::derive_knas_enc",
        kamf.as_octets(),
        Some(s_knas),
        move || {
            crate::here();
            let value = spare(nas_5gs::derive_knas_enc(black_box(kamf), nea2));
            crate::owned(&value);
        },
    );

    macro_rules! of {
        ($name:literal, $key:expr, $call:expr) => {
            derivation(cases, $name, $key.as_octets(), None, move || {
                crate::here();
                let value = spare($call);
                crate::owned(&value);
            });
        };
    }
    of!(
        "nas_5gs::derive_knas_int",
        kamf,
        nas_5gs::derive_knas_int(black_box(kamf), nia2)
    );
    of!(
        "nas_5gs::derive_kgnb",
        kamf,
        nas_5gs::derive_kgnb(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_kgnb, at a handover",
        kamf,
        nas_5gs::derive_kgnb(black_box(kamf), AccessKeyCount::Handover)
    );
    of!(
        "nas_5gs::derive_kn3iwf",
        kamf,
        nas_5gs::derive_kn3iwf(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_krrc_enc",
        kgnb,
        nas_5gs::derive_krrc_enc(black_box(kgnb), nea2)
    );
    of!(
        "nas_5gs::derive_krrc_int",
        kgnb,
        nas_5gs::derive_krrc_int(black_box(kgnb), nia2)
    );
    of!(
        "nas_5gs::derive_kup_enc",
        kgnb,
        nas_5gs::derive_kup_enc(black_box(kgnb), nea2)
    );
    of!(
        "nas_5gs::derive_kup_int",
        kgnb,
        nas_5gs::derive_kup_int(black_box(kgnb), nia2)
    );
    of!(
        "nas_5gs::derive_kng_ran_star",
        kgnb,
        nas_5gs::derive_kng_ran_star(black_box(kgnb), 501, 632_628)
    );
    of!(
        "nas_5gs::derive_kng_ran_star, from NH",
        nh,
        nas_5gs::derive_kng_ran_star(black_box(nh), 501, 632_628)
    );
    of!(
        "nas_5gs::derive_kng_ran_star_ng_enb",
        kgnb,
        nas_5gs::derive_kng_ran_star_ng_enb(black_box(kgnb), 503, 6_300)
    );
    of!(
        "nas_5gs::derive_nh",
        kamf,
        nas_5gs::derive_nh(black_box(kamf), kgnb)
    );
    of!(
        "nas_5gs::derive_mapped_kasme_idle",
        kamf,
        nas_5gs::derive_mapped_kasme_idle(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_mapped_kasme_handover",
        kamf,
        nas_5gs::derive_mapped_kasme_handover(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_mapped_kamf_idle",
        kasme,
        nas_5gs::derive_mapped_kamf_idle(black_box(kasme), count)
    );
    of!(
        "nas_5gs::derive_mapped_kamf_handover",
        kasme,
        nas_5gs::derive_mapped_kamf_handover(black_box(kasme), eps_nh)
    );
    of!(
        "nas_5gs::derive_kamf_prime",
        kamf,
        nas_5gs::derive_kamf_prime(
            black_box(kamf),
            nas_5gs::KamfMobilityDirection::IdleMobility,
            count
        )
    );
    of!(
        "nas_5gs::derive_kamf_prime_idle",
        kamf,
        nas_5gs::derive_kamf_prime_idle(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_kamf_prime_handover",
        kamf,
        nas_5gs::derive_kamf_prime_handover(black_box(kamf), count)
    );
    of!(
        "nas_5gs::derive_ksn",
        kgnb,
        nas_5gs::derive_ksn(black_box(kgnb), 7)
    );
    of!(
        "nas_5gs::derive_sor_mac_ausf",
        kausf,
        nas_5gs::derive_sor_mac_ausf(black_box(kausf), &[1, 2], 1, Some(&[0xaa, 0xbb]))
    );
    of!(
        "nas_5gs::derive_sor_mac_ue",
        kausf,
        nas_5gs::derive_sor_mac_ue(black_box(kausf), 1)
    );
    of!(
        "nas_5gs::derive_upu_mac_ausf",
        kausf,
        nas_5gs::derive_upu_mac_ausf(black_box(kausf), &[0xaa, 0xbb, 0xcc], 1)
    );
    of!(
        "nas_5gs::derive_upu_mac_ue",
        kausf,
        nas_5gs::derive_upu_mac_ue(black_box(kausf), 1)
    );
    of!(
        "nas_5gs::derive_tnap_usage_key",
        kn3iwf,
        nas_5gs::derive_tnap_usage_key(black_box(kn3iwf), nas_5gs::TnapKeyUsage::Ipsec)
    );
    of!(
        "nas_5gs::derive_kiab",
        kgnb,
        nas_5gs::derive_kiab(
            black_box(kgnb),
            nas_5gs::IabIpAddress::V4([192, 0, 2, 1]),
            nas_5gs::IabIpAddress::V4([198, 51, 100, 2]),
        )
    );
    of!(
        "nas_5gs::derive_kasme_srvcc",
        kamf,
        nas_5gs::derive_kasme_srvcc(black_box(kamf), count)
    );

    // RES* and XRES* go through SHA-256 alone: the scan looks for them
    let res_star = kept(nas_5gs::ResStar::new(&octets(
        "5cc9527f4d21c43bee83a15443acf1c4",
    )));
    let xres_star = kept(nas_5gs::XresStar::new(res_star.as_octets()));
    let of_hash = vec![secret("RES*", res_star.as_octets())];
    cases.add(
        "nas_5gs::compute_hres_star",
        1,
        of_hash.clone(),
        move || {
            crate::here();
            let value = spare(nas_5gs::compute_hres_star(rand, black_box(res_star)));
            crate::owned(&value);
        },
    );
    cases.add("nas_5gs::compute_hxres_star", 1, of_hash, move || {
        crate::here();
        let value = spare(nas_5gs::compute_hxres_star(rand, black_box(xres_star)));
        crate::owned(&value);
    });

    let plmn = Plmn::new("208", "93").expect("an MCC and an MNC");
    let s_kasme = s(0x10, &[&plmn.to_nas_octets(), &autn.as_octets()[..6]]);
    derivation(
        cases,
        "nas_eps::derive_kasme",
        &ck_ik,
        Some(s_kasme),
        move || {
            crate::here();
            let value = spare(nas_eps::derive_kasme(
                black_box(ck),
                black_box(ik),
                plmn,
                autn,
            ));
            crate::owned(&value);
        },
    );
    derivation(
        cases,
        "nas_eps::derive_kasme_handover",
        &ck_ik,
        None,
        move || {
            crate::here();
            let value = spare(nas_eps::derive_kasme_handover(
                black_box(ck),
                black_box(ik),
                0x1234_5678,
            ));
            crate::owned(&value);
        },
    );
    derivation(
        cases,
        "nas_eps::derive_kasme_idle_mobility",
        &ck_ik,
        None,
        move || {
            crate::here();
            let value = spare(nas_eps::derive_kasme_idle_mobility(
                black_box(ck),
                black_box(ik),
                1,
                2,
            ));
            crate::owned(&value);
        },
    );
    of!(
        "nas_eps::derive_kenb",
        kasme,
        nas_eps::derive_kenb(black_box(kasme), count)
    );
    of!(
        "nas_eps::derive_nh",
        kasme,
        nas_eps::derive_nh(black_box(kasme), kenb)
    );
    of!(
        "nas_eps::derive_kenb_star",
        kenb,
        nas_eps::derive_kenb_star(black_box(kenb), 42, 6300)
    );
    of!(
        "nas_eps::derive_kenb_star, from NH",
        eps_nh,
        nas_eps::derive_kenb_star(black_box(eps_nh), 42, 6300)
    );
    of!(
        "nas_eps::derive_knas_enc",
        kasme,
        nas_eps::derive_knas_enc(black_box(kasme), nea2)
    );
    of!(
        "nas_eps::derive_knas_int",
        kasme,
        nas_eps::derive_knas_int(black_box(kasme), nia2)
    );
    of!(
        "nas_eps::derive_krrc_enc",
        kenb,
        nas_eps::derive_krrc_enc(black_box(kenb), nea2)
    );
    of!(
        "nas_eps::derive_krrc_int",
        kenb,
        nas_eps::derive_krrc_int(black_box(kenb), nia2)
    );
    of!(
        "nas_eps::derive_kup_enc",
        kenb,
        nas_eps::derive_kup_enc(black_box(kenb), nea2)
    );
    of!(
        "nas_eps::derive_kup_int",
        kenb,
        nas_eps::derive_kup_int(black_box(kenb), nia2)
    );
    of!(
        "nas_eps::derive_ck_ik_handover",
        kasme,
        nas_eps::derive_ck_ik_handover(black_box(kasme), count)
    );
    of!(
        "nas_eps::derive_ck_ik_idle_mobility",
        kasme,
        nas_eps::derive_ck_ik_idle_mobility(black_box(kasme), count)
    );
    of!(
        "nas_eps::derive_ck_ik_srvcc",
        kasme,
        nas_eps::derive_ck_ik_srvcc(black_box(kasme), count)
    );
    of!(
        "nas_eps::derive_nas_token",
        kasme,
        nas_eps::derive_nas_token(black_box(kasme), count)
    );
    of!(
        "nas_eps::derive_skenb",
        kenb,
        nas_eps::derive_skenb(black_box(kenb), 0x0123)
    );
    of!(
        "nas_eps::derive_skgnb",
        kenb,
        nas_eps::derive_skgnb(black_box(kenb), 0x0123)
    );
    of!(
        "nas_eps::derive_lwip_psk",
        kenb,
        nas_eps::derive_lwip_psk(black_box(kenb), 0x0123)
    );
    of!(
        "nas_eps::derive_skwt",
        kenb,
        nas_eps::derive_skwt(black_box(kenb), 0x0123)
    );
    let master: &'static [u8; 32] = kept(key(0xaa));
    derivation(cases, "nas_eps::derive_kn", master, None, move || {
        crate::here();
        let value = spare(nas_eps::derive_kn(
            black_box(master),
            &[0x01, 0x23],
            b"208930000000001",
        ));
        crate::owned(&value);
    });
    let message = s(0x42, &[b"a derivation that the crate does not have"]);
    let s_kdf = message.clone();
    derivation(cases, "kdf::kdf", master, Some(s_kdf), move || {
        crate::here();
        let value = spare(kdf(black_box(master), &message));
        crate::owned(&value);
    });
    let derived: &'static [u8; 32] = kept(core::array::from_fn(|at| 0xbb ^ (at as u8 * 5)));
    let of_derived = vec![secret("the 256 bits that are derived", derived)];
    cases.add("kdf::extract_128", 1, of_derived, move || {
        crate::here();
        let value = spare(extract_128(black_box(derived)));
        crate::owned(&value);
    });
}

fn comparisons(cases: &mut Cases) {
    let expected: &'static [u8; 16] = kept(octets("5cc9527f4d21c43bee83a15443acf1c4"));
    let xres_star = kept(nas_5gs::XresStar::new(expected));
    let res_star = kept(nas_5gs::ResStar::new(expected));
    let kamf = kept(nas_5gs::KAmf::new(&core::array::from_fn(|at| {
        0x33 ^ (at as u8 * 7)
    })));
    let other = kept(kamf.clone());
    let of_response = vec![secret("XRES*", expected)];
    cases.add("constant_time_eq", 1, of_response.clone(), move || {
        crate::here();
        let value = spare(constant_time_eq(
            black_box(expected),
            black_box(res_star.as_octets()),
        ));
        crate::owned(&value);
    });
    cases.add("XresStar::accepts", 1, of_response, move || {
        crate::here();
        let value = spare(black_box(xres_star).accepts(black_box(res_star)));
        crate::owned(&value);
    });
    let of_key = vec![secret("KAMF", kamf.as_octets())];
    cases.add("a key == a key", 1, of_key, move || {
        crate::here();
        let value = spare(black_box(kamf) == black_box(other));
        crate::owned(&value);
    });
}

/// SUCI with the home network keys and the data of TS 33.501 Annex C.4,
/// whose intermediate values the Annex gives.
fn suci(cases: &mut Cases) {
    use nas_5gs::{HomeNetworkPrivateKey, Protection, RoutingIndicator, Suci};
    let h = |hexadecimal: &str| hex::decode(hexadecimal).expect("hexadecimal digits");
    let plmn = Plmn::new("274", "012").expect("an MCC and an MNC");
    let identity = |scheme: u8, output: &str| -> &'static [u8] {
        let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, scheme, 27];
        identity.extend(h(output));
        kept(identity).as_slice()
    };

    // Profile A, Annex C.4.3.1
    let octets_a: &'static [u8; 32] = kept(octets(
        "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d",
    ));
    let private_a = kept(HomeNetworkPrivateKey::profile_a(octets_a));
    let public_a = kept(private_a.public_key());
    let mut clamped = *octets_a;
    clamped[0] &= 248;
    clamped[31] = (clamped[31] & 127) | 64;
    let secrets_a = vec![
        secret("the home network private key", octets_a),
        secret("the home network private key, clamped", &clamped),
        secret(
            "the shared secret",
            &h("028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a"),
        ),
        secret("the encryption key", &h("2ba342cabd2b3b1e5e4e890da11b65f6")),
        secret("the ICB", &h("e2622cb0cdd08204e721c8ea9b95a7c6")),
        secret(
            "the MAC key",
            &h("d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2"),
        ),
    ];
    let suci_a = identity(
        1,
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
    );
    cases.add(
        "Suci::deconceal, Profile A",
        1,
        secrets_a.clone(),
        move || {
            let suci = prepared(|| {
                Suci::from_nas_octets(black_box(suci_a)).expect("the SUCI of Annex C.4.3.1")
            });
            crate::here();
            let supi = spare(suci.deconceal(Some(black_box(private_a))));
            crate::owned(&supi);
            assert!(supi.is_ok(), "its key");
        },
    );
    let of_key = secrets_a[..2].to_vec();
    cases.add(
        "HomeNetworkPrivateKey::profile_a",
        1,
        of_key.clone(),
        move || {
            crate::here();
            let value = spare(HomeNetworkPrivateKey::profile_a(black_box(octets_a)));
            crate::owned(&value);
        },
    );
    cases.add(
        "HomeNetworkPrivateKey::public_key, Profile A",
        1,
        of_key,
        move || {
            crate::here();
            let value = spare(black_box(private_a).public_key());
            crate::owned(&value);
        },
    );
    // The ephemeral key of a concealment is drawn: the scan cannot know
    // it, and looks at how deep the operation goes and at what is cleared
    cases.add("Suci::conceal_imsi, Profile A", 1, Vec::new(), move || {
        let protection = Protection::Ecies {
            key_id: 27,
            key: public_a,
        };
        crate::here();
        let suci = spare(Suci::conceal_imsi(
            plmn,
            black_box("001002086"),
            RoutingIndicator::default(),
            protection,
        ));
        crate::owned(&suci);
        assert!(suci.is_ok(), "a concealment");
    });

    // Profile B, Annex C.4.4.1
    let octets_b: &'static [u8; 32] = kept(octets(
        "f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda",
    ));
    let private_b = kept(HomeNetworkPrivateKey::profile_b(octets_b).expect("a key of Profile B"));
    let public_b = kept(private_b.public_key());
    let shared = h("6c7e6518980025b982fbb2ff746e3c2e85a196d252099a7ad23ea7b4c0959cae");
    let low_first = |octets: &[u8]| -> Vec<u8> { octets.iter().rev().copied().collect() };
    let secrets_b = vec![
        secret("the home network private key", octets_b),
        secret(
            "the home network private key, as a number",
            &low_first(octets_b),
        ),
        secret("the shared secret", &shared),
        secret("the shared secret, as a number", &low_first(&shared)),
        secret("the encryption key", &h("8a65c3aed80295c12bd55087e965702a")),
        secret("the ICB", &h("ef285b4061c3baee858ab6ec68487dae")),
        secret(
            "the MAC key",
            &h("a5ebac0bc48d9cf7ae5ce39cd840ac6c761aec04078fab954d634f923e901c64"),
        ),
    ];
    let suci_b = identity(
        2,
        "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d146a33fc2716ac7dae96aa30a4d",
    );
    cases.add(
        "Suci::deconceal, Profile B",
        1,
        secrets_b.clone(),
        move || {
            let suci = prepared(|| {
                Suci::from_nas_octets(black_box(suci_b)).expect("the SUCI of Annex C.4.4.1")
            });
            crate::here();
            let supi = spare(suci.deconceal(Some(black_box(private_b))));
            crate::owned(&supi);
            assert!(supi.is_ok(), "its key");
        },
    );
    let of_key = secrets_b[..2].to_vec();
    cases.add(
        "HomeNetworkPrivateKey::profile_b",
        1,
        of_key.clone(),
        move || {
            crate::here();
            let value = spare(HomeNetworkPrivateKey::profile_b(black_box(octets_b)));
            crate::owned(&value);
        },
    );
    cases.add(
        "HomeNetworkPrivateKey::public_key, Profile B",
        1,
        of_key,
        move || {
            crate::here();
            let value = spare(black_box(private_b).public_key());
            crate::owned(&value);
        },
    );
    cases.add("Suci::conceal_imsi, Profile B", 1, Vec::new(), move || {
        let protection = Protection::Ecies {
            key_id: 27,
            key: public_b,
        };
        crate::here();
        let suci = spare(Suci::conceal_imsi(
            plmn,
            black_box("001002086"),
            RoutingIndicator::default(),
            protection,
        ));
        crate::owned(&suci);
        assert!(suci.is_ok(), "a concealment");
    });

    // A network specific identifier, whose username of 17 octets takes two
    // blocks of keystream (Annex C.4.3.2)
    let nai = kept(
        Suci::from_nai(concat!(
            "type1.rid678.schid1.hnkey27.",
            "ecckey977d8b2fdaa7b64aa700d04227d5b440630ea4ec50f9082273a26bb678c92222.",
            "cip8e358a1582adb15322c10e515141d2039a.mac12e1d7783a97f1ac@3gpp.com"
        ))
        .expect("the SUCI of Annex C.4.3.2"),
    );
    let secrets_nai = vec![
        secret("the home network private key", octets_a),
        secret(
            "the shared secret",
            &h("511c1df473bb88317f923501f8ba944fd3b667d25699dcb552dbcef60bbdc56d"),
        ),
        secret("the encryption key", &h("fe77b87d87f40428edd71bca69d79059")),
        secret(
            "the MAC key",
            &h("d87b69f4fe8cd6b211264ea5e69f682f151a82252684cdb15a047e6ef0595028"),
        ),
    ];
    cases.add(
        "Suci::deconceal, Profile A, a NAI",
        1,
        secrets_nai,
        move || {
            crate::here();
            let supi = spare(black_box(nai).deconceal(Some(black_box(private_a))));
            crate::owned(&supi);
            assert!(supi.is_ok(), "its key");
        },
    );
}
