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

//! The time of the algorithms, the key derivations and SUCI, and their CPU
//! profile.
//!
//! ```bash
//! cargo bench --bench algorithms                      # every case
//! cargo bench --bench algorithms -- cipher/128-EEA1   # those whose name has it
//! cargo bench --bench algorithms -- --profile-time 10 cipher/128-EEA1/1500
//! go tool pprof -top target/criterion/cipher/128-EEA1/1500/profile/profile.pb
//! ```
//!
//! A benchmark is `group/algorithm/octets`: one call on a message of that
//! many octets, a short NAS message (64) or one that fills an IP packet
//! (1500). `cipher` and `mac` are the functions that take a key, and
//! `cipher-context` and `mac-context` the keyed contexts, which have the
//! round keys of AES and the subkeys of CMAC from one message to the next. With `--profile-time`, criterion runs the benchmark for that many
//! seconds under pprof, which samples the program a thousand times a second
//! and writes `profile.pb`, a profile that `go tool pprof` reads (`-top`,
//! `-list REGEX`, `-peek REGEX`). With `PROFILE=flamegraph` in the
//! environment it writes `flamegraph.svg` instead.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_security::nas_5gs::{
    HomeNetworkPrivateKey, HomeNetworkPublicKey, KNasEnc, KNasInt, Protection, Suci, Supi,
    derive_kamf, derive_kausf, derive_knas_int, derive_kseaf,
};
use oxirush_security::{
    Autn, Bearer, CipheringAlgorithm, CipheringContext, Ck, Direction, Ik, IntegrityAlgorithm,
    IntegrityContext, Plmn, nea_cipher, nia_mac,
};
use oxirush_security_benches::{PROFILE_A, PROFILE_B, message};
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

const KEY: [u8; 16] = [0x2b; 16];
const COUNT: u32 = 0x0000_1234;
const SIZES: [usize; 2] = [64, 1500];

fn ciphers(criterion: &mut Criterion) {
    let key = KNasEnc::new(&KEY);
    for form in ["cipher", "cipher-context"] {
        let mut group = criterion.benchmark_group(form);
        for (name, algorithm) in [
            ("128-EEA1", CipheringAlgorithm::Snow3g),
            ("128-EEA2", CipheringAlgorithm::Aes),
            ("128-EEA3", CipheringAlgorithm::Zuc),
        ] {
            let context = CipheringContext::new(&key, algorithm);
            for octets in SIZES {
                let mut data = message(octets);
                group.throughput(Throughput::Bytes(octets as u64));
                let (bearer, uplink) = (Bearer::ZERO, Direction::Uplink);
                group.bench_function(BenchmarkId::new(name, octets), |bencher| match form {
                    "cipher" => bencher.iter(|| {
                        let data = black_box(&mut data);
                        nea_cipher(black_box(&key), COUNT, bearer, uplink, data, algorithm)
                    }),
                    _ => bencher.iter(|| {
                        black_box(&context).cipher(COUNT, bearer, uplink, black_box(&mut data))
                    }),
                });
            }
        }
        group.finish();
    }
}

fn macs(criterion: &mut Criterion) {
    let key = KNasInt::new(&KEY);
    for form in ["mac", "mac-context"] {
        let mut group = criterion.benchmark_group(form);
        for (name, algorithm) in [
            ("128-EIA1", IntegrityAlgorithm::Snow3g),
            ("128-EIA2", IntegrityAlgorithm::Aes),
            ("128-EIA3", IntegrityAlgorithm::Zuc),
        ] {
            let context = IntegrityContext::new(&key, algorithm);
            for octets in SIZES {
                let data = message(octets);
                group.throughput(Throughput::Bytes(octets as u64));
                let (bearer, uplink) = (Bearer::ZERO, Direction::Uplink);
                group.bench_function(BenchmarkId::new(name, octets), |bencher| match form {
                    "mac" => bencher.iter(|| {
                        let data = black_box(&data);
                        nia_mac(black_box(&key), COUNT, bearer, uplink, data, algorithm)
                    }),
                    _ => bencher
                        .iter(|| black_box(&context).mac(COUNT, bearer, uplink, black_box(&data))),
                });
            }
        }
        group.finish();
    }
}

/// Each is one HMAC-SHA-256. The keys that a derivation returns are wiped
/// when they are dropped, which the times include.
fn key_derivations(criterion: &mut Criterion) {
    let (ck, ik) = (Ck::new(&[0x11; 16]), Ik::new(&[0x22; 16]));
    let autn = Autn::new(&[0x33; 16]);
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let supi = Supi::imsi("208930000000001").expect("an IMSI");
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &autn).expect("a short name");
    let k_seaf = derive_kseaf(&k_ausf, sn_name).expect("a short name");
    let k_amf = derive_kamf(&k_seaf, &supi, &[0, 0]).expect("an ABBA of two octets");

    let mut group = criterion.benchmark_group("kdf");
    group.bench_function("KAUSF", |bencher| {
        bencher.iter(|| derive_kausf(black_box(&ck), &ik, sn_name, &autn))
    });
    group.bench_function("KAMF", |bencher| {
        bencher.iter(|| derive_kamf(black_box(&k_seaf), &supi, &[0, 0]))
    });
    group.bench_function("KNASint", |bencher| {
        bencher.iter(|| derive_knas_int(black_box(&k_amf), IntegrityAlgorithm::NIA2))
    });
    group.finish();
}

/// Concealment and de-concealment of an IMSI whose MSIN has nine digits,
/// five octets in BCD: `Suci::conceal_imsi`, and `Suci::deconceal` of a
/// SUCI that is read already.
fn suci(criterion: &mut Criterion) {
    let plmn = Plmn::new("274", "012").expect("an MCC and an MNC");
    let ((private_a, public_a), (private_b, public_b)) = (PROFILE_A, PROFILE_B);
    let private_a = HomeNetworkPrivateKey::profile_a(&private_a);
    let public_a = HomeNetworkPublicKey::profile_a(&public_a);
    let private_b = HomeNetworkPrivateKey::profile_b(&private_b).expect("a key of Profile B");
    let public_b = HomeNetworkPublicKey::profile_b(&public_b).expect("a key of Profile B");
    let conceal = |key| {
        let protection = Protection::Ecies { key_id: 1, key };
        Suci::conceal_imsi(plmn, black_box("001002086"), "0", protection)
    };
    let suci_a = conceal(&public_a).expect("Profile A conceals");
    let suci_b = conceal(&public_b).expect("Profile B conceals");

    let mut group = criterion.benchmark_group("suci");
    group.bench_function("profile-a/conceal", |bencher| {
        bencher.iter(|| conceal(&public_a))
    });
    group.bench_function("profile-a/deconceal", |bencher| {
        bencher.iter(|| black_box(&suci_a).deconceal(Some(&private_a)))
    });
    group.bench_function("profile-b/conceal", |bencher| {
        bencher.iter(|| conceal(&public_b))
    });
    group.bench_function("profile-b/deconceal", |bencher| {
        bencher.iter(|| black_box(&suci_b).deconceal(Some(&private_b)))
    });
    group.finish();
}

fn configuration() -> Criterion {
    let output = match std::env::var("PROFILE").as_deref() {
        Ok("flamegraph") => Output::Flamegraph(None),
        _ => Output::Protobuf,
    };
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
        .with_profiler(PProfProfiler::new(1000, output))
}

criterion_group! {
    name = benches;
    config = configuration();
    targets = ciphers, macs, key_derivations, suci
}
criterion_main!(benches);
