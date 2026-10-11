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
//! (1500). With `--profile-time`, criterion runs the benchmark for that many
//! seconds under pprof, which samples the program a thousand times a second
//! and writes `profile.pb`, a profile that `go tool pprof` reads (`-top`,
//! `-list REGEX`, `-peek REGEX`). With `PROFILE=flamegraph` in the
//! environment it writes `flamegraph.svg` instead.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_security::nas_5gs::{
    derive_kamf, derive_kausf, derive_knas_int, derive_kseaf, suci_decrypt_a, suci_decrypt_b,
    suci_scheme_output_a, suci_scheme_output_b,
};
use oxirush_security::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher, nia_mac,
};
use oxirush_security_benches::{PROFILE_A, PROFILE_B, message};
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

const KEY: [u8; 16] = [0x2b; 16];
const COUNT: u32 = 0x0000_1234;
const SIZES: [usize; 2] = [64, 1500];

fn ciphers(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("cipher");
    for (name, algorithm) in [
        ("128-EEA1", CipheringAlgorithm::Snow3g),
        ("128-EEA2", CipheringAlgorithm::Aes),
        ("128-EEA3", CipheringAlgorithm::Zuc),
    ] {
        for octets in SIZES {
            let mut data = message(octets);
            group.throughput(Throughput::Bytes(octets as u64));
            group.bench_function(BenchmarkId::new(name, octets), |bencher| {
                bencher.iter(|| {
                    nea_cipher(
                        black_box(&KEY),
                        COUNT,
                        Bearer::ZERO,
                        Direction::Uplink,
                        black_box(&mut data),
                        algorithm,
                    )
                })
            });
        }
    }
    group.finish();
}

fn macs(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("mac");
    for (name, algorithm) in [
        ("128-EIA1", IntegrityAlgorithm::Snow3g),
        ("128-EIA2", IntegrityAlgorithm::Aes),
        ("128-EIA3", IntegrityAlgorithm::Zuc),
    ] {
        for octets in SIZES {
            let data = message(octets);
            group.throughput(Throughput::Bytes(octets as u64));
            group.bench_function(BenchmarkId::new(name, octets), |bencher| {
                bencher.iter(|| {
                    nia_mac(
                        black_box(&KEY),
                        COUNT,
                        Bearer::ZERO,
                        Direction::Uplink,
                        black_box(&data),
                        algorithm,
                    )
                })
            });
        }
    }
    group.finish();
}

/// Each is one HMAC-SHA-256.
fn key_derivations(criterion: &mut Criterion) {
    let (ck, ik, sqn_xor_ak) = ([0x11; 16], [0x22; 16], [0x33; 6]);
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak).expect("a short name");
    let k_seaf = derive_kseaf(&k_ausf, sn_name).expect("a short name");
    let k_amf = derive_kamf(&k_seaf, "208930000000001", &[0, 0]).expect("a short SUPI");

    let mut group = criterion.benchmark_group("kdf");
    group.bench_function("KAUSF", |bencher| {
        bencher.iter(|| derive_kausf(black_box(&ck), &ik, sn_name, &sqn_xor_ak))
    });
    group.bench_function("KAMF", |bencher| {
        bencher.iter(|| derive_kamf(black_box(&k_seaf), "208930000000001", &[0, 0]))
    });
    group.bench_function("KNASint", |bencher| {
        bencher.iter(|| derive_knas_int(black_box(&k_amf), IntegrityAlgorithm::NIA2))
    });
    group.finish();
}

/// Concealment and deconcealment of a five-octet MSIN.
fn suci(criterion: &mut Criterion) {
    let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];
    let ((private_a, public_a), (private_b, public_b)) = (PROFILE_A, PROFILE_B);
    let output_a = suci_scheme_output_a(&msin, &public_a).expect("Profile A conceals");
    let output_b = suci_scheme_output_b(&msin, &public_b).expect("Profile B conceals");

    let mut group = criterion.benchmark_group("suci");
    group.bench_function("profile-a/conceal", |bencher| {
        bencher.iter(|| suci_scheme_output_a(black_box(&msin), &public_a))
    });
    group.bench_function("profile-a/deconceal", |bencher| {
        bencher.iter(|| suci_decrypt_a(black_box(&output_a), &private_a))
    });
    group.bench_function("profile-b/conceal", |bencher| {
        bencher.iter(|| suci_scheme_output_b(black_box(&msin), &public_b))
    });
    group.bench_function("profile-b/deconceal", |bencher| {
        bencher.iter(|| suci_decrypt_b(black_box(&output_b), &private_b))
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
