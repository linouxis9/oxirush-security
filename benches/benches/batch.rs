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

//! The time of several messages at once, each with its own key and COUNT,
//! as an AMF, an MME or a load generator has them.
//!
//! ```bash
//! cargo bench --bench batch                    # every case
//! cargo bench --bench batch -- 16x64           # sixteen messages of 64 octets
//! cargo bench --bench batch -- 128-EEA3/single # those whose name has it
//! ```
//!
//! A benchmark is `<messages>x<octets>/algorithm/form`. The form `single` is
//! one call of the single-message function for each message, and `batch`
//! one call of the function of several messages for all of them. The forms
//! `single-context` and `batch-context` do the same from a keyed context
//! for each message, which has what its algorithm computes from the key
//! alone.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use oxirush_security::nas_5gs::{KNasEnc, KNasInt};
use oxirush_security::{
    Bearer, CipherJob, CipheringAlgorithm, CipheringContext, Direction, IntegrityAlgorithm,
    IntegrityContext, MacJob, nea_cipher, nea_cipher_batch, nia_mac, nia_mac_batch,
};
use oxirush_security_benches::message;
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

const COUNT: u32 = 0x0000_1234;
const SIZES: [usize; 2] = [64, 1500];

/// The octets of a key for each message.
fn keys<const N: usize>() -> [[u8; 16]; N] {
    std::array::from_fn(|index| std::array::from_fn(|octet| (index * 16 + octet) as u8 ^ 0x2b))
}

fn ciphers_of<const N: usize>(criterion: &mut Criterion) {
    let (bearer, uplink) = (Bearer::ZERO, Direction::Uplink);
    for octets in SIZES {
        let mut group = criterion.benchmark_group(format!("{N}x{octets}"));
        group.throughput(Throughput::Bytes((N * octets) as u64));
        for (name, algorithm) in [
            ("128-EEA1", CipheringAlgorithm::Snow3g),
            ("128-EEA2", CipheringAlgorithm::Aes),
            ("128-EEA3", CipheringAlgorithm::Zuc),
        ] {
            let keys = keys::<N>().each_ref().map(KNasEnc::new);
            let contexts = keys
                .each_ref()
                .map(|key| CipheringContext::new(key, algorithm));
            let mut data: [Vec<u8>; N] = std::array::from_fn(|_| message(octets));
            group.bench_function(BenchmarkId::new(name, "single"), |bencher| {
                bencher.iter(|| {
                    for ((key, data), count) in keys.iter().zip(&mut data).zip(COUNT..) {
                        let data = black_box(data);
                        nea_cipher(black_box(key), count, bearer, uplink, data, algorithm);
                    }
                })
            });
            group.bench_function(BenchmarkId::new(name, "batch"), |bencher| {
                bencher.iter(|| {
                    let mut messages = keys.iter().zip(&mut data).zip(COUNT..);
                    let mut jobs: [CipherJob<'_>; N] = std::array::from_fn(|_| {
                        let ((key, data), count) = messages.next().expect("N messages");
                        CipherJob::new(black_box(key), count, bearer, uplink, data, algorithm)
                    });
                    nea_cipher_batch(black_box(&mut jobs));
                })
            });
            // A context saves the key expansion of AES, and nothing of the
            // two other algorithms
            if algorithm != CipheringAlgorithm::Aes {
                continue;
            }
            group.bench_function(BenchmarkId::new(name, "single-context"), |bencher| {
                bencher.iter(|| {
                    for ((context, data), count) in contexts.iter().zip(&mut data).zip(COUNT..) {
                        black_box(context).cipher(count, bearer, uplink, black_box(data));
                    }
                })
            });
            group.bench_function(BenchmarkId::new(name, "batch-context"), |bencher| {
                bencher.iter(|| {
                    let mut messages = contexts.iter().zip(&mut data).zip(COUNT..);
                    let mut jobs: [CipherJob<'_>; N] = std::array::from_fn(|_| {
                        let ((context, data), count) = messages.next().expect("N messages");
                        black_box(context).job(count, bearer, uplink, data)
                    });
                    nea_cipher_batch(black_box(&mut jobs));
                })
            });
        }
        group.finish();
    }
}

fn macs_of<const N: usize>(criterion: &mut Criterion) {
    let (bearer, uplink) = (Bearer::ZERO, Direction::Uplink);
    for octets in SIZES {
        let mut group = criterion.benchmark_group(format!("{N}x{octets}"));
        group.throughput(Throughput::Bytes((N * octets) as u64));
        for (name, algorithm) in [
            ("128-EIA1", IntegrityAlgorithm::Snow3g),
            ("128-EIA2", IntegrityAlgorithm::Aes),
            ("128-EIA3", IntegrityAlgorithm::Zuc),
        ] {
            let keys = keys::<N>().each_ref().map(KNasInt::new);
            let contexts = keys
                .each_ref()
                .map(|key| IntegrityContext::new(key, algorithm));
            let data: [Vec<u8>; N] = std::array::from_fn(|_| message(octets));
            group.bench_function(BenchmarkId::new(name, "single"), |bencher| {
                bencher.iter(|| {
                    let mut macs = 0;
                    for ((key, data), count) in keys.iter().zip(&data).zip(COUNT..) {
                        let data = black_box(data);
                        macs ^= nia_mac(black_box(key), count, bearer, uplink, data, algorithm);
                    }
                    macs
                })
            });
            group.bench_function(BenchmarkId::new(name, "batch"), |bencher| {
                bencher.iter(|| {
                    let mut messages = keys.iter().zip(&data).zip(COUNT..);
                    let mut jobs: [MacJob<'_>; N] = std::array::from_fn(|_| {
                        let ((key, data), count) = messages.next().expect("N messages");
                        MacJob::new(black_box(key), count, bearer, uplink, data, algorithm)
                    });
                    nia_mac_batch(black_box(&mut jobs));
                    jobs.iter()
                        .fold(0, |macs, job| macs ^ job.mac().unwrap_or(0))
                })
            });
            // A context saves the key expansion of AES and the subkeys of
            // CMAC, and nothing of the two other algorithms
            if algorithm != IntegrityAlgorithm::Aes {
                continue;
            }
            group.bench_function(BenchmarkId::new(name, "single-context"), |bencher| {
                bencher.iter(|| {
                    let mut macs = 0;
                    for ((context, data), count) in contexts.iter().zip(&data).zip(COUNT..) {
                        macs ^= black_box(context).mac(count, bearer, uplink, black_box(data));
                    }
                    macs
                })
            });
            group.bench_function(BenchmarkId::new(name, "batch-context"), |bencher| {
                bencher.iter(|| {
                    let mut messages = contexts.iter().zip(&data).zip(COUNT..);
                    let mut jobs: [MacJob<'_>; N] = std::array::from_fn(|_| {
                        let ((context, data), count) = messages.next().expect("N messages");
                        black_box(context).job(count, bearer, uplink, data)
                    });
                    nia_mac_batch(black_box(&mut jobs));
                    jobs.iter()
                        .fold(0, |macs, job| macs ^ job.mac().unwrap_or(0))
                })
            });
        }
        group.finish();
    }
}

fn ciphers(criterion: &mut Criterion) {
    ciphers_of::<4>(criterion);
    ciphers_of::<8>(criterion);
    ciphers_of::<16>(criterion);
}

fn macs(criterion: &mut Criterion) {
    macs_of::<4>(criterion);
    macs_of::<8>(criterion);
    macs_of::<16>(criterion);
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
    targets = ciphers, macs
}

/// The benchmarks, on the scalar code when the build has the hooks of the
/// crate and `FORM=scalar` is in the environment: what a processor without
/// the vector and AES instructions runs.
fn main() {
    let run = || {
        benches();
        Criterion::default().configure_from_args().final_summary();
    };
    #[cfg(oxirush_security_hooks)]
    if std::env::var("FORM").as_deref() == Ok("scalar") {
        return oxirush_security::hooks::scalar(run);
    }
    run();
}
