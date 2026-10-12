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
//! A benchmark is `<messages>x<octets>/algorithm/single`: one call of the
//! function of one message for each message.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_security::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher, nia_mac,
};
use oxirush_security_benches::message;
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

const COUNT: u32 = 0x0000_1234;
const SIZES: [usize; 2] = [64, 1500];

/// A key for each message.
fn keys<const N: usize>() -> [[u8; 16]; N] {
    std::array::from_fn(|index| std::array::from_fn(|octet| (index * 16 + octet) as u8 ^ 0x2b))
}

fn ciphers_of<const N: usize>(criterion: &mut Criterion) {
    for octets in SIZES {
        let mut group = criterion.benchmark_group(format!("{N}x{octets}"));
        group.throughput(Throughput::Bytes((N * octets) as u64));
        for (name, algorithm) in [
            ("128-EEA1", CipheringAlgorithm::Snow3g),
            ("128-EEA2", CipheringAlgorithm::Aes),
            ("128-EEA3", CipheringAlgorithm::Zuc),
        ] {
            let keys = keys::<N>();
            let mut data: [Vec<u8>; N] = std::array::from_fn(|_| message(octets));
            group.bench_function(BenchmarkId::new(name, "single"), |bencher| {
                bencher.iter(|| {
                    for ((key, data), count) in keys.iter().zip(&mut data).zip(COUNT..) {
                        nea_cipher(
                            black_box(key),
                            count,
                            Bearer::ZERO,
                            Direction::Uplink,
                            black_box(data),
                            algorithm,
                        );
                    }
                })
            });
        }
        group.finish();
    }
}

fn macs_of<const N: usize>(criterion: &mut Criterion) {
    for octets in SIZES {
        let mut group = criterion.benchmark_group(format!("{N}x{octets}"));
        group.throughput(Throughput::Bytes((N * octets) as u64));
        for (name, algorithm) in [
            ("128-EIA1", IntegrityAlgorithm::Snow3g),
            ("128-EIA2", IntegrityAlgorithm::Aes),
            ("128-EIA3", IntegrityAlgorithm::Zuc),
        ] {
            let keys = keys::<N>();
            let data: [Vec<u8>; N] = std::array::from_fn(|_| message(octets));
            group.bench_function(BenchmarkId::new(name, "single"), |bencher| {
                bencher.iter(|| {
                    let mut macs = 0;
                    for ((key, data), count) in keys.iter().zip(&data).zip(COUNT..) {
                        macs ^= nia_mac(
                            black_box(key),
                            count,
                            Bearer::ZERO,
                            Direction::Uplink,
                            black_box(data),
                            algorithm,
                        );
                    }
                    macs
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
criterion_main!(benches);
