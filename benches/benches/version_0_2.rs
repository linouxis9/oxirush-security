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

//! The algorithms and a key derivation of oxirush-security 0.2.0, from
//! crates.io, on the messages and with the configuration of `algorithms`:
//! the columns of 0.2.0 in `README.md`.
//!
//! ```sh
//! cargo bench --bench version_0_2
//! ```
//!
//! A benchmark is `group/algorithm/octets` as in `algorithms`, under the
//! group `0.2.0/cipher`, `0.2.0/mac` or `0.2.0/kdf`.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use oxirush_security_0_2 as previous;
use oxirush_security_benches::message;
use std::hint::black_box;
use std::time::Duration;

const KEY: [u8; 16] = [0x2b; 16];
const COUNT: u32 = 0x0000_1234;
const SIZES: [usize; 2] = [64, 1500];

fn ciphers(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("0.2.0/cipher");
    for (name, algorithm) in [("128-EEA1", 1), ("128-EEA2", 2), ("128-EEA3", 3)] {
        for octets in SIZES {
            let mut data = message(octets);
            group.throughput(Throughput::Bytes(octets as u64));
            group.bench_function(BenchmarkId::new(name, octets), |bencher| {
                bencher.iter(|| {
                    let data = black_box(&mut data);
                    previous::nas_cipher(black_box(&KEY), COUNT, 0, 0, data, algorithm)
                })
            });
        }
    }
    group.finish();
}

fn macs(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("0.2.0/mac");
    for (name, algorithm) in [("128-EIA1", 1), ("128-EIA2", 2), ("128-EIA3", 3)] {
        for octets in SIZES {
            let data = message(octets);
            group.throughput(Throughput::Bytes(octets as u64));
            group.bench_function(BenchmarkId::new(name, octets), |bencher| {
                bencher.iter(|| {
                    let data = black_box(&data);
                    previous::nas_mac(black_box(&KEY), COUNT, 0, 0, data, algorithm)
                })
            });
        }
    }
    group.finish();
}

/// KNASint of 128-NIA2 from KAMF, one HMAC-SHA-256.
fn key_derivations(criterion: &mut Criterion) {
    let k_amf = [0x11; 32];
    let mut group = criterion.benchmark_group("0.2.0/kdf");
    group.bench_function("KNASint", |bencher| {
        bencher.iter(|| previous::nas_5gs::kdf::derive_nas_key(black_box(&k_amf), 0x02, 2))
    });
    group.finish();
}

fn configuration() -> Criterion {
    Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2))
}

criterion_group! {
    name = benches;
    config = configuration();
    targets = ciphers, macs, key_derivations
}
criterion_main!(benches);
