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

//! The time of MILENAGE for one subscriber, beside that of the `milenage`
//! crate 0.1.6.
//!
//! ```sh
//! cargo bench --bench milenage                  # every case
//! cargo bench --bench milenage -- f2345         # those whose name has it
//! ```
//!
//! A benchmark is `milenage/implementation/function`: one call, from K and
//! OPc. `milenage/N/function/form` is the vectors or the AUTN checks of N
//! subscribers, each with its K: `single` is a call for each, `batch` one
//! call of `authentication_vector_batch` or `check_autn_batch` for all. `oxirush` is this crate, on the AES instructions of the processor
//! where it has them; `milenage-0.1.6` is the `milenage` crate, whose AES is
//! that of the `aes` crate 0.8, which finds the AES instructions itself.
//! With the hooks of the crate and `FORM=scalar`, this crate runs its code
//! for a processor without them: the `aes` crate 0.9, which finds the
//! instructions too unless it is built with `--cfg aes_backend="soft"`, as
//! the `aes` crate 0.8 is with `--cfg aes_force_soft`.

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group};
use oxirush_security::milenage::{
    Amf, AutnJob, Auts, K, Milenage, Op, Opc, Sqn, VectorJob, authentication_vector_batch,
    check_autn_batch,
};
use oxirush_security::{Autn, Rand};
use pprof::criterion::{Output, PProfProfiler};
use std::hint::black_box;
use std::time::Duration;

/// TS 35.208 test set 1.
const K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
const OP: [u8; 16] = [
    0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18,
];
const OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];
const RAND: [u8; 16] = [
    0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
];
const SQN: [u8; 6] = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
const AMF: [u8; 2] = [0xb9, 0xb9];

fn oxirush(criterion: &mut Criterion) {
    let (k, op, opc) = (K::new(&K), Op::new(&OP), Opc::new(&OPC));
    let (rand, sqn, amf) = (Rand::new(&RAND), Sqn::new(&SQN), Amf::new(&AMF));
    let subscriber = Milenage::new(&k, &opc);
    let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
    let auts: Auts = subscriber.auts(&rand, &sqn);

    let mut group = criterion.benchmark_group("milenage/oxirush");
    group.bench_function("opc", |bencher| {
        bencher.iter(|| Opc::from_op(black_box(&k), black_box(&op)))
    });
    // The subscriber is made for each call, as a program that keeps K and
    // OPc and not the subscriber does
    group.bench_function("f1", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).f1(&rand, &sqn, &amf))
    });
    group.bench_function("f2345", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).f2345(&rand))
    });
    group.bench_function("vector", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).authentication_vector(&rand, &sqn, &amf))
    });
    group.bench_function("check-autn", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).check_autn(&rand, vector.autn()))
    });
    group.bench_function("auts", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).auts(&rand, &sqn))
    });
    group.bench_function("verify-auts", |bencher| {
        bencher.iter(|| Milenage::new(black_box(&k), &opc).verify_auts(&rand, &auts))
    });
    group.finish();
}

/// The same with the `milenage` crate: the AUTN and the AUTS from its
/// functions, as its users write them.
fn milenage_0_1_6(criterion: &mut Criterion) {
    let mut group = criterion.benchmark_group("milenage/milenage-0.1.6");
    group.bench_function("opc", |bencher| {
        bencher.iter(|| milenage::Milenage::new_with_op(black_box(K), OP).opc)
    });
    group.bench_function("f1", |bencher| {
        bencher.iter(|| milenage::Milenage::new_with_opc(black_box(K), OPC).f1(&RAND, &SQN, &AMF))
    });
    group.bench_function("f2345", |bencher| {
        bencher.iter(|| milenage::Milenage::new_with_opc(black_box(K), OPC).f2345(&RAND))
    });
    group.bench_function("vector", |bencher| {
        bencher.iter(|| {
            let mut subscriber = milenage::Milenage::new_with_opc(black_box(K), OPC);
            let (xres, ck, ik, ak) = subscriber.f2345(&RAND);
            let mac_a = subscriber.f1(&RAND, &SQN, &AMF);
            let mut autn = [0u8; 16];
            for (at, octet) in autn[..6].iter_mut().enumerate() {
                *octet = SQN[at] ^ ak[at];
            }
            autn[6..8].copy_from_slice(&AMF);
            autn[8..].copy_from_slice(&mac_a);
            (xres, ck, ik, autn)
        })
    });
    group.bench_function("auts", |bencher| {
        bencher.iter(|| {
            let mut subscriber = milenage::Milenage::new_with_opc(black_box(K), OPC);
            let ak_star = subscriber.f5star(&RAND);
            let mac_s = subscriber.f1star(&RAND, &SQN, &[0, 0]);
            let mut auts = [0u8; 14];
            for (at, octet) in auts[..6].iter_mut().enumerate() {
                *octet = SQN[at] ^ ak_star[at];
            }
            auts[6..].copy_from_slice(&mac_s);
            auts
        })
    });
    group.finish();
}

/// N subscribers, each with its K, its OPc and its RAND.
fn subscribers(n: usize) -> Vec<(Milenage, Rand)> {
    (0..n)
        .map(|index| {
            let mut k = K;
            k[0] ^= index as u8;
            k[1] ^= (index >> 8) as u8;
            let mut rand = RAND;
            rand[15] ^= index as u8;
            (
                Milenage::new(&K::new(&k), &Opc::new(&OPC)),
                Rand::new(&rand),
            )
        })
        .collect()
}

fn batches(criterion: &mut Criterion) {
    let (sqn, amf) = (Sqn::new(&SQN), Amf::new(&AMF));
    for n in [1, 4, 8, 64, 1024] {
        let subscribers = subscribers(n);
        let autns: Vec<Autn> = subscribers
            .iter()
            .map(|(subscriber, rand)| {
                subscriber
                    .authentication_vector(rand, &sqn, &amf)
                    .autn()
                    .clone()
            })
            .collect();
        let mut group = criterion.benchmark_group(format!("milenage/{n}"));
        group.throughput(Throughput::Elements(n as u64));
        group.bench_function(BenchmarkId::new("vector", "single"), |bencher| {
            bencher.iter(|| {
                for (subscriber, rand) in black_box(&subscribers) {
                    black_box(subscriber.authentication_vector(rand, &sqn, &amf));
                }
            })
        });
        group.bench_function(BenchmarkId::new("vector", "batch"), |bencher| {
            bencher.iter(|| {
                let mut jobs: Vec<VectorJob<'_>> = black_box(&subscribers)
                    .iter()
                    .map(|(subscriber, rand)| VectorJob::new(subscriber, rand, &sqn, &amf))
                    .collect();
                authentication_vector_batch(&mut jobs);
                jobs
            })
        });
        group.bench_function(BenchmarkId::new("check-autn", "single"), |bencher| {
            bencher.iter(|| {
                for ((subscriber, rand), autn) in black_box(&subscribers).iter().zip(&autns) {
                    let _ = black_box(subscriber.check_autn(rand, autn));
                }
            })
        });
        group.bench_function(BenchmarkId::new("check-autn", "batch"), |bencher| {
            bencher.iter(|| {
                let mut jobs: Vec<AutnJob<'_>> = (black_box(&subscribers).iter().zip(&autns))
                    .map(|((subscriber, rand), autn)| AutnJob::new(subscriber, rand, autn))
                    .collect();
                check_autn_batch(&mut jobs);
                jobs
            })
        });
        group.finish();
    }
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
    targets = oxirush, milenage_0_1_6, batches
}

/// The benchmarks, on the code of a processor without the AES
/// instructions when the build has the hooks of the crate and
/// `FORM=scalar` is in the environment.
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
