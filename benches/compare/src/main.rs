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

//! oxirush-security and the Rust crates that compute the same functions,
//! as `compare.sh` runs each:
//!
//! ```text
//! oxirush-security-compare <implementation> <case> <iterations>
//! ```
//!
//! The cases are `av`, an authentication vector of MILENAGE from K, OPc,
//! RAND, SQN and AMF, and `nea1` to `nia3`, the ciphering or the MAC of a
//! message of 1500 octets. The program does the case `iterations` times and
//! prints the nanoseconds, the allocations and the octets allocated per
//! operation, and the peak memory of the program in KiB.

use std::alloc::{GlobalAlloc, Layout, System};
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};
use std::time::Instant;

/// The allocator of the program, which counts the allocations and their
/// octets.
struct Counting;

static ALLOCATIONS: AtomicU64 = AtomicU64::new(0);
static OCTETS: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        OCTETS.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        unsafe { System.dealloc(pointer, layout) }
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        ALLOCATIONS.fetch_add(1, Relaxed);
        OCTETS.fetch_add(size as u64, Relaxed);
        unsafe { System.realloc(pointer, layout, size) }
    }
}

#[global_allocator]
static ALLOCATOR: Counting = Counting;

/// The inputs of every implementation: those of the 128-EEA2 and 128-EIA2
/// test sets of TS 33.401 annex C, and of MILENAGE test set 1 of TS 35.208.
const KEY: [u8; 16] = [
    0xd3, 0xc5, 0xd5, 0x92, 0x32, 0x7f, 0xb1, 0x1c, 0x40, 0x35, 0xc6, 0x68, 0x0a, 0xf8, 0xc6, 0xd1,
];
const COUNT: u32 = 0x398a_59b4;
const BEARER: u8 = 0x15;
const DIRECTION: u8 = 1;
const OPC: [u8; 16] = [
    0xcd, 0x63, 0xcb, 0x71, 0x95, 0x4a, 0x9f, 0x4e, 0x48, 0xa5, 0x99, 0x4e, 0x37, 0xa0, 0x2b, 0xaf,
];
const K: [u8; 16] = [
    0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
];
const RAND: [u8; 16] = [
    0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
];
const SQN: [u8; 6] = [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07];
const AMF: [u8; 2] = [0xb9, 0xb9];
const LENGTH: usize = 1500;

/// The peak memory of the program, in KiB.
fn peak_memory() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap_or_default();
    (status.lines())
        .find_map(|line| line.strip_prefix("VmHWM:"))
        .and_then(|kib| kib.trim().trim_end_matches("kB").trim().parse().ok())
        .unwrap_or(0)
}

/// Run `operation` `iterations` times, and print what one took.
fn timed<T>(iterations: u64, mut operation: impl FnMut() -> T) {
    black_box(operation());
    let (allocations, octets) = (ALLOCATIONS.load(Relaxed), OCTETS.load(Relaxed));
    let start = Instant::now();
    for _ in 0..iterations {
        black_box(operation());
    }
    let elapsed = start.elapsed().as_nanos() as f64;
    let operations = iterations as f64;
    println!(
        "{:.1} {:.2} {:.0} {}",
        elapsed / operations,
        (ALLOCATIONS.load(Relaxed) - allocations) as f64 / operations,
        (OCTETS.load(Relaxed) - octets) as f64 / operations,
        peak_memory()
    );
}

/// The IV of 128-EEA1 and of 128-EEA3: COUNT, then BEARER and DIRECTION,
/// twice (TS 33.401 annex B.1.2 and B.1.4).
fn iv() -> [u8; 16] {
    let mut iv = [0; 16];
    let fresh = (BEARER << 3) | (DIRECTION << 2);
    for half in [0, 8] {
        iv[half..half + 4].copy_from_slice(&COUNT.to_be_bytes());
        iv[half + 4] = fresh;
    }
    iv
}

fn oxirush_security(case: &str, iterations: u64) -> bool {
    use oxirush_security::milenage::{Amf, K as Key, Milenage, Opc, Sqn};
    use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection, nas_cipher, nas_mac};
    use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, Rand};
    let count = NasCount::new(COUNT & 0x00ff_ffff).expect("a NAS COUNT");
    let mut data = vec![0x5a_u8; LENGTH];
    let (enc, int) = (KNasEnc::new(&KEY), KNasInt::new(&KEY));
    let (access, direction) = (NasConnection::ThreeGpp, Direction::Downlink);
    let cipher =
        |algorithm, data: &mut [u8]| nas_cipher(&enc, count, access, direction, data, algorithm);
    let mac = |algorithm, data: &[u8]| nas_mac(&int, count, access, direction, data, algorithm);
    match case {
        "av" => {
            let (rand, sqn, amf) = (Rand::new(&RAND), Sqn::new(&SQN), Amf::new(&AMF));
            timed(iterations, || {
                let subscriber = Milenage::new(&Key::new(&K), &Opc::new(&OPC));
                subscriber.authentication_vector(&rand, &sqn, &amf)
            });
        }
        "nea1" => timed(iterations, || cipher(CipheringAlgorithm::NEA1, &mut data)),
        "nea2" => timed(iterations, || cipher(CipheringAlgorithm::NEA2, &mut data)),
        "nea3" => timed(iterations, || cipher(CipheringAlgorithm::NEA3, &mut data)),
        "nia1" => timed(iterations, || mac(IntegrityAlgorithm::NIA1, &data)),
        "nia2" => timed(iterations, || mac(IntegrityAlgorithm::NIA2, &data)),
        "nia3" => timed(iterations, || mac(IntegrityAlgorithm::NIA3, &data)),
        _ => return false,
    }
    true
}

/// An authentication vector of a `milenage` crate: f1 and f2345, and the
/// AUTN that SQN ⊕ AK, AMF and MAC-A make.
macro_rules! milenage_vector {
    ($krate:ident) => {
        || {
            let mut subscriber = $krate::Milenage::new_with_opc(K, OPC);
            let mac_a = subscriber.f1(&RAND, &SQN, &AMF);
            let (res, ck, ik, ak) = subscriber.f2345(&RAND);
            let mut autn = [0; 16];
            for (at, octet) in autn[..6].iter_mut().enumerate() {
                *octet = SQN[at] ^ ak[at];
            }
            autn[6..8].copy_from_slice(&AMF);
            autn[8..].copy_from_slice(&mac_a);
            (res, ck, ik, autn)
        }
    };
}

fn milenage_0_3(case: &str, iterations: u64) -> bool {
    case == "av" && {
        timed(iterations, milenage_vector!(milenage));
        true
    }
}

fn milenage_0_1(case: &str, iterations: u64) -> bool {
    case == "av" && {
        timed(iterations, milenage_vector!(milenage_0_1));
        true
    }
}

fn zuc_crate(case: &str, iterations: u64) -> bool {
    let mut data = vec![0x5a_u8; LENGTH];
    let bits = LENGTH * 8;
    match case {
        "nea3" => timed(iterations, || {
            zuc::eea3::eea3_xor_inplace(COUNT, BEARER, DIRECTION, &KEY, &mut data, bits)
        }),
        "nia3" => timed(iterations, || {
            zuc::eia3::Eia3Mac::compute(COUNT, BEARER, DIRECTION, &KEY, &data, bits)
        }),
        _ => return false,
    }
    true
}

/// The SNOW 3G and ZUC keystream generators of cryptography-rs, as
/// 128-EEA1 and 128-EEA3 use them; `constant_time` takes their variants
/// that read no table at an index from the state.
fn cryptography_rs(case: &str, iterations: u64, constant_time: bool) -> bool {
    use cryptography::{Snow3g, Snow3gCt, Zuc128, Zuc128Ct};
    let mut data = vec![0x5a_u8; LENGTH];
    let iv = iv();
    match (case, constant_time) {
        ("nea1", false) => timed(iterations, || Snow3g::new(&KEY, &iv).fill(&mut data)),
        ("nea1", true) => timed(iterations, || Snow3gCt::new(&KEY, &iv).fill(&mut data)),
        ("nea3", false) => timed(iterations, || Zuc128::new(&KEY, &iv).fill(&mut data)),
        ("nea3", true) => timed(iterations, || Zuc128Ct::new(&KEY, &iv).fill(&mut data)),
        _ => return false,
    }
    true
}

/// 128-EEA2 and 128-EIA2 of the RustCrypto crates: AES-CTR with the IV of
/// TS 33.401 annex B.1.3, and AES-CMAC over COUNT, BEARER, DIRECTION and
/// the message (B.2.3).
fn rustcrypto(case: &str, iterations: u64) -> bool {
    use aes::Aes128;
    use cmac::Mac;
    use ctr::cipher::{KeyIvInit, StreamCipher};
    let mut data = vec![0x5a_u8; LENGTH];
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&COUNT.to_be_bytes());
    iv[4] = (BEARER << 3) | (DIRECTION << 2);
    match case {
        "nea2" => timed(iterations, || {
            ctr::Ctr128BE::<Aes128>::new(&KEY.into(), &iv.into()).apply_keystream(&mut data)
        }),
        "nia2" => timed(iterations, || {
            let mut mac = <cmac::Cmac<Aes128> as Mac>::new(&KEY.into());
            mac.update(&iv[..8]);
            mac.update(&data);
            let tag = mac.finalize().into_bytes();
            u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]])
        }),
        _ => return false,
    }
    true
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let usage = "oxirush-security-compare <implementation> <case> <iterations>";
    let [implementation, case, iterations] = &arguments[..] else {
        panic!("{usage}");
    };
    let iterations = iterations.parse().expect("a number of iterations");
    let done = match implementation.as_str() {
        "oxirush-security" => oxirush_security(case, iterations),
        "milenage-0.3.1" => milenage_0_3(case, iterations),
        "milenage-0.1.6" => milenage_0_1(case, iterations),
        "zuc" => zuc_crate(case, iterations),
        "cryptography-rs" => cryptography_rs(case, iterations, false),
        "cryptography-rs-ct" => cryptography_rs(case, iterations, true),
        "rustcrypto" => rustcrypto(case, iterations),
        _ => panic!("{usage}"),
    };
    assert!(done, "{implementation} has no {case}");
}
