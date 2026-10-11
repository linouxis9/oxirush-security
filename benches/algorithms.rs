/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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

//! How long the algorithms and the key derivations take.
//!
//! ```bash
//! cargo bench --bench algorithms            # every case
//! cargo bench --bench algorithms -- EEA     # the cases whose name has "EEA"
//! ```
//!
//! Each case is timed in batches of about 20 ms, and the line shows the
//! fastest and the median batch, per call. The fastest is the one to
//! compare between two versions: what slows a batch down is the machine,
//! not the code. Pin the process to a core that does nothing else
//! (`taskset -c 3 cargo bench ...`) for figures that repeat.
//!
//! Without `--bench`, as `cargo test --benches` runs it, each case runs
//! once and nothing is timed.

use oxirush_security::nas_5gs::{derive_kamf, derive_kausf, derive_knas_int, derive_kseaf};
use oxirush_security::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher, nia_mac,
};
use std::hint::black_box;
use std::time::{Duration, Instant};

/// A batch lasts about this long.
const BATCH: Duration = Duration::from_millis(20);
/// Batches per case.
const BATCHES: usize = 25;

struct Bench {
    /// Whether to time, or to run each case once.
    timed: bool,
    /// Run the cases whose name contains this.
    filter: Option<String>,
}

impl Bench {
    fn case(&self, name: &str, octets: usize, mut call: impl FnMut()) {
        if self
            .filter
            .as_deref()
            .is_some_and(|filter| !name.contains(filter))
        {
            return;
        }
        if !self.timed {
            call();
            println!("{name}: ran once");
            return;
        }

        // The number of calls that fill a batch
        let mut calls: u32 = 1;
        loop {
            let start = Instant::now();
            for _ in 0..calls {
                call();
            }
            let elapsed = start.elapsed();
            if elapsed >= BATCH / 2 || calls >= 1 << 30 {
                break;
            }
            calls *= 2;
        }

        let mut batches: Vec<f64> = (0..BATCHES)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..calls {
                    call();
                }
                start.elapsed().as_nanos() as f64 / f64::from(calls)
            })
            .collect();
        batches.sort_by(f64::total_cmp);
        let (fastest, median) = (batches[0], batches[BATCHES / 2]);
        let rate = if octets == 0 {
            String::new()
        } else {
            format!(", {:7.1} MB/s", octets as f64 * 1e3 / fastest)
        };
        println!("{name:<34} {fastest:>10.1} ns fastest {median:>10.1} ns median{rate}");
    }
}

fn main() {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let bench = Bench {
        timed: arguments.iter().any(|argument| argument == "--bench"),
        filter: arguments
            .iter()
            .find(|argument| !argument.starts_with('-'))
            .cloned(),
    };

    let key = [0x2b; 16];
    let (count, bearer, direction) = (0x0000_1234, Bearer::ZERO, Direction::Uplink);

    // A short NAS message and one that fills an IP packet
    for octets in [64, 1500] {
        let mut data = vec![0x5a; octets];
        for (name, algorithm) in [
            ("128-EEA1 (SNOW 3G)", CipheringAlgorithm::Snow3g),
            ("128-EEA2 (AES-CTR)", CipheringAlgorithm::Aes),
            ("128-EEA3 (ZUC)", CipheringAlgorithm::Zuc),
        ] {
            bench.case(&format!("{name}, {octets} octets"), octets, || {
                nea_cipher(
                    black_box(&key),
                    count,
                    bearer,
                    direction,
                    black_box(&mut data),
                    algorithm,
                );
            });
        }
        for (name, algorithm) in [
            ("128-EIA1 (SNOW 3G)", IntegrityAlgorithm::Snow3g),
            ("128-EIA2 (AES-CMAC)", IntegrityAlgorithm::Aes),
            ("128-EIA3 (ZUC)", IntegrityAlgorithm::Zuc),
        ] {
            bench.case(&format!("{name}, {octets} octets"), octets, || {
                black_box(nia_mac(
                    black_box(&key),
                    count,
                    bearer,
                    direction,
                    black_box(&data),
                    algorithm,
                ));
            });
        }
    }

    // One HMAC-SHA-256 each
    let (ck, ik, sqn_xor_ak) = ([0x11; 16], [0x22; 16], [0x33; 6]);
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak).expect("a short name");
    let k_seaf = derive_kseaf(&k_ausf, sn_name).expect("a short name");
    let k_amf = derive_kamf(&k_seaf, "208930000000001", &[0, 0]).expect("a short SUPI");
    bench.case("KAUSF", 0, || {
        black_box(derive_kausf(black_box(&ck), &ik, sn_name, &sqn_xor_ak).expect("a short name"));
    });
    bench.case("KAMF", 0, || {
        black_box(
            derive_kamf(black_box(&k_seaf), "208930000000001", &[0, 0]).expect("a short SUPI"),
        );
    });
    bench.case("KNASint", 0, || {
        black_box(derive_knas_int(black_box(&k_amf), IntegrityAlgorithm::NIA2));
    });

    #[cfg(feature = "suci")]
    suci(&bench);
}

/// SUCI concealment and deconcealment of a five-octet MSIN.
#[cfg(feature = "suci")]
fn suci(bench: &Bench) {
    use oxirush_security::nas_5gs::{
        suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a, suci_scheme_output_b,
    };

    // The home network keys of TS 33.501 Annex C.4
    let private_a: [u8; 32] = [
        0xc5, 0x3c, 0x22, 0x20, 0x8b, 0x61, 0x86, 0x0b, 0x06, 0xc6, 0x2e, 0x54, 0x06, 0xa7, 0xb3,
        0x30, 0xc2, 0xb5, 0x77, 0xaa, 0x55, 0x58, 0x98, 0x15, 0x10, 0xd1, 0x28, 0x24, 0x7d, 0x38,
        0xbd, 0x1d,
    ];
    let public_a: [u8; 32] = [
        0x5a, 0x8d, 0x38, 0x86, 0x48, 0x20, 0x19, 0x7c, 0x33, 0x94, 0xb9, 0x26, 0x13, 0xb2, 0x0b,
        0x91, 0x63, 0x3c, 0xbd, 0x89, 0x71, 0x19, 0x27, 0x3b, 0xf8, 0xe4, 0xa6, 0xf4, 0xee, 0xc0,
        0xa6, 0x50,
    ];
    let private_b: [u8; 32] = [
        0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7, 0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68,
        0xb1, 0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac, 0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f,
        0xec, 0xda,
    ];
    let public_b: [u8; 33] = [
        0x02, 0x72, 0xda, 0x71, 0x97, 0x62, 0x34, 0xce, 0x83, 0x3a, 0x69, 0x07, 0x42, 0x58, 0x67,
        0xb8, 0x2e, 0x07, 0x4d, 0x44, 0xef, 0x90, 0x7d, 0xfb, 0x4b, 0x3e, 0x21, 0xc1, 0xc2, 0x25,
        0x6e, 0xbc, 0xd1,
    ];
    let msin = [0x00, 0x01, 0x20, 0x80, 0xf6];

    let output_a = suci_scheme_output_a(&msin, &public_a).expect("Profile A conceals");
    let output_b = suci_scheme_output_b(&msin, &public_b).expect("Profile B conceals");
    bench.case("SUCI Profile A, conceal", 0, || {
        black_box(suci_scheme_output_a(black_box(&msin), &public_a).expect("Profile A conceals"));
    });
    bench.case("SUCI Profile A, deconceal", 0, || {
        black_box(suci_decrypt_a(black_box(&output_a), &private_a).expect("its own output"));
    });
    bench.case("SUCI Profile B, conceal", 0, || {
        black_box(suci_scheme_output_b(black_box(&msin), &public_b).expect("Profile B conceals"));
    });
    bench.case("SUCI Profile B, deconceal", 0, || {
        black_box(suci_decrypt_b(black_box(&output_b), &private_b).expect("its own output"));
    });
}
