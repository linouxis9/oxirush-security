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

//! Demonstrate EPS NAS integrity algorithms (EIA1, EIA2, EIA3) per TS 33.401.
//!
//! Each algorithm computes a 32-bit MAC over the same message with the EPS
//! NAS bearer 0, and the SERVICE REQUEST short MAC takes its two least
//! significant octets (TS 24.301 §9.9.3.28).

use oxirush_security::nas_eps::{KNasInt, nas_mac, service_request_short_mac};
use oxirush_security::{Direction, IntegrityAlgorithm, NasCount};

fn main() {
    // Example 128-bit integrity key (KNASint)
    let key = KNasInt::new([
        0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff,
        0x48,
    ]);

    // The inputs of a NAS message: its 24-bit NAS COUNT and its direction.
    // The EPS NAS bearer is always 0
    let count = NasCount::new(0x00a6f056).expect("a 24-bit NAS COUNT");
    let direction = Direction::Uplink;

    // Sequence number followed by an EMM STATUS message
    let message = [0x56, 0x07, 0x60, 0x03];

    println!("=== EPS NAS integrity MAC computation ===\n");
    println!("Key:       {}", hex::encode(key.as_octets()));
    println!("COUNT:     0x{:08x}", count.get());
    println!("Direction: {} (uplink)", u8::from(direction));
    println!("Message:   {}\n", hex::encode(message));

    // One call for every algorithm
    let mac = |algorithm| nas_mac(&key, count, direction, &message, algorithm);

    let algorithms = [
        IntegrityAlgorithm::EIA1, // SNOW 3G
        IntegrityAlgorithm::EIA2, // AES-CMAC
        IntegrityAlgorithm::EIA3, // ZUC
        IntegrityAlgorithm::EIA0, // null integrity: the MAC is zero
    ];
    for algorithm in algorithms {
        println!("{:<8} MAC: 0x{:08x}", algorithm.name_eps(), mac(algorithm));
    }
    assert_eq!(
        mac(IntegrityAlgorithm::EIA0),
        0,
        "EIA0 must always return 0"
    );

    // SERVICE REQUEST: KSI 1, and the five low bits of the NAS COUNT, 0x16
    let ksi_and_sequence_number = (1 << 5) | 0x16;
    let short_mac = service_request_short_mac(
        &key,
        count,
        direction,
        ksi_and_sequence_number,
        IntegrityAlgorithm::EIA2,
    );
    println!("SERVICE REQUEST short MAC (EIA2): 0x{short_mac:04x}");

    // The MME has the NAS COUNT of the SERVICE REQUEST from those five bits
    // and from the lowest uplink NAS COUNT that it still accepts
    let lowest = NasCount::new(0x00a6f050).expect("a 24-bit NAS COUNT");
    let estimated = lowest.estimate_from_low_bits(ksi_and_sequence_number, 5);
    assert_eq!(estimated, Ok(count));

    // Each algorithm produces a different MAC for the same input
    assert_ne!(mac(IntegrityAlgorithm::EIA1), mac(IntegrityAlgorithm::EIA2));
    assert_ne!(mac(IntegrityAlgorithm::EIA2), mac(IntegrityAlgorithm::EIA3));

    println!("\nAll MACs computed successfully.");
}
