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

//! Demonstrate the NAS integrity algorithms of 5GS (NIA0, 128-NIA1,
//! 128-NIA2 and 128-NIA3) per TS 33.501.
//!
//! `nas_mac` computes the 32-bit MAC of the same message with each
//! algorithm.

use oxirush_security::nas_5gs::*;

fn main() {
    // Example 128-bit integrity key (KNASint)
    let key: [u8; 16] = [
        0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff,
        0x48,
    ];

    // The inputs of a NAS message: its 24-bit NAS COUNT, the NAS connection
    // (3GPP or non-3GPP access) and its direction
    let count = NasCount::new(0x00a6f056).expect("a 24-bit NAS COUNT");
    let connection = NasConnection::ThreeGpp;
    let direction = Direction::Uplink;

    // Example NAS message payload
    let message = b"Hello 5G NAS integrity!";

    println!("=== NAS Integrity MAC computation ===\n");
    println!("Key:       {}", hex::encode(key));
    println!("COUNT:     0x{:08x}", count.get());
    println!("Bearer:    {} (3GPP access)", u8::from(connection));
    println!("Direction: {} (uplink)", u8::from(direction));
    println!("Message:   {:?}\n", String::from_utf8_lossy(message));

    // One call for every algorithm
    let mac = |algorithm| nas_mac(&key, count, connection, direction, message, algorithm);

    // NIA1 — SNOW 3G (128-EIA1)
    let mac_nia1 = mac(IntegrityAlgorithm::NIA1);
    println!("NIA1 (SNOW 3G)  MAC: 0x{mac_nia1:08x}");

    // NIA2 — AES-CMAC (128-EIA2)
    let mac_nia2 = mac(IntegrityAlgorithm::NIA2);
    println!("NIA2 (AES-CMAC) MAC: 0x{mac_nia2:08x}");

    // NIA3 — ZUC (128-EIA3)
    let mac_nia3 = mac(IntegrityAlgorithm::NIA3);
    println!("NIA3 (ZUC)      MAC: 0x{mac_nia3:08x}");

    // NIA0 — null integrity (always returns 0)
    let mac_nia0 = mac(IntegrityAlgorithm::NIA0);
    println!("NIA0 (null)     MAC: 0x{mac_nia0:08x}");
    assert_eq!(mac_nia0, 0, "NIA0 must always return 0");

    // Each algorithm produces a different MAC for the same input
    assert_ne!(mac_nia1, mac_nia2);
    assert_ne!(mac_nia2, mac_nia3);

    println!("\nAll MACs computed successfully.");
}
