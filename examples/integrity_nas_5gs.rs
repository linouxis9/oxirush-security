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

//! Demonstrate NAS integrity algorithms (NIA1, NIA2, NIA3) per TS 33.501.
//!
//! Each algorithm computes a 32-bit MAC over the same message, showing
//! how to use the unified `nas_mac()` function and the individual
//! `nia1_mac`, `nia2_mac`, `nia3_mac` functions.

use oxirush_security::nas_5gs::*;

fn main() {
    // Example 128-bit integrity key (KNASint)
    let key: [u8; 16] = [
        0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff,
        0x48,
    ];

    // NAS security parameters
    let count: u32 = 0x00a6f056; // 24-bit NAS COUNT
    let bearer: u8 = 0x01; // 3GPP access; use 2 for non-3GPP access
    let direction: u8 = 0; // 0 = uplink, 1 = downlink

    // Example NAS message payload
    let message = b"Hello 5G NAS integrity!";

    println!("=== NAS Integrity MAC computation ===\n");
    println!(
        "Key:       {}",
        key.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    println!("COUNT:     0x{count:08x}");
    println!("Bearer:    {bearer}");
    println!("Direction: {direction} (uplink)");
    println!("Message:   {:?}\n", String::from_utf8_lossy(message));

    // NIA1 — SNOW 3G (128-EIA1)
    let mac_nia1 = nas_mac(&key, count, bearer, direction, message, 0x01);
    println!("NIA1 (SNOW 3G)  MAC: 0x{mac_nia1:08x}");

    // NIA2 — AES-CMAC (128-EIA2)
    let mac_nia2 = nas_mac(&key, count, bearer, direction, message, 0x02);
    println!("NIA2 (AES-CMAC) MAC: 0x{mac_nia2:08x}");

    // NIA3 — ZUC (128-EIA3)
    let mac_nia3 = nas_mac(&key, count, bearer, direction, message, 0x03);
    println!("NIA3 (ZUC)      MAC: 0x{mac_nia3:08x}");

    // NIA0 — null integrity (always returns 0)
    let mac_nia0 = nas_mac(&key, count, bearer, direction, message, 0x00);
    println!("NIA0 (null)     MAC: 0x{mac_nia0:08x}");
    assert_eq!(mac_nia0, 0, "NIA0 must always return 0");

    // Each algorithm produces a different MAC for the same input
    assert_ne!(mac_nia1, mac_nia2);
    assert_ne!(mac_nia2, mac_nia3);
    println!("\nAll MACs computed successfully.");
}
