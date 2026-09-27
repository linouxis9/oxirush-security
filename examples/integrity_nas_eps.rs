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

//! Demonstrate EPS NAS integrity algorithms (EIA1, EIA2, EIA3) per TS 33.401.
//!
//! Each algorithm computes a 32-bit MAC over the same message with the EPS
//! NAS bearer 0, and the SERVICE REQUEST short MAC takes its two least
//! significant octets (TS 24.301 §9.9.3.28).

use oxirush_security::nas_eps::*;

fn main() {
    // Example 128-bit integrity key (KNASint)
    let key: [u8; 16] = [
        0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff,
        0x48,
    ];

    // NAS security parameters; the EPS NAS bearer is always 0
    let count: u32 = 0x00a6f056; // 24-bit NAS COUNT
    let direction: u8 = 0; // 0 = uplink, 1 = downlink

    // Sequence number followed by an EMM STATUS message
    let message = [0x56, 0x07, 0x60, 0x03];

    println!("=== EPS NAS integrity MAC computation ===\n");
    println!("Key:       {}", hex::encode(key));
    println!("COUNT:     0x{count:08x}");
    println!("Direction: {direction} (uplink)");
    println!("Message:   {}\n", hex::encode(message));

    // EIA1 — SNOW 3G (128-EIA1)
    let mac_eia1 = nas_mac(&key, count, direction, &message, 0x01);
    println!("EIA1 (SNOW 3G)  MAC: 0x{mac_eia1:08x}");

    // EIA2 — AES-CMAC (128-EIA2)
    let mac_eia2 = nas_mac(&key, count, direction, &message, 0x02);
    println!("EIA2 (AES-CMAC) MAC: 0x{mac_eia2:08x}");

    // EIA3 — ZUC (128-EIA3)
    let mac_eia3 = nas_mac(&key, count, direction, &message, 0x03);
    println!("EIA3 (ZUC)      MAC: 0x{mac_eia3:08x}");

    // EIA0 — null integrity (always returns 0)
    let mac_eia0 = nas_mac(&key, count, direction, &message, 0x00);
    println!("EIA0 (null)     MAC: 0x{mac_eia0:08x}");
    assert_eq!(mac_eia0, 0, "EIA0 must always return 0");

    // SERVICE REQUEST: KSI 1, five COUNT bits 0x16
    let short_mac = service_request_short_mac(&key, count, direction, (1 << 5) | 0x16, 0x02);
    println!("SERVICE REQUEST short MAC (EIA2): 0x{short_mac:04x}");

    assert_ne!(mac_eia1, mac_eia2);
    assert_ne!(mac_eia2, mac_eia3);
    println!("\nAll MACs computed successfully.");
}
