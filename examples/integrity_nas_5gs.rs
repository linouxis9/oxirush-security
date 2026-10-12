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
//! algorithm, and a keyed context gives the same.

use oxirush_security::nas_5gs::{KNasInt, NasConnection, nas_mac};
use oxirush_security::{Direction, IntegrityAlgorithm, IntegrityContext, NasCount};

fn main() {
    // Example 128-bit integrity key (KNASint)
    let key = KNasInt::new(&[
        0x2b, 0xd6, 0x45, 0x9f, 0x82, 0xc5, 0xb3, 0x00, 0x95, 0x2c, 0x49, 0x10, 0x48, 0x81, 0xff,
        0x48,
    ]);

    // The inputs of a NAS message: its 24-bit NAS COUNT, the NAS connection
    // (3GPP or non-3GPP access) and its direction
    let count = NasCount::new(0x00a6f056).expect("a 24-bit NAS COUNT");
    let connection = NasConnection::ThreeGpp;
    let direction = Direction::Uplink;

    // Example NAS message payload
    let message = b"Hello 5G NAS integrity!";

    println!("=== NAS Integrity MAC computation ===\n");
    // A key shows its name and not its octets, unless they are asked for
    println!("Key:       {key:?}, {}", hex::encode(key.as_octets()));
    println!("COUNT:     0x{:08x}", count.get());
    println!("Bearer:    {} (3GPP access)", u8::from(connection));
    println!("Direction: {} (uplink)", u8::from(direction));
    println!("Message:   {:?}\n", String::from_utf8_lossy(message));

    // One call for every algorithm
    let mac = |algorithm| nas_mac(&key, count, connection, direction, message, algorithm);

    let algorithms = [
        IntegrityAlgorithm::NIA1, // SNOW 3G
        IntegrityAlgorithm::NIA2, // AES-CMAC
        IntegrityAlgorithm::NIA3, // ZUC
        IntegrityAlgorithm::NIA0, // null integrity: the MAC is zero
    ];
    for algorithm in algorithms {
        println!("{:<8} MAC: 0x{:08x}", algorithm.name_5gs(), mac(algorithm));

        // A context keeps the key and what the algorithm computes from it
        // alone, for the messages that follow
        let context = IntegrityContext::new(&key, algorithm);
        assert_eq!(
            context.mac(count, connection, direction, message),
            mac(algorithm)
        );
    }
    assert_eq!(
        mac(IntegrityAlgorithm::NIA0),
        0,
        "NIA0 must always return 0"
    );

    // Each algorithm produces a different MAC for the same input
    assert_ne!(mac(IntegrityAlgorithm::NIA1), mac(IntegrityAlgorithm::NIA2));
    assert_ne!(mac(IntegrityAlgorithm::NIA2), mac(IntegrityAlgorithm::NIA3));

    println!("\nAll MACs computed successfully.");
}
