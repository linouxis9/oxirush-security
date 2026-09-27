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

//! Demonstrate SUCI concealment per TS 33.501 Annex C.4.
//!
//! Shows:
//! - Null scheme (cleartext MSIN in BCD)
//! - Profile A (X25519 ECIES) — IMSI and textual NAI round-trips

use oxirush_security::nas_5gs::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn main() {
    let msin = "0000000001";
    println!("=== SUCI Concealment (TS 33.501 Annex C.4) ===\n");
    println!("MSIN: {msin}");

    // ── Null scheme ──────────────────────────────────────────────────────
    let msin_bcd = msin_to_bcd(msin);
    println!(
        "\n--- Null scheme (0x00) ---\nMSIN BCD: {}",
        hex::encode(&msin_bcd)
    );
    println!("(MSIN transmitted in cleartext)");

    // ── Profile A (X25519) ───────────────────────────────────────────────
    println!("\n--- Profile A (X25519 ECIES) ---");

    // Generate a home network key pair (normally provisioned by the operator)
    let home_priv_key = StaticSecret::random_from_rng(rand_core::OsRng);
    let home_pub_key = PublicKey::from(&home_priv_key);

    println!(
        "Home network public key:  {}",
        hex::encode(home_pub_key.as_bytes())
    );

    // UE side: conceal MSIN
    let scheme_output =
        suci_scheme_output_a(&msin_bcd, home_pub_key.as_bytes()).expect("Profile A conceal failed");
    let ephemeral_pub = &scheme_output[..32];
    let encrypted = &scheme_output[32..];
    println!("Ephemeral public key:      {}", hex::encode(ephemeral_pub));
    println!("Ciphertext + MAC:          {}", hex::encode(encrypted));

    // Home network side: deconceal MSIN
    let recovered =
        suci_decrypt_a(&scheme_output, home_priv_key.as_bytes()).expect("Profile A decrypt failed");
    println!("Recovered MSIN BCD:        {}", hex::encode(&recovered));

    assert_eq!(msin_bcd, recovered, "MSIN mismatch after deconceal!");
    println!("\nProfile A IMSI round-trip: OK");

    // Network-specific SUPIs use the TS 23.003 textual NAI form.
    let nai = conceal_network_specific_supi(
        "sensor-17@example.net",
        "0",
        NaiProtectionScheme::ProfileA {
            home_network_public_key_id: 1,
            home_network_public_key: home_pub_key.as_bytes(),
        },
    )
    .expect("NAI conceal failed");
    let encoded_nai = encode_nai_suci(&nai).expect("NAI encoding failed");
    let parsed_nai = parse_nai_suci(&encoded_nai).expect("NAI parsing failed");
    let recovered_nai =
        deconceal_network_specific_suci(&parsed_nai, Some(home_priv_key.as_bytes()))
            .expect("NAI deconceal failed");
    assert_eq!(recovered_nai, "sensor-17@example.net");
    println!("Profile A NAI round-trip:  OK");
}
