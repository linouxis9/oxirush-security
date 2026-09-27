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
//! - Profile A (X25519 ECIES) — conceal and deconceal round-trip

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
    println!("\nProfile A round-trip: OK");
}
