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

//! Demonstrate SUCI concealment per TS 33.501 Annex C.
//!
//! Shows:
//! - the null scheme, which leaves the MSIN in clear;
//! - Profile A (X25519 ECIES) for an IMSI, as a mobile identity of NAS;
//! - Profile B (secp256r1 ECIES) for a network specific identifier, in the
//!   NAI format.

use oxirush_security::Plmn;
use oxirush_security::nas_5gs::{
    HomeNetworkPrivateKey, Protection, SchemeOutput, Suci, SuciError, Supi,
};

fn main() -> Result<(), SuciError> {
    println!("=== SUCI concealment (TS 33.501 Annex C) ===\n");
    let plmn = Plmn::new("208", "93").expect("an MCC and an MNC");
    let msin = "0000000001";
    println!("IMSI: {} {} {msin}", plmn.mcc(), plmn.mnc());

    // ── Null scheme ──────────────────────────────────────────────────────
    let suci = Suci::conceal_imsi(plmn, msin, "0", Protection::Null)?;
    println!("\n--- Null scheme ---\n{suci}");
    println!("mobile identity: {}", hex::encode(suci.to_nas()?));
    println!("(the MSIN is in clear)");

    // ── Profile A (X25519) ───────────────────────────────────────────────
    println!("\n--- Profile A (X25519 ECIES) ---");

    // A key pair of the home network, which an operator provisions: the
    // private key stays in its SIDF, and the UEs have the public key with
    // its identifier
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).expect("the system random number generator");
    let private_a = HomeNetworkPrivateKey::profile_a(&seed);
    let public_a = private_a.public_key();
    println!(
        "home network public key: {}",
        hex::encode(public_a.to_octets())
    );

    // UE: conceal the MSIN
    let protection = Protection::Ecies {
        key_id: 1,
        key: &public_a,
    };
    let suci = Suci::conceal_imsi(plmn, msin, "0", protection)?;
    if let SchemeOutput::Ecies {
        ephemeral_public_key,
        ciphertext,
        mac_tag,
    } = suci.scheme_output()
    {
        println!(
            "ephemeral public key:    {}",
            hex::encode(ephemeral_public_key)
        );
        println!("ciphertext:              {}", hex::encode(ciphertext));
        println!("MAC tag:                 {}", hex::encode(mac_tag));
    }
    let identity = suci.to_nas()?;

    // SIDF: read the mobile identity, choose the key, de-conceal
    let received = Suci::from_nas(&identity)?;
    println!(
        "received: {:?}, key {}, routing indicator {}",
        received.protection_scheme(),
        received.home_network_public_key_id(),
        received.routing_indicator(),
    );
    let supi = received.deconceal(Some(&private_a))?;
    println!("SUPI: {supi}");
    assert_eq!(supi.identity(), "208930000000001");

    // ── Profile B, a network specific identifier ─────────────────────────
    println!("\n--- Profile B (secp256r1 ECIES), NAI format ---");
    getrandom::fill(&mut seed).expect("the system random number generator");
    let private_b = HomeNetworkPrivateKey::profile_b(&seed)?;
    let public_b = private_b.public_key();

    // UE: the username is concealed, and the realm is not
    let supi = Supi::network_specific("sensor-17@example.net").expect("a NAI");
    let protection = Protection::Ecies {
        key_id: 2,
        key: &public_b,
    };
    let nai = Suci::conceal_nai(&supi, "0", protection)?.to_nai();
    println!("{nai}");

    // SIDF: a key of the other profile is refused, and its own de-conceals
    let received = Suci::from_nai(&nai)?;
    println!(
        "with the key of Profile A: {:?}",
        received.deconceal(Some(&private_a))
    );
    let recovered = received.deconceal(Some(&private_b))?;
    println!("SUPI: {recovered}");
    assert_eq!(recovered, supi);

    Ok(())
}
