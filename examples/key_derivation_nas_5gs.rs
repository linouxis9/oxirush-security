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

//! Demonstrate the 5GS key derivation chain per TS 33.501 Annex A:
//! CK || IK -> KAUSF -> KSEAF -> KAMF -> KNASint / KNASenc -> K_gNB

use oxirush_security::nas_5gs::{
    Supi, derive_kamf, derive_kamf_prime_idle, derive_kausf, derive_kgnb, derive_knas_enc,
    derive_knas_int, derive_kseaf, derive_nh,
};
use oxirush_security::{
    Autn, CipheringAlgorithm, Ck, Ik, IntegrityAlgorithm, NasCount, SecurityError,
};

fn main() -> Result<(), SecurityError> {
    // Example 5G AKA outputs, and the AUTN of the authentication: SQN xor
    // AK, the AMF field and the MAC
    let ck = Ck::new([0x11; 16]);
    let ik = Ik::new([0x22; 16]);
    let mut autn = [0x33; 16];
    autn[6..].copy_from_slice(&[0x80, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
    let autn = Autn::new(autn);
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let abba = [0x00, 0x00]; // 5G standalone

    // CK || IK -> KAUSF. A key gives its octets when they are asked for
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &autn)?;
    println!("KAUSF: {}", hex::encode(k_ausf.as_octets()));

    // KAUSF -> KSEAF
    let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
    println!("KSEAF: {}", hex::encode(k_seaf.as_octets()));

    // KSEAF -> KAMF, with the SUPI: an IMSI by its digits
    let supi = Supi::imsi("208930000000001")?;
    let k_amf = derive_kamf(&k_seaf, &supi, &abba)?;
    println!("KAMF:  {}", hex::encode(k_amf.as_octets()));

    // KAMF -> KNASint, the 128-bit integrity key of the selected algorithm
    let k_nas_int = derive_knas_int(&k_amf, IntegrityAlgorithm::NIA2);
    println!("KNASint (NIA2): {}", hex::encode(k_nas_int.as_octets()));

    // KAMF -> KNASenc, the 128-bit ciphering key of the selected algorithm
    let k_nas_enc = derive_knas_enc(&k_amf, CipheringAlgorithm::NEA2);
    println!("KNASenc (NEA2): {}", hex::encode(k_nas_enc.as_octets()));

    // KAMF -> KAMF' for idle mobility, with the uplink NAS COUNT
    let uplink_nas_count = NasCount::ZERO;
    let k_amf_prime = derive_kamf_prime_idle(&k_amf, uplink_nas_count);
    println!("KAMF': {}", hex::encode(k_amf_prime.as_octets()));

    // KAMF -> K_gNB (for initial context setup), with the uplink NAS COUNT
    let k_gnb = derive_kgnb(&k_amf, uplink_nas_count);
    println!("K_gNB: {}", hex::encode(k_gnb.as_octets()));

    // K_gNB -> NH (for handover, NCC=1)
    let nh = derive_nh(&k_amf, &k_gnb);
    println!("NH (NCC=1): {}", hex::encode(nh.as_octets()));

    // The keys are wiped here, where they are dropped
    Ok(())
}
