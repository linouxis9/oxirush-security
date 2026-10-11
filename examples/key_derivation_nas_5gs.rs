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

use oxirush_security::nas_5gs::*;

fn main() -> Result<(), SecurityError> {
    // Example 5G-AKA outputs and AUTN field.
    let ck = [0x11; 16];
    let ik = [0x22; 16];
    let sqn_xor_ak = [0x33; 6];
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let abba = [0x00, 0x00]; // 5G standalone

    // CK || IK -> KAUSF
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak)?;
    println!("KAUSF: {}", hex::encode(k_ausf));

    // KAUSF -> KSEAF
    let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
    println!("KSEAF: {}", hex::encode(k_seaf));

    // KSEAF -> KAMF
    let supi = "208930000000001";
    let k_amf = derive_kamf(&k_seaf, supi, &abba)?;
    println!("KAMF:  {}", hex::encode(k_amf));

    // KAMF -> KNASint, the 128-bit integrity key of the selected algorithm
    let k_nas_int = derive_knas_int(&k_amf, IntegrityAlgorithm::NIA2);
    println!("KNASint (NIA2): {}", hex::encode(k_nas_int));

    // KAMF -> KNASenc, the 128-bit ciphering key of the selected algorithm
    let k_nas_enc = derive_knas_enc(&k_amf, CipheringAlgorithm::NEA2);
    println!("KNASenc (NEA2): {}", hex::encode(k_nas_enc));

    // KAMF -> KAMF' for idle mobility, with the uplink NAS COUNT
    let uplink_nas_count = NasCount::ZERO;
    let k_amf_prime = derive_kamf_prime_idle(&k_amf, uplink_nas_count);
    println!("KAMF': {}", hex::encode(k_amf_prime));

    // KAMF -> K_gNB (for initial context setup), with the uplink NAS COUNT
    let k_gnb = derive_kgnb(&k_amf, uplink_nas_count);
    println!("K_gNB: {}", hex::encode(k_gnb));

    // K_gNB -> NH (for handover, NCC=1)
    let nh = derive_nh(&k_amf, &k_gnb);
    println!("NH (NCC=1): {}", hex::encode(nh));

    Ok(())
}
