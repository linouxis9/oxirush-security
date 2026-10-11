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

//! Demonstrate the EPS key derivation chain per TS 33.401 Annex A:
//! CK || IK -> KASME -> KNASint / KNASenc -> KeNB -> NH

use oxirush_security::{common::plmn_to_bytes, nas_eps::*};

fn main() -> Result<(), SecurityError> {
    // Example key material; in practice CK and IK come from EPS AKA
    let ck = [0x11; 16];
    let ik = [0x22; 16];
    let sn_id = plmn_to_bytes("208", "93")?;
    let sqn_xor_ak = [0; 6];

    // CK || IK -> KASME
    let k_asme = derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak);
    println!("KASME: {}", hex::encode(k_asme));

    // KASME -> KNASint, the 128-bit integrity key of the selected algorithm
    let k_nas_int = derive_knas_int(&k_asme, IntegrityAlgorithm::EIA2);
    println!("KNASint (EIA2): {}", hex::encode(k_nas_int));

    // KASME -> KNASenc, the 128-bit ciphering key of the selected algorithm
    let k_nas_enc = derive_knas_enc(&k_asme, CipheringAlgorithm::EEA2);
    println!("KNASenc (EEA2): {}", hex::encode(k_nas_enc));

    // KASME -> KeNB (for initial context setup), with the uplink NAS COUNT
    let k_enb = derive_kenb(&k_asme, NasCount::ZERO);
    println!("KeNB: {}", hex::encode(k_enb));

    // KeNB -> NH (for handover, NCC=1)
    let nh = derive_nh(&k_asme, &k_enb);
    println!("NH (NCC=1): {}", hex::encode(nh));

    Ok(())
}
