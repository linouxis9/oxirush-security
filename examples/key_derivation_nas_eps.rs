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

//! Demonstrate the EPS key derivation chain per TS 33.401 Annex A:
//! CK || IK -> KASME -> KNASint / KNASenc -> KeNB -> NH

use oxirush_security::{common::plmn_to_bytes, nas_eps::*};

fn main() {
    // Example key material; in practice CK and IK come from EPS AKA
    let ck = [0x11; 16];
    let ik = [0x22; 16];
    let sn_id: [u8; 3] = plmn_to_bytes("208", "93").try_into().unwrap();
    let sqn_xor_ak = [0; 6];

    // CK || IK -> KASME
    let k_asme = derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak);
    println!("KASME: {}", hex::encode(k_asme));

    // KASME -> KNASint (EIA2 = algorithm ID 2, distinguisher 0x02)
    let k_nas_int = derive_nas_key(&k_asme, 0x02, 2); // integrity, EIA2
    println!("KNASint (EIA2): {}", hex::encode(k_nas_int));

    // KASME -> KNASenc (EEA2 = algorithm ID 2, distinguisher 0x01)
    let k_nas_enc = derive_nas_key(&k_asme, 0x01, 2); // ciphering, EEA2
    println!("KNASenc (EEA2): {}", hex::encode(k_nas_enc));

    // KASME -> KeNB (for initial context setup)
    let k_enb = derive_kenb(&k_asme, 0); // uplink NAS COUNT = 0
    println!("KeNB: {}", hex::encode(k_enb));

    // KeNB -> NH (for handover, NCC=1)
    let nh = derive_nh(&k_asme, &k_enb);
    println!("NH (NCC=1): {}", hex::encode(nh));
}
