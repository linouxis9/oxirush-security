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

//! Derive EPS keys and protect NAS bytes per TS 33.401.

use oxirush_security::{common::plmn_to_bytes, nas_eps as eps};

fn main() {
    let ck = [0x11; 16];
    let ik = [0x22; 16];
    let sn_id: [u8; 3] = plmn_to_bytes("208", "93").try_into().unwrap();
    let kasme = eps::derive_kasme(&ck, &ik, &sn_id, &[0; 6]);
    let knas_int = eps::extract_128(&eps::derive_nas_key(&kasme, 0x02, 2));
    let knas_enc = eps::extract_128(&eps::derive_nas_key(&kasme, 0x01, 2));

    let mut payload = vec![0x07, 0x60, 0x03]; // Plain EMM STATUS
    eps::nas_cipher(&knas_enc, 0, 0, &mut payload, 2);
    let mac = eps::nas_mac(&knas_int, 0, 0, &[&[0], payload.as_slice()].concat(), 2);
    let short_mac = eps::service_request_short_mac(&knas_int, 1, 0, 0x01, 2);

    println!("KASME: {}", hex::encode(kasme));
    println!("NAS MAC: {mac:08x}");
    println!("SERVICE REQUEST short MAC: {short_mac:04x}");
}
