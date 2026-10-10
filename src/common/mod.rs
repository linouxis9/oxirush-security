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

//! Shared KDF framing, algorithm cores, and PLMN utilities for 5GS and EPS.

pub mod algo;
pub(crate) mod ct;
pub mod error;
pub mod kdf;
pub mod nea;
pub mod nia;
pub mod plmn;
pub(crate) mod sha256;
pub mod snow3g;
pub mod zuc;

pub use algo::{
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
pub use ct::constant_time_eq;
pub use error::SecurityError;
pub use kdf::extract_128;
pub use nea::{
    nas_cipher, nas_cipher_bits, nea1_cipher, nea1_cipher_bits, nea2_cipher, nea2_cipher_bits,
    nea3_cipher, nea3_cipher_bits,
};
pub use nia::{nas_mac, nas_mac_bits, nia1_mac, nia2_mac, nia2_mac_bits, nia3_mac};
pub use plmn::{plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode};
