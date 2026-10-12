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

//! What 5GS and EPS share: the algorithms, the KDF framing of TS 33.220,
//! the types of their inputs, and the PLMN and TBCD encodings.

pub mod algo;
pub mod batch;
mod code;
pub(crate) mod ct;
pub mod error;
pub mod input;
pub mod kdf;
pub mod nea;
pub mod nia;
pub mod plmn;
pub(crate) mod sha256;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) mod simd;
pub mod snow3g;
pub mod zuc;

pub use algo::{
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
pub use batch::{CipherJob, MacJob, nea_cipher_batch, nia_mac_batch};
pub use code::{Code, Implementation, implementation};
pub use ct::constant_time_eq;
pub use error::SecurityError;
pub use input::{
    AccessKeyCount, Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount,
};
pub use kdf::extract_128;
pub use nea::{
    nea_cipher, nea_cipher_bits, nea1_cipher, nea1_cipher_bits, nea2_cipher, nea2_cipher_bits,
    nea3_cipher, nea3_cipher_bits,
};
pub use nia::{
    nia_mac, nia_mac_bits, nia1_mac, nia1_mac_bits, nia2_mac, nia2_mac_bits, nia3_mac,
    nia3_mac_bits,
};
pub use plmn::plmn_to_bytes;
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use plmn::{plmn_from_bytes, tbcd_decode, tbcd_encode};
