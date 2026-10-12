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

pub(crate) mod aes128;
pub(crate) mod algo;
pub(crate) mod batch;
pub(crate) mod code;
pub(crate) mod context;
pub(crate) mod ct;
pub(crate) mod error;
pub(crate) mod input;
pub(crate) mod kdf;
pub(crate) mod keys;
pub(crate) mod nea;
pub(crate) mod nia;
pub(crate) mod plmn;
pub(crate) mod sha256;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) mod simd;
pub(crate) mod snow3g;
pub(crate) mod zuc;
