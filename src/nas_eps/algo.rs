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

//! EPS NAS algorithm selection from UE network capability EEA/EIA bits.

/// Select EIA2, EIA1, or EIA3 from the UE EIA capability octet.
/// EIA0 is reserved for unauthenticated emergency operation.
pub fn select_integrity_algo(eia_capability: u8) -> Option<u8> {
    crate::common::algo::select_integrity_algo(eia_capability)
}

/// Select EEA2, EEA1, EEA3, or EEA0 from the UE EEA capability octet.
pub fn select_ciphering_algo(eea_capability: u8) -> Option<u8> {
    crate::common::algo::select_ciphering_algo(eea_capability)
}
