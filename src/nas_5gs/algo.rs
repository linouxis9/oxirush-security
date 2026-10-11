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

//! 5GS NAS algorithm selection from the 5G-EA and 5G-IA octets of the UE
//! security capability (TS 24.501 §9.11.3.54).

pub use crate::common::algo::{
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
