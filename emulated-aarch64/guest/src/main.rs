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

//! The workload on a bare AArch64 processor: the host calls `check` under
//! emulation, once for each case and each code.
#![no_std]
#![no_main]

// The names of the cases are the host's
#[allow(dead_code)]
#[path = "../../workload.rs"]
mod workload;

/// The digest of what case `case` computes: on the vector and AES
/// instructions when `scalar` is zero, and on the scalar code otherwise.
#[unsafe(no_mangle)]
pub extern "C" fn check(case: u64, scalar: u64) -> u64 {
    match scalar {
        0 => workload::run(case),
        _ => oxirush_security::hooks::scalar(|| workload::run(case)),
    }
}

/// A panic never returns to the host, which stops after a number of
/// instructions and says that the case did not end.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
