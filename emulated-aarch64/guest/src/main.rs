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
#[path = "../../leftovers.rs"]
mod leftovers;
#[allow(dead_code)]
#[path = "../../workload.rs"]
mod workload;

use core::cell::UnsafeCell;
use oxirush_security::hooks;

/// What the host asks for beside the cases of the workload: to prepare an
/// operation, to run it, and what was cleared after it.
const PREPARE: u64 = 1000;
const RUN: u64 = 2000;
const CLEARED: u64 = 3000;

/// The memory of the program that an emulated processor alone reads and
/// writes, one call at a time.
struct Kept<T>(UnsafeCell<T>);

// SAFETY: the program has one thread, which the host runs one call at a
// time.
unsafe impl<T> Sync for Kept<T> {}

static PREPARED: Kept<leftovers::Prepared> = Kept(UnsafeCell::new(leftovers::Prepared::new()));
/// How many areas of stack were cleared, then the address and the octets
/// of the first eight, then where the value of the operation is.
static REPORT: Kept<[u64; 19]> = Kept(UnsafeCell::new([0; 19]));

/// The digest of what case `case` computes: on the vector and AES
/// instructions when the low bit of `flags` is zero, and on the scalar
/// code otherwise.
///
/// From [`PREPARE`], [`RUN`] and [`CLEARED`] on, the call prepares an
/// operation of `leftovers.rs`, runs it, or gives the address of what was
/// cleared since the operation was prepared and of where its value is.
/// The second bit of `flags` runs the operation without the clearing that
/// follows its work: what is then given is what would have been cleared.
#[unsafe(no_mangle)]
pub extern "C" fn check(case: u64, flags: u64) -> u64 {
    let (scalar, unwiped) = (flags & 1 != 0, flags & 2 != 0);
    // SAFETY: nothing else has a reference to what the operations take
    // during the call, of which there is one at a time.
    let prepared = unsafe { &mut *PREPARED.0.get() };
    if case == CLEARED {
        let (areas, noted) = hooks::cleared();
        // SAFETY: as above, for the report.
        let report = unsafe { &mut *REPORT.0.get() };
        report[0] = areas as u64;
        let (places, _) = report[1..17].as_chunks_mut::<2>();
        for (place, (address, octets)) in places.iter_mut().zip(noted) {
            *place = [address as u64, octets as u64];
        }
        report[17..].copy_from_slice(&prepared.owned);
        return REPORT.0.get() as u64;
    }
    let mut work = || match case {
        RUN.. if unwiped => hooks::unwiped(|| prepared.run((case - RUN) as usize)),
        RUN.. => prepared.run((case - RUN) as usize),
        PREPARE.. => {
            prepared.prepare((case - PREPARE) as usize);
            // What was cleared so far is not of the operation
            hooks::cleared();
            0
        }
        _ => workload::run(case),
    };
    match scalar {
        false => work(),
        true => hooks::scalar(work),
    }
}

/// A panic never returns to the host, which stops after a number of
/// instructions and says that the case did not end.
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    loop {}
}
