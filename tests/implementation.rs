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

//! The code that the tests run is the code that their job is meant to run.
//!
//! A job of CI names in `OXIRUSH_SECURITY_EXPECT` the implementation that
//! its machine and its build must give: `Scalar`, `Vector128` or
//! `Vector256`. The test fails when [`implementation`] finds another, so
//! that a job that was meant to exercise the vector code cannot pass on the
//! scalar code. Without the variable it prints what runs.
//!
//! ```bash
//! OXIRUSH_SECURITY_EXPECT=Vector256 cargo test --test implementation -- --nocapture
//! ```

use oxirush_security::{CipheringAlgorithm, Implementation, IntegrityAlgorithm, implementation};

#[test]
fn the_implementation_is_the_one_that_the_job_expects() {
    let implementation = implementation();
    println!("oxirush-security runs: {implementation:?} ({implementation})");
    for (name, ciphering, integrity) in [
        (
            "SNOW 3G",
            CipheringAlgorithm::NEA1,
            IntegrityAlgorithm::NIA1,
        ),
        ("AES", CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2),
        ("ZUC", CipheringAlgorithm::NEA3, IntegrityAlgorithm::NIA3),
    ] {
        println!(
            "  {name}: ciphering on {}, {} side by side in a batch; integrity on {}, {} side by side",
            implementation.ciphering(ciphering),
            implementation.ciphering_side_by_side(ciphering),
            implementation.integrity(integrity),
            implementation.integrity_side_by_side(integrity),
        );
    }

    let Ok(expected) = std::env::var("OXIRUSH_SECURITY_EXPECT") else {
        return;
    };
    let expected = match expected.as_str() {
        "Scalar" => Implementation::Scalar,
        "Vector128" => Implementation::Vector128,
        "Vector256" => Implementation::Vector256,
        other => panic!("OXIRUSH_SECURITY_EXPECT is {other:?}: Scalar, Vector128 or Vector256"),
    };
    assert_eq!(
        implementation, expected,
        "this job was to run {expected:?}, and the processor or the build gives {implementation:?}"
    );
}
