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

//! The MILENAGE of Open5GS, from the source tree that `OPEN5GS` names:
//! `lib/crypt/milenage.c` and the AES of `lib/crypt/ogs-aes.c`, copied
//! beside `open5gs/ogs-crypt.h` of this package, which takes the place of
//! the rest of Open5GS. Without `OPEN5GS` the program has no Open5GS.

use std::path::PathBuf;

fn main() {
    println!("cargo::rerun-if-env-changed=OPEN5GS");
    println!("cargo::rerun-if-changed=open5gs/ogs-crypt.h");
    println!("cargo::rustc-check-cfg=cfg(open5gs)");
    let Some(root) = std::env::var_os("OPEN5GS") else {
        return;
    };
    let crypt = PathBuf::from(root).join("lib/crypt");
    let out = PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR")).join("open5gs");
    std::fs::create_dir_all(&out).expect("a directory for the sources");
    for file in ["milenage.c", "milenage.h", "ogs-aes.c", "ogs-aes.h"] {
        let from = crypt.join(file);
        println!("cargo::rerun-if-changed={}", from.display());
        std::fs::copy(&from, out.join(file))
            .unwrap_or_else(|error| panic!("{}: {error}", from.display()));
    }
    std::fs::copy("open5gs/ogs-crypt.h", out.join("ogs-crypt.h")).expect("the shim header");
    cc::Build::new()
        .file(out.join("milenage.c"))
        .file(out.join("ogs-aes.c"))
        .include(&out)
        .warnings(false)
        .compile("open5gs_milenage");
    println!("cargo::rustc-cfg=open5gs");
}
