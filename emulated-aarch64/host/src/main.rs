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

//! The vector code of AArch64 on an emulated processor.
//!
//! The guest program is the crate built for a bare AArch64 processor with
//! NEON and the AES instructions enabled, and the workload of
//! `workload.rs`. Unicorn runs it on its `max` processor. For each case
//! of the workload the host calls the guest twice, for the vector code and
//! for the scalar code, and computes the case itself on the processor that
//! it runs on. The three numbers must be equal; the case of the known
//! answers must give zero, and the guest must say that its vector code is
//! the one that runs.
//!
//! usage: oxirush-security-emulated-host <guest ELF file>

use std::process::ExitCode;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{Arm64CpuModel, RegisterARM64, Unicorn};

#[path = "../../workload.rs"]
mod workload;

/// Where the stack of the guest is, and its size.
const STACK: u64 = 0x7000_0000;
const STACK_SIZE: u64 = 0x10_0000;
/// Where the guest returns to, which stops the emulation.
const RETURN: u64 = 0x6000_0000;
/// The most instructions of a case: a guest that panics loops for ever.
const INSTRUCTIONS: usize = 20_000_000_000;

fn field<const N: usize>(file: &[u8], at: usize) -> Result<[u8; N], String> {
    let octets = file.get(at..at + N).ok_or("the file is cut short")?;
    Ok(octets.try_into().expect("N octets"))
}

/// A segment that an ELF file loads: its address, its octets in the file
/// and its size in memory.
type Segment<'a> = (u64, &'a [u8], u64);

/// The entry point of an ELF file of 64 bits, and the segments it loads.
fn segments(file: &[u8]) -> Result<(u64, Vec<Segment<'_>>), String> {
    if file.get(..6) != Some(b"\x7fELF\x02\x01") {
        return Err("not a little-endian ELF file of 64 bits".into());
    }
    let entry = u64::from_le_bytes(field(file, 0x18)?);
    let headers = u64::from_le_bytes(field(file, 0x20)?) as usize;
    let header_size = usize::from(u16::from_le_bytes(field(file, 0x36)?));
    let count = usize::from(u16::from_le_bytes(field(file, 0x38)?));
    let mut loaded = Vec::new();
    for index in 0..count {
        let at = headers + index * header_size;
        // PT_LOAD
        if u32::from_le_bytes(field(file, at)?) != 1 {
            continue;
        }
        let offset = u64::from_le_bytes(field(file, at + 0x08)?) as usize;
        let address = u64::from_le_bytes(field(file, at + 0x10)?);
        let in_file = u64::from_le_bytes(field(file, at + 0x20)?) as usize;
        let in_memory = u64::from_le_bytes(field(file, at + 0x28)?);
        let octets = file
            .get(offset..offset + in_file)
            .ok_or("a segment is cut short")?;
        loaded.push((address, octets, in_memory));
    }
    Ok((entry, loaded))
}

/// What went wrong, and at which step.
fn error<E: std::fmt::Debug>(what: &'static str) -> impl Fn(E) -> String {
    move |error| format!("{what}: {error:?}")
}

fn emulator(file: &[u8]) -> Result<(Unicorn<'static, ()>, u64), String> {
    let mut emulator =
        Unicorn::new(Arch::ARM64, Mode::LITTLE_ENDIAN).map_err(error("no AArch64 emulator"))?;
    emulator
        .ctl_set_cpu_model(Arm64CpuModel::MAX as i32)
        .map_err(error("no max processor"))?;

    let (entry, loaded) = segments(file)?;
    let first = loaded.iter().map(|(address, ..)| address & !0xfff).min();
    let last = loaded
        .iter()
        .map(|(address, _, size)| (address + size + 0xfff) & !0xfff)
        .max();
    let (Some(first), Some(last)) = (first, last) else {
        return Err("the file loads nothing".into());
    };
    emulator
        .mem_map(first, last - first, Prot::ALL)
        .map_err(error("the memory of the program"))?;
    for (address, octets, _) in loaded {
        emulator
            .mem_write(address, octets)
            .map_err(error("a segment"))?;
    }
    emulator
        .mem_map(STACK, STACK_SIZE, Prot::READ | Prot::WRITE)
        .map_err(error("the stack"))?;
    emulator
        .mem_map(RETURN, 0x1000, Prot::ALL)
        .map_err(error("the return address"))?;
    Ok((emulator, entry))
}

/// What the guest gives for a case, on its vector code or on its scalar
/// code: a fresh processor for each call.
fn guest(file: &[u8], case: u64, scalar: bool) -> Result<u64, String> {
    let (mut emulator, entry) = emulator(file)?;
    let write = |emulator: &mut Unicorn<'static, ()>, register, value| {
        emulator
            .reg_write(register, value)
            .map_err(error("a register"))
    };
    // Floating point and vector instructions are not trapped
    write(&mut emulator, RegisterARM64::CPACR_EL1, 3 << 20)?;
    write(&mut emulator, RegisterARM64::SP, STACK + STACK_SIZE - 0x100)?;
    write(&mut emulator, RegisterARM64::LR, RETURN)?;
    write(&mut emulator, RegisterARM64::X0, case)?;
    write(&mut emulator, RegisterARM64::X1, u64::from(scalar))?;
    emulator
        .emu_start(entry, RETURN, 0, INSTRUCTIONS)
        .map_err(error("the emulation stopped"))?;
    let stopped_at = emulator.reg_read(RegisterARM64::PC).map_err(error("PC"))?;
    if stopped_at != RETURN {
        return Err(format!("the case did not end: PC is {stopped_at:#x}"));
    }
    emulator.reg_read(RegisterARM64::X0).map_err(error("X0"))
}

fn main() -> ExitCode {
    let Some(path) = std::env::args().nth(1) else {
        eprintln!("usage: oxirush-security-emulated-host <guest ELF file>");
        return ExitCode::FAILURE;
    };
    let file = match std::fs::read(&path) {
        Ok(file) => file,
        Err(error) => {
            eprintln!("{path}: {error}");
            return ExitCode::FAILURE;
        }
    };

    let mut failures = 0;
    for (case, name) in (0..).zip(workload::CASES) {
        let results = (guest(&file, case, false), guest(&file, case, true));
        let (vector, scalar) = match results {
            (Ok(vector), Ok(scalar)) => (vector, scalar),
            (vector, scalar) => {
                println!("FAILED  {name}: vector code {vector:?}, scalar code {scalar:?}");
                failures += 1;
                continue;
            }
        };
        let host = workload::run(case);
        let ok = match case {
            // The guest runs its vector code, and its scalar code when told
            0 => {
                vector == workload::number_of(oxirush_security::Implementation::Vector128)
                    && scalar == workload::number_of(oxirush_security::Implementation::Scalar)
            }
            1 => vector == 0 && scalar == 0 && host == 0,
            _ => vector == scalar && vector == host,
        };
        failures += u32::from(!ok);
        println!(
            "{}  {name}: AArch64 vector code {vector:#018x}, AArch64 scalar code {scalar:#018x}, host {host:#018x}",
            if ok { "ok    " } else { "FAILED" }
        );
    }
    println!("the host runs {:?}", oxirush_security::implementation());
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
