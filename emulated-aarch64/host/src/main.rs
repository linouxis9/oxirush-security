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
//! The host then looks at what the operations of `leftovers.rs` leave on
//! the emulated processor: it paints the stack of the guest, runs an
//! operation, and reads the stack and the registers when it has returned.
//! Each operation runs without the clearing that follows its work, to
//! measure how deep the work goes below where the clearing starts, which
//! may be three quarters of what is cleared at most, and then as a
//! program has it. Nothing of its keys may be found then, the areas that
//! the crate cleared are zero, and the vector registers are zero.
//!
//! usage: oxirush-security-emulated-host <guest ELF file>

use std::process::ExitCode;
use unicorn_engine::unicorn_const::{Arch, Mode, Prot};
use unicorn_engine::{Arm64CpuModel, RegisterARM64, Unicorn};

// The operations themselves are the guest's
#[allow(dead_code)]
#[path = "../../leftovers.rs"]
mod leftovers;
// The values to look for, which the scan of x86-64 computes apart from the
// crate
#[allow(dead_code)]
#[path = "../../../leftovers/src/values.rs"]
mod values;
#[path = "../../workload.rs"]
mod workload;

use leftovers::Kind;
use values::Secret;

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

/// The stack pointer of the guest when the host calls it.
const TOP: u64 = STACK + STACK_SIZE - 0x100;

/// Call the guest on a processor: `check(case, flags)`, and what it
/// returns.
fn call(
    emulator: &mut Unicorn<'static, ()>,
    entry: u64,
    case: u64,
    flags: u64,
) -> Result<u64, String> {
    let write = |emulator: &mut Unicorn<'static, ()>, register, value| {
        emulator
            .reg_write(register, value)
            .map_err(error("a register"))
    };
    // Floating point and vector instructions are not trapped
    write(emulator, RegisterARM64::CPACR_EL1, 3 << 20)?;
    write(emulator, RegisterARM64::SP, TOP)?;
    write(emulator, RegisterARM64::LR, RETURN)?;
    write(emulator, RegisterARM64::X0, case)?;
    write(emulator, RegisterARM64::X1, flags)?;
    emulator
        .emu_start(entry, RETURN, 0, INSTRUCTIONS)
        .map_err(error("the emulation stopped"))?;
    let stopped_at = emulator.reg_read(RegisterARM64::PC).map_err(error("PC"))?;
    if stopped_at != RETURN {
        return Err(format!("the case did not end: PC is {stopped_at:#x}"));
    }
    emulator.reg_read(RegisterARM64::X0).map_err(error("X0"))
}

/// What the guest gives for a case, on its vector code or on its scalar
/// code: a fresh processor for each call.
fn guest(file: &[u8], case: u64, scalar: bool) -> Result<u64, String> {
    let (mut emulator, entry) = emulator(file)?;
    call(&mut emulator, entry, case, u64::from(scalar))
}

/// What the guest takes beside the cases of the workload: see its `check`.
const PREPARE: u64 = 1000;
const RUN: u64 = 2000;
const CLEARED: u64 = 3000;
/// The second bit of the flags: without the clearing after the work.
const UNWIPED: u64 = 2;

/// Octets below the stack pointer that are painted and read, and what
/// they are painted with.
const SCANNED: u64 = 256 * 1024;
const PATTERN: u8 = 0xa5;

/// Whether a piece of work that went `depth` octets deep used more than
/// three quarters of the `cleared` octets: the rule of `leftovers/`, which
/// says why.
fn too_deep(depth: u64, cleared: u64) -> bool {
    depth * 4 > cleared * 3
}

/// What an operation left on the emulated processor.
struct Left {
    /// The 256 KiB below the stack pointer of the call.
    stack: Vec<u8>,
    /// X1 to X17, which a function need not give back; X0 has its value.
    general: Vec<u64>,
    /// V0 to V31.
    vector: Vec<Box<[u8]>>,
    /// The areas that the crate cleared, or would have: the address and
    /// the octets of each.
    cleared: Vec<(u64, u64)>,
    /// Where the value of the operation is, which is the program's.
    owned: std::ops::Range<u64>,
}

/// Prepare operation `case` on a fresh processor, paint its stack, run the
/// operation and read what it left.
fn observe(file: &[u8], case: u64, scalar: bool, unwiped: bool) -> Result<Left, String> {
    let (mut emulator, entry) = emulator(file)?;
    let form = u64::from(scalar);
    call(&mut emulator, entry, PREPARE + case, form)?;
    emulator
        .mem_write(TOP - SCANNED, &vec![PATTERN; SCANNED as usize])
        .map_err(error("the paint"))?;
    let flags = form | if unwiped { UNWIPED } else { 0 };
    if call(&mut emulator, entry, RUN + case, flags)? == u64::MAX {
        return Err("the operation was not prepared".into());
    }

    let general = (RegisterARM64::X1 as i32..=RegisterARM64::X17 as i32)
        .map(|register| emulator.reg_read(register).map_err(error("a register")))
        .collect::<Result<_, _>>()?;
    let vector = (RegisterARM64::V0 as i32..=RegisterARM64::V31 as i32)
        .map(|register| {
            emulator
                .reg_read_long(register)
                .map_err(error("a vector register"))
        })
        .collect::<Result<_, _>>()?;
    let stack = emulator
        .mem_read_as_vec(TOP - SCANNED, SCANNED as usize)
        .map_err(error("the stack"))?;

    let report = call(&mut emulator, entry, CLEARED, 0)?;
    let report = emulator
        .mem_read_as_vec(report, 19 * 8)
        .map_err(|error| format!("what was cleared, at {report:#x}: {error:?}"))?;
    let (words, _) = report.as_chunks::<8>();
    let words: Vec<u64> = words.iter().map(|word| u64::from_le_bytes(*word)).collect();
    if words[0] > 8 {
        return Err(format!(
            "{} areas are cleared, more than are followed",
            words[0]
        ));
    }
    let (areas, _) = words[1..17].as_chunks::<2>();
    let cleared = areas
        .iter()
        .take(words[0] as usize)
        .map(|area| (area[0], area[1]))
        .collect();
    Ok(Left {
        stack,
        general,
        vector,
        cleared,
        owned: words[17]..words[18],
    })
}

impl Left {
    /// The lowest address that the operation wrote on the stack: that of
    /// the deepest octet that is no longer the pattern.
    fn lowest_written(&self) -> u64 {
        let untouched = self.stack.iter().take_while(|octet| **octet == PATTERN);
        TOP - SCANNED + untouched.count() as u64
    }

    /// The octets of the stack at `address` and after.
    fn at(&self, address: u64, octets: u64) -> &[u8] {
        let from = (address - (TOP - SCANNED)) as usize;
        &self.stack[from..from + octets as usize]
    }

    /// Where the secrets are found: on the stack, whole or by halves, and
    /// in the registers, eight octets in a row of them.
    fn findings(&self, secrets: &[Secret]) -> Vec<String> {
        let mut findings = Vec::new();
        for (name, secret) in secrets {
            let mut parts = vec![("", &secret[..])];
            if secret.len() >= 16 {
                let (first, second) = secret.split_at(secret.len() / 2);
                parts.extend([
                    ("the first half of ", first),
                    ("the second half of ", second),
                ]);
            }
            for (part, octets) in parts {
                // The value of the operation is the program's
                let owned = |at: usize| {
                    let address = TOP - SCANNED + at as u64;
                    self.owned.start <= address && address + octets.len() as u64 <= self.owned.end
                };
                let mut places = self.stack.windows(octets.len()).enumerate();
                let found = places.find(|(at, window)| *window == octets && !owned(*at));
                if let Some((at, _)) = found {
                    let below = SCANNED as usize - at;
                    findings.push(format!(
                        "{part}{name} on the stack, {below} octets below the call"
                    ));
                    break;
                }
            }
            let piece = secret.len().min(8);
            if piece < 4 {
                continue;
            }
            let held = |register: &[u8]| {
                secret
                    .windows(piece)
                    .any(|part| register.windows(piece).any(|window| window == part))
            };
            for (number, value) in (1..).zip(&self.general) {
                if held(&value.to_le_bytes()) {
                    findings.push(format!("{name} in x{number}"));
                }
            }
        }
        findings
    }
}

/// The values that an operation of `leftovers.rs` must not leave.
fn secrets_of(kind: Kind) -> Vec<Secret> {
    use oxirush_security::nas_5gs::{KAmf, KNasEnc, derive_knas_int};
    use oxirush_security::{Bearer, Direction, IntegrityAlgorithm, Snow3G, Zuc, nea_cipher};
    let (key, bearer) = (
        leftovers::KEY,
        Bearer::new(leftovers::BEARER).expect("five bits"),
    );
    let words =
        |words: &[u32]| -> Vec<u8> { words.iter().flat_map(|word| word.to_le_bytes()).collect() };
    let keystream = |key: &[u8; 16], algorithm: usize| {
        let mut keystream = vec![0u8; 64];
        nea_cipher(
            &KNasEnc::new(key),
            leftovers::COUNT,
            bearer,
            Direction::Downlink,
            &mut keystream,
            leftovers::CIPHERING[algorithm],
        );
        values::keystream_secrets(&keystream)
    };
    match kind {
        Kind::Ciphering(algorithm) => {
            let mut secrets = values::aes_secrets(&key);
            secrets.push(values::reversed(&key));
            secrets.extend(keystream(&key, algorithm));
            secrets
        }
        Kind::Integrity(_) => {
            let mut secrets = values::aes_secrets(&key);
            secrets.push(values::reversed(&key));
            secrets.extend(values::cmac_secrets(&key));
            secrets
        }
        Kind::Batch => (0..4)
            .flat_map(|index| {
                let key = leftovers::key_of(index);
                let mut secrets = values::aes_secrets(&key);
                secrets.truncate(3);
                secrets.push(values::reversed(&key));
                secrets.extend(keystream(&key, index % 3).into_iter().take(1));
                secrets
            })
            .collect(),
        Kind::Generator(snow3g) => {
            let mut expected = [0u32; 40];
            match snow3g {
                true => Snow3G::from_bytes(&key, &leftovers::IV).fill(&mut expected),
                false => Zuc::new(&key, &leftovers::IV).fill(&mut expected),
            }
            let mut secrets = vec![
                values::secret("the key", &key),
                values::secret("keystream words 0 to 3", &words(&expected[..4])),
                values::secret("keystream words 36 to 39", &words(&expected[36..])),
            ];
            secrets.extend(values::zuc_stages(&key, &leftovers::IV));
            secrets
        }
        Kind::Derivation => {
            let kamf = KAmf::new(&leftovers::KAMF);
            let derived = derive_knas_int(&kamf, IntegrityAlgorithm::Aes);
            // The key that is derived is the program's, in its memory
            let _ = derived;
            let s = values::s(0x69, &[&[0x02], &[0x02]]);
            values::hmac_secrets("KAMF", &leftovers::KAMF, &s)
        }
        Kind::Comparison => vec![values::secret("the key", &key)],
    }
}

/// Look at what operation `case` leaves in one form of the code. The line
/// that is printed, and whether nothing was left.
fn scan(file: &[u8], case: u64, kind: Kind, scalar: bool) -> Result<(String, bool), String> {
    let secrets = secrets_of(kind);
    // Without the clearing: what the scan sees of the operation, and how
    // deep its work goes below where the clearing starts
    let bare = observe(file, case, scalar, true)?;
    let seen = bare.findings(&secrets).len();
    let mut wrong = Vec::new();
    let (depth, of) = match bare.cleared.iter().min_by_key(|area| area.0) {
        Some((address, octets)) => {
            let depth = (address + octets).saturating_sub(bare.lowest_written());
            if too_deep(depth, *octets) {
                wrong.push(format!(
                    "the work goes {depth} octets deep, more than three quarters of the \
                     {octets} that are cleared"
                ));
            }
            (depth, *octets)
        }
        None => {
            wrong.push("nothing is cleared after the operation".to_string());
            (0, 0)
        }
    };

    // As a program has it
    let left = observe(file, case, scalar, false)?;
    wrong.extend(left.findings(&secrets));
    for (address, octets) in &left.cleared {
        if left.at(*address, *octets).iter().any(|octet| *octet != 0) {
            wrong.push(format!(
                "the stack is not zero from {} to {} octets below the call",
                TOP - address - octets,
                TOP - address
            ));
        }
    }
    let in_use = |(_, value): &(usize, &[u8])| value.iter().any(|octet| *octet != 0);
    let vectors: Vec<String> = left
        .vector
        .iter()
        .map(|value| &value[..])
        .enumerate()
        .filter(in_use)
        .map(|(number, _)| format!("v{number}"))
        .collect();
    if !vectors.is_empty() {
        wrong.push(format!("{} not zero", vectors.join(", ")));
    }
    let line = format!(
        "{depth:>6} {of:>8} {:>6}   {}",
        left.cleared.len(),
        match (wrong.is_empty(), seen) {
            (true, 0) => "nothing left".to_string(),
            (true, seen) => format!("nothing left ({seen} without the clearing)"),
            (false, _) => format!("LEFT: {}", wrong.join("; ")),
        }
    );
    Ok((line, wrong.is_empty()))
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

    // What the operations leave on the emulated processor
    println!(
        "\n{:<58} {:>12} {:>6} {:>8} {:>6}",
        "operation", "form", "depth", "cleared", "areas"
    );
    let mut seen = 0;
    for (case, (name, kind)) in (0..).zip(leftovers::CASES) {
        for (scalar, form) in [(false, "vector code"), (true, "scalar code")] {
            match scan(&file, case, kind, scalar) {
                Ok((line, nothing_left)) => {
                    println!("{name:<58} {form:>12} {line}");
                    failures += u32::from(!nothing_left);
                    seen += u32::from(line.contains("without the clearing"));
                }
                Err(error) => {
                    println!("{name:<58} {form:>12} FAILED: {error}");
                    failures += 1;
                }
            }
        }
    }
    if seen == 0 {
        println!("FAILED: the scan sees nothing even when nothing is cleared");
        failures += 1;
    }
    if failures == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
