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

//! What a public operation of oxirush-security leaves on the stack and in
//! the registers when it has returned.
//!
//! Each operation runs on a thread of its own, whose stack is first
//! painted with a pattern below the stack pointer. When the operation has
//! returned, the registers are stored as it left them and the 256 KiB below
//! the stack pointer are copied out. The keys of the operation, the values
//! that it derives from them and its keystream are then looked for in both.
//! They live on the heap of this program, which passes references alone:
//! what is found is a copy that the crate, or a crate that it uses, made and
//! did not wipe.
//!
//! Every operation runs twice in each form of the code (the vector
//! instructions of the processor, those of 128 bits alone, and none):
//!
//! - without the clearing that follows its work, to see that the scan does
//!   find what an operation leaves, and to measure how deep the work goes
//!   below where the clearing starts: the crate says which areas of the
//!   stack it would have cleared, and the work may use three quarters of
//!   the deepest of them at most;
//! - as a program has it. Nothing may be found then, each area that the
//!   crate cleared is zero, and the vector registers are zero.
//!
//! The program fails when one of these does not hold.
//!
//! It reads memory below its stack pointer and stores registers from
//! assembly: it is a test tool for x86-64, and nothing of the crate.

#[cfg(not(target_arch = "x86_64"))]
compile_error!("the scan reads the registers of x86-64");

mod cases;
mod values;

use oxirush_security::hooks::{cleared, narrow, scalar, unwiped};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Octets below the stack pointer that are painted, then copied out.
const SCANNED: usize = 256 * 1024;
/// What the stack is painted with before an operation.
const PATTERN: u8 = 0xa5;

/// Octets at the deep end of a cleared area that are not looked at.
const SLACK: usize = 64;

/// What the crate clears after any work when it is built with debug
/// assertions.
const UNOPTIMIZED: usize = 49152;

/// Whether a piece of work that went `depth` octets deep used more than
/// three quarters of the `cleared` octets.
///
/// The crate clears twice what the deepest work of each kind used where it
/// was run. A processor that nobody ran it on, a compiler or a new version
/// of a crate that it uses may go deeper: up to half as deep again, the
/// scan passes, and beyond that it fails while a quarter of what is
/// cleared is still not used, so that the figure is raised before an
/// operation leaves anything.
fn too_deep(depth: usize, cleared: usize) -> bool {
    depth * 4 > cleared * 3
}

/// The processor, and what of it chooses the code of the `aes` and `sha2`
/// crates: how deep an operation goes depends on it.
fn processor() -> String {
    // What Linux says of the first processor: the names of the features
    // of AVX-512 are not ones that Rust 1.88 lets a program ask for
    let text = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let field = |name: &str| {
        let line = text.lines().find(|line| line.starts_with(name))?;
        Some(line.split_once(':')?.1.trim())
    };
    let model = field("model name").unwrap_or("unknown");
    let flag =
        |name: &str| field("flags").is_some_and(|flags| flags.split(' ').any(|flag| flag == name));
    let has = [
        ("AES", flag("aes")),
        ("VAES", flag("vaes")),
        ("AVX2", flag("avx2")),
        ("AVX-512F", flag("avx512f")),
        ("SHA", flag("sha_ni")),
    ];
    let with: Vec<_> = has
        .iter()
        .filter(|(_, has)| *has)
        .map(|(name, _)| *name)
        .collect();
    let without: Vec<_> = has
        .iter()
        .filter(|(_, has)| !*has)
        .map(|(name, _)| *name)
        .collect();
    // On the AES instructions the counter mode of the crate has `aes`
    // encrypt a block after the other: its code for several, which the
    // processor chooses, is not called
    let aes = if cfg!(aes_backend = "soft") {
        "without instructions, as it is built"
    } else if has[0].1 {
        "on the AES instructions, a block after the other"
    } else {
        "without instructions"
    };
    format!(
        "processor: {model}, with {}{}\nthe aes crate runs {aes}",
        with.join(", "),
        if without.is_empty() {
            String::new()
        } else {
            format!(", without {}", without.join(", "))
        }
    )
}

/// The registers that an x86-64 function need not give back as it found
/// them: nine general ones, and the sixteen vector ones.
#[repr(C)]
struct Registers {
    general: [u64; 9],
    vector: [[u8; 32]; 16],
}

const GENERAL: [&str; 9] = ["rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11"];

/// The stack pointer of the function that calls the operation, the top of
/// what is copied out, and the lowest address that is painted: the depth
/// of an operation is counted from the first, in the copy that ends at the
/// second.
static CALLER: AtomicUsize = AtomicUsize::new(0);
static TOP: AtomicUsize = AtomicUsize::new(0);
static LOWEST: AtomicUsize = AtomicUsize::new(0);
/// Where the value of the operation is, which is the program's: its first
/// address and the one after its last.
static OWNED: [AtomicUsize; 2] = [AtomicUsize::new(0), AtomicUsize::new(0)];

/// Say where the value of the operation is. It is in the frame of the
/// function that called the operation, as the operation returned it and
/// not dropped: a key that an operation returns is found there, and is no
/// leftover.
#[inline(always)]
pub fn owned<T>(value: &T) {
    let from = value as *const T as usize;
    OWNED[0].store(from, Ordering::Relaxed);
    OWNED[1].store(from + size_of::<T>(), Ordering::Relaxed);
}

/// Note the stack pointer of the caller, and paint the stack below it
/// once more, up to the stack pointer itself. Each operation is called
/// from a function that does this just before: what the operation uses of
/// the stack is below, and what the function did to prepare it, an
/// allocation or the making of a context, is painted over.
#[inline(always)]
pub fn here() {
    let pointer: usize;
    // SAFETY (of a test tool): the instructions write the pattern from
    // the lowest painted address up to the stack pointer, where nothing
    // lives: the compiler is not told that they leave the stack alone, so
    // it keeps nothing below the stack pointer.
    unsafe {
        core::arch::asm!(
            "mov {pointer}, rsp",
            "mov rcx, rsp",
            "sub rcx, rdi",
            "cld",
            "rep stosb",
            pointer = out(reg) pointer,
            inout("rdi") LOWEST.load(Ordering::Relaxed) => _,
            in("al") PATTERN,
            out("rcx") _,
        );
    }
    CALLER.store(pointer, Ordering::Relaxed);
    // What was cleared before is not of the operation
    cleared();
    OWNED[0].store(0, Ordering::Relaxed);
    OWNED[1].store(0, Ordering::Relaxed);
}

/// Paint what is below the stack pointer, down to 256 KiB.
#[inline(never)]
fn paint() {
    let marker = 0u8;
    let lowest = (&raw const marker as usize) - 128 - SCANNED;
    LOWEST.store(lowest, Ordering::Relaxed);
    paint_from(lowest);
}

/// Paint from `lowest` up to what is just below the stack pointer.
#[inline(never)]
fn paint_from(lowest: usize) {
    let marker = 0u8;
    let top = (&raw const marker as usize) - 128;
    let mut at = lowest;
    while at < top {
        // SAFETY (of a test tool): below the stack pointer of this thread
        // and within its stack of 8 MiB, where nothing lives.
        unsafe { core::ptr::write_volatile(at as *mut u8, PATTERN) };
        at += 1;
    }
}

/// Copy out what is below the stack pointer: where the frames of the
/// operation were. No call and no allocation, so that the frame of this
/// function is a few words.
#[inline(never)]
fn copy_stack(out: *mut u8) {
    let marker = 0u8;
    let top = (&raw const marker as usize) - 128;
    TOP.store(top, Ordering::Relaxed);
    let from = top - SCANNED;
    let mut at = 0;
    while at < SCANNED {
        // SAFETY (of a test tool): the pages are those of this thread's
        // stack, painted by `paint` and written since by frames that have
        // returned.
        unsafe { *out.add(at) = core::ptr::read_volatile((from + at) as *const u8) };
        at += 1;
    }
}

/// Call `victim` and store the registers as it leaves them, with nothing
/// of the compiler between the two.
#[inline(never)]
fn call_and_store(victim: &mut dyn FnMut(), registers: &mut Registers) {
    extern "C" fn enter(victim: *mut &mut dyn FnMut()) {
        // SAFETY: the pointer is that of the reference below, which lives
        // for the call.
        (unsafe { &mut *victim })();
    }
    let mut victim = victim;
    let victim: *mut &mut dyn FnMut() = &mut victim;
    let wide = std::arch::is_x86_feature_detected!("avx");
    // SAFETY (of a test tool): `enter` is called as the C ABI has it, with
    // its argument in RDI and every register that a callee may change
    // declared so. R12 is given back by a callee as it found it, and holds
    // where the registers go. The stores write that structure alone.
    unsafe {
        if wide {
            core::arch::asm!(
                "call {enter}",
                "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
                "mov [r12 + 24], rsi", "mov [r12 + 32], rdi", "mov [r12 + 40], r8",
                "mov [r12 + 48], r9", "mov [r12 + 56], r10", "mov [r12 + 64], r11",
                "vmovdqu [r12 + 72], ymm0", "vmovdqu [r12 + 104], ymm1",
                "vmovdqu [r12 + 136], ymm2", "vmovdqu [r12 + 168], ymm3",
                "vmovdqu [r12 + 200], ymm4", "vmovdqu [r12 + 232], ymm5",
                "vmovdqu [r12 + 264], ymm6", "vmovdqu [r12 + 296], ymm7",
                "vmovdqu [r12 + 328], ymm8", "vmovdqu [r12 + 360], ymm9",
                "vmovdqu [r12 + 392], ymm10", "vmovdqu [r12 + 424], ymm11",
                "vmovdqu [r12 + 456], ymm12", "vmovdqu [r12 + 488], ymm13",
                "vmovdqu [r12 + 520], ymm14", "vmovdqu [r12 + 552], ymm15",
                enter = sym enter,
                in("rdi") victim,
                in("r12") registers as *mut Registers,
                clobber_abi("C"),
            );
        } else {
            core::arch::asm!(
                "call {enter}",
                "mov [r12], rax", "mov [r12 + 8], rcx", "mov [r12 + 16], rdx",
                "mov [r12 + 24], rsi", "mov [r12 + 32], rdi", "mov [r12 + 40], r8",
                "mov [r12 + 48], r9", "mov [r12 + 56], r10", "mov [r12 + 64], r11",
                "movdqu [r12 + 72], xmm0", "movdqu [r12 + 104], xmm1",
                "movdqu [r12 + 136], xmm2", "movdqu [r12 + 168], xmm3",
                "movdqu [r12 + 200], xmm4", "movdqu [r12 + 232], xmm5",
                "movdqu [r12 + 264], xmm6", "movdqu [r12 + 296], xmm7",
                "movdqu [r12 + 328], xmm8", "movdqu [r12 + 360], xmm9",
                "movdqu [r12 + 392], xmm10", "movdqu [r12 + 424], xmm11",
                "movdqu [r12 + 456], xmm12", "movdqu [r12 + 488], xmm13",
                "movdqu [r12 + 520], xmm14", "movdqu [r12 + 552], xmm15",
                enter = sym enter,
                in("rdi") victim,
                in("r12") registers as *mut Registers,
                clobber_abi("C"),
            );
        }
    }
}

/// What an operation left.
struct Left {
    /// The stack from 256 KiB below the top of the copy up to it.
    stack: Vec<u8>,
    /// Octets from the top of the copy down to the stack pointer of the
    /// caller of the operation.
    caller: usize,
    /// The stack pointer of the caller of the operation.
    caller_address: usize,
    /// Where the value of the operation is, in the copy.
    owned: std::ops::Range<usize>,
    registers: Registers,
}

impl Left {
    /// The lowest address that the operation wrote on the stack: that of
    /// the deepest octet that is no longer the pattern. The lowest octets
    /// of the copy are below what was painted.
    fn lowest_written(&self) -> usize {
        let unpainted = self.stack.len() - self.painted();
        let untouched = self.stack[unpainted..]
            .iter()
            .take_while(|octet| **octet == PATTERN);
        self.caller_address + self.caller - self.painted() + untouched.count()
    }

    /// The octets of the copy that were painted: those above the lowest
    /// painted address.
    fn painted(&self) -> usize {
        let top = self.caller_address + self.caller;
        (top - LOWEST.load(Ordering::Relaxed)).min(self.stack.len())
    }

    /// The vector registers that are not zero.
    fn vectors_in_use(&self) -> Vec<String> {
        let in_use = |(_, value): &(usize, &[u8; 32])| value.iter().any(|octet| *octet != 0);
        let vectors = self.registers.vector.iter().enumerate().filter(in_use);
        vectors.map(|(number, _)| format!("ymm{number}")).collect()
    }

    /// The octets of the stack from `from` to `to` octets below the
    /// caller of the operation.
    fn below(&self, from: usize, to: usize) -> &[u8] {
        let top = SCANNED - self.caller;
        &self.stack[top - to..top - from]
    }

    /// Where the secrets are found, in words for a reader: on the stack,
    /// and in the registers unless `registers` is false.
    fn findings(&self, secrets: &[values::Secret], registers: bool) -> Vec<String> {
        let mut findings = Vec::new();
        for (name, secret) in secrets {
            // A secret of sixteen octets or more may survive in part: each
            // half is looked for as well
            let mut parts = vec![("", &secret[..])];
            if secret.len() >= 16 {
                let (first, second) = secret.split_at(secret.len() / 2);
                parts.extend([
                    ("the first half of ", first),
                    ("the second half of ", second),
                ]);
            }
            for (part, octets) in parts {
                let places: Vec<isize> = self
                    .stack
                    .windows(octets.len())
                    .enumerate()
                    .filter(|(_, window)| window == &octets)
                    // The value of the operation is the program's
                    .filter(|(at, _)| {
                        !(self.owned.start <= *at && at + octets.len() <= self.owned.end)
                    })
                    .map(|(at, _)| SCANNED as isize - at as isize - self.caller as isize)
                    .collect();
                if let Some(deepest) = places.first() {
                    let copies = places.len();
                    findings.push(match *deepest {
                        below @ 0.. => format!(
                            "{part}{name} on the stack, {copies} time(s), {below} octets below \
                             the caller"
                        ),
                        above => format!(
                            "{part}{name} on the stack, {copies} time(s), {} octets above the \
                             stack pointer of the caller",
                            -above
                        ),
                    });
                    break;
                }
            }

            // A register holds eight octets, or thirty-two: any eight
            // octets in a row of the secret, where it has as many
            let piece = secret.len().min(8);
            if piece < 4 || !registers {
                continue;
            }
            let held = |register: &[u8]| {
                secret
                    .windows(piece)
                    .any(|part| register.windows(piece).any(|window| window == part))
            };
            for (register, value) in GENERAL.iter().zip(self.registers.general) {
                if held(&value.to_le_bytes()) {
                    findings.push(format!("{name} in {register}"));
                }
            }
            for (number, value) in self.registers.vector.iter().enumerate() {
                if held(value) {
                    findings.push(format!("{name} in ymm{number}"));
                }
            }
        }
        findings
    }
}

/// Run `victim` on a thread of its own, on a painted stack, and give what
/// it left.
fn observe(victim: impl FnOnce() + Send + 'static) -> Left {
    std::thread::Builder::new()
        .stack_size(8 << 20)
        .spawn(move || {
            let mut stack = vec![0u8; SCANNED];
            let mut registers = Registers {
                general: [0; 9],
                vector: [[0; 32]; 16],
            };
            let mut victim = Some(victim);
            let mut once = || {
                if let Some(victim) = victim.take() {
                    victim();
                }
            };
            let out = stack.as_mut_ptr();
            paint();
            call_and_store(&mut once, &mut registers);
            copy_stack(out);
            let (top, caller) = (TOP.load(Ordering::Relaxed), CALLER.load(Ordering::Relaxed));
            let lowest = top - SCANNED;
            let in_copy =
                |address: &AtomicUsize| address.load(Ordering::Relaxed).saturating_sub(lowest);
            Left {
                stack,
                caller: top.saturating_sub(caller),
                caller_address: caller,
                owned: in_copy(&OWNED[0])..in_copy(&OWNED[1]),
                registers,
            }
        })
        .expect("a thread")
        .join()
        .expect("the operation returns")
}

/// The forms of the code: on every instruction that the processor has, on
/// the vectors of 128 bits alone, and without a vector instruction. The
/// form is the program's, and is set around the whole observation: nothing
/// of the crate runs on the thread of an operation but the operation.
const FORMS: [&str; 3] = ["vector code", "128-bit vectors alone", "scalar code"];

fn in_form<R>(form: usize, work: impl FnOnce() -> R) -> R {
    match form {
        0 => work(),
        1 => narrow(work),
        _ => scalar(work),
    }
}

fn main() -> ExitCode {
    let only: Vec<String> = std::env::args().skip(1).collect();
    let cases = cases::all();
    let (mut failures, mut seen_unwiped) = (0, 0);
    // The deepest work for each number of octets that is cleared
    let mut deepest_of = std::collections::BTreeMap::<usize, (usize, String)>::new();
    println!("{}", processor());
    let implementation = oxirush_security::implementation();
    println!("oxirush-security runs: {implementation:?} ({implementation})");
    println!(
        "{:<58} {:>22} {:>6} {:>8} {:>6}",
        "operation", "form", "depth", "cleared", "areas"
    );
    for case in &cases {
        if !only.is_empty() && !only.iter().any(|part| case.name.contains(part.as_str())) {
            continue;
        }
        for (form, form_name) in FORMS.iter().enumerate().take(case.forms) {
            // Without the clearing: what the scan sees of the operation,
            // and how deep its work goes below where the clearing starts.
            // The crate says which areas it would have cleared: the work
            // is measured against the deepest of them.
            let run = case.run.clone();
            let bare = in_form(form, || unwiped(|| observe(move || run())));
            let seen = bare.findings(&case.secrets, true);
            seen_unwiped += seen.len();
            let (areas, noted) = cleared();
            let deepest = noted[..areas.min(noted.len())]
                .iter()
                .min_by_key(|area| area.0);
            let mut wrong = Vec::new();
            let (depth, of) = match deepest {
                Some((address, octets)) => {
                    let depth = (address + octets).saturating_sub(bare.lowest_written());
                    if too_deep(depth, *octets) {
                        wrong.push(format!(
                            "the work goes {depth} octets deep, more than three quarters \
                             of the {octets} that are cleared"
                        ));
                    }
                    let deepest = deepest_of.entry(*octets).or_default();
                    if depth > deepest.0 {
                        *deepest = (depth, format!("{}, {form_name}", case.name));
                    }
                    (depth, *octets)
                }
                None => {
                    wrong.push("nothing is cleared after the operation".to_string());
                    (0, 0)
                }
            };

            // As a program has it: none of the values is found, and each
            // area that the crate cleared is zero
            let run = case.run.clone();
            let left = in_form(form, || observe(move || run()));
            let (areas, noted) = cleared();
            wrong.extend(left.findings(&case.secrets, true));
            // What the operation returns in a register, on the stack, where
            // the crate is optimized: one built with debug assertions clears
            // 49152 octets after any work
            if of != UNOPTIMIZED {
                wrong.extend(left.findings(&case.returned, false));
            }
            if areas > noted.len() {
                wrong.push(format!(
                    "{areas} areas are cleared, more than the scan follows"
                ));
            }
            for (address, octets) in &noted[..areas.min(noted.len())] {
                let from = left.caller_address.saturating_sub(address + octets);
                // The crate reads the stack pointer for the scan a few
                // instructions before it clears, and the compiler may have
                // moved it by some words between the two: the deep end of
                // the area, far below the work, is given that much
                let to = left.caller_address.saturating_sub(*address) - SLACK;
                // `below` gives the area from its lowest address up
                let area = left.below(from, to);
                let written = |octet: &u8| *octet != 0;
                if let Some(deepest) = area.iter().position(written) {
                    let highest = area.iter().rposition(written).unwrap_or(deepest);
                    wrong.push(format!(
                        "the stack is cleared from {from} to {to} octets below the caller, \
                         and is not zero from {} to {}",
                        to - highest - 1,
                        to - deepest
                    ));
                }
            }
            let vectors = left.vectors_in_use();
            if !vectors.is_empty() {
                wrong.push(format!("{} not zero", vectors.join(", ")));
            }

            println!(
                "{:<58} {:>22} {:>6} {:>8} {:>6}   {}",
                case.name,
                form_name,
                depth,
                of,
                areas,
                match (wrong.is_empty(), seen.len()) {
                    (true, 0) => "nothing left".to_string(),
                    (true, seen) => format!("nothing left ({seen} without the clearing)"),
                    (false, _) => format!("LEFT: {}", wrong.join("; ")),
                }
            );
            if std::env::var_os("LEFTOVERS_VERBOSE").is_some() {
                for finding in &seen {
                    println!("    without the clearing: {finding}");
                }
                for (address, octets) in &noted[..areas.min(noted.len())] {
                    println!(
                        "    cleared: {octets} octets from {} below the caller",
                        left.caller_address as isize - (address + octets) as isize
                    );
                }
            }
            failures += usize::from(!wrong.is_empty());
        }
    }
    println!("{seen_unwiped} leftovers are seen when nothing is cleared after an operation");
    println!("the deepest work for each number of octets that is cleared:");
    for (cleared, (depth, name)) in &deepest_of {
        let share = depth * 100 / cleared;
        println!("{cleared:>8} {depth:>6} {share:>3} %   {name}");
    }
    if failures > 0 {
        println!("FAILED: {failures} operation(s) leave something, or go deeper than is cleared");
        return ExitCode::FAILURE;
    }
    if seen_unwiped == 0 && only.is_empty() {
        println!("FAILED: the scan sees nothing even when nothing is cleared");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
