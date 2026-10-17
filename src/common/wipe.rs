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

//! What an operation leaves behind it, wiped.
//!
//! The values that a function names are wiped where they are: keys, round
//! keys, generator states and keystream are `Zeroizing` or wiped by hand.
//! That does not reach what the compiler puts on the stack on its own, the
//! copies that it spills there, nor the registers. So the work of each
//! public operation that handles a key runs in a frame of its own, and
//! when it has returned:
//!
//! - the stack below is set to zero over more octets than the work uses
//!   there;
//! - on x86-64 and on AArch64, the registers that a function need not
//!   give back as it found them are set to zero.
//!
//! `leftovers/` in the repository measures how deep each operation goes
//! and looks for its keys and its keystream after it has returned: the
//! depths below come from it, and it fails when one of them is no longer
//! enough.
//!
//! A build with `--cfg oxirush_security_unwiped` does neither, and its
//! operations need no more stack than their own.

/// Octets of stack that are cleared after a piece of work, by its kind:
/// multiples of 64. Each is at least twice what the deepest work of the
/// kind used wherever it was run in an optimized build: on x86-64 in each
/// form of the code, with three versions of the compiler and several ways
/// of building, here and on the runners of CI, and on an emulated AArch64
/// processor. `leftovers/README.md` has the measures, and the scan fails
/// when a piece of work uses more than three quarters of what is cleared
/// after it.
pub(crate) mod depth {
    /// AES on its instructions with the round keys of a context, for one
    /// message.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) const AES_KEYED: usize = 1792;
    /// AES on its instructions from a key, for one message or for one
    /// after the other.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) const AES: usize = 2304;
    /// SNOW 3G and ZUC, for one message; the making of a generator.
    pub(crate) const MESSAGE: usize = 4096;
    /// What goes through the `aes` crate with a key: AES for one message
    /// on a processor without its instructions or a target without the
    /// vector code, the making of a keyed context, and the messages of a
    /// batch one after the other.
    ///
    /// On x86 the `aes` crate has code for a processor with AVX-512F, in
    /// which the counter mode of this crate is compiled as well. No
    /// machine here runs it: in the builds whose binary was read, its
    /// frames are up to 1700 octets more than those of its code on the AES
    /// instructions, and the figure is twice what that gives.
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    pub(crate) const PORTABLE: usize = 8192;
    /// What goes through the `aes` crate with a key, on a target where it
    /// has one code on instructions at most.
    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    pub(crate) const PORTABLE: usize = 6144;
    /// Several messages side by side.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) const LANES: usize = 18432;
    /// Words of keystream from a generator, and a comparison.
    pub(crate) const WORDS: usize = 1536;
    /// A key derivation: one HMAC-SHA-256.
    pub(crate) const DERIVATION: usize = 4096;
    /// SUCI: a scalar multiplication on Curve25519 or on secp256r1.
    #[cfg(feature = "suci")]
    pub(crate) const SUCI: usize = 12288;
}

/// AES on its instructions with the round keys of a context.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn aes_keyed<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::AES_KEYED }, R>(work)
}

/// AES on its instructions.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn aes<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::AES }, R>(work)
}

/// SNOW 3G or ZUC on one message, or a new generator.
#[inline(always)]
pub(crate) fn message<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::MESSAGE }, R>(work)
}

/// What goes through the `aes` crate with a key.
#[inline(always)]
pub(crate) fn portable<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::PORTABLE }, R>(work)
}

/// Several messages side by side.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[inline(always)]
pub(crate) fn lanes<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::LANES }, R>(work)
}

/// Words of keystream, or a comparison.
#[inline(always)]
pub(crate) fn words<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::WORDS }, R>(work)
}

/// A key derivation.
#[inline(always)]
pub(crate) fn derivation<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::DERIVATION }, R>(work)
}

/// A concealment or a de-concealment.
#[cfg(feature = "suci")]
#[inline(always)]
pub(crate) fn suci<R>(work: impl FnOnce() -> R) -> R {
    after::<{ depth::SUCI }, R>(work)
}

/// Run `work` in a frame of its own, then clear the registers and
/// `DEPTH` octets of the stack below the caller.
///
/// A function calls this last, so that the value of `work` goes from its
/// frame to where the program wants it and nowhere between, and the
/// function that returns holds no copy of it:
///
/// - a value of one word or less, which is returned in a general register,
///   is kept in a register that the clearing does not write while it
///   clears. The clearing then runs here, without a call: the compiler may
///   make the drop of a value a function of its own, which saves on the
///   stack what a register held, the result of the work, above what it
///   clears;
/// - a larger value is written where the program wants it by `work`
///   itself, and the clearing is what a value does when it is dropped,
///   after the result is in its place. Holding it across the clearing
///   would take vector registers, which the clearing writes, or the stack.
#[inline(always)]
fn after<const DEPTH: usize, R>(work: impl FnOnce() -> R) -> R {
    #[cfg(oxirush_security_unwiped)]
    return work();
    #[cfg(not(oxirush_security_unwiped))]
    {
        let clear = Clear::<DEPTH>;
        if size_of::<R>() <= size_of::<usize>() {
            let result = below(work);
            clear.now();
            result
        } else {
            let _clear = clear;
            below(work)
        }
    }
}

/// `work`, in a frame that is not that of the caller: what it puts on the
/// stack is below the caller, where the clearing is.
#[cfg(not(oxirush_security_unwiped))]
#[inline(never)]
fn below<R>(work: impl FnOnce() -> R) -> R {
    work()
}

/// The clearing of the registers and of `DEPTH` octets of stack, when it
/// is dropped or when [`now`](Self::now) says so.
#[cfg(not(oxirush_security_unwiped))]
struct Clear<const DEPTH: usize>;

#[cfg(not(oxirush_security_unwiped))]
impl<const DEPTH: usize> Clear<DEPTH> {
    /// Clear now, in the function that calls this, and not when the value
    /// is dropped.
    #[inline(always)]
    fn now(self) {
        core::mem::ManuallyDrop::new(self).clear();
    }
}

/// What is cleared in a build with debug assertions, whatever the work:
/// code that is not optimized goes several times deeper, and this is
/// twice what the deepest of it was measured to use.
#[cfg(not(oxirush_security_unwiped))]
const UNOPTIMIZED: usize = 49152;

#[cfg(not(oxirush_security_unwiped))]
impl<const DEPTH: usize> Drop for Clear<DEPTH> {
    #[inline(always)]
    fn drop(&mut self) {
        self.clear();
    }
}

#[cfg(not(oxirush_security_unwiped))]
impl<const DEPTH: usize> Clear<DEPTH> {
    #[inline(always)]
    fn clear(&self) {
        // On x86-64 and on AArch64, instructions clear the stack below
        // this function and the registers, without a call
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            let depth = if cfg!(debug_assertions) {
                UNOPTIMIZED
            } else {
                DEPTH
            };
            // The scan is told first: what telling it puts on the stack
            // is cleared with the rest. It is told as well when it has
            // turned the clearing off, to know how deep the work went
            // below where the clearing starts.
            #[cfg(oxirush_security_hooks)]
            {
                hooks::note(crate::common::simd::stack_pointer() - depth, depth);
                if !hooks::wiping() {
                    return;
                }
            }
            crate::common::simd::clear(depth);
        }
        // Elsewhere the frame of a function is where those of the work
        // were, and the registers stay as they are
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        {
            #[cfg(oxirush_security_hooks)]
            if !hooks::wiping() {
                return;
            }
            if cfg!(debug_assertions) {
                stack::<UNOPTIMIZED>();
            } else {
                stack::<DEPTH>();
            }
        }
    }
}

/// Set to zero `DEPTH` octets of the stack below the caller: the frame of
/// this function is where those of the work were.
#[cfg(not(any(
    oxirush_security_unwiped,
    target_arch = "x86_64",
    target_arch = "aarch64"
)))]
#[inline(never)]
fn stack<const DEPTH: usize>() {
    let mut area = [0u8; DEPTH];
    // The compiler cannot tell that nothing reads the zeros
    core::hint::black_box(&mut area);
    #[cfg(oxirush_security_hooks)]
    hooks::note(area.as_ptr() as usize, DEPTH);
}

/// What the scan of `leftovers/` turns off to see what an operation
/// leaves when nothing is wiped after it, and what it reads of the
/// clearing.
#[cfg(all(oxirush_security_hooks, not(oxirush_security_unwiped)))]
pub(crate) mod hooks {
    use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    static UNWIPED: AtomicBool = AtomicBool::new(false);
    /// The areas that were cleared: how many, and the address and the
    /// octets of the first of them.
    static AREAS: AtomicUsize = AtomicUsize::new(0);
    static NOTED: [[AtomicUsize; 2]; KEPT] =
        [const { [AtomicUsize::new(0), AtomicUsize::new(0)] }; KEPT];
    /// The areas whose place is kept.
    pub(crate) const KEPT: usize = 8;

    pub(crate) fn wiping() -> bool {
        !UNWIPED.load(Ordering::Relaxed)
    }

    /// Run `work` without the clearing of the registers and of the stack.
    pub(crate) fn unwiped<R>(work: impl FnOnce() -> R) -> R {
        let before = UNWIPED.swap(true, Ordering::Relaxed);
        let result = work();
        UNWIPED.store(before, Ordering::Relaxed);
        result
    }

    /// Note an area of stack that was cleared.
    #[inline(always)]
    pub(super) fn note(address: usize, octets: usize) {
        let at = AREAS.fetch_add(1, Ordering::Relaxed);
        if let Some([noted_address, noted_octets]) = NOTED.get(at) {
            noted_address.store(address, Ordering::Relaxed);
            noted_octets.store(octets, Ordering::Relaxed);
        }
    }

    /// How many areas of stack were cleared since the last call, and the
    /// address and the octets of the first [`KEPT`] of them.
    pub(crate) fn cleared() -> (usize, [(usize, usize); KEPT]) {
        let areas = AREAS.swap(0, Ordering::Relaxed);
        let noted = core::array::from_fn(|at| {
            let [address, octets] = &NOTED[at];
            (
                address.load(Ordering::Relaxed),
                octets.load(Ordering::Relaxed),
            )
        });
        (areas, noted)
    }
}
