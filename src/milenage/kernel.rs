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

//! The framework of MILENAGE (TS 35.206 §4.1) on the AES of the crate.
//!
//! A 128-bit value of the framework is a number whose first octet is the
//! high one, as TS 35.206 §2.2.3 writes it: rot(x, r) is then a rotation
//! of the number towards its high bit, and c2 is 1. A block of AES has its
//! first octet as the low one: the kernel turns the octets around on the
//! way in and on the way out.

use super::values::{K, Op, Opc};
use crate::common::aes128::Aes128;
use crate::common::error::SecurityError;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::{AesSchedule, Instructions};
use crate::common::wipe;
use core::fmt;
use zeroize::Zeroizing;

/// The constants of the framework: c1 to c5, which are added to the inputs
/// of the second encryption, and r1 to r5, by which they are rotated
/// (TS 35.206 §4.1).
///
/// [`Constants::default`] has those of TS 35.206 §4.1, which every USIM
/// of MILENAGE has unless its operator chose others: r1 = 64, r2 = 0,
/// r3 = 32, r4 = 64, r5 = 96, c1 = 0, and c2 to c5 the numbers 1, 2, 4 and
/// 8. An operator may choose others (§5.3), as some programmable USIMs let
/// it: [`Constants::new`] takes them, and
/// [`Milenage::with_constants`](super::Milenage::with_constants) a
/// subscriber of such a USIM.
///
/// ```
/// use oxirush_security::milenage::Constants;
///
/// // Those of TS 35.206 §4.1, written out
/// let mut c = [[0u8; 16]; 5];
/// for (constant, last) in c.iter_mut().zip([0, 1, 2, 4, 8]) {
///     constant[15] = last;
/// }
/// let written = Constants::new(c, [64, 0, 32, 64, 96])?;
/// assert_eq!(written, Constants::default());
///
/// // Two pairs (ci, ri) that are the same are refused
/// assert!(Constants::new([[0; 16]; 5], [0, 8, 16, 0, 32]).is_err());
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Constants {
    /// c1 to c5, as numbers whose first octet is the high one.
    c: [u128; 5],
    /// r1 to r5, in bits.
    r: [u8; 5],
}

impl Constants {
    /// Those of TS 35.206 §4.1.
    const SPECIFIED: Self = Self {
        c: [0, 1, 2, 4, 8],
        r: [64, 0, 32, 64, 96],
    };

    /// The constants c1 to c5, as their sixteen octets, and r1 to r5, in
    /// bits.
    ///
    /// An r above 127 is [`SecurityError::OutOfRange`] (TS 35.206 §2.3),
    /// and two pairs (ci, ri) that are the same are
    /// [`SecurityError::InvalidParameter`] (§5.3). §5.3 also recommends
    /// that c1 has an even number of ones and c2 to c5 an odd one, which
    /// is not checked.
    pub fn new(c: [[u8; 16]; 5], r: [u8; 5]) -> Result<Self, SecurityError> {
        if let Some(&rotation) = r.iter().find(|rotation| **rotation > 127) {
            return Err(SecurityError::OutOfRange {
                field: "r",
                maximum: 127,
                got: u64::from(rotation),
            });
        }
        let c = c.map(u128::from_be_bytes);
        for i in 0..5 {
            for j in i + 1..5 {
                if (c[i], r[i]) == (c[j], r[j]) {
                    return Err(SecurityError::InvalidParameter(
                        "the pairs (ci, ri) of MILENAGE are all different",
                    ));
                }
            }
        }
        Ok(Self { c, r })
    }

    /// The input of the second encryption of OUT1:
    /// TEMP ⊕ rot(IN1 ⊕ OPc, r1) ⊕ c1.
    pub(crate) fn input_1(&self, temp: u128, opc: u128, in1: u128) -> u128 {
        temp ^ (in1 ^ opc).rotate_left(self.r[0].into()) ^ self.c[0]
    }

    /// The input of the second encryption of OUTi, for `i` of 2 to 5:
    /// rot(TEMP ⊕ OPc, ri) ⊕ ci.
    pub(crate) fn input(&self, i: usize, temp: u128, opc: u128) -> u128 {
        (temp ^ opc).rotate_left(self.r[i - 1].into()) ^ self.c[i - 1]
    }
}

/// Those of TS 35.206 §4.1.
impl Default for Constants {
    fn default() -> Self {
        Self::SPECIFIED
    }
}

/// r1 to r5, then c1 to c5 in hexadecimal digits.
impl fmt::Debug for Constants {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Constants(r {:?}, c", self.r)?;
        for c in self.c {
            write!(f, " {c:032x}")?;
        }
        f.write_str(")")
    }
}

/// IN1 of OUT1: SQN || AMF || SQN || AMF.
pub(crate) fn in1(sqn: &[u8; 6], amf: &[u8; 2]) -> u128 {
    let mut half = [0u8; 8];
    half[..6].copy_from_slice(sqn);
    half[6..].copy_from_slice(amf);
    let half = u128::from(u64::from_be_bytes(half));
    (half << 64) | half
}

/// E\[x\]K, for blocks that are numbers whose first octet is the high one.
#[derive(Clone, Copy)]
pub(crate) enum Kernel<'a> {
    /// The round keys of K, on the AES instructions.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    Instructions(Instructions, &'a AesSchedule),
    /// The `aes` crate, with K.
    Portable(&'a Aes128),
}

impl Kernel<'_> {
    /// Encrypt each block where it is.
    pub(crate) fn encrypt<const N: usize>(self, blocks: &mut [u128; N]) {
        match self {
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            Self::Instructions(instructions, schedule) => {
                for block in blocks.iter_mut() {
                    *block = block.swap_bytes();
                }
                instructions.aes_encrypt([schedule; N], blocks);
                for block in blocks.iter_mut() {
                    *block = block.swap_bytes();
                }
            }
            Self::Portable(aes) => {
                let mut octets = Zeroizing::new(blocks.map(u128::to_be_bytes));
                aes.encrypt_blocks(&mut *octets);
                for (block, octets) in blocks.iter_mut().zip(octets.iter()) {
                    *block = u128::from_be_bytes(*octets);
                }
            }
        }
    }
}

/// Run `work` with the kernel of `k`, in a frame of its own whose stack
/// and registers are cleared after it: on the AES instructions where the
/// processor has them, with the `aes` crate elsewhere.
pub(crate) fn with_kernel<R>(k: &[u8; 16], work: impl FnOnce(Kernel<'_>) -> R) -> R {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return wipe::aes(|| with_instructions_kernel(instructions, k, work));
    }
    wipe::portable(|| with_portable_kernel(k, work))
}

/// Run `work` with the kernel of `k` on the AES instructions, for a caller
/// that clears after its own work.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn with_instructions_kernel<R>(
    instructions: Instructions,
    k: &[u8; 16],
    work: impl FnOnce(Kernel<'_>) -> R,
) -> R {
    let schedule = instructions.aes_schedules([k]);
    work(Kernel::Instructions(instructions, &schedule[0]))
}

/// Run `work` with the kernel of `k` on the `aes` crate, for a caller that
/// clears after its own work.
pub(crate) fn with_portable_kernel<R>(k: &[u8; 16], work: impl FnOnce(Kernel<'_>) -> R) -> R {
    work(Kernel::Portable(&Aes128::new(k)))
}

/// E\[x\]K for `N` subscribers side by side, each with its K, on the AES
/// instructions: block `i` is that of subscriber `i`.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
pub(crate) struct Lanes<'a, const N: usize> {
    pub(crate) instructions: Instructions,
    pub(crate) schedules: [&'a AesSchedule; N],
}

#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
impl<const N: usize> Lanes<'_, N> {
    /// Encrypt each block where it is, with the key of its subscriber, and
    /// add the OPc of its subscriber when there is one.
    pub(crate) fn encrypt(self, blocks: &mut [u128; N], opc: Option<&[u128; N]>) {
        for block in blocks.iter_mut() {
            *block = block.swap_bytes();
        }
        self.instructions.aes_encrypt(self.schedules, blocks);
        for (at, block) in blocks.iter_mut().enumerate() {
            *block = block.swap_bytes() ^ opc.map_or(0, |opc| opc[at]);
        }
    }
}

/// The work of one call for one RAND: OPc, and TEMP = E\[RAND ⊕ OPc\]K,
/// from which OUT1 to OUT5 are computed.
pub(crate) struct Temp<'a> {
    kernel: Kernel<'a>,
    constants: &'a Constants,
    opc: Zeroizing<u128>,
    temp: Zeroizing<u128>,
}

impl<'a> Temp<'a> {
    /// TEMP of `rand`.
    pub(crate) fn new(
        kernel: Kernel<'a>,
        constants: &'a Constants,
        opc: &[u8; 16],
        rand: &[u8; 16],
    ) -> Self {
        let opc = Zeroizing::new(u128::from_be_bytes(*opc));
        let mut temp = Zeroizing::new([u128::from_be_bytes(*rand) ^ *opc]);
        kernel.encrypt(&mut temp);
        Self {
            kernel,
            constants,
            opc,
            temp: Zeroizing::new(temp[0]),
        }
    }

    /// The input of the second encryption of OUT1, with IN1 of `sqn` and
    /// `amf`.
    pub(crate) fn input_1(&self, sqn: &[u8; 6], amf: &[u8; 2]) -> u128 {
        self.constants.input_1(*self.temp, *self.opc, in1(sqn, amf))
    }

    /// The input of the second encryption of OUTi, `i` of 2 to 5.
    pub(crate) fn input(&self, i: usize) -> u128 {
        self.constants.input(i, *self.temp, *self.opc)
    }

    /// OUT of each input: E\[input\]K ⊕ OPc. The encryptions run side by
    /// side.
    pub(crate) fn outputs<const N: usize>(&self, inputs: [u128; N]) -> Zeroizing<[u128; N]> {
        let mut blocks = Zeroizing::new(inputs);
        self.kernel.encrypt(&mut blocks);
        for block in blocks.iter_mut() {
            *block ^= *self.opc;
        }
        blocks
    }

    /// TEMP, for the tests of the intermediate values of TS 35.207.
    #[cfg(test)]
    pub(crate) fn temp(&self) -> u128 {
        *self.temp
    }
}

/// OPc of K and OP: OP ⊕ E\[OP\]K (TS 35.206 §4.1).
pub(crate) fn opc_of(k: &K, op: &Op) -> Opc {
    with_kernel(k.as_octets(), |kernel| {
        let op = Zeroizing::new(u128::from_be_bytes(*op.as_octets()));
        let mut block = Zeroizing::new([*op]);
        kernel.encrypt(&mut block);
        let opc = Zeroizing::new((block[0] ^ *op).to_be_bytes());
        Opc::new(&opc)
    })
}

/// The high 64 bits of a block, as octets.
pub(crate) fn high_64(block: u128) -> [u8; 8] {
    ((block >> 64) as u64).to_be_bytes()
}

/// The low 64 bits of a block, as octets.
pub(crate) fn low_64(block: u128) -> [u8; 8] {
    (block as u64).to_be_bytes()
}

/// The high 48 bits of a block, as octets.
pub(crate) fn high_48(block: u128) -> [u8; 6] {
    let octets = high_64(block);
    *octets.first_chunk().expect("eight octets")
}
