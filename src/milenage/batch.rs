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

//! Many subscribers at once, as a home network or a fleet of UEs has them.
//!
//! [`authentication_vector_batch`] and [`check_autn_batch`] give each job
//! what [`Milenage::authentication_vector`] and [`Milenage::check_autn`]
//! give it alone. On a processor with the AES instructions the key
//! expansions of eight subscribers run side by side, and so do their
//! encryptions, a block of each at a time; the stack and the registers are
//! cleared once, after the batch. Elsewhere the jobs are one after the
//! other, with the `aes` crate. The values are the same.
//!
//! What runs at a step depends on the number of jobs alone: the time of a
//! job depends on no key or value of another. The last group of a batch,
//! when it has fewer than eight jobs, runs as many places side by side as it
//! has jobs, rounded up to 1, 2, 4 or 8. The stack is cleared after the
//! batch over 18432 octets, which takes about as long as one vector: for
//! one or two subscribers, a call for each is faster.

use super::Milenage;
use super::aka::{AuthenticationVector, UsimResponse, response, vector};
use super::kernel::{Kernel, Temp, with_portable_kernel};
use super::values::{Amf, Sqn};
use crate::common::error::SecurityError;
use crate::common::keys::{Autn, Rand};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::Instructions;
use crate::common::wipe;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use zeroize::Zeroizing;

/// The authentication vector of a subscriber in a batch: what
/// [`Milenage::authentication_vector`] takes, and the vector once the batch
/// has made it.
pub struct VectorJob<'a> {
    subscriber: &'a Milenage,
    rand: &'a Rand,
    sqn: &'a Sqn,
    amf: &'a Amf,
    vector: Option<AuthenticationVector>,
}

impl<'a> VectorJob<'a> {
    /// The vector of `rand`, `sqn` and `amf` for `subscriber`.
    pub fn new(subscriber: &'a Milenage, rand: &'a Rand, sqn: &'a Sqn, amf: &'a Amf) -> Self {
        Self {
            subscriber,
            rand,
            sqn,
            amf,
            vector: None,
        }
    }

    /// The vector, once [`authentication_vector_batch`] has made it:
    /// `None` before.
    pub fn vector(&self) -> Option<&AuthenticationVector> {
        self.vector.as_ref()
    }

    /// The vector, taken out of the job.
    pub fn into_vector(self) -> Option<AuthenticationVector> {
        self.vector
    }

    /// The vector, as the function of one subscriber makes it, with the
    /// kernel of its K, for a caller that clears after its own work.
    fn alone(&mut self, kernel: Kernel<'_>) {
        let (subscriber, rand) = (self.subscriber, self.rand.as_octets());
        let temp = Temp::new(
            kernel,
            &subscriber.constants,
            subscriber.opc.as_octets(),
            rand,
        );
        self.vector = Some(vector(&temp, self.rand, self.sqn, self.amf));
    }
}

/// The check of an AUTN by a USIM in a batch: what
/// [`Milenage::check_autn`] takes, and what it gives once the batch has
/// checked it.
pub struct AutnJob<'a> {
    subscriber: &'a Milenage,
    rand: &'a Rand,
    autn: &'a Autn,
    response: Option<Result<UsimResponse, SecurityError>>,
}

impl<'a> AutnJob<'a> {
    /// The check of `autn` for the challenge `rand`, by `subscriber`.
    pub fn new(subscriber: &'a Milenage, rand: &'a Rand, autn: &'a Autn) -> Self {
        Self {
            subscriber,
            rand,
            autn,
            response: None,
        }
    }

    /// What [`Milenage::check_autn`] gives, once [`check_autn_batch`] has
    /// checked the AUTN: `None` before.
    pub fn response(&self) -> Option<Result<&UsimResponse, SecurityError>> {
        self.response
            .as_ref()
            .map(|response| response.as_ref().map_err(Clone::clone))
    }

    /// What [`Milenage::check_autn`] gives, taken out of the job.
    pub fn into_response(self) -> Option<Result<UsimResponse, SecurityError>> {
        self.response
    }

    /// The check, as the function of one subscriber makes it, with the
    /// kernel of its K, for a caller that clears after its own work.
    fn alone(&mut self, kernel: Kernel<'_>) {
        let (subscriber, rand) = (self.subscriber, self.rand.as_octets());
        let temp = Temp::new(
            kernel,
            &subscriber.constants,
            subscriber.opc.as_octets(),
            rand,
        );
        self.response = Some(response(&temp, self.rand, self.autn));
    }
}

/// Make the authentication vector of each job, which
/// [`VectorJob::vector`] then gives.
///
/// ```
/// use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn, VectorJob};
/// use oxirush_security::{Rand, milenage};
///
/// // A thousand subscribers, each with its K, its RAND and its next SQN
/// let subscribers: Vec<Milenage> = (0..1000u16)
///     .map(|n| {
///         let mut k = [0x46; 16];
///         k[..2].copy_from_slice(&n.to_be_bytes());
///         Milenage::new(&K::new(&k), &Opc::new(&[0xcd; 16]))
///     })
///     .collect();
/// let rands: Vec<Rand> = (0..1000u16).map(|n| Rand::new(&[n as u8; 16])).collect();
/// let (sqn, amf) = (Sqn::try_from(32)?, Amf::new(&[0x80, 0x00]));
///
/// let mut jobs: Vec<_> = (subscribers.iter().zip(&rands))
///     .map(|(subscriber, rand)| VectorJob::new(subscriber, rand, &sqn, &amf))
///     .collect();
/// milenage::authentication_vector_batch(&mut jobs);
/// let alone = subscribers[7].authentication_vector(&rands[7], &sqn, &amf);
/// assert_eq!(jobs[7].vector().unwrap().autn(), alone.autn());
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
pub fn authentication_vector_batch(jobs: &mut [VectorJob<'_>]) {
    if jobs.is_empty() {
        return;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return wipe::lanes(|| lanes::vectors(instructions, jobs));
    }
    wipe::portable(|| {
        for job in jobs {
            let k = job.subscriber.k.as_octets();
            with_portable_kernel(k, |kernel| job.alone(kernel));
        }
    });
}

/// Check the AUTN of each job, as [`Milenage::check_autn`] does, which
/// [`AutnJob::response`] then gives.
pub fn check_autn_batch(jobs: &mut [AutnJob<'_>]) {
    if jobs.is_empty() {
        return;
    }
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return wipe::lanes(|| lanes::responses(instructions, jobs));
    }
    wipe::portable(|| {
        for job in jobs {
            let k = job.subscriber.k.as_octets();
            with_portable_kernel(k, |kernel| job.alone(kernel));
        }
    });
}

/// The jobs of a batch on the AES instructions, eight subscribers at a
/// time.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
mod lanes {
    use super::*;
    use crate::common::simd::AesSchedule;
    use crate::milenage::aka::{response_of, sqn_and_amf_of, vector_of};
    use crate::milenage::kernel::{Lanes, in1};

    /// How many subscribers are taken together: the AES instructions of a
    /// processor run the rounds of as many blocks side by side.
    const GROUP: usize = 8;

    /// Each group of `jobs` through `group`, with as many places side by
    /// side as it has jobs: 1, 2, 4 or 8. A place without a job takes the
    /// last job again, whose values it computes and does not keep.
    macro_rules! by_groups {
        ($instructions:expr, $jobs:expr, $group:ident) => {
            for jobs in $jobs.chunks_mut(GROUP) {
                match jobs.len() {
                    1 => $group::<1>($instructions, jobs),
                    2 => $group::<2>($instructions, jobs),
                    3 | 4 => $group::<4>($instructions, jobs),
                    _ => $group::<GROUP>($instructions, jobs),
                }
            }
        };
    }

    /// The subscribers of a group, side by side: the round keys of their
    /// K, their OPc and their TEMP.
    struct Group<'s, const N: usize> {
        subscribers: [&'s Milenage; N],
        lanes: Lanes<'s, N>,
        opc: Zeroizing<[u128; N]>,
        temp: Zeroizing<[u128; N]>,
    }

    impl<'s, const N: usize> Group<'s, N> {
        /// The encryptions of TEMP, with the round keys of each K.
        fn new(subscribers: [&'s Milenage; N], lanes: Lanes<'s, N>, rands: [&Rand; N]) -> Self {
            let opc = Zeroizing::new(subscribers.map(|s| u128::from_be_bytes(*s.opc.as_octets())));
            let rand = |at: usize| u128::from_be_bytes(*rands[at].as_octets());
            let mut temp = Zeroizing::new(core::array::from_fn(|at| rand(at) ^ opc[at]));
            lanes.encrypt(&mut temp, None);
            Self {
                subscribers,
                lanes,
                opc,
                temp,
            }
        }

        /// OUTi of each subscriber, `i` of 2 to 5.
        fn outputs(&self, i: usize) -> Zeroizing<[u128; N]> {
            self.outputs_of(|at, temp, opc| self.subscribers[at].constants.input(i, temp, opc))
        }

        /// OUT1 of each subscriber, with the IN1 that `in1` gives it.
        fn outputs_1(&self, in1: impl Fn(usize) -> u128) -> Zeroizing<[u128; N]> {
            let constants = |at: usize| &self.subscribers[at].constants;
            self.outputs_of(|at, temp, opc| constants(at).input_1(temp, opc, in1(at)))
        }

        /// The encryptions of what `input` gives each subscriber, side by
        /// side, with its OPc added.
        fn outputs_of(&self, input: impl Fn(usize, u128, u128) -> u128) -> Zeroizing<[u128; N]> {
            let mut out = Zeroizing::new(core::array::from_fn(|at| {
                input(at, self.temp[at], self.opc[at])
            }));
            self.lanes.encrypt(&mut out, Some(&self.opc));
            out
        }
    }

    /// The subscribers of the first `N` places, the last job taking the
    /// places that have none, and the round keys of their K, side by side.
    fn expanded<'s, const N: usize>(
        instructions: Instructions,
        subscriber: impl Fn(usize) -> &'s Milenage,
    ) -> ([&'s Milenage; N], Zeroizing<[AesSchedule; N]>) {
        let subscribers: [&Milenage; N] = core::array::from_fn(subscriber);
        let schedules = instructions.aes_schedules(subscribers.map(|s| s.k.as_octets()));
        (subscribers, schedules)
    }

    pub(super) fn vectors(instructions: Instructions, jobs: &mut [VectorJob<'_>]) {
        by_groups!(instructions, jobs, vector_group);
    }

    /// The vectors of a group of `N` jobs or fewer: OUT1 to OUT4.
    fn vector_group<const N: usize>(instructions: Instructions, jobs: &mut [VectorJob<'_>]) {
        let job = |at: usize| &jobs[at.min(jobs.len() - 1)];
        let (subscribers, schedules) = expanded::<N>(instructions, |at| job(at).subscriber);
        let lanes = Lanes {
            instructions,
            schedules: schedules.each_ref(),
        };
        let group = Group::new(subscribers, lanes, core::array::from_fn(|at| job(at).rand));
        let out1 = group.outputs_1(|at| in1(job(at).sqn.as_octets(), job(at).amf.as_octets()));
        let [out2, out3, out4] = [2, 3, 4].map(|i| group.outputs(i));
        for (at, job) in jobs.iter_mut().enumerate() {
            let out = [out2[at], out3[at], out4[at]];
            job.vector = Some(vector_of(job.rand, job.sqn, job.amf, out1[at], out));
        }
    }

    pub(super) fn responses(instructions: Instructions, jobs: &mut [AutnJob<'_>]) {
        by_groups!(instructions, jobs, response_group);
    }

    /// The responses of a group of `N` jobs or fewer: OUT2 to OUT4, then
    /// OUT1 of the SQN that AK gives.
    fn response_group<const N: usize>(instructions: Instructions, jobs: &mut [AutnJob<'_>]) {
        let job = |at: usize| &jobs[at.min(jobs.len() - 1)];
        let (subscribers, schedules) = expanded::<N>(instructions, |at| job(at).subscriber);
        let lanes = Lanes {
            instructions,
            schedules: schedules.each_ref(),
        };
        let group = Group::new(subscribers, lanes, core::array::from_fn(|at| job(at).rand));
        let [out2, out3, out4] = [2, 3, 4].map(|i| group.outputs(i));
        let out1 = group.outputs_1(|at| {
            let (sqn, amf) = sqn_and_amf_of(job(at).autn, out2[at]);
            in1(&sqn, &amf)
        });
        for (at, job) in jobs.iter_mut().enumerate() {
            let out = [out2[at], out3[at], out4[at]];
            job.response = Some(response_of(job.rand, job.autn, out1[at], out));
        }
    }
}
