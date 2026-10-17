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

//! MILENAGE, the example algorithm set of 3GPP for the authentication and
//! key generation functions f1, f1\*, f2, f3, f4, f5 and f5\* (TS 35.205,
//! TS 35.206), and the authentication of TS 33.102 on it.
//!
//! ```rust
//! use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
//! use oxirush_security::Rand;
//!
//! // A subscriber: K and OPc, which its USIM and its home network share
//! let octets = |s: &str| hex::decode(s).unwrap();
//! let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc"))?;
//! let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf"))?;
//! let subscriber = Milenage::new(&k, &opc);
//!
//! // Home network: an authentication vector for a RAND, its next SQN and
//! // an AMF with the separation bit
//! let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35"))?;
//! let (sqn, amf) = (Sqn::try_from(0x2a)?, Amf::new(&[0x80, 0x00]));
//! let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
//!
//! // UE: the USIM checks the MAC of AUTN, and gives SQN for the ME to judge
//! let response = subscriber.check_autn(vector.rand(), vector.autn())?;
//! assert_eq!(response.sqn().get(), 0x2a);
//! assert!(response.amf().separation_bit());
//! assert!(vector.xres().accepts(response.res()));
//!
//! // A USIM whose SQNMS is ahead answers with an AUTS, which the home
//! // network reads back
//! let auts = subscriber.auts(&rand, &Sqn::try_from(0x40)?);
//! assert_eq!(subscriber.verify_auts(&rand, &auts)?.get(), 0x40);
//! # Ok::<(), oxirush_security::SecurityError>(())
//! ```
//!
//! [`Milenage`] is a subscriber: K, OPc, and the constants of the
//! framework, which are those of TS 35.206 §4.1 unless its operator chose
//! others ([`Constants`]). Each of its operations runs AES on the
//! instructions of the processor where it has them, and with the `aes`
//! crate elsewhere, and clears the stack and the registers that it used
//! when it returns, as every operation of the crate that computes with a
//! key does.
//!
//! | Operation | What it computes | Clause |
//! |-----------|------------------|--------|
//! | [`Opc::from_op`] | OPc = OP ⊕ E\[OP\]K | TS 35.206 §4.1 |
//! | [`Milenage::f1`], [`f1_star`](Milenage::f1_star) | MAC-A, MAC-S | TS 35.206 §4.1 |
//! | [`f2`](Milenage::f2), [`f3`](Milenage::f3), [`f4`](Milenage::f4), [`f5`](Milenage::f5), [`f5_star`](Milenage::f5_star), [`f2345`](Milenage::f2345) | RES, CK, IK, AK, AK\* | TS 35.206 §4.1 |
//! | [`authentication_vector`](Milenage::authentication_vector) | RAND, XRES, CK, IK and AUTN = SQN ⊕ AK \|\| AMF \|\| MAC-A, in the home network | TS 33.102 §6.3.2 |
//! | [`check_autn`](Milenage::check_autn) | In the USIM: SQN from AUTN, MAC-A checked, then RES, CK and IK | TS 33.102 §6.3.3 |
//! | [`auts`](Milenage::auts) | In the USIM: AUTS = SQNMS ⊕ AK\* \|\| MAC-S, with an AMF of zeros | TS 33.102 §6.3.3 |
//! | [`verify_auts`](Milenage::verify_auts) | In the home network: SQNMS from AUTS, MAC-S checked | TS 33.102 §6.3.5 |
//! | [`AuthenticationVector::xres_star`], [`UsimResponse::res_star`] | XRES\* and RES\* of 5GS, from the outputs of MILENAGE | TS 33.501 Annex A.4 |
//! | [`authentication_vector_batch`], [`check_autn_batch`] | The vectors, or the checks of AUTN, of many subscribers | TS 33.102 §6.3.2 and §6.3.3 |
//!
//! A MAC is compared in a time that does not depend on where it differs.
//! What the crate does not decide is the policy of the caller: whether a
//! SQN is fresh (TS 33.102 §6.3.3 and Annex C), and whether the AMF has
//! the separation bit that EPS and 5GS ask for (TS 33.401 §6.1.1,
//! TS 33.501 §6.1.3.2). [`UsimResponse`] gives both, and a UE whose SQN is
//! out of range answers with [`Milenage::auts`].
//!
//! K, OP, OPc, AK, AK\* and XRES are keys, wiped when they are dropped
//! and printed without their octets; SQN, AMF, MAC-A, MAC-S, RES and AUTS
//! print whole, as RAND and AUTN of the crate root do.
//!
//! [`authentication_vector_batch`] and [`check_autn_batch`] make the
//! vectors or check the AUTNs of many subscribers in one call: on the AES
//! instructions eight subscribers run side by side, and a thousand take
//! half the time of a call for each.
//!
//! # Types
//!
//! | Type | Octets | Kind |
//! |------|-------:|------|
//! | [`K`], [`Op`], [`Opc`] | 16 | Key |
//! | [`Ak`], [`AkStar`] | 6 | Key |
//! | [`Xres`] | 8 | Key |
//! | [`Rand`], [`Autn`](crate::Autn) | 16 | Public value, at the crate root |
//! | [`Ck`], [`Ik`] | 16 | Key, at the crate root |
//! | [`Sqn`] | 6 | Public value, with [`Sqn::get`] and `TryFrom<u64>` |
//! | [`Amf`] | 2 | Public value, with [`Amf::separation_bit`] |
//! | [`MacA`], [`MacS`], [`Res`] | 8 | Public value |
//! | [`Auts`] | 14 | Public value |
//!
//! TUAK, the other algorithm set of 3GPP (TS 35.231), is not in the crate.

mod aka;
mod batch;
mod kernel;
#[cfg(test)]
mod tests;
mod values;

pub use aka::{AuthenticationVector, UsimResponse};
pub use batch::{AutnJob, VectorJob, authentication_vector_batch, check_autn_batch};
pub use kernel::Constants;
pub use values::{Ak, AkStar, Amf, Auts, K, MacA, MacS, Op, Opc, Res, Sqn, Xres};

use crate::common::keys::{Ck, Ik, Rand};
use core::fmt;
use kernel::{Temp, high_48, high_64, low_64, with_kernel};

/// A subscriber of MILENAGE: its K and its OPc, and the constants of the
/// framework.
///
/// It is wiped when it is dropped, and `{:?}` prints nothing of K or OPc.
/// Making one computes nothing: each function computes from K.
///
/// ```
/// use oxirush_security::milenage::{K, Milenage, Op, Opc};
/// use oxirush_security::Rand;
///
/// // TS 35.208 test set 1: OPc from OP, then f2 to f5
/// let k = K::new(&[
///     0x46, 0x5b, 0x5c, 0xe8, 0xb1, 0x99, 0xb4, 0x9f, 0xaa, 0x5f, 0x0a, 0x2e, 0xe2, 0x38, 0xa6, 0xbc,
/// ]);
/// let op = Op::new(&[
///     0xcd, 0xc2, 0x02, 0xd5, 0x12, 0x3e, 0x20, 0xf6, 0x2b, 0x6d, 0x67, 0x6a, 0xc7, 0x2c, 0xb3, 0x18,
/// ]);
/// let rand = Rand::new(&[
///     0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf, 0x35,
/// ]);
/// let subscriber = Milenage::new(&k, &Opc::from_op(&k, &op));
/// let (res, ck, ik, ak) = subscriber.f2345(&rand);
/// assert_eq!(res.as_octets(), &[0xa5, 0x42, 0x11, 0xd5, 0xe3, 0xba, 0x50, 0xbf]);
/// assert_eq!(ak.as_octets(), &[0xaa, 0x68, 0x9c, 0x64, 0x83, 0x70]);
/// assert_eq!(ck, subscriber.f3(&rand));
/// assert_eq!(ik, subscriber.f4(&rand));
/// ```
#[derive(Clone)]
pub struct Milenage {
    k: K,
    opc: Opc,
    constants: Constants,
}

impl Milenage {
    /// The subscriber of `k` and `opc`, with the constants of TS 35.206
    /// §4.1. [`Opc::from_op`] gives OPc where OP is known.
    pub fn new(k: &K, opc: &Opc) -> Self {
        Self::with_constants(k, opc, Constants::default())
    }

    /// The subscriber of `k` and `opc`, with constants that its operator
    /// chose (TS 35.206 §5.3).
    pub fn with_constants(k: &K, opc: &Opc, constants: Constants) -> Self {
        Self {
            k: k.clone(),
            opc: opc.clone(),
            constants,
        }
    }

    /// The constants of the framework.
    pub fn constants(&self) -> Constants {
        self.constants
    }

    /// Run `work` on TEMP of `rand`, in a frame whose stack and registers
    /// are cleared after it.
    fn run<R>(&self, rand: &Rand, work: impl FnOnce(&Temp<'_>) -> R) -> R {
        let (k, opc, rand) = (self.k.as_octets(), self.opc.as_octets(), rand.as_octets());
        with_kernel(k, |kernel| {
            work(&Temp::new(kernel, &self.constants, opc, rand))
        })
    }

    /// f1: MAC-A of `sqn`, `rand` and `amf`, the MAC of an AUTN.
    pub fn f1(&self, rand: &Rand, sqn: &Sqn, amf: &Amf) -> MacA {
        self.run(rand, |temp| {
            let out1 = temp.outputs([temp.input_1(sqn.as_octets(), amf.as_octets())]);
            MacA::new(&high_64(out1[0]))
        })
    }

    /// f1\*: MAC-S of `sqn_ms`, `rand` and `amf`. That of an AUTS has an
    /// AMF of zeros, which [`auts`](Self::auts) gives it.
    pub fn f1_star(&self, rand: &Rand, sqn_ms: &Sqn, amf: &Amf) -> MacS {
        self.run(rand, |temp| {
            let out1 = temp.outputs([temp.input_1(sqn_ms.as_octets(), amf.as_octets())]);
            MacS::new(&low_64(out1[0]))
        })
    }

    /// f2: RES, or the XRES of the home network.
    pub fn f2(&self, rand: &Rand) -> Res {
        self.run(rand, |temp| {
            Res::new(&low_64(temp.outputs([temp.input(2)])[0]))
        })
    }

    /// f3: CK.
    pub fn f3(&self, rand: &Rand) -> Ck {
        self.run(rand, |temp| {
            Ck::new(&temp.outputs([temp.input(3)])[0].to_be_bytes())
        })
    }

    /// f4: IK.
    pub fn f4(&self, rand: &Rand) -> Ik {
        self.run(rand, |temp| {
            Ik::new(&temp.outputs([temp.input(4)])[0].to_be_bytes())
        })
    }

    /// f5: AK, which conceals the SQN of an AUTN.
    pub fn f5(&self, rand: &Rand) -> Ak {
        self.run(rand, |temp| {
            Ak::new(&high_48(temp.outputs([temp.input(2)])[0]))
        })
    }

    /// f5\*: AK\*, which conceals the SQNMS of an AUTS.
    pub fn f5_star(&self, rand: &Rand) -> AkStar {
        self.run(rand, |temp| {
            AkStar::new(&high_48(temp.outputs([temp.input(5)])[0]))
        })
    }

    /// f2, f3, f4 and f5 at once: RES, CK, IK and AK, from one TEMP.
    pub fn f2345(&self, rand: &Rand) -> (Res, Ck, Ik, Ak) {
        self.run(rand, |temp| {
            let out = temp.outputs([temp.input(2), temp.input(3), temp.input(4)]);
            (
                Res::new(&low_64(out[0])),
                Ck::new(&out[1].to_be_bytes()),
                Ik::new(&out[2].to_be_bytes()),
                Ak::new(&high_48(out[0])),
            )
        })
    }
}

/// The constants, and nothing of K or OPc.
impl fmt::Debug for Milenage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Milenage")
            .field("constants", &self.constants)
            .finish_non_exhaustive()
    }
}
