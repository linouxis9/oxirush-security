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

//! The authentication of TS 33.102 §6.3 on MILENAGE: the vector of the
//! home network, the check of AUTN in the USIM, and the AUTS of a
//! re-synchronisation.

use super::Milenage;
use super::kernel::{Temp, high_64, low_64};
use super::values::{Amf, Auts, Res, Sqn, Xres};
use crate::common::error::SecurityError;
use crate::common::keys::{Autn, Ck, Ik, Rand};
use crate::nas_5gs::{ResStar, XresStar, compute_res_star, compute_xres_star};
use subtle::ConstantTimeEq;

/// The AMF of MAC-S in an AUTS: zeros (TS 33.102 §6.3.3).
const AUTS_AMF: [u8; 2] = [0; 2];

/// An authentication vector, which a home network makes for a subscriber
/// (TS 33.102 §6.3.2): RAND, XRES, CK, IK and AUTN.
///
/// It is wiped when it is dropped, but for RAND and AUTN, which the
/// network sends. `{:?}` prints RAND and AUTN, and nothing of XRES, CK
/// and IK.
#[derive(Clone, Debug)]
pub struct AuthenticationVector {
    rand: Rand,
    xres: Xres,
    ck: Ck,
    ik: Ik,
    autn: Autn,
}

impl AuthenticationVector {
    /// RAND, the challenge.
    pub fn rand(&self) -> &Rand {
        &self.rand
    }

    /// XRES, the response that is expected: f2 of RAND.
    pub fn xres(&self) -> &Xres {
        &self.xres
    }

    /// CK: f3 of RAND.
    pub fn ck(&self) -> &Ck {
        &self.ck
    }

    /// IK: f4 of RAND.
    pub fn ik(&self) -> &Ik {
        &self.ik
    }

    /// AUTN = SQN ⊕ AK || AMF || MAC-A.
    pub fn autn(&self) -> &Autn {
        &self.autn
    }

    /// XRES\* of 5GS (TS 33.501 Annex A.4), from CK, IK, RAND and XRES and
    /// the serving network name, such as
    /// `5G:mnc093.mcc208.3gppnetwork.org`: what
    /// [`nas_5gs::compute_xres_star`](crate::nas_5gs::compute_xres_star)
    /// gives. A name above 65535 octets is
    /// [`SecurityError::InputTooLong`].
    pub fn xres_star(&self, sn_name: &[u8]) -> Result<XresStar, SecurityError> {
        let xres = self.xres.as_octets();
        compute_xres_star(&self.ck, &self.ik, sn_name, &self.rand, xres)
    }
}

/// What a USIM gives back for a challenge whose AUTN it checked
/// (TS 33.102 §6.3.3): RES, CK and IK, with the SQN and the AMF of the
/// AUTN, which the ME judges.
///
/// It is wiped when it is dropped, but for the values that the network
/// sent. `{:?}` prints RAND, SQN and AMF, and nothing of RES, CK and IK.
#[derive(Clone, Debug)]
pub struct UsimResponse {
    rand: Rand,
    sqn: Sqn,
    amf: Amf,
    res: Res,
    ck: Ck,
    ik: Ik,
}

impl UsimResponse {
    /// The SQN of the AUTN: SQN ⊕ AK, then ⊕ AK. Whether it is fresh is the
    /// caller's to decide (TS 33.102 Annex C); a SQN out of range is
    /// answered with [`Milenage::auts`].
    pub fn sqn(&self) -> &Sqn {
        &self.sqn
    }

    /// The AMF of the AUTN, whose separation bit EPS and 5GS ask for.
    pub fn amf(&self) -> &Amf {
        &self.amf
    }

    /// RES: f2 of RAND.
    pub fn res(&self) -> &Res {
        &self.res
    }

    /// CK: f3 of RAND.
    pub fn ck(&self) -> &Ck {
        &self.ck
    }

    /// IK: f4 of RAND.
    pub fn ik(&self) -> &Ik {
        &self.ik
    }

    /// RES\* of 5GS (TS 33.501 Annex A.4), from CK, IK, RAND and RES and
    /// the serving network name, such as
    /// `5G:mnc093.mcc208.3gppnetwork.org`: what
    /// [`nas_5gs::compute_res_star`](crate::nas_5gs::compute_res_star)
    /// gives. A name above 65535 octets is
    /// [`SecurityError::InputTooLong`].
    pub fn res_star(&self, sn_name: &[u8]) -> Result<ResStar, SecurityError> {
        let res = self.res.as_octets();
        compute_res_star(&self.ck, &self.ik, sn_name, &self.rand, res)
    }
}

/// `octets` ⊕ the high 48 bits of `block`: a SQN that an AK of f5 or of
/// f5\* conceals, or reveals.
fn xor_48(octets: &[u8; 6], block: u128) -> [u8; 6] {
    let mut number = [0u8; 8];
    number[2..].copy_from_slice(octets);
    let number = u64::from_be_bytes(number) ^ (block >> 80) as u64;
    *number.to_be_bytes().last_chunk().expect("eight octets")
}

impl Milenage {
    /// The authentication vector of `rand`, `sqn` and `amf`, in the home
    /// network (TS 33.102 §6.3.2): MAC-A = f1, XRES = f2, CK = f3, IK = f4
    /// and AK = f5, and AUTN = SQN ⊕ AK || AMF || MAC-A.
    ///
    /// The home network draws a RAND that nobody can predict and takes the
    /// next SQN of the subscriber, which it keeps (TS 33.102 Annex C). EPS
    /// and 5GS take an AMF with the separation bit (TS 33.401 §6.1.1,
    /// TS 33.501 §6.1.3.2).
    ///
    /// ```
    /// use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    /// use oxirush_security::Rand;
    ///
    /// // The subscriber and the challenge of TS 35.208 test set 1
    /// # let octets = |s: &str| hex::decode(s).unwrap();
    /// # let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
    /// # let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
    /// # let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
    /// let subscriber = Milenage::new(&k, &opc);
    /// let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607).unwrap(), Amf::new(&[0xb9, 0xb9]));
    /// let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
    /// assert_eq!(hex::encode(vector.autn().as_octets()), "55f328b43577b9b94a9ffac354dfafb3");
    /// assert_eq!(hex::encode(vector.xres().as_octets()), "a54211d5e3ba50bf");
    /// ```
    pub fn authentication_vector(&self, rand: &Rand, sqn: &Sqn, amf: &Amf) -> AuthenticationVector {
        self.run(rand, |temp| vector(temp, rand, sqn, amf))
    }

    /// Check the AUTN of a challenge in the USIM (TS 33.102 §6.3.3): AK =
    /// f5 of `rand` gives SQN from SQN ⊕ AK, and f1 of SQN, `rand` and the
    /// AMF of `autn` is compared with its MAC-A, in a time that does not
    /// depend on where they differ. Then RES = f2, CK = f3 and IK = f4.
    ///
    /// A MAC-A that is not that one is [`SecurityError::MacFailure`], which
    /// a UE answers with the cause "MAC failure". Otherwise the caller
    /// judges [`UsimResponse::sqn`], and the separation bit of
    /// [`UsimResponse::amf`] in EPS and 5GS, before it sends RES or RES\*.
    ///
    /// ```
    /// use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
    /// use oxirush_security::{Autn, Rand, SecurityError};
    ///
    /// // The AUTN of the example of `authentication_vector`, in the USIM
    /// # let octets = |s: &str| hex::decode(s).unwrap();
    /// # let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
    /// # let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
    /// # let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
    /// let usim = Milenage::new(&k, &opc);
    /// let autn = Autn::from_slice(&octets("55f328b43577b9b94a9ffac354dfafb3")).unwrap();
    /// let response = usim.check_autn(&rand, &autn).unwrap();
    /// assert_eq!(response.sqn().get(), 0xff9b_b4d0_b607);
    /// assert!(response.amf().separation_bit());
    ///
    /// // An AUTN of another network is refused
    /// let forged = Autn::new(&[0; 16]);
    /// assert!(matches!(usim.check_autn(&rand, &forged), Err(SecurityError::MacFailure)));
    /// ```
    pub fn check_autn(&self, rand: &Rand, autn: &Autn) -> Result<UsimResponse, SecurityError> {
        self.run(rand, |temp| response(temp, rand, autn))
    }

    /// The AUTS of SQNMS, the highest SQN that the USIM has taken, for the
    /// challenge `rand` whose SQN it found out of range (TS 33.102
    /// §6.3.3): SQNMS ⊕ f5\* of `rand`, then MAC-S = f1\* of SQNMS, `rand`
    /// and an AMF of zeros.
    ///
    /// ```
    /// use oxirush_security::milenage::{K, Milenage, Opc, Sqn};
    /// use oxirush_security::Rand;
    ///
    /// let subscriber = Milenage::new(&K::new(&[0x46; 16]), &Opc::new(&[0xcd; 16]));
    /// let rand = Rand::new(&[0x23; 16]);
    ///
    /// // The USIM is at SQN 64, and the home network reads it back
    /// let auts = subscriber.auts(&rand, &Sqn::try_from(64).unwrap());
    /// assert_eq!(format!("{auts:?}"), "Auts(5ef40417ef4cb9ac9e76640b820d)");
    /// assert_eq!(subscriber.verify_auts(&rand, &auts).unwrap().get(), 64);
    /// ```
    pub fn auts(&self, rand: &Rand, sqn_ms: &Sqn) -> Auts {
        self.run(rand, |temp| auts(temp, sqn_ms))
    }

    /// SQNMS from the AUTS that a USIM sent for the challenge `rand`, in
    /// the home network (TS 33.102 §6.3.5): SQNMS ⊕ AK\* ⊕ f5\* of `rand`,
    /// once the MAC-S of the AUTS is that of SQNMS, `rand` and an AMF of
    /// zeros. `rand` is that of the challenge that the AUTS answers, which
    /// the serving network gives with it.
    ///
    /// A MAC-S that is not that one is [`SecurityError::MacFailure`]: the
    /// home network does not take SQNMS. Whether it then resets its SQN to
    /// SQNMS is its own to decide (§6.3.5).
    ///
    /// ```
    /// use oxirush_security::milenage::{Auts, K, Milenage, Opc};
    /// use oxirush_security::{Rand, SecurityError};
    ///
    /// // The AUTS of the example of `auts`, then the same with one bit changed
    /// let subscriber = Milenage::new(&K::new(&[0x46; 16]), &Opc::new(&[0xcd; 16]));
    /// let rand = Rand::new(&[0x23; 16]);
    /// let mut auts = *Auts::from_slice(&hex::decode("5ef40417ef4cb9ac9e76640b820d").unwrap())
    ///     .unwrap()
    ///     .as_octets();
    /// assert_eq!(subscriber.verify_auts(&rand, &Auts::new(&auts)).unwrap().get(), 64);
    /// auts[13] ^= 1;
    /// let refused = subscriber.verify_auts(&rand, &Auts::new(&auts));
    /// assert!(matches!(refused, Err(SecurityError::MacFailure)));
    /// ```
    pub fn verify_auts(&self, rand: &Rand, auts: &Auts) -> Result<Sqn, SecurityError> {
        self.run(rand, |temp| sqn_ms_of(temp, auts))
    }
}

/// The vector of a TEMP: OUT1 to OUT4, side by side.
pub(crate) fn vector(temp: &Temp<'_>, rand: &Rand, sqn: &Sqn, amf: &Amf) -> AuthenticationVector {
    let input_1 = temp.input_1(sqn.as_octets(), amf.as_octets());
    let out = temp.outputs([input_1, temp.input(2), temp.input(3), temp.input(4)]);
    vector_of(rand, sqn, amf, out[0], [out[1], out[2], out[3]])
}

/// The vector of OUT1, and of OUT2 to OUT4.
pub(crate) fn vector_of(
    rand: &Rand,
    sqn: &Sqn,
    amf: &Amf,
    out1: u128,
    [out2, out3, out4]: [u128; 3],
) -> AuthenticationVector {
    let mut autn = [0u8; 16];
    autn[..6].copy_from_slice(&xor_48(sqn.as_octets(), out2));
    autn[6..8].copy_from_slice(amf.as_octets());
    autn[8..].copy_from_slice(&high_64(out1));
    AuthenticationVector {
        rand: rand.clone(),
        xres: Xres::new(&low_64(out2)),
        ck: Ck::new(&out3.to_be_bytes()),
        ik: Ik::new(&out4.to_be_bytes()),
        autn: Autn::new(&autn),
    }
}

/// The response of a TEMP to an AUTN: OUT2 to OUT4 side by side, then
/// OUT1 of the SQN that AK gives.
pub(crate) fn response(
    temp: &Temp<'_>,
    rand: &Rand,
    autn: &Autn,
) -> Result<UsimResponse, SecurityError> {
    let out = temp.outputs([temp.input(2), temp.input(3), temp.input(4)]);
    let (sqn, amf) = sqn_and_amf_of(autn, out[0]);
    let out1 = temp.outputs([temp.input_1(&sqn, &amf)]);
    response_of(rand, autn, out1[0], *out)
}

/// The SQN of an AUTN, which AK in OUT2 conceals, and its AMF: the input of
/// OUT1 in the USIM.
pub(crate) fn sqn_and_amf_of(autn: &Autn, out2: u128) -> ([u8; 6], [u8; 2]) {
    let amf = [autn.as_octets()[6], autn.as_octets()[7]];
    (xor_48(autn.sqn_xor_ak(), out2), amf)
}

/// The response to an AUTN of OUT1, its XMAC-A, and of OUT2 to OUT4.
pub(crate) fn response_of(
    rand: &Rand,
    autn: &Autn,
    out1: u128,
    [out2, out3, out4]: [u128; 3],
) -> Result<UsimResponse, SecurityError> {
    if !bool::from(high_64(out1)[..].ct_eq(&autn.as_octets()[8..])) {
        return Err(SecurityError::MacFailure);
    }
    let (sqn, amf) = sqn_and_amf_of(autn, out2);
    Ok(UsimResponse {
        rand: rand.clone(),
        sqn: Sqn::new(&sqn),
        amf: Amf::new(&amf),
        res: Res::new(&low_64(out2)),
        ck: Ck::new(&out3.to_be_bytes()),
        ik: Ik::new(&out4.to_be_bytes()),
    })
}

/// The AUTS of a TEMP and SQNMS: OUT1 and OUT5 side by side.
pub(crate) fn auts(temp: &Temp<'_>, sqn_ms: &Sqn) -> Auts {
    let out = temp.outputs([temp.input_1(sqn_ms.as_octets(), &AUTS_AMF), temp.input(5)]);
    let mut auts = [0u8; 14];
    auts[..6].copy_from_slice(&xor_48(sqn_ms.as_octets(), out[1]));
    auts[6..].copy_from_slice(&low_64(out[0]));
    Auts::new(&auts)
}

/// SQNMS of an AUTS and a TEMP: OUT5, then OUT1 of the SQNMS that AK\*
/// gives.
pub(crate) fn sqn_ms_of(temp: &Temp<'_>, auts: &Auts) -> Result<Sqn, SecurityError> {
    let out5 = temp.outputs([temp.input(5)]);
    let (concealed, mac_s) = auts.as_octets().split_at(6);
    let concealed: &[u8; 6] = concealed.try_into().expect("six octets");
    let sqn_ms = xor_48(concealed, out5[0]);
    let out1 = temp.outputs([temp.input_1(&sqn_ms, &AUTS_AMF)]);
    if !bool::from(low_64(out1[0])[..].ct_eq(mac_s)) {
        return Err(SecurityError::MacFailure);
    }
    Ok(Sqn::new(&sqn_ms))
}
