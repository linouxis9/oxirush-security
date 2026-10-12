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

//! 5GS key derivation per 3GPP TS 33.501 Annex A.

use super::keys::{
    AccessKey, HresStar, HxresStar, KAmf, KAusf, KGnb, KIab, KN3iwf, KNasEnc, KNasInt, KRrcEnc,
    KRrcInt, KSeaf, KSn, KTnap, KUpEnc, KUpInt, Nh, NodeKey, ResStar, XresStar,
};
use super::supi::Supi;
use crate::SecurityError;
use crate::common::input::{AccessKeyCount, CipheringAlgorithm, IntegrityAlgorithm, NasCount};
use crate::common::kdf::{checked_parameter, derive, derive_algorithm_key, low_128};
use crate::common::keys::{Autn, Ck, Ik, Rand};
use crate::common::wipe;
use crate::nas_eps::KAsme;
use zeroize::Zeroizing;

/// FC of the algorithm key derivation function (TS 33.501 Annex A.8).
const FC_ALGORITHM_KEY: u8 = 0x69;

fn ck_ik(ck: &Ck, ik: &Ik) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key[..16].copy_from_slice(ck.as_octets());
    key[16..].copy_from_slice(ik.as_octets());
    key
}

/// Derive KAUSF from CK || IK (TS 33.501 Annex A.2, FC=0x6A).
///
/// `sn_name` is the serving network name, such as
/// `5G:mnc093.mcc208.3gppnetwork.org`, and `autn` the AUTN of the
/// authentication, whose SQN xor AK the derivation takes. A name longer
/// than 65535 octets is [`SecurityError::InputTooLong`].
pub fn derive_kausf(ck: &Ck, ik: &Ik, sn_name: &[u8], autn: &Autn) -> Result<KAusf, SecurityError> {
    wipe::derivation(|| {
        let sn_name = checked_parameter(sn_name)?;
        let parameters: [&[u8]; 2] = [sn_name, autn.sqn_xor_ak()];
        Ok(KAusf::new(&derive(
            ck_ik(ck, ik).as_ref(),
            0x6a,
            &parameters,
        )))
    })
}

/// Derive KSEAF from KAUSF (TS 33.501 Annex A.6, FC=0x6C).
///
/// An `sn_name` longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kseaf(kausf: &KAusf, sn_name: &[u8]) -> Result<KSeaf, SecurityError> {
    wipe::derivation(|| {
        let sn_name = checked_parameter(sn_name)?;
        Ok(KSeaf::new(&derive(kausf.as_octets(), 0x6C, &[sn_name])))
    })
}

/// Derive KAMF from KSEAF (TS 33.501 Annex A.7, FC=0x6D).
///
/// The derivation takes the SUPI as its identity alone, the digits of an
/// IMSI or the NAI of another SUPI, without the `imsi-` or `nai-` that the
/// service based interfaces write in front (Annex A.7.0). [`Supi`] gives
/// it, whichever form the SUPI came in.
///
/// `abba` is the ABBA parameter, `[0x00, 0x00]` in the releases so far
/// (Annex A.7.1). One that is not 2 to 255 octets long, the lengths that
/// its information element has (TS 24.501 §9.11.3.10), is
/// [`SecurityError::InvalidParameter`].
pub fn derive_kamf(kseaf: &KSeaf, supi: &Supi<'_>, abba: &[u8]) -> Result<KAmf, SecurityError> {
    wipe::derivation(|| {
        if !(2..=255).contains(&abba.len()) {
            return Err(SecurityError::InvalidParameter(
                "ABBA is 2 to 255 octets long",
            ));
        }
        // A SUPI is at most 507 octets long
        let parameters = [supi.identity().as_bytes(), abba];
        Ok(KAmf::new(&derive(kseaf.as_octets(), 0x6D, &parameters)))
    })
}

/// Derive KNASenc, the NAS ciphering key of `algorithm`, from KAMF
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x01).
pub fn derive_knas_enc(kamf: &KAmf, algorithm: CipheringAlgorithm) -> KNasEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kamf.as_octets(), FC_ALGORITHM_KEY, 0x01, algorithm.into());
        KNasEnc::new(&key)
    })
}

/// Derive KNASint, the NAS integrity key of `algorithm`, from KAMF
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x02).
pub fn derive_knas_int(kamf: &KAmf, algorithm: IntegrityAlgorithm) -> KNasInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kamf.as_octets(), FC_ALGORITHM_KEY, 0x02, algorithm.into());
        KNasInt::new(&key)
    })
}

/// RES* or XRES* (TS 33.501 Annex A.4, FC=0x6B): the 128 least significant
/// bits of the KDF over the serving network name, RAND and RES or XRES.
fn response_star(
    ck: &Ck,
    ik: &Ik,
    sn_name: &[u8],
    rand: &Rand,
    response: &[u8],
) -> Result<[u8; 16], SecurityError> {
    if !(4..=16).contains(&response.len()) {
        return Err(SecurityError::InvalidParameter(
            "RES and XRES are 4 to 16 octets long",
        ));
    }
    let sn_name = checked_parameter(sn_name)?;
    let parameters = [sn_name, rand.as_octets(), response];
    let full = Zeroizing::new(derive(ck_ik(ck, ik).as_ref(), 0x6B, &parameters));
    Ok(low_128(&full))
}

/// Compute RES*, in a UE, from the RES of its USIM (TS 33.501 Annex A.4,
/// FC=0x6B).
///
/// A `res` that is not 4 to 16 octets long, the lengths of RES
/// (TS 33.102 §6.3.7), is [`SecurityError::InvalidParameter`], and an
/// `sn_name` longer than 65535 octets [`SecurityError::InputTooLong`].
pub fn compute_res_star(
    ck: &Ck,
    ik: &Ik,
    sn_name: &[u8],
    rand: &Rand,
    res: &[u8],
) -> Result<ResStar, SecurityError> {
    wipe::derivation(|| {
        response_star(ck, ik, sn_name, rand, res).map(|octets| ResStar::new(&octets))
    })
}

/// Compute XRES*, in the home network, from XRES (TS 33.501 Annex A.4,
/// FC=0x6B). [`XresStar::accepts`] compares the RES* of a UE with it.
///
/// An `xres` that is not 4 to 16 octets long is
/// [`SecurityError::InvalidParameter`], and an `sn_name` longer than 65535
/// octets [`SecurityError::InputTooLong`].
pub fn compute_xres_star(
    ck: &Ck,
    ik: &Ik,
    sn_name: &[u8],
    rand: &Rand,
    xres: &[u8],
) -> Result<XresStar, SecurityError> {
    wipe::derivation(|| {
        response_star(ck, ik, sn_name, rand, xres).map(|octets| XresStar::new(&octets))
    })
}

/// Compute HRES*, in the SEAF, from the RES* of a UE: the 128 least
/// significant bits of SHA-256(RAND || RES*) (TS 33.501 Annex A.5).
/// [`HxresStar::accepts`] compares it with the HXRES* of the AUSF.
pub fn compute_hres_star(rand: &Rand, res_star: &ResStar) -> HresStar {
    wipe::derivation(|| {
        let parts: [&[u8]; 2] = [rand.as_octets(), res_star.as_octets()];
        HresStar::new(&low_128(&crate::common::sha256::sha256(&parts)))
    })
}

/// Compute HXRES*, in the AUSF, from XRES*: the 128 least significant bits
/// of SHA-256(RAND || XRES*) (TS 33.501 Annex A.5).
pub fn compute_hxres_star(rand: &Rand, xres_star: &XresStar) -> HxresStar {
    wipe::derivation(|| {
        let parts: [&[u8]; 2] = [rand.as_octets(), xres_star.as_octets()];
        HxresStar::new(&low_128(&crate::common::sha256::sha256(&parts)))
    })
}

/// Derive KgNB from KAMF and the uplink NAS COUNT of 3GPP access
/// (TS 33.501 Annex A.9, FC=0x6E, access type distinguisher 0x01).
///
/// `ul_nas_count` is the uplink NAS COUNT of the message that started the
/// derivation, a SECURITY MODE COMPLETE or a SERVICE REQUEST for instance,
/// as a [`NasCount`]. At an N2 handover with a KAMF change and at a
/// handover from EPS it is [`AccessKeyCount::Handover`] (§6.9.2.3.3,
/// §8.4.2).
pub fn derive_kgnb(kamf: &KAmf, ul_nas_count: impl Into<AccessKeyCount>) -> KGnb {
    wipe::derivation(|| {
        let count = ul_nas_count.into().get().to_be_bytes();
        KGnb::new(&derive(kamf.as_octets(), 0x6E, &[&count, &[0x01]]))
    })
}

/// Derive KN3IWF, which is also KWAGF, KTNGF, and KTWIF, from KAMF and the
/// uplink NAS COUNT of non-3GPP access (TS 33.501 Annex A.9, FC=0x6E,
/// access type distinguisher 0x02).
pub fn derive_kn3iwf(kamf: &KAmf, ul_nas_count: NasCount) -> KN3iwf {
    wipe::derivation(|| {
        let count = ul_nas_count.get().to_be_bytes();
        KN3iwf::new(&derive(kamf.as_octets(), 0x6E, &[&count, &[0x02]]))
    })
}

/// Derive KRRCenc, the RRC ciphering key of `algorithm`, from KgNB, or
/// from the KSN of a secondary node (TS 33.501 Annex A.8, algorithm type
/// distinguisher 0x03).
///
/// With S-KgNB as the key this is also the derivation of an SgNB
/// (TS 33.401 Annex A.19), like the three functions that follow:
/// [`nas_eps::derive_skgnb`](crate::nas_eps::derive_skgnb) gives it as a
/// [`KGnb`].
pub fn derive_krrc_enc(key: &impl NodeKey, algorithm: CipheringAlgorithm) -> KRrcEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(key.key_octets(), FC_ALGORITHM_KEY, 0x03, algorithm.into());
        KRrcEnc::new(&key)
    })
}

/// Derive KRRCint, the RRC integrity key of `algorithm`, from KgNB or KSN
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x04).
pub fn derive_krrc_int(key: &impl NodeKey, algorithm: IntegrityAlgorithm) -> KRrcInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(key.key_octets(), FC_ALGORITHM_KEY, 0x04, algorithm.into());
        KRrcInt::new(&key)
    })
}

/// Derive KUPenc, the user plane ciphering key of `algorithm`, from KgNB
/// or KSN (TS 33.501 Annex A.8, algorithm type distinguisher 0x05).
pub fn derive_kup_enc(key: &impl NodeKey, algorithm: CipheringAlgorithm) -> KUpEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(key.key_octets(), FC_ALGORITHM_KEY, 0x05, algorithm.into());
        KUpEnc::new(&key)
    })
}

/// Derive KUPint, the user plane integrity key of `algorithm`, from KgNB
/// or KSN (TS 33.501 Annex A.8, algorithm type distinguisher 0x06).
pub fn derive_kup_int(key: &impl NodeKey, algorithm: IntegrityAlgorithm) -> KUpInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(key.key_octets(), FC_ALGORITHM_KEY, 0x06, algorithm.into());
        KUpInt::new(&key)
    })
}

fn out_of_range(field: &'static str, maximum: u32, got: u32) -> SecurityError {
    SecurityError::OutOfRange {
        field,
        maximum: maximum.into(),
        got: got.into(),
    }
}

/// Derive KNG-RAN* for a target gNB (TS 33.501 Annex A.11, FC=0x70). The
/// target takes it as its KgNB.
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB.
/// `arfcn_dl` is the NR-ARFCN of the target PCell SSB (three octets).
///
/// A `pci` above 1007 or an `arfcn_dl` above 3279165 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kng_ran_star(
    base_key: &impl AccessKey,
    pci: u16,
    arfcn_dl: u32,
) -> Result<KGnb, SecurityError> {
    wipe::derivation(|| {
        if pci > 1007 {
            return Err(out_of_range("NR PCI", 1007, pci.into()));
        }
        if arfcn_dl > 3_279_165 {
            return Err(out_of_range("NR-ARFCN", 3_279_165, arfcn_dl));
        }
        let parameters: [&[u8]; 2] = [&pci.to_be_bytes(), &arfcn_dl.to_be_bytes()[1..]];
        Ok(KGnb::new(&derive(base_key.key_octets(), 0x70, &parameters)))
    })
}

/// Derive KNG-RAN* for a target ng-eNB (TS 33.501 Annex A.12, FC=0x71).
/// The target takes it as its Kng-eNB.
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB or
/// Kng-eNB. EARFCN-DL is always three octets here, unlike KeNB* in
/// TS 33.401.
///
/// A `pci` above 503 or an `earfcn_dl` above 262143 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kng_ran_star_ng_enb(
    base_key: &impl AccessKey,
    pci: u16,
    earfcn_dl: u32,
) -> Result<KGnb, SecurityError> {
    wipe::derivation(|| {
        if pci > 503 {
            return Err(out_of_range("E-UTRA PCI", 503, pci.into()));
        }
        if earfcn_dl > 262_143 {
            return Err(out_of_range("EARFCN-DL", 262_143, earfcn_dl));
        }
        let parameters: [&[u8]; 2] = [&pci.to_be_bytes(), &earfcn_dl.to_be_bytes()[1..]];
        Ok(KGnb::new(&derive(base_key.key_octets(), 0x71, &parameters)))
    })
}

/// Derive the Next Hop parameter NH (TS 33.501 Annex A.10, FC=0x6F).
///
/// `sync_input` is KgNB for the first NH, and the NH before it for each
/// one after.
pub fn derive_nh(kamf: &KAmf, sync_input: &impl AccessKey) -> Nh {
    wipe::derivation(|| Nh::new(&derive(kamf.as_octets(), 0x6F, &[sync_input.key_octets()])))
}

/// Map KAMF to KASME' for idle 5GS to EPS mobility (TS 33.501 Annex A.14.1, FC=0x73).
/// `ul_nas_count` is the COUNT used by the mobility-triggering 5GS NAS message.
pub fn derive_mapped_kasme_idle(kamf: &KAmf, ul_nas_count: NasCount) -> KAsme {
    wipe::derivation(|| {
        let count = ul_nas_count.get().to_be_bytes();
        KAsme::new(&derive(kamf.as_octets(), 0x73, &[&count]))
    })
}

/// Map KAMF to KASME' for a handover from 5GS to EPS (TS 33.501
/// Annex A.14.2, FC=0x74).
pub fn derive_mapped_kasme_handover(kamf: &KAmf, dl_nas_count: NasCount) -> KAsme {
    wipe::derivation(|| {
        let count = dl_nas_count.get().to_be_bytes();
        KAsme::new(&derive(kamf.as_octets(), 0x74, &[&count]))
    })
}

/// Map KASME to KAMF' for idle EPS to 5GS mobility (TS 33.501
/// Annex A.15.1, FC=0x75). `tau_ul_nas_count` is the uplink NAS COUNT of
/// the TRACKING AREA UPDATE REQUEST that the REGISTRATION REQUEST has. The
/// NAS COUNTs of the new 5G NAS security context start at zero.
pub fn derive_mapped_kamf_idle(kasme: &KAsme, tau_ul_nas_count: NasCount) -> KAmf {
    wipe::derivation(|| {
        let count = tau_ul_nas_count.get().to_be_bytes();
        KAmf::new(&derive(kasme.as_octets(), 0x75, &[&count]))
    })
}

/// Map KASME to KAMF' for a handover from EPS to 5GS (TS 33.501
/// Annex A.15.2, FC=0x76). `nh` is the NH of EPS that the source MME
/// gives.
pub fn derive_mapped_kamf_handover(kasme: &KAsme, nh: &crate::nas_eps::Nh) -> KAmf {
    wipe::derivation(|| KAmf::new(&derive(kasme.as_octets(), 0x76, &[nh.as_octets()])))
}

/// KAMF-to-KAMF' mobility direction (TS 33.501 Annex A.13).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KamfMobilityDirection {
    /// Idle mobility uses the uplink NAS COUNT and direction value `0x00`.
    IdleMobility,
    /// Handover uses the downlink NAS COUNT and direction value `0x01`.
    Handover,
}

/// Derive KAMF' for horizontal 5GS mobility (TS 33.501 Annex A.13, FC=0x72).
pub fn derive_kamf_prime(
    kamf: &KAmf,
    direction: KamfMobilityDirection,
    nas_count: NasCount,
) -> KAmf {
    wipe::derivation(|| {
        let direction = match direction {
            KamfMobilityDirection::IdleMobility => [0x00],
            KamfMobilityDirection::Handover => [0x01],
        };
        let count = nas_count.get().to_be_bytes();
        KAmf::new(&derive(kamf.as_octets(), 0x72, &[&direction, &count]))
    })
}

/// Derive KAMF' for idle mobility using the uplink NAS COUNT.
pub fn derive_kamf_prime_idle(kamf: &KAmf, ul_nas_count: NasCount) -> KAmf {
    derive_kamf_prime(kamf, KamfMobilityDirection::IdleMobility, ul_nas_count)
}

/// Derive KAMF' for handover using the downlink NAS COUNT.
pub fn derive_kamf_prime_handover(kamf: &KAmf, dl_nas_count: NasCount) -> KAmf {
    derive_kamf_prime(kamf, KamfMobilityDirection::Handover, dl_nas_count)
}

/// Derive KSN for dual connectivity from the KgNB or Kng-eNB of the master
/// node (TS 33.501 Annex A.16, FC=0x79).
pub fn derive_ksn(kgnb: &KGnb, sn_counter: u16) -> KSn {
    wipe::derivation(|| {
        KSn::new(&derive(
            kgnb.as_octets(),
            0x79,
            &[&sn_counter.to_be_bytes()],
        ))
    })
}

fn checked_procedure_counter(counter: u16) -> Result<[u8; 2], SecurityError> {
    if counter == 0 {
        Err(SecurityError::InvalidParameter(
            "SoR/UPU counter zero is reserved",
        ))
    } else {
        Ok(counter.to_be_bytes())
    }
}

/// Derive SoR-MAC-IAUSF (TS 33.501 Annex A.17, FC=0x77).
///
/// Counter freshness and replay state are procedural responsibilities of the
/// caller. `None` omits P2/L2; `Some(&[])` includes a zero-length P2/L2 pair.
pub fn derive_sor_mac_ausf(
    kausf: &KAusf,
    header: &[u8],
    counter: u16,
    p2: Option<&[u8]>,
) -> Result<[u8; 16], SecurityError> {
    wipe::derivation(|| {
        let header = checked_parameter(header)?;
        let counter = checked_procedure_counter(counter)?;
        let kausf = kausf.as_octets();
        let full = Zeroizing::new(match p2 {
            Some(p2) => {
                let p2 = checked_parameter(p2)?;
                derive(kausf, 0x77, &[header, &counter, p2])
            }
            None => derive(kausf, 0x77, &[header, &counter]),
        });
        Ok(low_128(&full))
    })
}

/// Derive SoR-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.18, FC=0x78).
pub fn derive_sor_mac_ue(kausf: &KAusf, counter: u16) -> Result<[u8; 16], SecurityError> {
    wipe::derivation(|| {
        let counter = checked_procedure_counter(counter)?;
        let full = Zeroizing::new(derive(kausf.as_octets(), 0x78, &[&[0x01], &counter]));
        Ok(low_128(&full))
    })
}

/// Derive UPU-MAC-IAUSF (TS 33.501 Annex A.19, FC=0x7B).
pub fn derive_upu_mac_ausf(
    kausf: &KAusf,
    upu_data: &[u8],
    counter: u16,
) -> Result<[u8; 16], SecurityError> {
    wipe::derivation(|| {
        let upu_data = checked_parameter(upu_data)?;
        let counter = checked_procedure_counter(counter)?;
        let full = Zeroizing::new(derive(kausf.as_octets(), 0x7b, &[upu_data, &counter]));
        Ok(low_128(&full))
    })
}

/// Derive UPU-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.20, FC=0x7C).
pub fn derive_upu_mac_ue(kausf: &KAusf, counter: u16) -> Result<[u8; 16], SecurityError> {
    wipe::derivation(|| {
        let counter = checked_procedure_counter(counter)?;
        let full = Zeroizing::new(derive(kausf.as_octets(), 0x7c, &[&[0x01], &counter]));
        Ok(low_128(&full))
    })
}

/// Usage distinguisher for TS 33.501 Annex A.22 key derivation.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TnapKeyUsage {
    /// KTIPSec.
    Ipsec = 0x01,
    /// KTNAP.
    Tnap = 0x02,
    /// KFT.
    FastTransition = 0x03,
}

/// Derive KTIPSec, KTNAP, or KFT from KTNGF, which [`derive_kn3iwf`] gives
/// (TS 33.501 Annex A.22, FC=0x84).
pub fn derive_tnap_usage_key(ktngf: &KN3iwf, usage: TnapKeyUsage) -> KTnap {
    wipe::derivation(|| KTnap::new(&derive(ktngf.as_octets(), 0x84, &[&[usage as u8]])))
}

/// Typed IAB IP address used by TS 33.501 Annex A.23.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IabIpAddress {
    /// IPv4 address.
    V4([u8; 4]),
    /// IPv6 address.
    V6([u8; 16]),
}

impl IabIpAddress {
    fn octets(&self) -> &[u8] {
        match self {
            Self::V4(value) => value,
            Self::V6(value) => value,
        }
    }
}

/// Derive KIAB from the KgNB of the IAB node, or its S-KgNB, and the IP
/// addresses of the donor and of the node (TS 33.501 Annex A.23).
pub fn derive_kiab(kgnb: &KGnb, donor: IabIpAddress, node: IabIpAddress) -> KIab {
    wipe::derivation(|| {
        let parameters = [donor.octets(), node.octets()];
        KIab::new(&derive(kgnb.as_octets(), 0x83, &parameters))
    })
}

/// Derive KASME_SRVCC from KAMF for SRVCC to UTRAN CS (TS 33.501 Annex A.21,
/// FC=0x7D). `dl_nas_count` is the current downlink 5G NAS COUNT; the AMF
/// then increments it, and the UE estimates it from four LSBs (Annex J,
/// steps 2 and 10).
/// [`nas_eps::derive_ck_ik_srvcc`](crate::nas_eps::derive_ck_ik_srvcc)
/// takes it as a KASME.
pub fn derive_kasme_srvcc(kamf: &KAmf, dl_nas_count: NasCount) -> KAsme {
    wipe::derivation(|| {
        let count = dl_nas_count.get().to_be_bytes();
        KAsme::new(&derive(kamf.as_octets(), 0x7D, &[&count]))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::kdf::{extract_128, kdf};

    fn count(value: u32) -> NasCount {
        NasCount::new(value).unwrap()
    }

    fn octets<const N: usize>(hexadecimal: &str) -> [u8; N] {
        hex::decode(hexadecimal).unwrap().try_into().unwrap()
    }

    /// The octets 0, 1, 2 and so on.
    fn counting() -> [u8; 32] {
        core::array::from_fn(|index| index as u8)
    }

    #[test]
    fn access_and_handover_keys_follow_annex_a() {
        // Expected values computed independently with HMAC-SHA-256 over the
        // S strings of TS 33.501 Annex A.8, A.9, A.11, and A.12.
        let (kamf, kgnb) = (KAmf::new(&[0x5a; 32]), KGnb::new(&[0x5a; 32]));
        assert_eq!(
            hex::encode(derive_kgnb(&kamf, count(0x0102)).as_octets()),
            "4780bc81acc4eadb7cccf496e3981b7dd44840f8c99dcb09944d07fa19d4094f"
        );
        assert_eq!(
            hex::encode(derive_kn3iwf(&kamf, count(0x0102)).as_octets()),
            "ca3c93d0e70afc503dd7e7661a6b4bdb56f80ebab8358ee1b4c86d952a494fcb"
        );
        assert_eq!(
            hex::encode(derive_krrc_int(&kgnb, IntegrityAlgorithm::NIA2).as_octets()),
            "fe7a7f2bf63c9a96fcf854c507e52227"
        );
        assert_eq!(
            hex::encode(
                derive_kng_ran_star(&kgnb, 1007, 632_628)
                    .unwrap()
                    .as_octets()
            ),
            "055073f4af9d56dedbf4a277be30de51d4c074a11c58847394e3a9af800d9b8e"
        );
        assert_eq!(
            hex::encode(
                derive_kng_ran_star_ng_enb(&kgnb, 503, 6_300)
                    .unwrap()
                    .as_octets()
            ),
            "b22d48526024fd5b8988d58b19d7bf5466e013da35c25003dd11906f926440fc"
        );
        // NH is the other key that a node derives its next key from
        let nh = Nh::new(&[0x5a; 32]);
        assert_eq!(
            derive_kng_ran_star(&nh, 1007, 632_628),
            derive_kng_ran_star(&kgnb, 1007, 632_628)
        );
    }

    /// The largest values: PCI 1007 and NR-ARFCN 3279165 (TS 38.331
    /// PhysCellId and ARFCN-ValueNR), PCI 503 and EARFCN 262143 (TS 36.331
    /// PhysCellId and ARFCN-ValueEUTRA-r9).
    #[test]
    fn a_cell_identity_or_a_frequency_out_of_range_is_an_error() {
        let key = KGnb::new(&[0x5a; 32]);
        assert!(derive_kng_ran_star(&key, 1007, 3_279_165).is_ok());
        assert_eq!(
            derive_kng_ran_star(&key, 1008, 0),
            Err(SecurityError::OutOfRange {
                field: "NR PCI",
                maximum: 1007,
                got: 1008
            })
        );
        assert_eq!(
            derive_kng_ran_star(&key, 0, 3_279_166),
            Err(SecurityError::OutOfRange {
                field: "NR-ARFCN",
                maximum: 3_279_165,
                got: 3_279_166
            })
        );
        assert!(derive_kng_ran_star_ng_enb(&key, 503, 262_143).is_ok());
        assert!(derive_kng_ran_star_ng_enb(&key, 504, 0).is_err());
        assert!(derive_kng_ran_star_ng_enb(&key, 0, 262_144).is_err());
    }

    /// TS 33.501 Table A.8-1: the algorithm type distinguishers 0x01 to
    /// 0x06, each with the identity of its algorithm, and the 128 least
    /// significant bits of the output.
    #[test]
    fn algorithm_keys_use_the_distinguishers_of_table_a_8_1() {
        let key = [0x5a; 32];
        let (kamf, kgnb, ksn) = (KAmf::new(&key), KGnb::new(&key), KSn::new(&key));
        let expected =
            |kind: u8, identity: u8| *extract_128(&kdf(&key, &[0x69, kind, 0, 1, identity, 0, 1]));
        for (identity, ciphering, integrity) in [
            (0, CipheringAlgorithm::NEA0, IntegrityAlgorithm::NIA0),
            (1, CipheringAlgorithm::NEA1, IntegrityAlgorithm::NIA1),
            (2, CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2),
            (3, CipheringAlgorithm::NEA3, IntegrityAlgorithm::NIA3),
        ] {
            assert_eq!(derive_knas_enc(&kamf, ciphering), expected(0x01, identity));
            assert_eq!(derive_knas_int(&kamf, integrity), expected(0x02, identity));
            assert_eq!(derive_krrc_enc(&kgnb, ciphering), expected(0x03, identity));
            assert_eq!(derive_krrc_int(&kgnb, integrity), expected(0x04, identity));
            assert_eq!(derive_kup_enc(&kgnb, ciphering), expected(0x05, identity));
            assert_eq!(derive_kup_int(&kgnb, integrity), expected(0x06, identity));
            // A secondary node derives its keys from KSN in the same way
            assert_eq!(derive_krrc_enc(&ksn, ciphering), expected(0x03, identity));
            assert_eq!(derive_kup_int(&ksn, integrity), expected(0x06, identity));
        }
    }

    #[test]
    fn kasme_srvcc_uses_fc_0x7d_and_the_downlink_count() {
        let kamf = KAmf::new(&[0x5a; 32]);
        assert_eq!(
            derive_kasme_srvcc(&kamf, count(0x0102)),
            *kdf(
                kamf.as_octets(),
                &[0x7d, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04]
            )
        );
    }

    #[test]
    fn mapped_kamf_vectors() {
        let kasme = KAsme::new(&counting());
        let nh = crate::nas_eps::Nh::new(&core::array::from_fn(|i| (i + 32) as u8));
        assert_eq!(
            hex::encode(derive_mapped_kamf_idle(&kasme, count(0x0012_3456)).as_octets()),
            "eb553a2dc491745c18c4d717b577e068485326c458a726838abe755f38666beb"
        );
        assert_eq!(
            hex::encode(derive_mapped_kamf_handover(&kasme, &nh).as_octets()),
            "38d4b0135f82c7b44cf54c76232badc8ac02744ef43225ade981dcde7ca9ba8f"
        );
    }

    #[test]
    fn mapped_kasme_vectors() {
        let kamf = KAmf::new(&counting());
        assert_eq!(
            hex::encode(derive_mapped_kasme_idle(&kamf, count(0x0012_3456)).as_octets()),
            "e72331cceed3329aefe6d0148472d17d51968ca45e0a0a570bb9e889fe2ee69e"
        );
        assert_eq!(
            hex::encode(derive_mapped_kasme_handover(&kamf, count(0x0012_3456)).as_octets()),
            "6f4cb30cdb2d7dcc45fc9f2bcf5a10fcb90c2c4cba1ef3deb22917eadafbf832"
        );
    }

    #[test]
    fn release_19_annex_a_missing_entry_vectors() {
        let key = counting();
        let (kamf, kgnb, kausf) = (KAmf::new(&key), KGnb::new(&key), KAusf::new(&key));
        assert_eq!(
            hex::encode(derive_kamf_prime_handover(&kamf, count(0x0012_3456)).as_octets()),
            "efe7440adf3f3ee4182cb1d78c0b9a7fcc20451a9cd572fa3b1a0ebc195b3f61"
        );
        assert_eq!(
            derive_kamf_prime_idle(&kamf, count(0x0012_3456)),
            *kdf(&key, &[0x72, 0x00, 0, 1, 0x00, 0x12, 0x34, 0x56, 0, 4])
        );
        assert_eq!(
            hex::encode(derive_ksn(&kgnb, 0x1234).as_octets()),
            "2411a7d723a135f48666c2bfe081713f9e2de6fa3f29830ae470ebe1dacdfb60"
        );
        assert_eq!(
            hex::encode(derive_sor_mac_ausf(&kausf, &[1, 2], 1, Some(&[0xaa, 0xbb])).unwrap()),
            "6fcf7ef205010336dcc5d7877fe3a68b"
        );
        assert_eq!(
            hex::encode(derive_sor_mac_ue(&kausf, 1).unwrap()),
            "4a67dd7f904e7c8f668238aa702c4a9f"
        );
        assert_eq!(
            hex::encode(derive_upu_mac_ausf(&kausf, &[0xaa, 0xbb, 0xcc], 1).unwrap()),
            "7c7d2cb5d4ca23c2f41ab3bb5d56f01a"
        );
        assert_eq!(
            hex::encode(derive_upu_mac_ue(&kausf, 1).unwrap()),
            "c954bbe60cbf81b3be14051c2b21116c"
        );
        assert!(derive_sor_mac_ue(&kausf, 0).is_err());
        assert!(derive_upu_mac_ue(&kausf, 0).is_err());
        let kn3iwf = KN3iwf::new(&key);
        assert_eq!(
            hex::encode(derive_tnap_usage_key(&kn3iwf, TnapKeyUsage::Ipsec).as_octets()),
            "c25821c31c7451e77c344846cde14d9fdc7bab10b9151415aa5f3461dad781a3"
        );
        assert_eq!(
            hex::encode(
                derive_kiab(
                    &kgnb,
                    IabIpAddress::V4([192, 0, 2, 1]),
                    IabIpAddress::V4([198, 51, 100, 2]),
                )
                .as_octets()
            ),
            "57474ba433a9a48e72743db190442669bd5f48d0a45e209f774cb95532a10461"
        );
    }

    #[test]
    fn kgnb_accepts_all_ones_mobility_sentinel() {
        let kamf = KAmf::new(&counting());
        assert_eq!(
            hex::encode(derive_kgnb(&kamf, AccessKeyCount::Handover).as_octets()),
            "ad824bf330fd0ac91c5bcffe66ac497d549711f555849c1114b06d969191d2df"
        );
        // 2^32 - 1 in the COUNT parameter, and the access type of 3GPP
        assert_eq!(
            derive_kgnb(&kamf, AccessKeyCount::Handover),
            *kdf(
                kamf.as_octets(),
                &[0x6e, 0xff, 0xff, 0xff, 0xff, 0, 4, 0x01, 0, 1]
            )
        );
    }

    #[test]
    fn hres_star_matches_independent_sha256_probe() {
        let rand = Rand::new(&core::array::from_fn(|index| index as u8));
        let res_star = ResStar::new(&core::array::from_fn(|index| 0x20 + index as u8));
        assert_eq!(
            hex::encode(compute_hres_star(&rand, &res_star).as_octets()),
            "acc5770d8e61512db590e08855d7ad43"
        );
        // HXRES* is the same hash, of the value that the network expects
        let xres_star = XresStar::new(res_star.as_octets());
        assert_eq!(
            compute_hxres_star(&rand, &xres_star).as_octets(),
            compute_hres_star(&rand, &res_star).as_octets()
        );
    }

    fn autn(sqn_xor_ak: [u8; 6]) -> Autn {
        let mut autn = [0; 16];
        autn[..6].copy_from_slice(&sqn_xor_ak);
        // The AMF field and the MAC, which no derivation takes
        autn[6..].copy_from_slice(&[0x80, 0x00, 1, 2, 3, 4, 5, 6, 7, 8]);
        Autn::new(&autn)
    }

    #[test]
    fn kausf_uses_fc_6a() {
        let (ck, ik) = (Ck::new(&[0; 16]), Ik::new(&[0x11; 16]));
        let sn = b"5G:mnc093.mcc208.3gppnetwork.org";
        assert_eq!(
            hex::encode(
                derive_kausf(&ck, &ik, sn, &autn([1, 2, 3, 4, 5, 6]))
                    .unwrap()
                    .as_octets()
            ),
            "8e71503f94996eabee6ed9cec7ace8d6f31c1883f969330a9d72140cce5b5d16"
        );
    }

    /// A parameter of variable length that does not fit the two-octet L of
    /// TS 33.220 Annex B.2, a RES outside the 4 to 16 octets of
    /// TS 33.102 §6.3.7, and an ABBA outside the 2 to 255 of
    /// TS 24.501 §9.11.3.10.
    #[test]
    fn inputs_that_the_kdf_cannot_take_are_errors() {
        let (ck, ik, rand) = (Ck::new(&[0; 16]), Ik::new(&[0; 16]), Rand::new(&[0; 16]));
        let too_long = vec![b'a'; 65536];
        let refused = SecurityError::InputTooLong {
            maximum: 65535,
            got: 65536,
        };
        assert_eq!(
            derive_kausf(&ck, &ik, &too_long, &autn([0; 6])).unwrap_err(),
            refused
        );
        assert_eq!(
            derive_kseaf(&KAusf::new(&[0; 32]), &too_long).unwrap_err(),
            refused
        );
        assert_eq!(
            compute_xres_star(&ck, &ik, &too_long, &rand, &[0; 8]).unwrap_err(),
            refused
        );
        for length in [0, 3, 17] {
            assert_eq!(
                compute_xres_star(&ck, &ik, b"5G:x", &rand, &vec![0; length]).unwrap_err(),
                SecurityError::InvalidParameter("RES and XRES are 4 to 16 octets long")
            );
            assert!(compute_res_star(&ck, &ik, b"5G:x", &rand, &vec![0; length]).is_err());
        }
        for length in [4, 16] {
            assert!(compute_xres_star(&ck, &ik, b"5G:x", &rand, &vec![0; length]).is_ok());
        }

        let (kseaf, supi) = (KSeaf::new(&[0; 32]), Supi::imsi("208930000000001").unwrap());
        for length in [0, 1, 256] {
            assert_eq!(
                derive_kamf(&kseaf, &supi, &vec![0; length]).unwrap_err(),
                SecurityError::InvalidParameter("ABBA is 2 to 255 octets long")
            );
        }
        assert!(derive_kamf(&kseaf, &supi, &[0; 255]).is_ok());
    }

    #[test]
    fn five_g_aka_key_chain_matches_another_implementation() {
        // CK, IK, RES, RAND, and SQN XOR AK are the MILENAGE outputs of
        // TS 35.208 test set 1. TS 33.501 Annex A has no test data: the
        // expected values are those that `tests/five_g_aka_chain.py`
        // derives with the HMAC-SHA-256 of Python's standard library over
        // the S strings of Annex A.2 to A.10.
        let ck = Ck::new(&octets("b40ba9a3c58b2a05bbf0d987b21bf8cb"));
        let ik = Ik::new(&octets("f769bcd751044604127672711c6d3441"));
        let rand = Rand::new(&octets("23553cbe9637a89d218ae64dae47bf35"));
        let res = hex::decode("a54211d5e3ba50bf").unwrap();
        let autn = autn([0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77]);
        let sn = b"5G:mnc093.mcc208.3gppnetwork.org";

        let kausf = derive_kausf(&ck, &ik, sn, &autn).unwrap();
        assert_eq!(
            hex::encode(kausf.as_octets()),
            "f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9"
        );
        let xres_star = compute_xres_star(&ck, &ik, sn, &rand, &res).unwrap();
        assert_eq!(
            hex::encode(xres_star.as_octets()),
            "5cc9527f4d21c43bee83a15443acf1c4"
        );
        let hxres_star = compute_hxres_star(&rand, &xres_star);
        assert_eq!(
            hex::encode(hxres_star.as_octets()),
            "6970075e3c8245fdc2073003cf166279"
        );
        // The UE computes the same RES*, and the two sides accept it
        let res_star = compute_res_star(&ck, &ik, sn, &rand, &res).unwrap();
        assert!(xres_star.accepts(&res_star));
        assert!(hxres_star.accepts(&compute_hres_star(&rand, &res_star)));
        assert!(!xres_star.accepts(&ResStar::new(&[0; 16])));
        assert!(!hxres_star.accepts(&HresStar::new(&[0; 16])));

        let kseaf = derive_kseaf(&kausf, sn).unwrap();
        assert_eq!(
            hex::encode(kseaf.as_octets()),
            "cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa"
        );
        let supi = Supi::imsi("208930000000001").unwrap();
        let kamf = derive_kamf(&kseaf, &supi, &[0x00, 0x00]).unwrap();
        assert_eq!(
            hex::encode(kamf.as_octets()),
            "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4"
        );
        assert_eq!(
            hex::encode(derive_knas_enc(&kamf, CipheringAlgorithm::NEA2).as_octets()),
            "f47ae570afde775373d1b313d2176f54"
        );
        assert_eq!(
            hex::encode(derive_knas_int(&kamf, IntegrityAlgorithm::NIA2).as_octets()),
            "28ddb5356880149b9fee22f2367522a4"
        );
        let kgnb = derive_kgnb(&kamf, NasCount::ZERO);
        assert_eq!(
            hex::encode(kgnb.as_octets()),
            "c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005"
        );
        let nh = derive_nh(&kamf, &kgnb);
        assert_eq!(
            hex::encode(nh.as_octets()),
            "383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b"
        );
        // The next NH comes from the one before it
        assert_ne!(derive_nh(&kamf, &nh), nh);
    }

    /// TS 33.501 Annex A.7.0: P0 of the derivation of KAMF is the SUPI as
    /// TS 23.003 §2.2 has an IMSI, its digits, and not the form of the
    /// service based interfaces with `imsi-` in front.
    ///
    /// The keys are those that Open5GS (`ogs_kdf_kausf_5gs`,
    /// `ogs_kdf_kseaf`, `ogs_kdf_kamf`, v2.7.6) and Python's `hmac` give
    /// for the IMSI 274012001002086 of TS 33.501 Annex C.4, as the second
    /// review of this crate recorded them. 0.2.0 took the SUPI as a
    /// string, and gave another KAMF for `imsi-274012001002086`.
    #[test]
    fn kamf_takes_the_identity_of_a_supi_in_either_form() {
        let ck = Ck::new(&octets("5dbdbb2954e8f3cde665b046179a5098"));
        let ik = Ik::new(&octets("59a92d3b476a0443487055cf88b2307b"));
        let sn = b"5G:mnc012.mcc274.3gppnetwork.org";
        let autn = autn(octets("33484dc2136b"));
        let kausf = derive_kausf(&ck, &ik, sn, &autn).unwrap();
        assert_eq!(
            hex::encode(kausf.as_octets()),
            "f26e74228b5c31f23ee1cf0bc19ffbf9bffbb634f669735269d1ca078ee5b665"
        );
        let kseaf = derive_kseaf(&kausf, sn).unwrap();
        assert_eq!(
            hex::encode(kseaf.as_octets()),
            "e51039fe94eee5044488cde4ffd610ece389153baf7f6736ef41d998df11a149"
        );
        let kamf = "1df794e8213a60c9a9c80e4eb0d6132f86275620f455b323832d859dda7d7dfb";
        for supi in [
            Supi::imsi("274012001002086").unwrap(),
            Supi::parse("imsi-274012001002086").unwrap(),
        ] {
            assert_eq!(
                hex::encode(derive_kamf(&kseaf, &supi, &[0, 0]).unwrap().as_octets()),
                kamf
            );
        }
        // A network specific identifier is its NAI, without `nai-`
        let nai = Supi::parse("nai-user17@example.com").unwrap();
        assert_eq!(
            derive_kamf(&kseaf, &nai, &[0, 0]).unwrap(),
            *kdf(
                kseaf.as_octets(),
                b"\x6duser17@example.com\x00\x12\x00\x00\x00\x02"
            )
        );
    }
}
