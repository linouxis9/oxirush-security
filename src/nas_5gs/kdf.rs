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

use crate::SecurityError;
use crate::common::input::{AccessKeyCount, CipheringAlgorithm, IntegrityAlgorithm, NasCount};
pub use crate::common::kdf::{build_s, extract_128, kdf};
use crate::common::kdf::{checked_parameter, derive, derive_algorithm_key};
use zeroize::Zeroizing;

/// FC of the algorithm key derivation function (TS 33.501 Annex A.8).
const FC_ALGORITHM_KEY: u8 = 0x69;

fn ck_ik(ck: &[u8; 16], ik: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    key
}

/// Derive KAUSF from CK || IK (TS 33.501 Annex A.2, FC=0x6A).
///
/// `sn_name` is the serving network name, such as
/// `5G:mnc093.mcc208.3gppnetwork.org`. One longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kausf(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
) -> Result<[u8; 32], SecurityError> {
    let sn_name = checked_parameter(sn_name)?;
    Ok(derive(ck_ik(ck, ik).as_ref(), 0x6a, &[sn_name, sqn_xor_ak]))
}

/// Derive KSEAF from KAUSF (TS 33.501 Annex A.6, FC=0x6C).
///
/// An `sn_name` longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kseaf(kausf: &[u8; 32], sn_name: &[u8]) -> Result<[u8; 32], SecurityError> {
    Ok(derive(kausf, 0x6C, &[checked_parameter(sn_name)?]))
}

/// Derive KAMF from KSEAF (TS 33.501 Annex A.7, FC=0x6D).
///
/// `supi` is the SUPI without its type prefix: the digits of an IMSI, or a
/// NAI, GCI or GLI as it is. `abba` is the ABBA parameter, `[0x00, 0x00]`
/// in the releases so far (Annex A.7.1). Either longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kamf(kseaf: &[u8; 32], supi: &str, abba: &[u8]) -> Result<[u8; 32], SecurityError> {
    let supi = checked_parameter(supi.as_bytes())?;
    Ok(derive(kseaf, 0x6D, &[supi, checked_parameter(abba)?]))
}

/// Derive KNASenc, the NAS ciphering key of `algorithm`, from KAMF
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x01).
pub fn derive_knas_enc(kamf: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kamf, FC_ALGORITHM_KEY, 0x01, algorithm.into())
}

/// Derive KNASint, the NAS integrity key of `algorithm`, from KAMF
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x02).
pub fn derive_knas_int(kamf: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kamf, FC_ALGORITHM_KEY, 0x02, algorithm.into())
}

/// Compute `HRES* = SHA-256(RAND || RES*)[16:32]` for local verification of the UE's RES*.
///
/// Compare it with HXRES* through
/// [`constant_time_eq`](crate::common::constant_time_eq), not with `==`.
pub fn compute_hres_star(rand: &[u8; 16], res_star: &[u8; 16]) -> [u8; 16] {
    extract_128(&crate::common::sha256::sha256(&[rand, res_star]))
}

/// Derive KgNB from KAMF and the uplink NAS COUNT of 3GPP access
/// (TS 33.501 Annex A.9, FC=0x6E, access type distinguisher 0x01).
///
/// `ul_nas_count` is the uplink NAS COUNT of the message that started the
/// derivation, a SECURITY MODE COMPLETE or a SERVICE REQUEST for instance,
/// as a [`NasCount`]. At an N2 handover with a KAMF change and at a
/// handover from EPS it is [`AccessKeyCount::Handover`] (§6.9.2.3.3,
/// §8.4.2).
pub fn derive_kgnb(kamf: &[u8; 32], ul_nas_count: impl Into<AccessKeyCount>) -> [u8; 32] {
    let count = ul_nas_count.into().get().to_be_bytes();
    derive(kamf, 0x6E, &[&count, &[0x01]])
}

/// Derive KN3IWF, which is also KWAGF, KTNGF, and KTWIF, from KAMF and the
/// uplink NAS COUNT of non-3GPP access (TS 33.501 Annex A.9, FC=0x6E,
/// access type distinguisher 0x02).
pub fn derive_kn3iwf(kamf: &[u8; 32], ul_nas_count: NasCount) -> [u8; 32] {
    let count = ul_nas_count.get().to_be_bytes();
    derive(kamf, 0x6E, &[&count, &[0x02]])
}

/// Derive KRRCenc, the RRC ciphering key of `algorithm`, from KgNB
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x03).
///
/// With S-KgNB as the key this is also the derivation of an SgNB
/// (TS 33.401 Annex A.19), like the three functions that follow.
pub fn derive_krrc_enc(kgnb: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kgnb, FC_ALGORITHM_KEY, 0x03, algorithm.into())
}

/// Derive KRRCint, the RRC integrity key of `algorithm`, from KgNB
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x04).
pub fn derive_krrc_int(kgnb: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kgnb, FC_ALGORITHM_KEY, 0x04, algorithm.into())
}

/// Derive KUPenc, the user plane ciphering key of `algorithm`, from KgNB
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x05).
pub fn derive_kup_enc(kgnb: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kgnb, FC_ALGORITHM_KEY, 0x05, algorithm.into())
}

/// Derive KUPint, the user plane integrity key of `algorithm`, from KgNB
/// (TS 33.501 Annex A.8, algorithm type distinguisher 0x06).
pub fn derive_kup_int(kgnb: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kgnb, FC_ALGORITHM_KEY, 0x06, algorithm.into())
}

fn out_of_range(field: &'static str, maximum: u32, got: u32) -> SecurityError {
    SecurityError::OutOfRange {
        field,
        maximum: maximum.into(),
        got: got.into(),
    }
}

/// Derive KNG-RAN* for a target gNB (TS 33.501 Annex A.11, FC=0x70).
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB or
/// KeNB. `arfcn_dl` is the NR-ARFCN of the target PCell SSB (three octets).
///
/// A `pci` above 1007 or an `arfcn_dl` above 3279165 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kng_ran_star(
    base_key: &[u8; 32],
    pci: u16,
    arfcn_dl: u32,
) -> Result<[u8; 32], SecurityError> {
    if pci > 1007 {
        return Err(out_of_range("NR PCI", 1007, pci.into()));
    }
    if arfcn_dl > 3_279_165 {
        return Err(out_of_range("NR-ARFCN", 3_279_165, arfcn_dl));
    }
    Ok(derive(
        base_key,
        0x70,
        &[&pci.to_be_bytes(), &arfcn_dl.to_be_bytes()[1..]],
    ))
}

/// Derive KNG-RAN* for a target ng-eNB (TS 33.501 Annex A.12, FC=0x71).
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB or
/// KeNB. EARFCN-DL is always three octets here, unlike KeNB* in TS 33.401.
///
/// A `pci` above 503 or an `earfcn_dl` above 262143 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kng_ran_star_ng_enb(
    base_key: &[u8; 32],
    pci: u16,
    earfcn_dl: u32,
) -> Result<[u8; 32], SecurityError> {
    if pci > 503 {
        return Err(out_of_range("E-UTRA PCI", 503, pci.into()));
    }
    if earfcn_dl > 262_143 {
        return Err(out_of_range("EARFCN-DL", 262_143, earfcn_dl));
    }
    Ok(derive(
        base_key,
        0x71,
        &[&pci.to_be_bytes(), &earfcn_dl.to_be_bytes()[1..]],
    ))
}

/// Derive Next Hop (NH) key for handover key refresh (TS 33.501 Annex A.10, FC=0x6F)
///
/// `sync_input`: K_gNB (first NH) or previous NH (subsequent NHs).
pub fn derive_nh(kamf: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    derive(kamf, 0x6F, &[sync_input.as_ref()])
}

/// Map KAMF to KASME for idle 5GS to EPS mobility (TS 33.501 Annex A.14, FC=0x73).
/// `ul_nas_count` is the COUNT used by the mobility-triggering 5GS NAS message.
pub fn derive_mapped_kasme_idle(kamf: &[u8; 32], ul_nas_count: NasCount) -> [u8; 32] {
    derive(kamf, 0x73, &[&ul_nas_count.get().to_be_bytes()])
}

/// Map KAMF to KASME for connected 5GS to EPS handover (Annex A.14, FC=0x74).
pub fn derive_mapped_kasme_handover(kamf: &[u8; 32], dl_nas_count: NasCount) -> [u8; 32] {
    derive(kamf, 0x74, &[&dl_nas_count.get().to_be_bytes()])
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
    kamf: &[u8; 32],
    direction: KamfMobilityDirection,
    nas_count: NasCount,
) -> [u8; 32] {
    let direction = match direction {
        KamfMobilityDirection::IdleMobility => [0x00],
        KamfMobilityDirection::Handover => [0x01],
    };
    derive(kamf, 0x72, &[&direction, &nas_count.get().to_be_bytes()])
}

/// Derive KAMF' for idle mobility using the uplink NAS COUNT.
pub fn derive_kamf_prime_idle(kamf: &[u8; 32], ul_nas_count: NasCount) -> [u8; 32] {
    derive_kamf_prime(kamf, KamfMobilityDirection::IdleMobility, ul_nas_count)
}

/// Derive KAMF' for handover using the downlink NAS COUNT.
pub fn derive_kamf_prime_handover(kamf: &[u8; 32], dl_nas_count: NasCount) -> [u8; 32] {
    derive_kamf_prime(kamf, KamfMobilityDirection::Handover, dl_nas_count)
}

/// Derive KSN for dual connectivity (TS 33.501 Annex A.16, FC=0x79).
pub fn derive_ksn(base_key: &[u8; 32], sn_counter: u16) -> [u8; 32] {
    derive(base_key, 0x79, &[&sn_counter.to_be_bytes()])
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
    kausf: &[u8; 32],
    header: &[u8],
    counter: u16,
    p2: Option<&[u8]>,
) -> Result<[u8; 16], SecurityError> {
    let header = checked_parameter(header)?;
    let counter = checked_procedure_counter(counter)?;
    let full = match p2 {
        Some(p2) => {
            let p2 = checked_parameter(p2)?;
            derive(kausf, 0x77, &[header, &counter, p2])
        }
        None => derive(kausf, 0x77, &[header, &counter]),
    };
    Ok(extract_128(&full))
}

/// Derive SoR-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.18, FC=0x78).
pub fn derive_sor_mac_ue(kausf: &[u8; 32], counter: u16) -> Result<[u8; 16], SecurityError> {
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&derive(kausf, 0x78, &[&[0x01], &counter])))
}

/// Derive UPU-MAC-IAUSF (TS 33.501 Annex A.19, FC=0x7B).
pub fn derive_upu_mac_ausf(
    kausf: &[u8; 32],
    upu_data: &[u8],
    counter: u16,
) -> Result<[u8; 16], SecurityError> {
    let upu_data = checked_parameter(upu_data)?;
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&derive(kausf, 0x7b, &[upu_data, &counter])))
}

/// Derive UPU-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.20, FC=0x7C).
pub fn derive_upu_mac_ue(kausf: &[u8; 32], counter: u16) -> Result<[u8; 16], SecurityError> {
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&derive(kausf, 0x7c, &[&[0x01], &counter])))
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

/// Derive KTIPSec, KTNAP, or KFT (TS 33.501 Annex A.22, FC=0x84).
pub fn derive_tnap_usage_key(base_key: &[u8; 32], usage: TnapKeyUsage) -> [u8; 32] {
    derive(base_key, 0x84, &[&[usage as u8]])
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

/// Derive KIAB from donor and IAB-node IP addresses (TS 33.501 Annex A.23).
pub fn derive_kiab(base_key: &[u8; 32], donor: IabIpAddress, node: IabIpAddress) -> [u8; 32] {
    derive(base_key, 0x83, &[donor.octets(), node.octets()])
}

/// Derive KASME_SRVCC from KAMF for SRVCC to UTRAN CS (TS 33.501 Annex A.21,
/// FC=0x7D). `dl_nas_count` is the current downlink 5G NAS COUNT; the AMF
/// then increments it, and the UE estimates it from four LSBs (Annex J,
/// steps 2 and 10).
pub fn derive_kasme_srvcc(kamf: &[u8; 32], dl_nas_count: NasCount) -> [u8; 32] {
    derive(kamf, 0x7D, &[&dl_nas_count.get().to_be_bytes()])
}

/// Compute XRES* for 5G-AKA (TS 33.501 Annex A.4, FC=0x6B)
///
/// Compare the RES* of the UE with it through
/// [`constant_time_eq`](crate::common::constant_time_eq), not with `==`.
///
/// An `xres` that is not 4 to 16 octets long, the lengths of RES
/// (TS 33.102 §6.3.7), is [`SecurityError::InvalidParameter`], and an
/// `sn_name` longer than 65535 octets [`SecurityError::InputTooLong`].
pub fn compute_xres_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    rand: &[u8; 16],
    xres: &[u8],
) -> Result<[u8; 16], SecurityError> {
    if !(4..=16).contains(&xres.len()) {
        return Err(SecurityError::InvalidParameter(
            "XRES must be 4 to 16 octets long",
        ));
    }
    let sn_name = checked_parameter(sn_name)?;
    let mut full = derive(
        ck_ik(ck, ik).as_ref(),
        0x6B,
        &[sn_name, rand.as_ref(), xres],
    );
    let xres_star = extract_128(&full);
    zeroize::Zeroize::zeroize(&mut full);
    Ok(xres_star)
}

#[cfg(test)]
mod interworking_tests {
    use super::*;

    fn count(value: u32) -> NasCount {
        NasCount::new(value).unwrap()
    }

    #[test]
    fn access_and_handover_keys_follow_annex_a() {
        // Expected values computed independently with HMAC-SHA-256 over the
        // S strings of TS 33.501 Annex A.8, A.9, A.11, and A.12.
        let key = [0x5a; 32];
        assert_eq!(
            hex::encode(derive_kgnb(&key, count(0x0102))),
            "4780bc81acc4eadb7cccf496e3981b7dd44840f8c99dcb09944d07fa19d4094f"
        );
        assert_eq!(
            hex::encode(derive_kn3iwf(&key, count(0x0102))),
            "ca3c93d0e70afc503dd7e7661a6b4bdb56f80ebab8358ee1b4c86d952a494fcb"
        );
        assert_eq!(
            hex::encode(derive_krrc_int(&key, IntegrityAlgorithm::NIA2)),
            "fe7a7f2bf63c9a96fcf854c507e52227"
        );
        assert_eq!(
            hex::encode(derive_kng_ran_star(&key, 1007, 632_628).unwrap()),
            "055073f4af9d56dedbf4a277be30de51d4c074a11c58847394e3a9af800d9b8e"
        );
        assert_eq!(
            hex::encode(derive_kng_ran_star_ng_enb(&key, 503, 6_300).unwrap()),
            "b22d48526024fd5b8988d58b19d7bf5466e013da35c25003dd11906f926440fc"
        );
    }

    /// The largest values: PCI 1007 and NR-ARFCN 3279165 (TS 38.331
    /// PhysCellId and ARFCN-ValueNR), PCI 503 and EARFCN 262143 (TS 36.331
    /// PhysCellId and ARFCN-ValueEUTRA-r9).
    #[test]
    fn a_cell_identity_or_a_frequency_out_of_range_is_an_error() {
        let key = [0x5a; 32];
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
        let expected =
            |kind: u8, identity: u8| extract_128(&kdf(&key, &[0x69, kind, 0, 1, identity, 0, 1]));
        for (identity, ciphering, integrity) in [
            (0, CipheringAlgorithm::NEA0, IntegrityAlgorithm::NIA0),
            (1, CipheringAlgorithm::NEA1, IntegrityAlgorithm::NIA1),
            (2, CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2),
            (3, CipheringAlgorithm::NEA3, IntegrityAlgorithm::NIA3),
        ] {
            assert_eq!(derive_knas_enc(&key, ciphering), expected(0x01, identity));
            assert_eq!(derive_knas_int(&key, integrity), expected(0x02, identity));
            assert_eq!(derive_krrc_enc(&key, ciphering), expected(0x03, identity));
            assert_eq!(derive_krrc_int(&key, integrity), expected(0x04, identity));
            assert_eq!(derive_kup_enc(&key, ciphering), expected(0x05, identity));
            assert_eq!(derive_kup_int(&key, integrity), expected(0x06, identity));
        }
    }

    #[test]
    fn kasme_srvcc_uses_fc_0x7d_and_the_downlink_count() {
        let kamf = [0x5a; 32];
        assert_eq!(
            derive_kasme_srvcc(&kamf, count(0x0102)),
            kdf(&kamf, &[0x7d, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04])
        );
    }

    #[test]
    fn mapped_kasme_vectors() {
        let kamf = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(derive_mapped_kasme_idle(&kamf, count(0x0012_3456))),
            "e72331cceed3329aefe6d0148472d17d51968ca45e0a0a570bb9e889fe2ee69e"
        );
        assert_eq!(
            hex::encode(derive_mapped_kasme_handover(&kamf, count(0x0012_3456))),
            "6f4cb30cdb2d7dcc45fc9f2bcf5a10fcb90c2c4cba1ef3deb22917eadafbf832"
        );
    }

    #[test]
    fn release_19_annex_a_missing_entry_vectors() {
        let key = core::array::from_fn(|index| index as u8);
        assert_eq!(
            hex::encode(derive_kamf_prime_handover(&key, count(0x0012_3456))),
            "efe7440adf3f3ee4182cb1d78c0b9a7fcc20451a9cd572fa3b1a0ebc195b3f61"
        );
        assert_eq!(
            derive_kamf_prime_idle(&key, count(0x0012_3456)),
            kdf(&key, &[0x72, 0x00, 0, 1, 0x00, 0x12, 0x34, 0x56, 0, 4])
        );
        assert_eq!(
            hex::encode(derive_ksn(&key, 0x1234)),
            "2411a7d723a135f48666c2bfe081713f9e2de6fa3f29830ae470ebe1dacdfb60"
        );
        assert_eq!(
            hex::encode(derive_sor_mac_ausf(&key, &[1, 2], 1, Some(&[0xaa, 0xbb])).unwrap()),
            "6fcf7ef205010336dcc5d7877fe3a68b"
        );
        assert_eq!(
            hex::encode(derive_sor_mac_ue(&key, 1).unwrap()),
            "4a67dd7f904e7c8f668238aa702c4a9f"
        );
        assert_eq!(
            hex::encode(derive_upu_mac_ausf(&key, &[0xaa, 0xbb, 0xcc], 1).unwrap()),
            "7c7d2cb5d4ca23c2f41ab3bb5d56f01a"
        );
        assert_eq!(
            hex::encode(derive_upu_mac_ue(&key, 1).unwrap()),
            "c954bbe60cbf81b3be14051c2b21116c"
        );
        assert!(derive_sor_mac_ue(&key, 0).is_err());
        assert!(derive_upu_mac_ue(&key, 0).is_err());
        assert_eq!(
            hex::encode(derive_tnap_usage_key(&key, TnapKeyUsage::Ipsec)),
            "c25821c31c7451e77c344846cde14d9fdc7bab10b9151415aa5f3461dad781a3"
        );
        assert_eq!(
            hex::encode(derive_kiab(
                &key,
                IabIpAddress::V4([192, 0, 2, 1]),
                IabIpAddress::V4([198, 51, 100, 2]),
            )),
            "57474ba433a9a48e72743db190442669bd5f48d0a45e209f774cb95532a10461"
        );
    }

    #[test]
    fn kgnb_accepts_all_ones_mobility_sentinel() {
        let key = core::array::from_fn(|index| index as u8);
        assert_eq!(
            hex::encode(derive_kgnb(&key, AccessKeyCount::Handover)),
            "ad824bf330fd0ac91c5bcffe66ac497d549711f555849c1114b06d969191d2df"
        );
        // 2^32 - 1 in the COUNT parameter, and the access type of 3GPP
        assert_eq!(
            derive_kgnb(&key, AccessKeyCount::Handover),
            kdf(&key, &[0x6e, 0xff, 0xff, 0xff, 0xff, 0, 4, 0x01, 0, 1])
        );
    }

    #[test]
    fn hres_star_matches_independent_sha256_probe() {
        let rand: [u8; 16] = core::array::from_fn(|index| index as u8);
        let res_star: [u8; 16] = core::array::from_fn(|index| 0x20 + index as u8);
        assert_eq!(
            hex::encode(compute_hres_star(&rand, &res_star)),
            "acc5770d8e61512db590e08855d7ad43"
        );
    }

    #[test]
    fn kausf_uses_fc_6a() {
        let ck = [0u8; 16];
        let ik = [0x11; 16];
        let sn = b"5G:mnc093.mcc208.3gppnetwork.org";
        let sqn_xor_ak = [1, 2, 3, 4, 5, 6];
        assert_eq!(
            hex::encode(derive_kausf(&ck, &ik, sn, &sqn_xor_ak).unwrap()),
            "8e71503f94996eabee6ed9cec7ace8d6f31c1883f969330a9d72140cce5b5d16"
        );
    }

    /// A parameter of variable length that does not fit the two-octet L of
    /// TS 33.220 Annex B.2, and a RES outside the 4 to 16 octets of
    /// TS 33.102 §6.3.7.
    #[test]
    fn inputs_that_the_kdf_cannot_take_are_errors() {
        let (ck, ik, rand, key) = ([0; 16], [0; 16], [0; 16], [0; 32]);
        let too_long = vec![b'a'; 65536];
        let refused = Err(SecurityError::InputTooLong {
            maximum: 65535,
            got: 65536,
        });
        assert_eq!(derive_kausf(&ck, &ik, &too_long, &[0; 6]), refused);
        assert_eq!(derive_kseaf(&key, &too_long), refused);
        let supi = String::from_utf8(too_long.clone()).unwrap();
        assert_eq!(derive_kamf(&key, &supi, &[0, 0]), refused);
        assert_eq!(derive_kamf(&key, "208930000000001", &too_long), refused);
        assert_eq!(
            compute_xres_star(&ck, &ik, &too_long, &rand, &[0; 8]),
            Err(SecurityError::InputTooLong {
                maximum: 65535,
                got: 65536,
            })
        );
        for length in [0, 3, 17] {
            assert_eq!(
                compute_xres_star(&ck, &ik, b"5G:x", &rand, &vec![0; length]),
                Err(SecurityError::InvalidParameter(
                    "XRES must be 4 to 16 octets long"
                ))
            );
        }
        for length in [4, 16] {
            assert!(compute_xres_star(&ck, &ik, b"5G:x", &rand, &vec![0; length]).is_ok());
        }
    }

    #[test]
    fn five_g_aka_key_chain_matches_another_implementation() {
        // CK, IK, RES, RAND, and SQN XOR AK are the MILENAGE outputs of
        // TS 35.208 test set 1. TS 33.501 Annex A has no test data: the
        // expected values are those that `tests/five_g_aka_chain.py`
        // derives with the HMAC-SHA-256 of Python's standard library over
        // the S strings of Annex A.2 to A.10.
        let ck: [u8; 16] = hex::decode("b40ba9a3c58b2a05bbf0d987b21bf8cb")
            .unwrap()
            .try_into()
            .unwrap();
        let ik: [u8; 16] = hex::decode("f769bcd751044604127672711c6d3441")
            .unwrap()
            .try_into()
            .unwrap();
        let rand: [u8; 16] = hex::decode("23553cbe9637a89d218ae64dae47bf35")
            .unwrap()
            .try_into()
            .unwrap();
        let res = hex::decode("a54211d5e3ba50bf").unwrap();
        let sqn_xor_ak = [0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77];
        let sn = b"5G:mnc093.mcc208.3gppnetwork.org";

        let kausf = derive_kausf(&ck, &ik, sn, &sqn_xor_ak).unwrap();
        assert_eq!(
            hex::encode(kausf),
            "f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9"
        );
        let xres_star = compute_xres_star(&ck, &ik, sn, &rand, &res).unwrap();
        assert_eq!(hex::encode(xres_star), "5cc9527f4d21c43bee83a15443acf1c4");
        assert_eq!(
            hex::encode(compute_hres_star(&rand, &xres_star)),
            "6970075e3c8245fdc2073003cf166279"
        );
        let kseaf = derive_kseaf(&kausf, sn).unwrap();
        assert_eq!(
            hex::encode(kseaf),
            "cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa"
        );
        let kamf = derive_kamf(&kseaf, "208930000000001", &[0x00, 0x00]).unwrap();
        assert_eq!(
            hex::encode(kamf),
            "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4"
        );
        assert_eq!(
            hex::encode(derive_knas_enc(&kamf, CipheringAlgorithm::NEA2)),
            "f47ae570afde775373d1b313d2176f54"
        );
        assert_eq!(
            hex::encode(derive_knas_int(&kamf, IntegrityAlgorithm::NIA2)),
            "28ddb5356880149b9fee22f2367522a4"
        );
        let kgnb = derive_kgnb(&kamf, NasCount::ZERO);
        assert_eq!(
            hex::encode(kgnb),
            "c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005"
        );
        assert_eq!(
            hex::encode(derive_nh(&kamf, &kgnb)),
            "383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b"
        );
    }
}
