/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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
pub use crate::common::kdf::{build_s, extract_128, kdf};
use crate::common::kdf::{derive_algorithm_key, nas_count_input};
use zeroize::Zeroizing;

/// Derive KAUSF from CK || IK (TS 33.501 Annex A.2, FC=0x6A).
pub fn derive_kausf(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    derive_kausf_nonstandard(ck, ik, sn_name, sqn_xor_ak, 0x6a)
}

/// Backwards-compatible spelling of [`derive_kausf`].
#[deprecated(since = "0.1.0", note = "use derive_kausf; Annex A.2 fixes FC to 0x6A")]
pub fn derive_kausf_standard(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    derive_kausf(ck, ik, sn_name, sqn_xor_ak)
}

/// Derive using an explicitly non-standard KAUSF function code.
///
/// This escape hatch exists only for interoperability experiments. It does not
/// implement TS 33.501 Annex A.2 unless `fc` is `0x6A`, and is intentionally
/// not re-exported from the crate root.
pub(crate) fn derive_kausf_nonstandard(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
    fc: u8,
) -> [u8; 32] {
    let mut ck_ik = Zeroizing::new([0u8; 32]);
    ck_ik[..16].copy_from_slice(ck);
    ck_ik[16..].copy_from_slice(ik);
    let s = build_s(fc, &[sn_name, sqn_xor_ak]);
    kdf(ck_ik.as_ref(), &s)
}

/// Derive KSEAF from KAUSF (TS 33.501 Annex A.6, FC=0x6C)
pub fn derive_kseaf(kausf: &[u8; 32], sn_name: &[u8]) -> [u8; 32] {
    let s = build_s(0x6C, &[sn_name]);
    kdf(kausf, &s)
}

/// Derive KAMF from KSEAF (TS 33.501 Annex A.7, FC=0x6D)
///
/// `supi_digits`: SUPI without its type prefix (IMSI, NAI, GCI, or GLI).
pub fn derive_kamf(kseaf: &[u8; 32], supi_digits: &str, abba: &[u8]) -> [u8; 32] {
    let s = build_s(0x6D, &[supi_digits.as_bytes(), abba]);
    kdf(kseaf, &s)
}

/// Derive NAS keys from KAMF (TS 33.501 Annex A.8, FC=0x69)
///
/// algo_type: 0x01 = NAS-enc-alg, 0x02 = NAS-int-prot-alg
/// algo_id:   three-bit NAS algorithm ID; values 4 through 7 are reserved.
///
/// Returns the full 32-byte output; take the last 16 bytes as the 128-bit key.
///
/// # Panics
///
/// Panics if `algo_type` is not 0x01 or 0x02, or `algo_id` exceeds 7.
pub fn derive_nas_key(kamf: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        matches!(algo_type, 0x01 | 0x02),
        "invalid 5GS NAS algorithm type"
    );
    assert!(algo_id <= 7, "invalid 5GS NAS algorithm identity");
    derive_algorithm_key(kamf, 0x69, algo_type, algo_id)
}

/// Compute `HRES* = SHA-256(RAND || RES*)[16:32]` for local verification of the UE's RES*.
pub fn compute_hres_star(rand: &[u8; 16], res_star: &[u8; 16]) -> [u8; 16] {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(rand.as_ref());
    h.update(res_star);
    h.finalize()[16..]
        .try_into()
        .expect("SHA-256 output yields 16-byte tail")
}

/// Derive K_gNB from K_AMF and UL NAS COUNT (TS 33.501 Annex A.9, FC=0x6E)
///
/// `ul_nas_count`: the UL NAS COUNT value used in the trigger message
/// (SecurityModeComplete for initial registration, ServiceRequest for reconnection).
///
/// Access type distinguisher P1 = 0x01 (3GPP access).
///
/// `u32::MAX` is the TS 33.501 clauses 6.9.2.3.3 and 8.4.2 freshness
/// sentinel used during horizontal KAMF derivation and 5GS/EPS handover.
///
/// # Panics
///
/// Panics if `ul_nas_count` is outside the ordinary 24-bit NAS COUNT range and
/// is not the all-ones sentinel.
pub fn derive_kgnb(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    assert!(
        ul_nas_count <= 0x00ff_ffff || ul_nas_count == u32::MAX,
        "NAS COUNT exhausted"
    );
    let count_bytes = ul_nas_count.to_be_bytes();
    let access_type: &[u8] = &[0x01]; // 3GPP access
    let s = build_s(0x6E, &[&count_bytes, access_type]);
    kdf(kamf, &s)
}

/// Derive KN3IWF, which is also KWAGF, KTNGF, and KTWIF, from KAMF and the
/// uplink NAS COUNT of non-3GPP access (TS 33.501 Annex A.9, FC=0x6E,
/// access type distinguisher 0x02).
///
/// # Panics
///
/// Panics if `ul_nas_count` exceeds 2^24 - 1.
pub fn derive_kn3iwf(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(
        kamf,
        &build_s(0x6E, &[&nas_count_input(ul_nas_count), &[0x02]]),
    )
}

/// Derive an AS key from KgNB (TS 33.501 Annex A.8, FC=0x69).
///
/// `algo_type` is 0x03 RRC encryption, 0x04 RRC integrity, 0x05 UP
/// encryption, or 0x06 UP integrity; `algo_id` is the four-bit algorithm
/// identity. Take the last 16 bytes as the 128-bit key.
///
/// # Panics
///
/// Panics if `algo_type` is outside 0x03 to 0x06, or `algo_id` exceeds 15.
pub fn derive_as_key(kgnb: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        (0x03..=0x06).contains(&algo_type),
        "invalid 5GS AS algorithm type"
    );
    assert!(algo_id <= 0x0f, "invalid 5GS algorithm identity");
    derive_algorithm_key(kgnb, 0x69, algo_type, algo_id)
}

/// Derive KNG-RAN* for a target gNB (TS 33.501 Annex A.11, FC=0x70).
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB or
/// KeNB. `arfcn_dl` is the NR-ARFCN of the target PCell SSB (three octets).
///
/// # Panics
///
/// Panics if `pci` exceeds 1007 or `arfcn_dl` exceeds 3279165.
pub fn derive_kng_ran_star(base_key: &[u8; 32], pci: u16, arfcn_dl: u32) -> [u8; 32] {
    assert!(pci <= 1007, "NR PCI must be at most 1007");
    assert!(arfcn_dl <= 3_279_165, "NR-ARFCN must be at most 3279165");
    kdf(
        base_key,
        &build_s(0x70, &[&pci.to_be_bytes(), &arfcn_dl.to_be_bytes()[1..]]),
    )
}

/// Derive KNG-RAN* for a target ng-eNB (TS 33.501 Annex A.12, FC=0x71).
///
/// `base_key` is NH when the NCC increases, otherwise the current KgNB or
/// KeNB. EARFCN-DL is always three octets here, unlike KeNB* in TS 33.401.
///
/// # Panics
///
/// Panics if `pci` exceeds 503 or `earfcn_dl` exceeds 262143.
pub fn derive_kng_ran_star_ng_enb(base_key: &[u8; 32], pci: u16, earfcn_dl: u32) -> [u8; 32] {
    assert!(pci <= 503, "E-UTRA PCI must be at most 503");
    assert!(earfcn_dl <= 262_143, "EARFCN-DL must be at most 262143");
    kdf(
        base_key,
        &build_s(0x71, &[&pci.to_be_bytes(), &earfcn_dl.to_be_bytes()[1..]]),
    )
}

/// Derive Next Hop (NH) key for handover key refresh (TS 33.501 Annex A.10, FC=0x6F)
///
/// `sync_input`: K_gNB (first NH) or previous NH (subsequent NHs).
pub fn derive_nh(kamf: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    let s = Zeroizing::new(build_s(0x6F, &[sync_input.as_ref()]));
    kdf(kamf, &s)
}

/// Map KAMF to KASME for idle 5GS to EPS mobility (TS 33.501 Annex A.14, FC=0x73).
/// `ul_nas_count` is the COUNT used by the mobility-triggering 5GS NAS message.
///
/// # Panics
///
/// Panics if `ul_nas_count` exceeds 2^24 - 1.
pub fn derive_mapped_kasme_idle(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(kamf, &build_s(0x73, &[&nas_count_input(ul_nas_count)]))
}

/// Map KAMF to KASME for connected 5GS to EPS handover (Annex A.14, FC=0x74).
///
/// # Panics
///
/// Panics if `dl_nas_count` exceeds 2^24 - 1.
pub fn derive_mapped_kasme_handover(kamf: &[u8; 32], dl_nas_count: u32) -> [u8; 32] {
    kdf(kamf, &build_s(0x74, &[&nas_count_input(dl_nas_count)]))
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
    nas_count: u32,
) -> Result<[u8; 32], SecurityError> {
    if nas_count > 0x00ff_ffff {
        return Err(SecurityError::InvalidParameter("NAS COUNT exceeds 24 bits"));
    }
    let direction = match direction {
        KamfMobilityDirection::IdleMobility => [0x00],
        KamfMobilityDirection::Handover => [0x01],
    };
    Ok(kdf(
        kamf,
        &build_s(0x72, &[&direction, &nas_count.to_be_bytes()]),
    ))
}

/// Derive KAMF' for idle mobility using the uplink NAS COUNT.
pub fn derive_kamf_prime_idle(
    kamf: &[u8; 32],
    ul_nas_count: u32,
) -> Result<[u8; 32], SecurityError> {
    derive_kamf_prime(kamf, KamfMobilityDirection::IdleMobility, ul_nas_count)
}

/// Derive KAMF' for handover using the downlink NAS COUNT.
pub fn derive_kamf_prime_handover(
    kamf: &[u8; 32],
    dl_nas_count: u32,
) -> Result<[u8; 32], SecurityError> {
    derive_kamf_prime(kamf, KamfMobilityDirection::Handover, dl_nas_count)
}

/// Derive KSN for dual connectivity (TS 33.501 Annex A.16, FC=0x79).
pub fn derive_ksn(base_key: &[u8; 32], sn_counter: u16) -> [u8; 32] {
    kdf(base_key, &build_s(0x79, &[&sn_counter.to_be_bytes()]))
}

fn checked_kdf_parameter(input: &[u8]) -> Result<&[u8], SecurityError> {
    if input.len() > u16::MAX as usize {
        Err(SecurityError::InputTooLong {
            maximum: u16::MAX as usize,
            got: input.len(),
        })
    } else {
        Ok(input)
    }
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
    let header = checked_kdf_parameter(header)?;
    let counter = checked_procedure_counter(counter)?;
    let full = match p2 {
        Some(p2) => {
            let p2 = checked_kdf_parameter(p2)?;
            kdf(kausf, &build_s(0x77, &[header, &counter, p2]))
        }
        None => kdf(kausf, &build_s(0x77, &[header, &counter])),
    };
    Ok(extract_128(&full))
}

/// Derive SoR-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.18, FC=0x78).
pub fn derive_sor_mac_ue(kausf: &[u8; 32], counter: u16) -> Result<[u8; 16], SecurityError> {
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&kdf(
        kausf,
        &build_s(0x78, &[&[0x01], &counter]),
    )))
}

/// Derive UPU-MAC-IAUSF (TS 33.501 Annex A.19, FC=0x7B).
pub fn derive_upu_mac_ausf(
    kausf: &[u8; 32],
    upu_data: &[u8],
    counter: u16,
) -> Result<[u8; 16], SecurityError> {
    let upu_data = checked_kdf_parameter(upu_data)?;
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&kdf(
        kausf,
        &build_s(0x7b, &[upu_data, &counter]),
    )))
}

/// Derive UPU-MAC-IUE/XMAC-IUE (TS 33.501 Annex A.20, FC=0x7C).
pub fn derive_upu_mac_ue(kausf: &[u8; 32], counter: u16) -> Result<[u8; 16], SecurityError> {
    let counter = checked_procedure_counter(counter)?;
    Ok(extract_128(&kdf(
        kausf,
        &build_s(0x7c, &[&[0x01], &counter]),
    )))
}

/// Usage distinguisher for TS 33.501 Annex A.22 key derivation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TnapKeyUsage {
    Ipsec = 0x01,
    Tnap = 0x02,
    FastTransition = 0x03,
}

/// Derive KTIPSec, KTNAP, or KFT (TS 33.501 Annex A.22, FC=0x84).
pub fn derive_tnap_usage_key(base_key: &[u8; 32], usage: TnapKeyUsage) -> [u8; 32] {
    kdf(base_key, &build_s(0x84, &[&[usage as u8]]))
}

/// Typed IAB IP address used by TS 33.501 Annex A.23.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IabIpAddress {
    V4([u8; 4]),
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
    kdf(base_key, &build_s(0x83, &[donor.octets(), node.octets()]))
}

/// Derive KASME_SRVCC from KAMF for SRVCC to UTRAN CS (TS 33.501 Annex A.21,
/// FC=0x7D). `dl_nas_count` is the current downlink 5G NAS COUNT; the AMF
/// then increments it, and the UE estimates it from four LSBs (Annex J,
/// steps 2 and 10).
///
/// # Panics
///
/// Panics if `dl_nas_count` exceeds 2^24 - 1.
pub fn derive_kasme_srvcc(kamf: &[u8; 32], dl_nas_count: u32) -> [u8; 32] {
    kdf(kamf, &build_s(0x7D, &[&nas_count_input(dl_nas_count)]))
}

/// Compute XRES* for 5G-AKA (TS 33.501 Annex A.4, FC=0x6B)
///
/// # Panics
///
/// Panics if `xres` is not 4 to 16 octets long.
pub fn compute_xres_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    rand: &[u8; 16],
    xres: &[u8],
) -> Vec<u8> {
    assert!(
        (4..=16).contains(&xres.len()),
        "XRES must contain 4 to 16 bytes"
    );
    let mut ck_ik = Zeroizing::new([0u8; 32]);
    ck_ik[..16].copy_from_slice(ck);
    ck_ik[16..].copy_from_slice(ik);
    let s = build_s(0x6B, &[sn_name, rand.as_ref(), xres]);
    let full = kdf(ck_ik.as_ref(), &s);
    full[16..].to_vec()
}

#[cfg(test)]
mod interworking_tests {
    use super::*;

    #[test]
    fn access_and_handover_keys_follow_annex_a() {
        // Expected values computed independently with HMAC-SHA-256 over the
        // S strings of TS 33.501 Annex A.8, A.9, A.11, and A.12.
        let key = [0x5a; 32];
        assert_eq!(
            hex::encode(derive_kgnb(&key, 0x0102)),
            "4780bc81acc4eadb7cccf496e3981b7dd44840f8c99dcb09944d07fa19d4094f"
        );
        assert_eq!(
            hex::encode(derive_kn3iwf(&key, 0x0102)),
            "ca3c93d0e70afc503dd7e7661a6b4bdb56f80ebab8358ee1b4c86d952a494fcb"
        );
        assert_eq!(
            hex::encode(derive_as_key(&key, 0x04, 2)),
            "9abef21a9eadba59c82f1bcd3e27204dfe7a7f2bf63c9a96fcf854c507e52227"
        );
        assert_eq!(
            hex::encode(derive_kng_ran_star(&key, 1007, 632_628)),
            "055073f4af9d56dedbf4a277be30de51d4c074a11c58847394e3a9af800d9b8e"
        );
        assert_eq!(
            hex::encode(derive_kng_ran_star_ng_enb(&key, 503, 6_300)),
            "b22d48526024fd5b8988d58b19d7bf5466e013da35c25003dd11906f926440fc"
        );
        assert!(std::panic::catch_unwind(|| derive_as_key(&key, 0x02, 2)).is_err());
        assert!(std::panic::catch_unwind(|| derive_kng_ran_star(&key, 1008, 0)).is_err());
    }

    #[test]
    fn kasme_srvcc_uses_fc_0x7d_and_the_downlink_count() {
        let kamf = [0x5a; 32];
        assert_eq!(
            derive_kasme_srvcc(&kamf, 0x0102),
            kdf(&kamf, &[0x7d, 0x00, 0x00, 0x01, 0x02, 0x00, 0x04])
        );
    }

    #[test]
    fn mapped_kasme_vectors() {
        let kamf = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(derive_mapped_kasme_idle(&kamf, 0x0012_3456)),
            "e72331cceed3329aefe6d0148472d17d51968ca45e0a0a570bb9e889fe2ee69e"
        );
        assert_eq!(
            hex::encode(derive_mapped_kasme_handover(&kamf, 0x0012_3456)),
            "6f4cb30cdb2d7dcc45fc9f2bcf5a10fcb90c2c4cba1ef3deb22917eadafbf832"
        );
    }

    #[test]
    fn release_19_annex_a_missing_entry_vectors() {
        let key = core::array::from_fn(|index| index as u8);
        assert_eq!(
            hex::encode(derive_kamf_prime_handover(&key, 0x0012_3456).unwrap()),
            "efe7440adf3f3ee4182cb1d78c0b9a7fcc20451a9cd572fa3b1a0ebc195b3f61"
        );
        assert!(derive_kamf_prime_idle(&key, 0x0100_0000).is_err());
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
            hex::encode(derive_kgnb(&key, u32::MAX)),
            "ad824bf330fd0ac91c5bcffe66ac497d549711f555849c1114b06d969191d2df"
        );
    }

    #[test]
    #[should_panic(expected = "NAS COUNT exhausted")]
    fn kgnb_rejects_non_sentinel_count_above_24_bits() {
        derive_kgnb(&[0; 32], 0x0100_0000);
    }

    #[test]
    #[should_panic(expected = "NAS COUNT exhausted")]
    fn kn3iwf_rejects_count_above_24_bits() {
        derive_kn3iwf(&[0; 32], 0x0100_0000);
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
    fn kausf_standard_entry_point_fixes_fc_to_6a() {
        let ck = [0u8; 16];
        let ik = [0x11; 16];
        let sn = b"5G:mnc093.mcc208.3gppnetwork.org";
        let sqn_xor_ak = [1, 2, 3, 4, 5, 6];
        assert_eq!(
            hex::encode(derive_kausf(&ck, &ik, sn, &sqn_xor_ak)),
            "8e71503f94996eabee6ed9cec7ace8d6f31c1883f969330a9d72140cce5b5d16"
        );
        assert_eq!(
            hex::encode(derive_kausf_nonstandard(&ck, &ik, sn, &sqn_xor_ak, 0x6b)),
            "feeff2764fff058992855a125bd6f1260e38a50f3949cbe5b527ba7f62703200"
        );
    }
}
