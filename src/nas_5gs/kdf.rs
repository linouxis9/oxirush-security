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

/// 5GS key derivation per 3GPP TS 33.501 Annex A.
pub use crate::common::kdf::{build_s, extract_128, kdf};
use crate::common::kdf::{derive_algorithm_key, nas_count_input};

/// Derive KAUSF from CK || IK (TS 33.501 Annex A.2)
///
/// TS 33.501 Annex A.2 requires FC=0x6A on both UE and network sides.
/// The `fc` parameter is retained for callers that need legacy compatibility;
/// use [`derive_kausf_standard`] for specification-conformant derivation.
pub fn derive_kausf(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
    fc: u8,
) -> [u8; 32] {
    let ck_ik: Vec<u8> = ck.iter().chain(ik.iter()).copied().collect();
    let s = build_s(fc, &[sn_name, sqn_xor_ak]);
    kdf(&ck_ik, &s)
}

/// Derive KAUSF with the TS 33.501 Annex A.2 FC=0x6A.
pub fn derive_kausf_standard(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    derive_kausf(ck, ik, sn_name, sqn_xor_ak, 0x6a)
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
pub fn derive_nas_key(kamf: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        matches!(algo_type, 0x01 | 0x02),
        "invalid 5GS NAS algorithm type"
    );
    assert!(algo_id <= 7, "invalid 5GS NAS algorithm identity");
    derive_algorithm_key(kamf, 0x69, algo_type, algo_id)
}

/// Compute HRES* = SHA-256(RAND || RES*)[16:32] for local verification of the UE's RES*.
pub fn compute_hres_star(rand: &[u8; 16], res_star: &[u8]) -> [u8; 16] {
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
pub fn derive_kgnb(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    let count_bytes = ul_nas_count.to_be_bytes();
    let access_type: &[u8] = &[0x01]; // 3GPP access
    let s = build_s(0x6E, &[&count_bytes, access_type]);
    kdf(kamf, &s)
}

/// Derive Next Hop (NH) key for handover key refresh (TS 33.501 Annex A.10, FC=0x6F)
///
/// `sync_input`: K_gNB (first NH) or previous NH (subsequent NHs).
pub fn derive_nh(kamf: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    let s = build_s(0x6F, &[sync_input.as_ref()]);
    kdf(kamf, &s)
}

/// Map KAMF to KASME for idle 5GS to EPS mobility (TS 33.501 Annex A.14, FC=0x73).
/// `ul_nas_count` is the COUNT used by the mobility-triggering 5GS NAS message.
pub fn derive_mapped_kasme_idle(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(kamf, &build_s(0x73, &[&nas_count_input(ul_nas_count)]))
}

/// Map KAMF to KASME for connected 5GS to EPS handover (Annex A.14, FC=0x74).
pub fn derive_mapped_kasme_handover(kamf: &[u8; 32], dl_nas_count: u32) -> [u8; 32] {
    kdf(kamf, &build_s(0x74, &[&nas_count_input(dl_nas_count)]))
}

/// Compute XRES* for 5G-AKA (TS 33.501 Annex A.4, FC=0x6B)
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
    let ck_ik: Vec<u8> = ck.iter().chain(ik.iter()).copied().collect();
    let s = build_s(0x6B, &[sn_name, rand.as_ref(), xres]);
    let full = kdf(&ck_ik, &s);
    full[16..].to_vec()
}

#[cfg(test)]
mod interworking_tests {
    use super::*;

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
}
