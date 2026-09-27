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

//! EPS key derivation per 3GPP TS 33.401 Annex A.

use crate::common::kdf::{build_s, derive_algorithm_key, kdf, nas_count_input};
use zeroize::Zeroizing;

fn ck_ik(ck: &[u8; 16], ik: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    key
}

/// Derive KASME from CK || IK, serving network identity, and SQN XOR AK.
///
/// `sn_id` uses the same PLMN octets as [`crate::plmn::plmn_to_bytes`].
/// TS 33.401 Annex A.2, FC=0x10.
pub fn derive_kasme(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_id: &[u8; 3],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    kdf(ck_ik(ck, ik).as_ref(), &build_s(0x10, &[sn_id, sqn_xor_ak]))
}

/// Derive KeNB from KASME and uplink NAS COUNT (Annex A.3, FC=0x11).
/// TS 33.501 §8.3.2 step 2 uses the COUNT `0xffffffff` at 5GS to EPS
/// handover, and §8.4.2 step 3 does the same for KgNB.
pub fn derive_kenb(kasme: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x11, &[&ul_nas_count.to_be_bytes()]))
}

/// Derive NH from KASME and KeNB or the previous NH (Annex A.4, FC=0x12).
pub fn derive_nh(kasme: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    kdf(kasme, &Zeroizing::new(build_s(0x12, &[sync_input])))
}

/// Derive KeNB* for a target cell (Annex A.5, FC=0x13).
///
/// `base_key` is KeNB for horizontal derivation or NH for vertical derivation.
/// EARFCN-DL uses two octets through 65535 and three above that.
///
/// # Panics
///
/// Panics if `pci` exceeds 503 or `earfcn_dl` exceeds 262143.
pub fn derive_kenb_star(base_key: &[u8; 32], pci: u16, earfcn_dl: u32) -> [u8; 32] {
    assert!(pci <= 503, "PCI must be at most 503");
    assert!(earfcn_dl <= 262_143, "EARFCN-DL must be at most 262143");
    let earfcn = earfcn_dl.to_be_bytes();
    let encoded_earfcn = if earfcn_dl <= u16::MAX as u32 {
        &earfcn[2..]
    } else {
        &earfcn[1..]
    };
    kdf(
        base_key,
        &build_s(0x13, &[&pci.to_be_bytes(), encoded_earfcn]),
    )
}

/// Derive an EPS NAS key from KASME (Annex A.7, FC=0x15).
///
/// `algo_type` is 0x01 for ciphering or 0x02 for integrity; supported
/// `algo_id` is the three-bit EPS algorithm identifier (0 through 7). Use
/// [`crate::extract_128`] for the 128-bit EEA/EIA key.
///
/// # Panics
///
/// Panics if `algo_type` is not 0x01 or 0x02, or `algo_id` exceeds 7.
pub fn derive_nas_key(kasme: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        matches!(algo_type, 0x01 | 0x02),
        "invalid EPS NAS algorithm type"
    );
    assert!(algo_id <= 7, "invalid EPS algorithm identity");
    derive_algorithm_key(kasme, 0x15, algo_type, algo_id)
}

/// Derive an AS key from KeNB (Annex A.7, FC=0x15).
///
/// `algo_type` is 0x03 RRC encryption, 0x04 RRC integrity, 0x05 UP
/// encryption, or 0x06 UP integrity. Supported `algo_id` values are 0 through 3.
///
/// # Panics
///
/// Panics if `algo_type` or `algo_id` is outside those ranges.
pub fn derive_as_key(kenb: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        (0x03..=0x06).contains(&algo_type),
        "invalid EPS AS algorithm type"
    );
    assert!(algo_id <= 3, "unsupported EPS algorithm identity");
    derive_algorithm_key(kenb, 0x15, algo_type, algo_id)
}

/// Map KASME to CK' || IK' at handover (TS 33.401 Annex A.8, FC=0x16).
///
/// # Panics
///
/// Panics if `dl_nas_count` exceeds 2^24 - 1.
pub fn derive_ck_ik_handover(kasme: &[u8; 32], dl_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x16, &[&nas_count_input(dl_nas_count)]))
}

/// Derive the full NAS token KDF output (Annex A.9, FC=0x17).
/// The two least significant octets are sent on the wire.
///
/// # Panics
///
/// Panics if `ul_nas_count` exceeds 2^24 - 1.
pub fn derive_nas_token_full(kasme: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x17, &[&nas_count_input(ul_nas_count)]))
}

/// Derive the two-octet NAS token transmitted during inter-RAT mobility.
///
/// # Panics
///
/// Panics if `ul_nas_count` exceeds 2^24 - 1.
pub fn derive_nas_token(kasme: &[u8; 32], ul_nas_count: u32) -> [u8; 2] {
    let full = derive_nas_token_full(kasme, ul_nas_count);
    [full[30], full[31]]
}

/// Map CK || IK to K'ASME at handover (Annex A.10, FC=0x18).
pub fn derive_kasme_handover(ck: &[u8; 16], ik: &[u8; 16], nonce_mme: u32) -> [u8; 32] {
    kdf(
        ck_ik(ck, ik).as_ref(),
        &build_s(0x18, &[&nonce_mme.to_be_bytes()]),
    )
}

/// Map CK || IK to K'ASME at idle mobility (Annex A.11, FC=0x19).
pub fn derive_kasme_idle_mobility(
    ck: &[u8; 16],
    ik: &[u8; 16],
    nonce_ue: u32,
    nonce_mme: u32,
) -> [u8; 32] {
    kdf(
        ck_ik(ck, ik).as_ref(),
        &build_s(0x19, &[&nonce_ue.to_be_bytes(), &nonce_mme.to_be_bytes()]),
    )
}

/// Derive CKSRVCC || IKSRVCC from KASME or KASME_SRVCC (Annex A.12, FC=0x1A).
///
/// # Panics
///
/// Panics if `dl_nas_count` exceeds 2^24 - 1.
pub fn derive_ck_ik_srvcc(kasme: &[u8; 32], dl_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x1a, &[&nas_count_input(dl_nas_count)]))
}

/// Map KASME to CK' || IK' at idle mobility (Annex A.13, FC=0x1B).
///
/// # Panics
///
/// Panics if `ul_nas_count` exceeds 2^24 - 1.
pub fn derive_ck_ik_idle_mobility(kasme: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x1b, &[&nas_count_input(ul_nas_count)]))
}

/// Derive S-KeNB or S-KgNB for dual connectivity (Annex A.15, FC=0x1C).
pub fn derive_skenb(kenb: &[u8; 32], scg_counter: u16) -> [u8; 32] {
    kdf(kenb, &build_s(0x1c, &[&scg_counter.to_be_bytes()]))
}

/// Derive LWIP-PSK for LTE/WLAN integration (Annex A.16, FC=0x1E).
pub fn derive_lwip_psk(kenb: &[u8; 32], lwip_counter: u16) -> [u8; 32] {
    kdf(kenb, &build_s(0x1e, &[&lwip_counter.to_be_bytes()]))
}

/// Derive K_n for IOPS subscriber key separation (Annex A.17, FC=0x1D).
/// `f_n` is the operator-proprietary f(n) value; `imsi` is its encoded IMSI.
///
/// # Panics
///
/// Panics if `f_n` or `imsi` exceeds 65535 octets.
pub fn derive_kn(mk: &[u8], f_n: &[u8], imsi: &[u8]) -> [u8; 32] {
    kdf(mk, &build_s(0x1d, &[f_n, imsi]))
}

/// Derive S-KWT for LTE/WLAN aggregation (Annex A.18, FC=0x1F).
pub fn derive_skwt(kenb: &[u8; 32], wt_counter: u16) -> [u8; 32] {
    kdf(kenb, &build_s(0x1f, &[&wt_counter.to_be_bytes()]))
}

/// Derive SgNB algorithm key from S-KgNB (Annex A.19 / TS 33.501 A.8, FC=0x69).
///
/// # Panics
///
/// Panics if `algo_type` is not an SgNB key type or `algo_id` exceeds 3.
pub fn derive_sgnb_algorithm_key(skg_nb: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    assert!(
        (0x03..=0x06).contains(&algo_type),
        "invalid SgNB algorithm type"
    );
    assert!(algo_id <= 3, "unsupported SgNB algorithm identity");
    derive_algorithm_key(skg_nb, 0x69, algo_type, algo_id)
}

/// Map KASME to KAMF for idle EPS to 5GS mobility (TS 33.501 Annex A.15, FC=0x75).
/// The new 5GS NAS COUNTs start at zero after the context is installed.
///
/// # Panics
///
/// Panics if `tau_ul_nas_count` exceeds 2^24 - 1.
pub fn derive_mapped_kamf_idle(kasme: &[u8; 32], tau_ul_nas_count: u32) -> [u8; 32] {
    kdf(kasme, &build_s(0x75, &[&nas_count_input(tau_ul_nas_count)]))
}

/// Map KASME to KAMF for connected EPS to 5GS handover (Annex A.15, FC=0x76).
pub fn derive_mapped_kamf_handover(kasme: &[u8; 32], nh: &[u8; 32]) -> [u8; 32] {
    kdf(kasme, &Zeroizing::new(build_s(0x76, &[nh])))
}

/// Compute HASHMME or HASHUE over a plain ATTACH REQUEST or TRACKING AREA
/// UPDATE REQUEST (TS 33.401 Annex I.2).
///
/// The KDF key is 256 zero bits and S is the unprotected message as sent on
/// the uplink, without an FC octet. The hash is the 64 least significant bits.
pub fn compute_hash_mme(plain_request: &[u8]) -> [u8; 8] {
    let full = kdf(&[0; 32], plain_request);
    let mut hash = [0; 8];
    hash.copy_from_slice(&full[24..]);
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::extract_128;

    #[test]
    fn hash_mme_matches_network_values_in_capture() {
        // Embedded ATTACH REQUEST vectors and the HASHMME values returned by
        // the corresponding network SECURITY MODE COMMANDs.
        for (request, hash) in [
            (
                "07410108991007000020160605e0e000000000250243d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
                "b1e1115a6c47a750",
            ),
            (
                "07410108991007000020160605e0e000000000250244d011d1271d8080211001000010810600000000830600000000000a00000d00001000c0d0c1",
                "6b9a4755adf9bf7e",
            ),
        ] {
            let request = hex::decode(request).unwrap();
            assert_eq!(hex::encode(compute_hash_mme(&request)), hash);
        }
    }

    #[test]
    fn mapped_kamf_vectors() {
        let kasme = core::array::from_fn(|i| i as u8);
        let nh = core::array::from_fn(|i| (i + 32) as u8);
        assert_eq!(
            hex::encode(derive_mapped_kamf_idle(&kasme, 0x0012_3456)),
            "eb553a2dc491745c18c4d717b577e068485326c458a726838abe755f38666beb"
        );
        assert_eq!(
            hex::encode(derive_mapped_kamf_handover(&kasme, &nh)),
            "38d4b0135f82c7b44cf54c76232badc8ac02744ef43225ade981dcde7ca9ba8f"
        );
    }

    #[test]
    fn eps_kdf_annex_a_inputs() {
        let ck: [u8; 16] = core::array::from_fn(|i| i as u8);
        let ik: [u8; 16] = core::array::from_fn(|i| (i + 16) as u8);
        let kasme = derive_kasme(&ck, &ik, &[0x02, 0xf8, 0x39], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(
            hex::encode(kasme),
            "8a58509be1c244dc519dd5fbd4305f4192c782fe6ff79438d1fa7ff9740bbb30"
        );
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        assert_eq!(
            hex::encode(derive_nas_key(&key, 1, 2)),
            "7c3efee61cc2d3e6823c33d84f42c8734eb6379f81a769c754e9dc2534ff77b9"
        );
        assert_eq!(
            hex::encode(extract_128(&derive_nas_key(&key, 1, 2))),
            "4eb6379f81a769c754e9dc2534ff77b9"
        );
        assert_eq!(
            hex::encode(derive_kenb(&key, 258)),
            "5df775f16633b7e14575d47423c64d2062b6c8a5f10f3db6c234cbbf4dbe3237"
        );
        assert_eq!(
            hex::encode(derive_nh(&key, &key)),
            "7bf9464bc8eeb207517c813f7dbc0ab8e69a410bbfc42c44c98cc7ea8ae30c7b"
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&key, 42, 6300)),
            "f93166c8f78f1df39674bae749e42483fb6c7310aba47a0250b58a7fc1b50c20"
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&key, 42, 70000)),
            "3618729a2dc241123c1e08bc76aa2828bd3a1c67c6317116c53148c470bd33b2"
        );
    }

    #[test]
    fn eps_kdf_interworking_and_dual_connectivity_vectors() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let ck: [u8; 16] = key[..16].try_into().unwrap();
        let ik: [u8; 16] = key[16..].try_into().unwrap();
        let count = 0x0012_3456;
        assert_eq!(
            hex::encode(derive_ck_ik_handover(&key, count)),
            "242509d73fcf33220a4641e6a07cf18f02f948a95ee84355e0b9439b1d0dd700"
        );
        assert_eq!(
            hex::encode(derive_nas_token_full(&key, count)),
            "b3f915c1428ce3d0f49e8e89e84460bf6eb68f0a72859583864c2e8df79a0668"
        );
        assert_eq!(derive_nas_token(&key, count), [0x06, 0x68]);
        assert_eq!(
            hex::encode(derive_kasme_handover(&ck, &ik, 0x1234_5678)),
            "f0fdd0678c200d0bc94fe7073e9e5abc252b11be183d0274f29ee895457b6c56"
        );
        assert_eq!(
            hex::encode(derive_kasme_idle_mobility(
                &ck,
                &ik,
                0x0102_0304,
                0x1234_5678
            )),
            "28ada05dd47868ca359dda734d5169415cf262ee0ebba98a0b92227f7ed10c7b"
        );
        assert_eq!(
            hex::encode(derive_ck_ik_srvcc(&key, count)),
            "24535f189286e0669aba6fa001563ddba8fd203c24edc6fd4357202e648ce48b"
        );
        assert_eq!(
            hex::encode(derive_ck_ik_idle_mobility(&key, count)),
            "3f9fdf623b9b3a1dc45ca30206773a7a591d351f831f4b0abb60cea5493de3b8"
        );
        assert_eq!(
            hex::encode(derive_skenb(&key, 0x0123)),
            "33a14244121c11ee70d1ff64fecb9d25a92791587712f47d85e277e0260b9686"
        );
        assert_eq!(
            hex::encode(derive_lwip_psk(&key, 0x0123)),
            "b870389602b0611f4c63b886f434ef0b4fa53866b894e5fe3d2f1507d31d77bf"
        );
        assert_eq!(
            hex::encode(derive_kn(&key, &[0x01, 0x23], b"208930000000001")),
            "7e1c7c360af6f9c207fb595915b6ba3a2b682cd93ee988e1edf8ca64dd62b7c6"
        );
        assert_eq!(
            hex::encode(derive_skwt(&key, 0x0123)),
            "8f008e0d6d0e9fd9b179cb6bc1f2059e903c9d514818dcebd2b6027ff16f6944"
        );
        assert_eq!(
            hex::encode(derive_sgnb_algorithm_key(&key, 3, 2)),
            "0cef98c42f65403890b7ca3f20a52f8362e9c027277cfbcea25a0af641e7accf"
        );
        assert_eq!(
            hex::encode(derive_kenb(&key, u32::MAX)),
            "fe3156f5d68e325cb928061beace8637b064ce155ae1507fb5a44c4a08f19d69"
        );
    }
}
