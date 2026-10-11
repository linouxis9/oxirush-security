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

use crate::SecurityError;
use crate::common::input::{AccessKeyCount, CipheringAlgorithm, IntegrityAlgorithm, NasCount};
use crate::common::kdf::{checked_parameter, derive_algorithm_key, fixed_s, kdf};
use zeroize::Zeroizing;

/// FC of the algorithm key derivation function (TS 33.401 Annex A.7).
const FC_ALGORITHM_KEY: u8 = 0x15;

fn ck_ik(ck: &[u8; 16], ik: &[u8; 16]) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key[..16].copy_from_slice(ck);
    key[16..].copy_from_slice(ik);
    key
}

/// Derive KASME from CK || IK, serving network identity, and SQN XOR AK.
///
/// `sn_id` is the PLMN identity in the three octets that
/// [`plmn_to_bytes`](crate::plmn::plmn_to_bytes) gives.
/// TS 33.401 Annex A.2, FC=0x10.
pub fn derive_kasme(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_id: &[u8; 3],
    sqn_xor_ak: &[u8; 6],
) -> [u8; 32] {
    kdf(ck_ik(ck, ik).as_ref(), &fixed_s(0x10, &[sn_id, sqn_xor_ak]))
}

/// Derive KeNB from KASME and the uplink NAS COUNT (Annex A.3, FC=0x11).
///
/// `ul_nas_count` is the uplink NAS COUNT of the message that started the
/// derivation, as a [`NasCount`]. At a handover from 5GS it is
/// [`AccessKeyCount::Handover`] (TS 33.501 §8.3.2).
pub fn derive_kenb(kasme: &[u8; 32], ul_nas_count: impl Into<AccessKeyCount>) -> [u8; 32] {
    let count = ul_nas_count.into().get().to_be_bytes();
    kdf(kasme, &fixed_s(0x11, &[&count]))
}

/// Derive NH from KASME and KeNB or the previous NH (Annex A.4, FC=0x12).
pub fn derive_nh(kasme: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    kdf(kasme, &Zeroizing::new(fixed_s(0x12, &[sync_input])))
}

/// Derive KeNB* for a target cell (Annex A.5, FC=0x13).
///
/// `base_key` is KeNB for horizontal derivation or NH for vertical derivation.
/// EARFCN-DL uses two octets through 65535 and three above that.
///
/// A `pci` above 503 or an `earfcn_dl` above 262143 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kenb_star(
    base_key: &[u8; 32],
    pci: u16,
    earfcn_dl: u32,
) -> Result<[u8; 32], SecurityError> {
    if pci > 503 {
        return Err(SecurityError::OutOfRange {
            field: "E-UTRA PCI",
            maximum: 503,
            got: pci.into(),
        });
    }
    if earfcn_dl > 262_143 {
        return Err(SecurityError::OutOfRange {
            field: "EARFCN-DL",
            maximum: 262_143,
            got: earfcn_dl.into(),
        });
    }
    let earfcn = earfcn_dl.to_be_bytes();
    let encoded_earfcn = if earfcn_dl <= u16::MAX as u32 {
        &earfcn[2..]
    } else {
        &earfcn[1..]
    };
    Ok(kdf(
        base_key,
        &fixed_s(0x13, &[&pci.to_be_bytes(), encoded_earfcn]),
    ))
}

/// Derive KNASenc, the NAS ciphering key of `algorithm`, from KASME
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x01).
pub fn derive_knas_enc(kasme: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kasme, FC_ALGORITHM_KEY, 0x01, algorithm.into())
}

/// Derive KNASint, the NAS integrity key of `algorithm`, from KASME
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x02).
pub fn derive_knas_int(kasme: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kasme, FC_ALGORITHM_KEY, 0x02, algorithm.into())
}

/// Derive KRRCenc, the RRC ciphering key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x03).
///
/// The keys of an SgNB come from S-KgNB with the function of TS 33.501
/// (TS 33.401 Annex A.19): use
/// [`nas_5gs::derive_krrc_enc`](crate::nas_5gs::derive_krrc_enc) and the
/// three beside it for those.
pub fn derive_krrc_enc(kenb: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kenb, FC_ALGORITHM_KEY, 0x03, algorithm.into())
}

/// Derive KRRCint, the RRC integrity key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x04).
pub fn derive_krrc_int(kenb: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kenb, FC_ALGORITHM_KEY, 0x04, algorithm.into())
}

/// Derive KUPenc, the user plane ciphering key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x05).
pub fn derive_kup_enc(kenb: &[u8; 32], algorithm: CipheringAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kenb, FC_ALGORITHM_KEY, 0x05, algorithm.into())
}

/// Derive KUPint, the user plane integrity key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x06).
pub fn derive_kup_int(kenb: &[u8; 32], algorithm: IntegrityAlgorithm) -> [u8; 16] {
    derive_algorithm_key(kenb, FC_ALGORITHM_KEY, 0x06, algorithm.into())
}

/// Map KASME to CK' || IK' at handover (TS 33.401 Annex A.8, FC=0x16).
pub fn derive_ck_ik_handover(kasme: &[u8; 32], dl_nas_count: NasCount) -> [u8; 32] {
    kdf(kasme, &fixed_s(0x16, &[&dl_nas_count.get().to_be_bytes()]))
}

/// Derive the full NAS token KDF output (Annex A.9, FC=0x17).
/// The two least significant octets are sent on the wire.
pub fn derive_nas_token_full(kasme: &[u8; 32], ul_nas_count: NasCount) -> [u8; 32] {
    kdf(kasme, &fixed_s(0x17, &[&ul_nas_count.get().to_be_bytes()]))
}

/// Derive the two-octet NAS token transmitted during inter-RAT mobility.
pub fn derive_nas_token(kasme: &[u8; 32], ul_nas_count: NasCount) -> [u8; 2] {
    let full = derive_nas_token_full(kasme, ul_nas_count);
    [full[30], full[31]]
}

/// Map CK || IK to K'ASME at handover (Annex A.10, FC=0x18).
pub fn derive_kasme_handover(ck: &[u8; 16], ik: &[u8; 16], nonce_mme: u32) -> [u8; 32] {
    kdf(
        ck_ik(ck, ik).as_ref(),
        &fixed_s(0x18, &[&nonce_mme.to_be_bytes()]),
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
        &fixed_s(0x19, &[&nonce_ue.to_be_bytes(), &nonce_mme.to_be_bytes()]),
    )
}

/// Derive CKSRVCC || IKSRVCC from KASME or KASME_SRVCC (Annex A.12, FC=0x1A).
pub fn derive_ck_ik_srvcc(kasme: &[u8; 32], dl_nas_count: NasCount) -> [u8; 32] {
    kdf(kasme, &fixed_s(0x1a, &[&dl_nas_count.get().to_be_bytes()]))
}

/// Map KASME to CK' || IK' at idle mobility (Annex A.13, FC=0x1B).
pub fn derive_ck_ik_idle_mobility(kasme: &[u8; 32], ul_nas_count: NasCount) -> [u8; 32] {
    kdf(kasme, &fixed_s(0x1b, &[&ul_nas_count.get().to_be_bytes()]))
}

/// Derive S-KeNB or S-KgNB for dual connectivity (Annex A.15, FC=0x1C).
pub fn derive_skenb(kenb: &[u8; 32], scg_counter: u16) -> [u8; 32] {
    kdf(kenb, &fixed_s(0x1c, &[&scg_counter.to_be_bytes()]))
}

/// Derive LWIP-PSK for LTE/WLAN integration (Annex A.16, FC=0x1E).
pub fn derive_lwip_psk(kenb: &[u8; 32], lwip_counter: u16) -> [u8; 32] {
    kdf(kenb, &fixed_s(0x1e, &[&lwip_counter.to_be_bytes()]))
}

/// Derive K_n for IOPS subscriber key separation (Annex A.17, FC=0x1D).
/// `f_n` is the operator-proprietary f(n) value; `imsi` is its encoded IMSI.
///
/// An `f_n` or an `imsi` longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kn(mk: &[u8], f_n: &[u8], imsi: &[u8]) -> Result<[u8; 32], SecurityError> {
    let s = fixed_s(0x1d, &[checked_parameter(f_n)?, checked_parameter(imsi)?]);
    Ok(kdf(mk, &s))
}

/// Derive S-KWT for LTE/WLAN aggregation (Annex A.18, FC=0x1F).
pub fn derive_skwt(kenb: &[u8; 32], wt_counter: u16) -> [u8; 32] {
    kdf(kenb, &fixed_s(0x1f, &[&wt_counter.to_be_bytes()]))
}

/// Map KASME to KAMF for idle EPS to 5GS mobility (TS 33.501 Annex A.15, FC=0x75).
/// The new 5GS NAS COUNTs start at zero after the context is installed.
pub fn derive_mapped_kamf_idle(kasme: &[u8; 32], tau_ul_nas_count: NasCount) -> [u8; 32] {
    kdf(
        kasme,
        &fixed_s(0x75, &[&tau_ul_nas_count.get().to_be_bytes()]),
    )
}

/// Map KASME to KAMF for connected EPS to 5GS handover (Annex A.15, FC=0x76).
pub fn derive_mapped_kamf_handover(kasme: &[u8; 32], nh: &[u8; 32]) -> [u8; 32] {
    kdf(kasme, &Zeroizing::new(fixed_s(0x76, &[nh])))
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

    fn count(value: u32) -> NasCount {
        NasCount::new(value).unwrap()
    }

    /// TS 33.401 Annex A.7: the algorithm type distinguishers 0x01 to 0x06,
    /// each with the identity of its algorithm, and the 128 least
    /// significant bits of the output.
    #[test]
    fn algorithm_keys_use_the_distinguishers_of_annex_a_7() {
        let key = [0x5a; 32];
        let expected =
            |kind: u8, identity: u8| extract_128(&kdf(&key, &[0x15, kind, 0, 1, identity, 0, 1]));
        for (identity, ciphering, integrity) in [
            (0, CipheringAlgorithm::EEA0, IntegrityAlgorithm::EIA0),
            (1, CipheringAlgorithm::EEA1, IntegrityAlgorithm::EIA1),
            (2, CipheringAlgorithm::EEA2, IntegrityAlgorithm::EIA2),
            (3, CipheringAlgorithm::EEA3, IntegrityAlgorithm::EIA3),
        ] {
            assert_eq!(derive_knas_enc(&key, ciphering), expected(0x01, identity));
            assert_eq!(derive_knas_int(&key, integrity), expected(0x02, identity));
            assert_eq!(derive_krrc_enc(&key, ciphering), expected(0x03, identity));
            assert_eq!(derive_krrc_int(&key, integrity), expected(0x04, identity));
            assert_eq!(derive_kup_enc(&key, ciphering), expected(0x05, identity));
            assert_eq!(derive_kup_int(&key, integrity), expected(0x06, identity));
        }
    }

    /// PCI up to 503 and EARFCN up to 262143 (TS 36.331 PhysCellId and
    /// ARFCN-ValueEUTRA-r9), and a parameter that fits the two-octet L.
    #[test]
    fn inputs_out_of_range_are_errors() {
        let key = [0x5a; 32];
        assert!(derive_kenb_star(&key, 503, 262_143).is_ok());
        assert_eq!(
            derive_kenb_star(&key, 504, 0),
            Err(SecurityError::OutOfRange {
                field: "E-UTRA PCI",
                maximum: 503,
                got: 504
            })
        );
        assert_eq!(
            derive_kenb_star(&key, 0, 262_144),
            Err(SecurityError::OutOfRange {
                field: "EARFCN-DL",
                maximum: 262_143,
                got: 262_144
            })
        );
        let too_long = vec![0; 65536];
        assert!(derive_kn(&key, &too_long, b"1").is_err());
        assert!(derive_kn(&key, b"1", &too_long).is_err());
    }

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
            hex::encode(derive_mapped_kamf_idle(&kasme, count(0x0012_3456))),
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
            hex::encode(derive_knas_enc(&key, CipheringAlgorithm::EEA2)),
            "4eb6379f81a769c754e9dc2534ff77b9"
        );
        assert_eq!(
            hex::encode(derive_kenb(&key, count(258))),
            "5df775f16633b7e14575d47423c64d2062b6c8a5f10f3db6c234cbbf4dbe3237"
        );
        assert_eq!(
            hex::encode(derive_nh(&key, &key)),
            "7bf9464bc8eeb207517c813f7dbc0ab8e69a410bbfc42c44c98cc7ea8ae30c7b"
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&key, 42, 6300).unwrap()),
            "f93166c8f78f1df39674bae749e42483fb6c7310aba47a0250b58a7fc1b50c20"
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&key, 42, 70000).unwrap()),
            "3618729a2dc241123c1e08bc76aa2828bd3a1c67c6317116c53148c470bd33b2"
        );
    }

    #[test]
    fn eps_kdf_interworking_and_dual_connectivity_vectors() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let ck: [u8; 16] = key[..16].try_into().unwrap();
        let ik: [u8; 16] = key[16..].try_into().unwrap();
        let count = count(0x0012_3456);
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
            hex::encode(derive_kn(&key, &[0x01, 0x23], b"208930000000001").unwrap()),
            "7e1c7c360af6f9c207fb595915b6ba3a2b682cd93ee988e1edf8ca64dd62b7c6"
        );
        assert_eq!(
            hex::encode(derive_skwt(&key, 0x0123)),
            "8f008e0d6d0e9fd9b179cb6bc1f2059e903c9d514818dcebd2b6027ff16f6944"
        );
        // An SgNB key, from S-KgNB with the function of TS 33.501 Annex A.8
        assert_eq!(
            hex::encode(crate::nas_5gs::derive_krrc_enc(
                &key,
                CipheringAlgorithm::NEA2
            )),
            "62e9c027277cfbcea25a0af641e7accf"
        );
        assert_eq!(
            hex::encode(derive_kenb(&key, AccessKeyCount::Handover)),
            "fe3156f5d68e325cb928061beace8637b064ce155ae1507fb5a44c4a08f19d69"
        );
    }
}
