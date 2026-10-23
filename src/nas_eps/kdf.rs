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

//! EPS key derivation per 3GPP TS 33.401 Annex A.

use super::keys::{
    AccessKey, CkPrime, CkSrvcc, IkPrime, IkSrvcc, KAsme, KEnb, KNasEnc, KNasInt, KRrcEnc, KRrcInt,
    KUpEnc, KUpInt, Kn, LwipPsk, NasToken, Nh, SKwt,
};
use crate::SecurityError;
use crate::common::input::{AccessKeyCount, CipheringAlgorithm, IntegrityAlgorithm, NasCount};
use crate::common::kdf::{checked_parameter, derive, derive_algorithm_key, kdf};
use crate::common::keys::{Autn, Ck, Ik};
use crate::common::wipe;
use crate::nas_5gs::KGnb;
use oxirush_utils::identity::Plmn;
use zeroize::Zeroizing;

/// FC of the algorithm key derivation function (TS 33.401 Annex A.7).
const FC_ALGORITHM_KEY: u8 = 0x15;

fn ck_ik(ck: &Ck, ik: &Ik) -> Zeroizing<[u8; 32]> {
    let mut key = Zeroizing::new([0u8; 32]);
    key[..16].copy_from_slice(ck.as_octets());
    key[16..].copy_from_slice(ik.as_octets());
    key
}

/// The two keys of 128 bits that 256 derived bits are: the most
/// significant half, then the least significant one.
fn halves(full: Zeroizing<[u8; 32]>) -> ([u8; 16], [u8; 16]) {
    let (first, second) = full.split_at(16);
    (
        first.try_into().expect("sixteen octets"),
        second.try_into().expect("sixteen octets"),
    )
}

/// Derive KASME from CK || IK, the serving network identity and the AUTN of
/// the authentication, whose SQN xor AK the derivation takes (TS 33.401
/// Annex A.2, FC=0x10).
///
/// ```
/// use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
/// use oxirush_security::nas_eps::derive_kasme;
/// use oxirush_security::{Plmn, Rand};
///
/// // The vector of the subscriber of TS 35.208 test set 1, in the network 208-93
/// # let octets = |s: &str| hex::decode(s).unwrap();
/// # let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
/// # let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
/// # let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
/// # let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607).unwrap(), Amf::new(&[0xb9, 0xb9]));
/// let vector = Milenage::new(&k, &opc).authentication_vector(&rand, &sqn, &amf);
/// let serving_network = Plmn::new("208", "93").unwrap();
/// let kasme = derive_kasme(vector.ck(), vector.ik(), serving_network, vector.autn());
/// let expected = "ba595c5419be71add1212bc8e1bd843afd26e58c0ad8d54f144686b5f55cda77";
/// assert_eq!(hex::encode(kasme.as_octets()), expected);
/// ```
pub fn derive_kasme(ck: &Ck, ik: &Ik, serving_network: Plmn, autn: &Autn) -> KAsme {
    wipe::derivation(|| {
        let sn_id = serving_network.to_nas_octets();
        let parameters: [&[u8]; 2] = [&sn_id, autn.sqn_xor_ak()];
        KAsme::new(&derive(ck_ik(ck, ik).as_ref(), 0x10, &parameters))
    })
}

/// Derive KeNB from KASME and the uplink NAS COUNT (Annex A.3, FC=0x11).
///
/// `ul_nas_count` is the uplink NAS COUNT of the message that started the
/// derivation, as a [`NasCount`]. At a handover from 5GS it is
/// [`AccessKeyCount::Handover`] (TS 33.501 §8.3.2).
///
/// ```
/// use oxirush_security::NasCount;
/// use oxirush_security::nas_eps::{KAsme, derive_kenb};
///
/// // The KASME of the example of `derive_kasme`, and the uplink NAS COUNT
/// // of the ATTACH REQUEST that set the context up
/// let kasme = "ba595c5419be71add1212bc8e1bd843afd26e58c0ad8d54f144686b5f55cda77";
/// let kasme = KAsme::from_slice(&hex::decode(kasme).unwrap()).unwrap();
/// let kenb = derive_kenb(&kasme, NasCount::ZERO);
/// let expected = "1221d2b558e3f2403b6115b5e103535f72c300cede7b330b7975d0da633eaa0e";
/// assert_eq!(hex::encode(kenb.as_octets()), expected);
/// ```
pub fn derive_kenb(kasme: &KAsme, ul_nas_count: impl Into<AccessKeyCount>) -> KEnb {
    wipe::derivation(|| {
        let count = ul_nas_count.into().get().to_be_bytes();
        KEnb::new(&derive(kasme.as_octets(), 0x11, &[&count]))
    })
}

/// Derive NH from KASME (Annex A.4, FC=0x12). `sync_input` is KeNB for the
/// first NH, and the NH before it for each one after.
pub fn derive_nh(kasme: &KAsme, sync_input: &impl AccessKey) -> Nh {
    wipe::derivation(|| Nh::new(&derive(kasme.as_octets(), 0x12, &[sync_input.key_octets()])))
}

/// Derive KeNB* for a target cell (Annex A.5, FC=0x13). The target eNB
/// takes it as its KeNB.
///
/// `base_key` is KeNB for horizontal derivation or NH for vertical derivation.
/// EARFCN-DL uses two octets through 65535 and three above that.
///
/// A `pci` above 503 or an `earfcn_dl` above 262143 is
/// [`SecurityError::OutOfRange`].
pub fn derive_kenb_star(
    base_key: &impl AccessKey,
    pci: u16,
    earfcn_dl: u32,
) -> Result<KEnb, SecurityError> {
    wipe::derivation(|| {
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
        let encoded_earfcn = if earfcn_dl <= 0xffff {
            &earfcn[2..]
        } else {
            &earfcn[1..]
        };
        let parameters: [&[u8]; 2] = [&pci.to_be_bytes(), encoded_earfcn];
        Ok(KEnb::new(&derive(base_key.key_octets(), 0x13, &parameters)))
    })
}

/// Derive KNASenc, the NAS ciphering key of `algorithm`, from KASME
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x01).
pub fn derive_knas_enc(kasme: &KAsme, algorithm: CipheringAlgorithm) -> KNasEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kasme.as_octets(), FC_ALGORITHM_KEY, 0x01, algorithm.into());
        KNasEnc::new(&key)
    })
}

/// Derive KNASint, the NAS integrity key of `algorithm`, from KASME
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x02).
pub fn derive_knas_int(kasme: &KAsme, algorithm: IntegrityAlgorithm) -> KNasInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kasme.as_octets(), FC_ALGORITHM_KEY, 0x02, algorithm.into());
        KNasInt::new(&key)
    })
}

/// Derive KRRCenc, the RRC ciphering key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x03).
///
/// The keys of an SgNB come from S-KgNB with the function of TS 33.501
/// (TS 33.401 Annex A.19): [`derive_skgnb`] gives it as the key that
/// [`nas_5gs::derive_krrc_enc`](crate::nas_5gs::derive_krrc_enc) and the
/// three beside it take.
pub fn derive_krrc_enc(kenb: &KEnb, algorithm: CipheringAlgorithm) -> KRrcEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kenb.as_octets(), FC_ALGORITHM_KEY, 0x03, algorithm.into());
        KRrcEnc::new(&key)
    })
}

/// Derive KRRCint, the RRC integrity key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x04).
pub fn derive_krrc_int(kenb: &KEnb, algorithm: IntegrityAlgorithm) -> KRrcInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kenb.as_octets(), FC_ALGORITHM_KEY, 0x04, algorithm.into());
        KRrcInt::new(&key)
    })
}

/// Derive KUPenc, the user plane ciphering key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x05).
pub fn derive_kup_enc(kenb: &KEnb, algorithm: CipheringAlgorithm) -> KUpEnc {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kenb.as_octets(), FC_ALGORITHM_KEY, 0x05, algorithm.into());
        KUpEnc::new(&key)
    })
}

/// Derive KUPint, the user plane integrity key of `algorithm`, from KeNB
/// (TS 33.401 Annex A.7, algorithm type distinguisher 0x06).
pub fn derive_kup_int(kenb: &KEnb, algorithm: IntegrityAlgorithm) -> KUpInt {
    wipe::derivation(|| {
        let key = derive_algorithm_key(kenb.as_octets(), FC_ALGORITHM_KEY, 0x06, algorithm.into());
        KUpInt::new(&key)
    })
}

/// Map KASME to CK' and IK' at handover (TS 33.401 Annex A.8, FC=0x16).
pub fn derive_ck_ik_handover(kasme: &KAsme, dl_nas_count: NasCount) -> (CkPrime, IkPrime) {
    wipe::derivation(|| {
        let count = dl_nas_count.get().to_be_bytes();
        let (ck, ik) = halves(Zeroizing::new(derive(kasme.as_octets(), 0x16, &[&count])));
        (CkPrime::new(&ck), IkPrime::new(&ik))
    })
}

/// Derive the NAS token of a mobility to UTRAN or GERAN (Annex A.9,
/// FC=0x17). [`NasToken::transmitted`] is the two octets that are sent.
pub fn derive_nas_token(kasme: &KAsme, ul_nas_count: NasCount) -> NasToken {
    wipe::derivation(|| {
        let count = ul_nas_count.get().to_be_bytes();
        NasToken::new(&derive(kasme.as_octets(), 0x17, &[&count]))
    })
}

/// Map CK || IK to K'ASME at handover (Annex A.10, FC=0x18).
pub fn derive_kasme_handover(ck: &Ck, ik: &Ik, nonce_mme: u32) -> KAsme {
    wipe::derivation(|| {
        let nonce = nonce_mme.to_be_bytes();
        KAsme::new(&derive(ck_ik(ck, ik).as_ref(), 0x18, &[&nonce]))
    })
}

/// Map CK || IK to K'ASME at idle mobility (Annex A.11, FC=0x19).
pub fn derive_kasme_idle_mobility(ck: &Ck, ik: &Ik, nonce_ue: u32, nonce_mme: u32) -> KAsme {
    wipe::derivation(|| {
        let parameters: [&[u8]; 2] = [&nonce_ue.to_be_bytes(), &nonce_mme.to_be_bytes()];
        KAsme::new(&derive(ck_ik(ck, ik).as_ref(), 0x19, &parameters))
    })
}

/// Derive CKSRVCC and IKSRVCC from KASME, or from the KASME_SRVCC that
/// [`nas_5gs::derive_kasme_srvcc`](crate::nas_5gs::derive_kasme_srvcc)
/// gives (Annex A.12, FC=0x1A).
pub fn derive_ck_ik_srvcc(kasme: &KAsme, dl_nas_count: NasCount) -> (CkSrvcc, IkSrvcc) {
    wipe::derivation(|| {
        let count = dl_nas_count.get().to_be_bytes();
        let (ck, ik) = halves(Zeroizing::new(derive(kasme.as_octets(), 0x1a, &[&count])));
        (CkSrvcc::new(&ck), IkSrvcc::new(&ik))
    })
}

/// Map KASME to CK' and IK' at idle mobility (Annex A.13, FC=0x1B).
pub fn derive_ck_ik_idle_mobility(kasme: &KAsme, ul_nas_count: NasCount) -> (CkPrime, IkPrime) {
    wipe::derivation(|| {
        let count = ul_nas_count.get().to_be_bytes();
        let (ck, ik) = halves(Zeroizing::new(derive(kasme.as_octets(), 0x1b, &[&count])));
        (CkPrime::new(&ck), IkPrime::new(&ik))
    })
}

/// Derive S-KeNB, the key of a secondary eNB, which takes it as its KeNB
/// (Annex A.15, FC=0x1C).
pub fn derive_skenb(kenb: &KEnb, scg_counter: u16) -> KEnb {
    wipe::derivation(|| {
        KEnb::new(&derive(
            kenb.as_octets(),
            0x1c,
            &[&scg_counter.to_be_bytes()],
        ))
    })
}

/// Derive S-KgNB, the key of a secondary gNB, which takes it as its KgNB:
/// the derivation of [`derive_skenb`] (Annex A.15, FC=0x1C).
pub fn derive_skgnb(kenb: &KEnb, scg_counter: u16) -> KGnb {
    wipe::derivation(|| {
        KGnb::new(&derive(
            kenb.as_octets(),
            0x1c,
            &[&scg_counter.to_be_bytes()],
        ))
    })
}

/// Derive LWIP-PSK for LTE/WLAN integration (Annex A.16, FC=0x1E).
pub fn derive_lwip_psk(kenb: &KEnb, lwip_counter: u16) -> LwipPsk {
    wipe::derivation(|| {
        LwipPsk::new(&derive(
            kenb.as_octets(),
            0x1e,
            &[&lwip_counter.to_be_bytes()],
        ))
    })
}

/// Derive K_n for IOPS subscriber key separation (Annex A.17, FC=0x1D).
/// `mk` is the master key, `f_n` the operator-proprietary f(n) value and
/// `imsi` its encoded IMSI.
///
/// An `f_n` or an `imsi` longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_kn(mk: &[u8], f_n: &[u8], imsi: &[u8]) -> Result<Kn, SecurityError> {
    wipe::derivation(|| {
        let (f_n, imsi) = (checked_parameter(f_n)?, checked_parameter(imsi)?);
        Ok(Kn::new(&derive(mk, 0x1d, &[f_n, imsi])))
    })
}

/// Derive S-KWT for LTE/WLAN aggregation (Annex A.18, FC=0x1F).
pub fn derive_skwt(kenb: &KEnb, wt_counter: u16) -> SKwt {
    wipe::derivation(|| {
        SKwt::new(&derive(
            kenb.as_octets(),
            0x1f,
            &[&wt_counter.to_be_bytes()],
        ))
    })
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
    use crate::common::kdf::{extract_128, kdf};

    fn count(value: u32) -> NasCount {
        NasCount::new(value).unwrap()
    }

    /// The octets 0, 1, 2 and so on.
    fn counting() -> [u8; 32] {
        core::array::from_fn(|index| index as u8)
    }

    /// TS 33.401 Annex A.7: the algorithm type distinguishers 0x01 to 0x06,
    /// each with the identity of its algorithm, and the 128 least
    /// significant bits of the output.
    #[test]
    fn algorithm_keys_use_the_distinguishers_of_annex_a_7() {
        let key = [0x5a; 32];
        let (kasme, kenb) = (KAsme::new(&key), KEnb::new(&key));
        let expected =
            |kind: u8, identity: u8| *extract_128(&kdf(&key, &[0x15, kind, 0, 1, identity, 0, 1]));
        for (identity, ciphering, integrity) in [
            (0, CipheringAlgorithm::EEA0, IntegrityAlgorithm::EIA0),
            (1, CipheringAlgorithm::EEA1, IntegrityAlgorithm::EIA1),
            (2, CipheringAlgorithm::EEA2, IntegrityAlgorithm::EIA2),
            (3, CipheringAlgorithm::EEA3, IntegrityAlgorithm::EIA3),
        ] {
            assert_eq!(derive_knas_enc(&kasme, ciphering), expected(0x01, identity));
            assert_eq!(derive_knas_int(&kasme, integrity), expected(0x02, identity));
            assert_eq!(derive_krrc_enc(&kenb, ciphering), expected(0x03, identity));
            assert_eq!(derive_krrc_int(&kenb, integrity), expected(0x04, identity));
            assert_eq!(derive_kup_enc(&kenb, ciphering), expected(0x05, identity));
            assert_eq!(derive_kup_int(&kenb, integrity), expected(0x06, identity));
        }
    }

    /// PCI up to 503 and EARFCN up to 262143 (TS 36.331 PhysCellId and
    /// ARFCN-ValueEUTRA-r9), and a parameter that fits the two-octet L.
    #[test]
    fn inputs_out_of_range_are_errors() {
        let key = KEnb::new(&[0x5a; 32]);
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
        assert!(derive_kn(&[0x5a; 32], &too_long, b"1").is_err());
        assert!(derive_kn(&[0x5a; 32], b"1", &too_long).is_err());
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
    fn eps_kdf_annex_a_inputs() {
        let ck = Ck::new(&core::array::from_fn(|i| i as u8));
        let ik = Ik::new(&core::array::from_fn(|i| (i + 16) as u8));
        // SQN xor AK, then the AMF field and the MAC, which are not taken
        let autn = Autn::new(&[1, 2, 3, 4, 5, 6, 0x80, 0, 9, 9, 9, 9, 9, 9, 9, 9]);
        // The SN id is the PLMN identity of the NAS messages, 02 f8 39
        let serving_network = Plmn::new("208", "93").unwrap();
        let kasme = derive_kasme(&ck, &ik, serving_network, &autn);
        assert_eq!(
            hex::encode(kasme.as_octets()),
            "8a58509be1c244dc519dd5fbd4305f4192c782fe6ff79438d1fa7ff9740bbb30"
        );
        let (kasme, kenb) = (KAsme::new(&counting()), KEnb::new(&counting()));
        assert_eq!(
            hex::encode(derive_knas_enc(&kasme, CipheringAlgorithm::EEA2).as_octets()),
            "4eb6379f81a769c754e9dc2534ff77b9"
        );
        assert_eq!(
            hex::encode(derive_kenb(&kasme, count(258)).as_octets()),
            "5df775f16633b7e14575d47423c64d2062b6c8a5f10f3db6c234cbbf4dbe3237"
        );
        assert_eq!(
            hex::encode(derive_nh(&kasme, &kenb).as_octets()),
            "7bf9464bc8eeb207517c813f7dbc0ab8e69a410bbfc42c44c98cc7ea8ae30c7b"
        );
        // The next NH comes from the one before it
        assert_eq!(
            derive_nh(&kasme, &Nh::new(&counting())),
            derive_nh(&kasme, &kenb)
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&kenb, 42, 6300).unwrap().as_octets()),
            "f93166c8f78f1df39674bae749e42483fb6c7310aba47a0250b58a7fc1b50c20"
        );
        assert_eq!(
            hex::encode(derive_kenb_star(&kenb, 42, 70000).unwrap().as_octets()),
            "3618729a2dc241123c1e08bc76aa2828bd3a1c67c6317116c53148c470bd33b2"
        );
    }

    /// The two keys of a pair, one after the other.
    fn pair<const N: usize>(first: &[u8; N], second: &[u8; N]) -> String {
        hex::encode(first) + &hex::encode(second)
    }

    #[test]
    fn eps_kdf_interworking_and_dual_connectivity_vectors() {
        let key = counting();
        let (kasme, kenb) = (KAsme::new(&key), KEnb::new(&key));
        let ck = Ck::from_slice(&key[..16]).unwrap();
        let ik = Ik::from_slice(&key[16..]).unwrap();
        let count = count(0x0012_3456);
        let (ck_prime, ik_prime) = derive_ck_ik_handover(&kasme, count);
        assert_eq!(
            pair(ck_prime.as_octets(), ik_prime.as_octets()),
            "242509d73fcf33220a4641e6a07cf18f02f948a95ee84355e0b9439b1d0dd700"
        );
        let token = derive_nas_token(&kasme, count);
        assert_eq!(
            hex::encode(token.as_octets()),
            "b3f915c1428ce3d0f49e8e89e84460bf6eb68f0a72859583864c2e8df79a0668"
        );
        assert_eq!(token.transmitted(), [0x06, 0x68]);
        assert_eq!(
            hex::encode(derive_kasme_handover(&ck, &ik, 0x1234_5678).as_octets()),
            "f0fdd0678c200d0bc94fe7073e9e5abc252b11be183d0274f29ee895457b6c56"
        );
        assert_eq!(
            hex::encode(derive_kasme_idle_mobility(&ck, &ik, 0x0102_0304, 0x1234_5678).as_octets()),
            "28ada05dd47868ca359dda734d5169415cf262ee0ebba98a0b92227f7ed10c7b"
        );
        let (ck_srvcc, ik_srvcc) = derive_ck_ik_srvcc(&kasme, count);
        assert_eq!(
            pair(ck_srvcc.as_octets(), ik_srvcc.as_octets()),
            "24535f189286e0669aba6fa001563ddba8fd203c24edc6fd4357202e648ce48b"
        );
        let (ck_prime, ik_prime) = derive_ck_ik_idle_mobility(&kasme, count);
        assert_eq!(
            pair(ck_prime.as_octets(), ik_prime.as_octets()),
            "3f9fdf623b9b3a1dc45ca30206773a7a591d351f831f4b0abb60cea5493de3b8"
        );
        assert_eq!(
            hex::encode(derive_skenb(&kenb, 0x0123).as_octets()),
            "33a14244121c11ee70d1ff64fecb9d25a92791587712f47d85e277e0260b9686"
        );
        assert_eq!(
            hex::encode(derive_lwip_psk(&kenb, 0x0123).as_octets()),
            "b870389602b0611f4c63b886f434ef0b4fa53866b894e5fe3d2f1507d31d77bf"
        );
        assert_eq!(
            hex::encode(
                derive_kn(&key, &[0x01, 0x23], b"208930000000001")
                    .unwrap()
                    .as_octets()
            ),
            "7e1c7c360af6f9c207fb595915b6ba3a2b682cd93ee988e1edf8ca64dd62b7c6"
        );
        assert_eq!(
            hex::encode(derive_skwt(&kenb, 0x0123).as_octets()),
            "8f008e0d6d0e9fd9b179cb6bc1f2059e903c9d514818dcebd2b6027ff16f6944"
        );
        // S-KgNB is derived as S-KeNB is, and is a key of an NR node: its
        // algorithm keys come from the function of TS 33.501 Annex A.8
        let skgnb = derive_skgnb(&kenb, 0x0123);
        assert_eq!(skgnb.as_octets(), derive_skenb(&kenb, 0x0123).as_octets());
        assert_eq!(
            hex::encode(
                crate::nas_5gs::derive_krrc_enc(
                    &crate::nas_5gs::KGnb::new(&key),
                    CipheringAlgorithm::NEA2
                )
                .as_octets()
            ),
            "62e9c027277cfbcea25a0af641e7accf"
        );
        assert_eq!(
            hex::encode(derive_kenb(&kasme, AccessKeyCount::Handover).as_octets()),
            "fe3156f5d68e325cb928061beace8637b064ce155ae1507fb5a44c4a08f19d69"
        );
    }
}
