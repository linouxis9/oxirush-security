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

//! The keys of EAP-AKA' (RFC 9048, which obsoletes RFC 5448), the method of
//! the primary authentication of 5GS beside 5G AKA (TS 33.501 §6.1.3.1 and
//! Annex F): CK' and IK' of the access network's name, then the keys that
//! PRF' derives of them and of the peer's identity, whose EMSK gives KAUSF.
//!
//! ```
//! use oxirush_security::eap_aka_prime::{Keys, derive_ck_ik_prime};
//! use oxirush_security::{Autn, Ck, Ik};
//! # let octets = |s: &str| hex::decode(s).unwrap();
//! // RFC 9048 Appendix D, case 1: test set 19 of TS 35.208.
//! let ck = Ck::from_slice(&octets("5349fbe098649f948f5d2e973a81c00f")).unwrap();
//! let ik = Ik::from_slice(&octets("9744871ad32bf9bbd1dd5ce54e3e2e5a")).unwrap();
//! let autn = Autn::from_slice(&octets("bb52e91c747ac3ab2a5c23d15ee351d5")).unwrap();
//! let (ck_prime, ik_prime) = derive_ck_ik_prime(&ck, &ik, b"WLAN", &autn).unwrap();
//! let keys = Keys::derive(&ck_prime, &ik_prime, b"0555444333222111");
//! let k_aut = "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea";
//! assert_eq!(hex::encode(keys.k_aut().as_octets()), k_aut);
//! // KAUSF is the first 256 bits of the EMSK (TS 33.501 Annex F).
//! assert_eq!(keys.kausf().as_octets()[..], keys.emsk().as_octets()[..32]);
//! ```

use zeroize::Zeroizing;

use crate::common::error::SecurityError;
use crate::common::kdf::{checked_parameter, derive};
use crate::common::keys::{Autn, Ck, Ik, key};
use crate::common::wipe;
use crate::nas_5gs::KAusf;

key! {
    /// CK', the ciphering key of AKA bound to the access network's name
    /// (RFC 9048 §3.3).
    CkPrime, 16
}
key! {
    /// IK', the integrity key of AKA bound to the access network's name
    /// (RFC 9048 §3.3).
    IkPrime, 16
}
key! {
    /// K_encr, the key of AT_ENCR_DATA (RFC 9048 §3.3).
    KEncr, 16
}
key! {
    /// K_aut, the key of AT_MAC (RFC 9048 §3.3).
    KAut, 32
}
key! {
    /// K_re, the key of fast re-authentication (RFC 9048 §3.3).
    KRe, 32
}
key! {
    /// MSK, the Master Session Key (RFC 9048 §3.3).
    Msk, 64
}
key! {
    /// EMSK, the Extended Master Session Key (RFC 9048 §3.3).
    Emsk, 64
}

/// FC of the derivation of CK' and IK' (TS 33.402 Annex A.2).
const FC: u8 = 0x20;

/// The octets of the keys that PRF' gives: K_encr, K_aut, K_re, MSK and
/// EMSK, in this order (RFC 9048 §3.3), of seven blocks of HMAC-SHA-256.
const KEYING: usize = 16 + 32 + 32 + 64 + 64;
const BLOCKS: usize = KEYING.div_ceil(32);

/// CK' and IK' of an authentication vector's CK, IK and AUTN for the
/// access network `network_name` (RFC 9048 §3.3; TS 33.402 Annex A.2): the
/// KDF of CK || IK with FC 0x20, the network name and SQN xor AK; CK' is the
/// first 128 bits of its output, IK' the last.
///
/// A network name longer than 65535 octets is
/// [`SecurityError::InputTooLong`].
pub fn derive_ck_ik_prime(
    ck: &Ck,
    ik: &Ik,
    network_name: &[u8],
    autn: &Autn,
) -> Result<(CkPrime, IkPrime), SecurityError> {
    wipe::derivation(|| {
        let network_name = checked_parameter(network_name)?;
        let mut key = Zeroizing::new([0; 32]);
        key[..16].copy_from_slice(ck.as_octets());
        key[16..].copy_from_slice(ik.as_octets());
        let output = Zeroizing::new(derive(&key[..], FC, &[network_name, autn.sqn_xor_ak()]));
        let (ck_prime, ik_prime) = output.split_at(16);
        Ok((
            CkPrime::from_slice(ck_prime)?,
            IkPrime::from_slice(ik_prime)?,
        ))
    })
}

/// The keys of a full authentication with EAP-AKA' (RFC 9048 §3.3): MK =
/// PRF'(IK' | CK', "EAP-AKA'" | Identity), cut into K_encr, K_aut, K_re, MSK
/// and EMSK.
pub struct Keys {
    k_encr: KEncr,
    k_aut: KAut,
    k_re: KRe,
    msk: Msk,
    emsk: Emsk,
}

impl Keys {
    /// The keys of CK' and IK' for the peer `identity`, as the
    /// EAP-Response/Identity or AT_IDENTITY gave it; in 5GS, the SUPI (TS
    /// 33.501 Annex F). PRF'(K, S) is T1 | T2 | ..., Tn = HMAC-SHA-256(K,
    /// Tn-1 | S | n) (RFC 9048 §3.4.1).
    pub fn derive(ck_prime: &CkPrime, ik_prime: &IkPrime, identity: &[u8]) -> Self {
        wipe::derivation(|| {
            let mut key = Zeroizing::new([0; 32]);
            key[..16].copy_from_slice(ik_prime.as_octets());
            key[16..].copy_from_slice(ck_prime.as_octets());
            let mut output = Zeroizing::new([0; BLOCKS * 32]);
            for block in 0..BLOCKS {
                let (before, rest) = output.split_at_mut(block * 32);
                let previous = before.get(before.len().saturating_sub(32)..).unwrap_or(&[]);
                let t = Zeroizing::new(crate::common::sha256::hmac_sha256_of(&key[..], |hmac| {
                    use sha2::Digest;
                    hmac.update(previous);
                    hmac.update(b"EAP-AKA'");
                    hmac.update(identity);
                    hmac.update([block as u8 + 1]);
                }));
                rest[..32].copy_from_slice(&t[..]);
            }
            let (k_encr, rest) = output.split_at(16);
            let (k_aut, rest) = rest.split_at(32);
            let (k_re, rest) = rest.split_at(32);
            let (msk, rest) = rest.split_at(64);
            let emsk = &rest[..64];
            Self {
                k_encr: KEncr::new(k_encr.try_into().expect("16 octets")),
                k_aut: KAut::new(k_aut.try_into().expect("32 octets")),
                k_re: KRe::new(k_re.try_into().expect("32 octets")),
                msk: Msk::new(msk.try_into().expect("64 octets")),
                emsk: Emsk::new(emsk.try_into().expect("64 octets")),
            }
        })
    }

    /// K_encr.
    pub fn k_encr(&self) -> &KEncr {
        &self.k_encr
    }

    /// K_aut.
    pub fn k_aut(&self) -> &KAut {
        &self.k_aut
    }

    /// K_re.
    pub fn k_re(&self) -> &KRe {
        &self.k_re
    }

    /// The MSK.
    pub fn msk(&self) -> &Msk {
        &self.msk
    }

    /// The EMSK.
    pub fn emsk(&self) -> &Emsk {
        &self.emsk
    }

    /// KAUSF: the 256 most significant bits of the EMSK (TS 33.501 Annex
    /// F).
    pub fn kausf(&self) -> KAusf {
        KAusf::new(self.emsk.as_octets()[..32].try_into().expect("32 octets"))
    }
}

impl core::fmt::Debug for Keys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Keys(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn octets(text: &str) -> Vec<u8> {
        hex::decode(text.replace(' ', "")).unwrap()
    }

    /// The four cases of RFC 9048 Appendix D: the identity
    /// "0555444333222111", the network names "WLAN" and "HRPD", the AKA of
    /// test set 19 of TS 35.208 and artificial values.
    #[test]
    fn the_keys_of_the_test_vectors_of_rfc_9048() {
        let identity = b"0555444333222111";
        let aka_19 = (
            "81e92b6c0ee0e12ebceba8d92a99dfa5",
            "bb52e91c747ac3ab2a5c23d15ee351d5",
            "9744871ad32bf9bbd1dd5ce54e3e2e5a",
            "5349fbe098649f948f5d2e973a81c00f",
        );
        let artificial = (
            "e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0",
            "a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0",
            "b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0",
            "c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0",
        );
        // Network name, (RAND, AUTN, IK, CK), then CK', IK', K_encr, K_aut,
        // K_re, MSK and EMSK.
        let cases = [
            (
                "WLAN",
                aka_19,
                [
                    "0093 962d 0dd8 4aa5 684b 045c 9edf fa04",
                    "ccfc 230c a74f cc96 c0a5 d611 64f5 a76c",
                    "766f a0a6 c317 174b 812d 52fb cd11 a179",
                    "0842 ea72 2ff6 835b fa20 3249 9fc3 ec23 c2f0 e388 b4f0 7543 ffc6 77f1 696d 71ea",
                    "cf83 aa8b c7e0 aced 892a cc98 e76a 9b20 95b5 58c7 795c 7094 715c b339 3aa7 d17a",
                    "67c4 2d9a a56c 1b79 e295 e345 9fc3 d187 d42b e0bf 818d 3070 e362 c5e9 67a4 d544 \
                     e8ec fe19 358a b303 9aff 03b7 c930 588c 055b abee 58a0 2650 b067 ec4e 9347 c75a",
                    "f861 703c d775 590e 16c7 679e a387 4ada 8663 11de 2907 64d7 60cf 76df 647e a01c \
                     313f 6992 4bdd 7650 ca9b ac14 1ea0 75c4 ef9e 8029 c0e2 90cd bad5 638b 63bc 23fb",
                ],
            ),
            (
                "HRPD",
                aka_19,
                [
                    "3820 f027 7fa5 f777 32b1 fb1d 90c1 a0da",
                    "db94 a0ab 557e f6c9 ab48 619c a05b 9a9f",
                    "05ad 73ac 915f ce89 ac77 e152 0d82 187b",
                    "5b4a caef 62c6 ebb8 882b 2f3d 534c 4b35 2773 37a0 0184 f20f f25d 224c 04be 2afd",
                    "3f90 bf5c 6e5e f325 ff04 eb5e f653 9fa8 cca8 3981 94fb d00b e425 b3f4 0dba 10ac",
                    "87b3 2157 0117 cd6c 95ab 6c43 6fb5 073f f15c f855 05d2 bc5b b735 5fc2 1ea8 a757 \
                     57e8 f86a 2b13 8002 e057 5291 3bb4 3b82 f868 a961 17e9 1a2d 95f5 2667 7d57 2900",
                    "c891 d5f2 0f14 8a10 0755 3e2d ea55 5c9c b672 e967 5f4a 66b4 bafa 0273 79f9 3aee \
                     539a 5979 d0a0 042b 9d2a e28b ed3b 17a3 1dc8 ab75 072b 80bd 0c1d a612 466e 402c",
                ],
            ),
            (
                "WLAN",
                artificial,
                [
                    "cd4c 8e5c 68f5 7dd1 d7d7 dfd0 c538 e577",
                    "3ece 6b70 5dbb f7df c459 a112 80c6 5524",
                    "897d 302f a284 7416 488c 28e2 0dcb 7be4",
                    "c407 00e7 7224 83ae 3dc7 139e b0b8 8bb5 58cb 3081 eccd 057f 9207 d128 6ee7 dd53",
                    "0a59 1a22 dd8b 5b1c f29e 3d50 8c91 dbbd b4ae e230 5189 2c42 b6a2 de66 ea50 4473",
                    "9f7d ca9e 37bb 2202 9ed9 86e7 cd09 d4a7 0d1a c76d 9553 5c5c ac40 a750 4699 bb89 \
                     61a2 9ef6 f3e9 0f18 3de5 861a d1be dc81 ce99 1639 1b40 1aa0 06c9 8785 a575 6df7",
                    "724d e00b db9e 5681 87be 3fe7 4611 4557 d501 8779 537e e37f 4d3c 6c73 8cb9 7b9d \
                     c651 bc19 bfad c344 ffe2 b52c a78b d831 6b51 dacc 5f2b 1440 cb95 1552 1cc7 ba23",
                ],
            ),
            (
                "HRPD",
                artificial,
                [
                    "8310 a71c e6f7 5488 9613 da8f 64d5 fb46",
                    "5adf 1436 0ae8 3819 2db2 3f6f cb7f 8c76",
                    "745e 7439 ba23 8f50 fcac 4d15 d47c d1d9",
                    "3e1d 2aa4 e677 025c fd86 2a4b e183 61a1 3a64 5765 5714 63df 833a 9759 e809 9879",
                    "99da 835e 2ae8 2462 576f e651 6fad 1f80 2f0f a119 1655 dd0a 273d a96d 04e0 fcd3",
                    "c6d3 a6e0 ceea 951e b20d 74f3 2c30 61d0 680a 04b0 b086 ee87 00ac e3e0 b95f a026 \
                     83c2 87be ee44 4322 94ff 98af 26d2 cc78 3bac e75c 4b0a f7fd feb5 511b a8e4 cbd0",
                    "7fb5 6813 838a dafa 99d1 40c2 f198 f6da cebf b6af ee44 4961 1054 02b5 08c7 f363 \
                     352c b291 9644 b504 63e6 a693 5415 0147 ae09 cbc5 4b8a 651d 8787 a689 3ed8 536d",
                ],
            ),
        ];
        for (name, (_rand, autn, ik, ck), expected) in cases {
            let ck = Ck::from_slice(&octets(ck)).unwrap();
            let ik = Ik::from_slice(&octets(ik)).unwrap();
            let autn = Autn::from_slice(&octets(autn)).unwrap();
            let (ck_prime, ik_prime) =
                derive_ck_ik_prime(&ck, &ik, name.as_bytes(), &autn).unwrap();
            let keys = Keys::derive(&ck_prime, &ik_prime, identity);
            let derived: [&[u8]; 7] = [
                ck_prime.as_octets(),
                ik_prime.as_octets(),
                keys.k_encr().as_octets(),
                keys.k_aut().as_octets(),
                keys.k_re().as_octets(),
                keys.msk().as_octets(),
                keys.emsk().as_octets(),
            ];
            for (at, (derived, expected)) in derived.iter().zip(expected).enumerate() {
                assert_eq!(*derived, octets(expected), "{name}, key {at}");
            }
            assert_eq!(keys.kausf().as_octets()[..], octets(expected[6])[..32]);
        }
    }

    /// A network name that a KDF parameter cannot hold is refused.
    #[test]
    fn a_network_name_longer_than_a_parameter_is_refused() {
        let (ck, ik, autn) = (Ck::new(&[0; 16]), Ik::new(&[0; 16]), Autn::new(&[0; 16]));
        let name = [0; 65536];
        assert!(matches!(
            derive_ck_ik_prime(&ck, &ik, &name, &autn),
            Err(SecurityError::InputTooLong { .. })
        ));
    }
}
