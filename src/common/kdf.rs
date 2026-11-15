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

//! Shared 3GPP TS 33.220 Annex B.2 HMAC-SHA-256 KDF framing.

use crate::common::error::SecurityError;
use crate::common::wipe;
use zeroize::Zeroizing;

/// Longest KDF parameter: its length field L has two octets.
const MAXIMUM_PARAMETER: usize = u16::MAX as usize;

/// The KDF of TS 33.220 Annex B.2: HMAC-SHA-256(key, S), where S is FC,
/// then each parameter with its length after it. `build_s` lays it out,
/// with the `alloc` feature.
///
/// The 256 bits are a key, of a kind that the crate does not know: they
/// are wiped when the value is dropped, and `*` gives the array. The HMAC
/// state is wiped on return.
pub fn kdf(key: &[u8], s: &[u8]) -> Zeroizing<[u8; 32]> {
    wipe::derivation(|| Zeroizing::new(super::sha256::hmac_sha256(key, s)))
}

/// Build the S parameter: FC || (P_i || L_i)*.
///
/// A parameter longer than 65535 octets, which the two-octet L cannot
/// express, is [`SecurityError::InputTooLong`].
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub fn build_s(fc: u8, params: &[&[u8]]) -> Result<alloc::vec::Vec<u8>, SecurityError> {
    // Exact capacity: the vector never reallocates, so a caller that wipes
    // S leaves no copy of a key parameter in freed memory.
    let mut s =
        alloc::vec::Vec::with_capacity(1 + params.iter().map(|p| p.len() + 2).sum::<usize>());
    s.push(fc);
    for parameter in params {
        s.extend_from_slice(checked_parameter(parameter)?);
        s.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
    }
    Ok(s)
}

/// A KDF parameter, or the error for one longer than its L can express.
pub(crate) fn checked_parameter(parameter: &[u8]) -> Result<&[u8], SecurityError> {
    if parameter.len() > MAXIMUM_PARAMETER {
        Err(SecurityError::InputTooLong {
            maximum: MAXIMUM_PARAMETER,
            got: parameter.len(),
        })
    } else {
        Ok(parameter)
    }
}

/// The key that `key` and the S of `fc` and `params` give: HMAC-SHA-256 of
/// FC || (P_i || L_i)*, which goes to the hasher part after part. S is
/// never in memory, on the heap or elsewhere: a parameter that is a key
/// has no copy to wipe.
///
/// The parameters are known to fit their L: arrays, and slices that went
/// through [`checked_parameter`].
pub(crate) fn derive(key: &[u8], fc: u8, params: &[&[u8]]) -> [u8; 32] {
    use sha2::Digest;
    super::sha256::hmac_sha256_of(key, |s| {
        s.update([fc]);
        for parameter in params {
            debug_assert!(parameter.len() <= MAXIMUM_PARAMETER);
            s.update(parameter);
            s.update((parameter.len() as u16).to_be_bytes());
        }
    })
}

/// Derive a 128-bit algorithm key with the parameter layout that TS 33.501
/// Annex A.8 and TS 33.401 Annex A.7 share: the algorithm type
/// distinguisher, then the algorithm identity. The key is the 128 least
/// significant bits of the 256 derived.
pub(crate) fn algorithm_key(key: &[u8; 32], fc: u8, algo_type: u8, algo_id: u8) -> [u8; 16] {
    let mut full = derive(key, fc, &[&[algo_type], &[algo_id]]);
    let algorithm_key = low_128(&full);
    zeroize::Zeroize::zeroize(&mut full);
    algorithm_key
}

/// The key of an algorithm that `key` gives (TS 33.501 Annex A.8 and A.9,
/// TS 33.401 Annex A.7): the KDF of the FC `fc`, 0x69 of KAMF, KgNB or KSN
/// and 0x15 of KASME or KeNB, of the algorithm type distinguisher
/// `algorithm_type` (0x01 for NAS ciphering to 0x06 for UP integrity), then
/// of the identity `algorithm`. The key is the 128 least significant bits of
/// the 256 derived, wiped when the value is dropped.
///
/// The two numbers are taken as they are, for a key that the typed
/// derivations, such as [`nas_5gs::derive_knas_int`](crate::nas_5gs::derive_knas_int),
/// do not give: that of an identity that names no algorithm among them.
///
/// ```
/// use oxirush_security::kdf::derive_algorithm_key;
/// use oxirush_security::identity::Algorithm;
/// use oxirush_security::nas_5gs::{KAmf, derive_knas_int};
///
/// let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
/// let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();
/// // KNASint of 128-NIA2: the type distinguisher 0x02, the identity 2
/// let key = derive_algorithm_key(&k_amf, 0x69, 0x02, 2);
/// assert_eq!(hex::encode(*key), "28ddb5356880149b9fee22f2367522a4");
/// assert_eq!(*key, *derive_knas_int(&KAmf::new(&k_amf), Algorithm::Aes).as_octets());
/// ```
pub fn derive_algorithm_key(
    key: &[u8; 32],
    fc: u8,
    algorithm_type: u8,
    algorithm: u8,
) -> Zeroizing<[u8; 16]> {
    wipe::derivation(|| Zeroizing::new(algorithm_key(key, fc, algorithm_type, algorithm)))
}

/// The 128 least significant bits of the 256 of a KDF output, which is
/// how the algorithm keys are taken from it (TS 33.501 Annex A.8,
/// TS 33.401 Annex A.7). They are wiped when the value is dropped.
pub fn extract_128(full: &[u8; 32]) -> Zeroizing<[u8; 16]> {
    wipe::words(|| Zeroizing::new(low_128(full)))
}

/// The 128 least significant bits of 256.
pub(crate) fn low_128(full: &[u8; 32]) -> [u8; 16] {
    let mut key = [0; 16];
    key.copy_from_slice(&full[16..]);
    key
}

#[cfg(all(test, feature = "alloc"))]
mod tests {
    use super::*;

    /// TS 33.220 Annex B.2: S = FC || P0 || L0 || P1 || L1, each L the
    /// two-octet length of its P.
    #[test]
    fn s_is_the_fc_then_each_parameter_and_its_length() {
        assert_eq!(
            build_s(0x6a, &[b"ab", &[], &[0xff; 3]]),
            Ok(vec![
                0x6a, b'a', b'b', 0x00, 0x02, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x03
            ])
        );
        assert_eq!(build_s(0x10, &[]), Ok(vec![0x10]));
    }

    /// The derivations give the hasher FC and the parameters part after
    /// part: the key is that of the S that `build_s` lays out.
    #[test]
    fn a_key_is_derived_from_s_without_s_in_memory() {
        let key = [0x4b; 32];
        let long = vec![0xa5; 300];
        let sets: [&[&[u8]]; 5] = [
            &[],
            &[&[]],
            &[b"5G:mnc093.mcc208.3gppnetwork.org", &[0x55; 6]],
            &[&[0x01], &[0x02], &[], &[0x03; 32]],
            &[&long, &[0xff; 64], &long[..63]],
        ];
        for (fc, params) in (0x10..).zip(sets) {
            let s = build_s(fc, params).unwrap();
            assert_eq!(derive(&key, fc, params), *kdf(&key, &s), "FC {fc:#x}");
        }
    }

    /// The key of an algorithm is that of the derivation of its system,
    /// and a number that names no algorithm gives one too.
    #[test]
    fn an_algorithm_key_is_that_of_its_system() {
        use crate::identity::Algorithm;
        let root = [0x5c; 32];
        let kamf = crate::nas_5gs::KAmf::new(&root);
        let kasme = crate::nas_eps::KAsme::new(&root);
        assert_eq!(
            *derive_algorithm_key(&root, 0x69, 0x02, 2),
            *crate::nas_5gs::derive_knas_int(&kamf, Algorithm::Aes).as_octets()
        );
        assert_eq!(
            *derive_algorithm_key(&root, 0x15, 0x01, 3),
            *crate::nas_eps::derive_knas_enc(&kasme, Algorithm::Zuc).as_octets()
        );
        let s = build_s(0x69, &[&[0x01], &[0x0f]]).unwrap();
        assert_eq!(
            *derive_algorithm_key(&root, 0x69, 0x01, 0x0f),
            *extract_128(&kdf(&root, &s))
        );
    }

    #[test]
    fn a_parameter_longer_than_its_length_field_is_refused() {
        let longest = vec![0; 65535];
        assert_eq!(build_s(0x6a, &[&longest]).unwrap().len(), 1 + 65535 + 2);
        let too_long = vec![0; 65536];
        assert_eq!(
            build_s(0x6a, &[&[1], &too_long]),
            Err(SecurityError::InputTooLong {
                maximum: 65535,
                got: 65536
            })
        );
    }
}
