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

//! Shared 3GPP TS 33.220 Annex B.2 HMAC-SHA-256 KDF framing.

use crate::common::error::SecurityError;

/// Longest KDF parameter: its length field L has two octets.
const MAXIMUM_PARAMETER: usize = u16::MAX as usize;

/// Generic KDF: HMAC-SHA-256(key, S). The HMAC state is wiped on return.
pub fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    super::sha256::hmac_sha256(key, s)
}

/// Build the S parameter: FC || (P_i || L_i)*.
///
/// A parameter longer than 65535 octets, which the two-octet L cannot
/// express, is [`SecurityError::InputTooLong`].
pub fn build_s(fc: u8, params: &[&[u8]]) -> Result<Vec<u8>, SecurityError> {
    for parameter in params {
        checked_parameter(parameter)?;
    }
    Ok(fixed_s(fc, params))
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

/// S of parameters that are known to fit their L: arrays, and slices that
/// went through [`checked_parameter`].
pub(crate) fn fixed_s(fc: u8, params: &[&[u8]]) -> Vec<u8> {
    // Exact capacity: the vector never reallocates, so a caller that wipes
    // S leaves no copy of a key parameter in freed memory.
    let mut s = Vec::with_capacity(1 + params.iter().map(|p| p.len() + 2).sum::<usize>());
    s.push(fc);
    for p in params {
        debug_assert!(p.len() <= MAXIMUM_PARAMETER);
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    s
}

/// Derive a 128-bit algorithm key with the parameter layout that TS 33.501
/// Annex A.8 and TS 33.401 Annex A.7 share: the algorithm type
/// distinguisher, then the algorithm identity. The key is the 128 least
/// significant bits of the 256 derived.
pub(crate) fn derive_algorithm_key(key: &[u8; 32], fc: u8, algo_type: u8, algo_id: u8) -> [u8; 16] {
    let mut full = kdf(key, &fixed_s(fc, &[&[algo_type], &[algo_id]]));
    let algorithm_key = extract_128(&full);
    zeroize::Zeroize::zeroize(&mut full);
    algorithm_key
}

/// Extract the least significant 128 bits of a KDF output.
pub fn extract_128(full: &[u8; 32]) -> [u8; 16] {
    let mut key = [0; 16];
    key.copy_from_slice(&full[16..]);
    key
}

#[cfg(test)]
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
