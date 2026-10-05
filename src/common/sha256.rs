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

//! SHA-256 and HMAC-SHA-256 that wipe their state.
//!
//! The sha2 0.10 and hmac 0.12 types leave their chaining value, which is
//! as sensitive as the key it absorbed, in memory they do not clear. These
//! run sha2's compression function over state that is wiped on drop.

use sha2::digest::generic_array::GenericArray;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

/// Initial hash value (FIPS 180-4 §5.3.3).
const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// SHA-256 (FIPS 180-4).
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct Sha256 {
    state: [u32; 8],
    block: [u8; 64],
    filled: usize,
    length: u64,
}

impl Sha256 {
    pub(crate) fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            block: [0; 64],
            filled: 0,
            length: 0,
        }
    }

    pub(crate) fn update(&mut self, mut data: &[u8]) {
        self.length = self.length.wrapping_add(data.len() as u64);
        while !data.is_empty() {
            let take = (64 - self.filled).min(data.len());
            self.block[self.filled..self.filled + take].copy_from_slice(&data[..take]);
            self.filled += take;
            data = &data[take..];
            if self.filled == 64 {
                sha2::compress256(
                    &mut self.state,
                    core::slice::from_ref(GenericArray::from_slice(&self.block)),
                );
                self.filled = 0;
            }
        }
    }

    pub(crate) fn finalize(mut self) -> [u8; 32] {
        // The padding: a one bit, zeros up to 56 octets modulo 64, and the
        // message length in bits (FIPS 180-4 §5.1.1).
        let bits = self.length.wrapping_mul(8).to_be_bytes();
        self.update(&[0x80]);
        while self.filled != 56 {
            self.update(&[0]);
        }
        self.update(&bits);
        let mut digest = [0; 32];
        for (octets, word) in digest
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(self.state.iter())
        {
            *octets = word.to_be_bytes();
        }
        digest
    }
}

/// HMAC-SHA-256 (RFC 2104).
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut pad = Zeroizing::new([0u8; 64]);
    if key.len() > pad.len() {
        let mut hash = Sha256::new();
        hash.update(key);
        let mut hashed_key = hash.finalize();
        pad[..32].copy_from_slice(&hashed_key);
        hashed_key.zeroize();
    } else {
        pad[..key.len()].copy_from_slice(key);
    }

    for octet in pad.iter_mut() {
        *octet ^= 0x36;
    }
    let mut inner = Sha256::new();
    inner.update(pad.as_ref());
    inner.update(data);
    let inner_digest = Zeroizing::new(inner.finalize());

    for octet in pad.iter_mut() {
        *octet ^= 0x36 ^ 0x5c;
    }
    let mut outer = Sha256::new();
    outer.update(pad.as_ref());
    outer.update(inner_digest.as_ref());
    outer.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    /// Every length around the padding boundaries, split at every point,
    /// against the sha2 digest.
    #[test]
    fn sha256_matches_sha2() {
        let message: Vec<u8> = (0..200u8).map(|octet| octet.wrapping_mul(29)).collect();
        for length in 0..message.len() {
            let expected: [u8; 32] = sha2::Sha256::digest(&message[..length]).into();
            for split in [0, length / 3, length] {
                let mut hash = Sha256::new();
                hash.update(&message[..split]);
                hash.update(&message[split..length]);
                assert_eq!(hash.finalize(), expected, "length {length} split {split}");
            }
        }
    }

    /// RFC 4231 test cases 1, 2, 3, 6 and 7: short, long and hashed keys.
    #[test]
    fn hmac_sha256_matches_rfc_4231() {
        let cases: [(Vec<u8>, &[u8], &str); 5] = [
            (
                vec![0x0b; 20],
                b"Hi There",
                "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            ),
            (
                b"Jefe".to_vec(),
                b"what do ya want for nothing?",
                "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843",
            ),
            (
                vec![0xaa; 20],
                &[0xdd; 50],
                "773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe",
            ),
            (
                vec![0xaa; 131],
                b"Test Using Larger Than Block-Size Key - Hash Key First",
                "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
            ),
            (
                vec![0xaa; 131],
                b"This is a test using a larger than block-size key and a larger than block-size data. The key needs to be hashed before being used by the HMAC algorithm.",
                "9b09ffa71b942fcb27635fbcd5b0e944bfdc63644f0713938a7f51535c3a35e2",
            ),
        ];
        for (key, data, expected) in cases {
            assert_eq!(hex::encode(hmac_sha256(&key, data)), expected);
        }
    }
}
