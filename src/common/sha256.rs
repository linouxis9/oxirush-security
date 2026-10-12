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

//! SHA-256 and HMAC-SHA-256 that leave no key material behind.
//!
//! SHA-256 is that of the `sha2` crate. With its `zeroize` feature the
//! hasher wipes its chaining value, which is as sensitive as the key it
//! absorbed, and its block buffer when it is dropped.
//!
//! HMAC is the framing of RFC 2104 over that hasher, written here: the
//! `hmac` crate wipes its two hash states in the same way, but its
//! `new_from_slice` leaves the block of the key and its `finalize` the
//! inner hash in their stack frames. Here both are wiped.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

// The hasher and the AES key schedule wipe themselves on drop only with the
// `zeroize` features of their crates: this fails to compile without them.
const _: fn() = || {
    fn wiped_on_drop<T: zeroize::ZeroizeOnDrop>() {}
    wiped_on_drop::<Sha256>();
    wiped_on_drop::<aes::Aes128Enc>();
};

/// SHA-256 (FIPS 180-4) of the concatenation of `parts`, in a buffer that
/// is wiped on drop.
pub(crate) fn sha256(parts: &[&[u8]]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    let mut digest = Zeroizing::new([0u8; 32]);
    hash.finalize_into((&mut *digest).into());
    digest
}

/// HMAC-SHA-256 (RFC 2104).
pub(crate) fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    hmac_sha256_of(key, |message| message.update(data))
}

/// HMAC-SHA-256 of the message that `write` gives the hasher, part after
/// part: the message is nowhere else in memory.
pub(crate) fn hmac_sha256_of(key: &[u8], write: impl FnOnce(&mut Sha256)) -> [u8; 32] {
    // The key, hashed when it is longer than a block, then padded with zeros
    let mut pad = Zeroizing::new([0u8; 64]);
    if key.len() > pad.len() {
        pad[..32].copy_from_slice(sha256(&[key]).as_ref());
    } else {
        pad[..key.len()].copy_from_slice(key);
    }

    for octet in pad.iter_mut() {
        *octet ^= 0x36;
    }
    let mut hash = Sha256::new();
    hash.update(pad.as_ref());
    write(&mut hash);
    let mut inner = Zeroizing::new([0u8; 32]);
    hash.finalize_into((&mut *inner).into());

    for octet in pad.iter_mut() {
        *octet ^= 0x36 ^ 0x5c;
    }
    *sha256(&[pad.as_ref(), inner.as_ref()])
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FIPS 180-4 examples: "abc", the empty message, and the 448-bit
    /// message that fills a block with its padding; then a message split
    /// into parts at every point.
    #[test]
    fn sha256_matches_the_fips_180_4_examples() {
        for (message, expected) in [
            (
                &b"abc"[..],
                "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            ),
            (
                b"",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            ),
            (
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
                "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
            ),
        ] {
            assert_eq!(hex::encode(*sha256(&[message])), expected);
            for split in 0..=message.len() {
                let (first, second) = message.split_at(split);
                assert_eq!(hex::encode(*sha256(&[first, second])), expected);
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

    /// A key of exactly one block is used as it is, and one octet more is
    /// hashed first (RFC 2104 §2).
    #[test]
    fn hmac_sha256_hashes_only_a_key_longer_than_a_block() {
        let block = [0x5a; 64];
        let longer = [0x5a; 65];
        let hashed = sha256(&[&longer]);
        assert_eq!(
            hmac_sha256(&longer, b"data"),
            hmac_sha256(hashed.as_ref(), b"data")
        );
        assert_ne!(hmac_sha256(&block, b"data"), hmac_sha256(&longer, b"data"));
    }
}
