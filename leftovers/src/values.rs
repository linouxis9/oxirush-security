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

//! The values to look for after an operation, computed apart from the
//! crate: the round keys of AES, the subkeys of CMAC, the blocks and the
//! inner hash of HMAC, the stages of ZUC.

use sha2::{Digest, Sha256};

/// A value that an operation must not leave, with its name.
pub type Secret = (String, Vec<u8>);

pub fn secret(name: &str, octets: &[u8]) -> Secret {
    (name.to_string(), octets.to_vec())
}

/// The S-box of AES: the inverse in GF(2^8), then the affine map
/// (FIPS 197 §5.1.1).
fn sbox(x: u8) -> u8 {
    let mut inverse = 0u8;
    if x != 0 {
        for candidate in 1..=255u8 {
            let (mut a, mut b, mut product) = (x, candidate, 0u8);
            for _ in 0..8 {
                if b & 1 != 0 {
                    product ^= a;
                }
                let high = a & 0x80;
                a <<= 1;
                if high != 0 {
                    a ^= 0x1b;
                }
                b >>= 1;
            }
            if product == 1 {
                inverse = candidate;
                break;
            }
        }
    }
    let (mut result, mut rotated) = (inverse, inverse);
    for _ in 0..4 {
        rotated = rotated.rotate_left(1);
        result ^= rotated;
    }
    result ^ 0x63
}

/// The eleven round keys of AES-128 (FIPS 197 §5.2).
pub fn round_keys(key: &[u8; 16]) -> [[u8; 16]; 11] {
    let mut words = [[0u8; 4]; 44];
    for (word, octets) in words.iter_mut().zip(key.chunks(4)) {
        word.copy_from_slice(octets);
    }
    let mut constant = 1u8;
    for at in 4..44 {
        let mut word = words[at - 1];
        if at % 4 == 0 {
            word = [
                sbox(word[1]) ^ constant,
                sbox(word[2]),
                sbox(word[3]),
                sbox(word[0]),
            ];
            constant = (constant << 1) ^ if constant & 0x80 != 0 { 0x1b } else { 0 };
        }
        words[at] = core::array::from_fn(|octet| words[at - 4][octet] ^ word[octet]);
    }
    core::array::from_fn(|round| core::array::from_fn(|at| words[4 * round + at / 4][at % 4]))
}

/// A key of AES with what is expanded from it.
pub fn aes_secrets(key: &[u8; 16]) -> Vec<Secret> {
    let keys = round_keys(key);
    let mut secrets = vec![secret("the key", key)];
    for round in [1, 2, 5, 9, 10] {
        secrets.push(secret(&format!("AES round key {round}"), &keys[round]));
    }
    secrets
}

/// L, K1 and K2 of AES-CMAC with a key (RFC 4493 §2.3), each as its
/// octets and as the number whose first octet is the low one.
pub fn cmac_secrets(key: &[u8; 16]) -> Vec<Secret> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let mut l = [0u8; 16];
    aes::Aes128Enc::new(key.into()).encrypt_block((&mut l).into());
    let double = |block: [u8; 16]| {
        let value = u128::from_be_bytes(block);
        ((value << 1) ^ if value >> 127 == 1 { 0x87 } else { 0 }).to_be_bytes()
    };
    let (k1, k2) = (double(l), double(double(l)));
    let reversed = |block: [u8; 16]| -> Vec<u8> { block.iter().rev().copied().collect() };
    vec![
        secret("CMAC L", &l),
        secret("CMAC K1", &k1),
        secret("CMAC K2", &k2),
        secret("CMAC K1, as a number", &reversed(k1)),
        secret("CMAC K2, as a number", &reversed(k2)),
    ]
}

/// The words of a key of SNOW 3G as the generator loads them: the last
/// word first, each with its low octet first, which is the key reversed.
pub fn reversed(key: &[u8; 16]) -> Secret {
    let octets: Vec<u8> = key.iter().rev().copied().collect();
    secret("the key, as the words of SNOW 3G", &octets)
}

/// The stages of the LFSR of ZUC as a key and an IV load them: the octet
/// of the key in bits 23 to 30 (TS 35.222 §3.6.1).
pub fn zuc_stages(key: &[u8; 16], iv: &[u8; 16]) -> Vec<Secret> {
    const D: [u32; 16] = [
        0x44d7, 0x26bc, 0x626b, 0x135e, 0x5789, 0x35e2, 0x7135, 0x09af, 0x4d78, 0x2f13, 0x6bc4,
        0x1af1, 0x5e26, 0x3c4d, 0x789a, 0x47ac,
    ];
    let stages: Vec<u8> = (0..16)
        .flat_map(|at| {
            let stage = (u32::from(key[at]) << 23) | (D[at] << 8) | u32::from(iv[at]);
            stage.to_le_bytes()
        })
        .collect();
    vec![
        secret("ZUC stages 0 to 3", &stages[..16]),
        secret("ZUC stages 12 to 15", &stages[48..]),
    ]
}

/// The IV of 128-EEA3 (TS 35.221 §3.2).
pub fn eea3_iv(count: u32, bearer: u8, direction: u8) -> [u8; 16] {
    let mut iv = [0u8; 16];
    iv[..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = (bearer << 3) | (direction << 2);
    iv.copy_within(0..8, 8);
    iv
}

/// Keystream as an operation may hold it: its octets, and its 32-bit words
/// with their low octet first.
pub fn keystream_secrets(keystream: &[u8]) -> Vec<Secret> {
    let words: Vec<u8> = keystream
        .chunks(4)
        .flat_map(|word| word.iter().rev().copied().collect::<Vec<u8>>())
        .collect();
    vec![
        secret("keystream octets 0 to 15", &keystream[..16]),
        secret("keystream octets 16 to 31", &keystream[16..32]),
        secret("keystream words 0 to 3", &words[..16]),
        secret("keystream words 4 to 7", &words[16..32]),
        secret("keystream words 12 to 15", &words[48..64]),
    ]
}

/// The S of TS 33.220 Annex B.2: FC, then each parameter and its length.
pub fn s(fc: u8, parameters: &[&[u8]]) -> Vec<u8> {
    let mut s = vec![fc];
    for parameter in parameters {
        s.extend_from_slice(parameter);
        s.extend_from_slice(&(parameter.len() as u16).to_be_bytes());
    }
    s
}

/// What HMAC-SHA-256 of `message` with `key` handles: the key, its two
/// padded blocks, the inner hash and the 256 bits of the result, of which
/// a derivation may return half.
pub fn hmac_secrets(name: &str, key: &[u8], message: &[u8]) -> Vec<Secret> {
    let pad = |with: u8| -> Vec<u8> { key.iter().map(|octet| octet ^ with).collect() };
    let block = |with: u8| {
        let mut block = pad(with);
        block.resize(64, with);
        block
    };
    let inner = Sha256::new()
        .chain_update(block(0x36))
        .chain_update(message)
        .finalize();
    let outer = Sha256::new()
        .chain_update(block(0x5c))
        .chain_update(inner)
        .finalize();
    vec![
        secret(name, key),
        secret(&format!("{name} xor ipad"), &pad(0x36)),
        secret(&format!("{name} xor opad"), &pad(0x5c)),
        secret("the inner hash of HMAC", &inner),
        secret("the 256 bits that are derived", &outer),
    ]
}
