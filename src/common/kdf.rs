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

use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generic KDF: HMAC-SHA-256(key, S).
pub fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts any key size per RFC 2104");
    mac.update(s);
    mac.finalize().into_bytes().into()
}

/// Build the S parameter: FC || (P_i || L_i)*.
///
/// # Panics
///
/// Panics if a parameter exceeds 65535 octets.
pub fn build_s(fc: u8, params: &[&[u8]]) -> Vec<u8> {
    // Exact capacity: the vector never reallocates, so a caller that wipes
    // S leaves no copy of a key parameter in freed memory.
    let mut s = Vec::with_capacity(1 + params.iter().map(|p| p.len() + 2).sum::<usize>());
    s.push(fc);
    for p in params {
        assert!(p.len() <= 0xFFFF, "KDF parameter exceeds 65535 bytes");
        s.extend_from_slice(p);
        s.extend_from_slice(&(p.len() as u16).to_be_bytes());
    }
    s
}

/// Derive a 3GPP algorithm key using the shared parameter layout.
pub(crate) fn derive_algorithm_key(key: &[u8; 32], fc: u8, algo_type: u8, algo_id: u8) -> [u8; 32] {
    kdf(key, &build_s(fc, &[&[algo_type], &[algo_id]]))
}

/// Encode a 24-bit NAS COUNT as the four-octet KDF parameter. Callers
/// document that a COUNT above 2^24 - 1 panics.
pub(crate) fn nas_count_input(count: u32) -> [u8; 4] {
    assert!(count <= 0x00ff_ffff, "NAS COUNT exhausted");
    count.to_be_bytes()
}

/// Extract the least significant 128 bits of a KDF output.
pub fn extract_128(full: &[u8; 32]) -> [u8; 16] {
    full[16..]
        .try_into()
        .expect("32-byte array yields 16-byte tail")
}
