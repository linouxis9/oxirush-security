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

//! 5GS NAS ciphering and integrity using the shared NEA/NIA algorithm cores.

pub use crate::common::{
    nas_cipher_bits, nas_mac_bits, nea1_cipher, nea1_cipher_bits, nea2_cipher, nea2_cipher_bits,
    nea3_cipher, nea3_cipher_bits, nia1_mac, nia2_mac, nia2_mac_bits, nia3_mac,
};

/// Compute a 5GS NAS MAC with a 24-bit NAS COUNT and NAS connection identifier 1 or 2.
///
/// # Panics
///
/// Panics if `count` exceeds 2^24 - 1, `bearer` is not 1 or 2, `direction`
/// exceeds 1, or `algo_id` exceeds 3.
pub fn nas_mac(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    message: &[u8],
    algo_id: u8,
) -> u32 {
    assert!(count <= 0x00ff_ffff, "5GS NAS COUNT exhausted");
    assert!(
        (1..=2).contains(&bearer),
        "invalid 5GS NAS connection identifier"
    );
    assert!(direction <= 1, "invalid 5GS NAS direction");
    assert!(algo_id <= 3, "unsupported 5GS integrity algorithm");
    crate::common::nas_mac(key, count, bearer, direction, message, algo_id)
}

/// Cipher or decipher a 5GS NAS payload with the selected NEA algorithm.
///
/// # Panics
///
/// Panics under the conditions of [`nas_mac`].
pub fn nas_cipher(
    key: &[u8; 16],
    count: u32,
    bearer: u8,
    direction: u8,
    data: &mut [u8],
    algo_id: u8,
) {
    assert!(count <= 0x00ff_ffff, "5GS NAS COUNT exhausted");
    assert!(
        (1..=2).contains(&bearer),
        "invalid 5GS NAS connection identifier"
    );
    assert!(direction <= 1, "invalid 5GS NAS direction");
    assert!(algo_id <= 3, "unsupported 5GS ciphering algorithm");
    crate::common::nas_cipher(key, count, bearer, direction, data, algo_id);
}

/// Compute the MAC of a NAS Container (NASC) for N2 handover with a KAMF
/// change or for EPS to 5GS handover (TS 33.501 §6.9.2.3.3, §8.4.2).
///
/// The inputs are fixed: COUNT is 2^32 - 1, DIRECTION is 1, and BEARER is
/// the NAS connection identifier for 3GPP access, 0x01. The COUNT is used
/// only for this MAC and does not change the NAS COUNTs.
///
/// # Panics
///
/// Panics if `algo_id` exceeds 3.
pub fn nas_container_mac(key: &[u8; 16], message: &[u8], algo_id: u8) -> u32 {
    assert!(algo_id <= 3, "unsupported 5GS integrity algorithm");
    crate::common::nas_mac(key, u32::MAX, 0x01, 1, message, algo_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nas_container_mac_uses_the_reserved_count() {
        let key = [0x11; 16];
        let container = [0x01, 0x00, 0x00, 0x05, 0x22];
        assert_eq!(
            nas_container_mac(&key, &container, 2),
            crate::common::nas_mac(&key, 0xffff_ffff, 1, 1, &container, 2)
        );
        assert_ne!(
            nas_container_mac(&key, &container, 2),
            crate::common::nas_mac(&key, 0x00ff_ffff, 1, 1, &container, 2)
        );
    }

    #[test]
    fn nas_connection_identifier_is_one_or_two() {
        let key = [0x11; 16];
        let payload = [0x7e, 0x00, 0x41, 0x01];
        assert_eq!(nas_mac(&key, 1, 1, 0, &payload, 2), 0x7f88_ff87);
        assert!(std::panic::catch_unwind(|| nas_mac(&key, 1, 0, 0, &payload, 2)).is_err());
        assert!(std::panic::catch_unwind(|| nas_mac(&key, 1, 3, 0, &payload, 2)).is_err());
    }
}
