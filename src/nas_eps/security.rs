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

//! EPS NAS EIA/EEA use with zero bearer and a 24-bit COUNT.

pub use crate::common::{
    nas_cipher_bits, nas_mac_bits, nea1_cipher, nea1_cipher_bits, nea2_cipher, nea2_cipher_bits,
    nea3_cipher, nea3_cipher_bits, nia1_mac, nia2_mac, nia2_mac_bits, nia3_mac,
};

/// Compute an EPS NAS MAC-I with BEARER=0 (EIA0/1/2/3).
///
/// `message` is the sequence-number octet followed by the protected payload.
///
/// # Panics
///
/// Panics if `count` exceeds 2^24 - 1, `direction` exceeds 1, or `algo_id`
/// exceeds 3.
pub fn nas_mac(key: &[u8; 16], count: u32, direction: u8, message: &[u8], algo_id: u8) -> u32 {
    assert!(count <= 0x00ff_ffff, "EPS NAS COUNT exhausted");
    assert!(direction <= 1, "invalid EPS NAS direction");
    assert!(algo_id <= 3, "unsupported EPS integrity algorithm");
    crate::nia::nas_mac(key, count, 0, direction, message, algo_id)
}

/// Cipher or decipher an EPS NAS payload with BEARER=0 (EEA0/1/2/3).
///
/// # Panics
///
/// Panics if `count` exceeds 2^24 - 1, `direction` exceeds 1, or `algo_id`
/// exceeds 3.
pub fn nas_cipher(key: &[u8; 16], count: u32, direction: u8, data: &mut [u8], algo_id: u8) {
    assert!(count <= 0x00ff_ffff, "EPS NAS COUNT exhausted");
    assert!(direction <= 1, "invalid EPS NAS direction");
    assert!(algo_id <= 3, "unsupported EPS ciphering algorithm");
    crate::nea::nas_cipher(key, count, 0, direction, data, algo_id);
}

/// Compute UL_NAS_MAC and XDL_NAS_MAC for RRC connection re-establishment
/// with the control plane CIoT EPS optimisation (TS 33.401 §7.4.4).
///
/// The NAS-MAC uses KNASint, the uplink NAS COUNT of the next uplink
/// message, DIRECTION 0, and the 28-bit target Cell-ID as the message. The
/// first 16 bits are UL_NAS_MAC and the last 16 bits XDL_NAS_MAC. The UE
/// then increments its uplink NAS COUNT as if it had sent a message.
///
/// TS 33.401 §7.4.4 names the target Cell-ID as the protected message
/// without giving its encoding. The target eNB passes it to the MME as the
/// 28-bit E-UTRAN Cell Identifier (TS 36.413 §9.2.1.38), so this function
/// left aligns the value in four octets and inputs only those 28 bits to
/// the selected 128-EIA algorithm. That reading is this crate's: no test
/// data or other implementation exists to check it against.
///
/// # Panics
///
/// Panics if `ul_count` exceeds 2^24 - 1, `target_cell_id` exceeds 28 bits,
/// or `algo_id` exceeds 3.
pub fn re_establishment_nas_mac(
    key: &[u8; 16],
    ul_count: u32,
    target_cell_id: u32,
    algo_id: u8,
) -> (u16, u16) {
    assert!(ul_count <= 0x00ff_ffff, "EPS NAS COUNT exhausted");
    assert!(
        target_cell_id <= 0x0fff_ffff,
        "E-UTRAN Cell Identifier must be 28 bits"
    );
    let encoded = (target_cell_id << 4).to_be_bytes();
    let mac = crate::common::nas_mac_bits(key, ul_count, 0, 0, &encoded, 28, algo_id);
    ((mac >> 16) as u16, mac as u16)
}

/// Compute the two least significant octets of a SERVICE REQUEST MAC.
///
/// `ksi_and_sequence_number` contains the 3-bit KSI and 5-bit NAS SQN.
/// TS 24.301 section 9.9.3.28 protects octets 1 and 2 of the short message.
///
/// # Panics
///
/// Panics under the conditions of [`nas_mac`].
pub fn service_request_short_mac(
    key: &[u8; 16],
    count: u32,
    direction: u8,
    ksi_and_sequence_number: u8,
    algo_id: u8,
) -> u16 {
    service_request_short_mac_with_header(
        key,
        count,
        direction,
        0xc7,
        ksi_and_sequence_number,
        algo_id,
    )
}

/// Compute a short MAC using the actual received SERVICE REQUEST first octet.
/// TS 24.301 table 9.3.1 also interprets header nibbles D–F as SERVICE REQUEST.
///
/// # Panics
///
/// Panics if `first_octet` is not a SERVICE REQUEST header, or under the
/// conditions of [`nas_mac`].
pub fn service_request_short_mac_with_header(
    key: &[u8; 16],
    count: u32,
    direction: u8,
    first_octet: u8,
    ksi_and_sequence_number: u8,
    algo_id: u8,
) -> u16 {
    assert!(matches!(first_octet, 0xc7 | 0xd7 | 0xe7 | 0xf7));
    nas_mac(
        key,
        count,
        direction,
        &[first_octet, ksi_and_sequence_number],
        algo_id,
    ) as u16
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_establishment_mac_authenticates_the_28_bit_cell_id() {
        let key = [0x33; 16];
        assert_eq!(
            re_establishment_nas_mac(&key, 7, 0x0123_4567, 2),
            (0xe14e, 0xc9e7)
        );
    }

    #[test]
    fn eps_nas_algorithms_share_eea_eia_cores() {
        let key = [0x23; 16];
        let mut payload = b"EPS NAS security".to_vec();
        for algo in 0..=3 {
            let mac = nas_mac(&key, 10, 0, &payload, algo);
            assert_eq!(mac, crate::nas_mac(&key, 10, 0, 0, &payload, algo));
            let original = payload.clone();
            nas_cipher(&key, 10, 0, &mut payload, algo);
            nas_cipher(&key, 10, 0, &mut payload, algo);
            assert_eq!(payload, original);
        }
        assert_eq!(
            service_request_short_mac(&key, 10, 0, 0x2a, 2),
            crate::nas_mac(&key, 10, 0, 0, &[0xc7, 0x2a], 2) as u16
        );
    }
}
