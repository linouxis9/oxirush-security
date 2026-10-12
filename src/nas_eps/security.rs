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

//! EPS NAS integrity and ciphering (TS 33.401 §8.1 and §8.2): the
//! algorithms with BEARER 0 and a 24-bit NAS COUNT.

use super::keys::{KNasEnc, KNasInt};
use crate::common::batch::{CipherJob, MacJob};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};
use crate::common::nea::nea_cipher;
use crate::common::nia::{nia_mac, nia_mac_bits};

/// Compute the MAC of an EPS NAS message, with BEARER 0.
///
/// `message` is what the MAC covers: the sequence number octet, then the
/// NAS message, ciphered when it is to be.
pub fn nas_mac(
    key: &KNasInt,
    count: NasCount,
    direction: Direction,
    message: &[u8],
    algorithm: IntegrityAlgorithm,
) -> u32 {
    nia_mac(
        key,
        count.get(),
        Bearer::ZERO,
        direction,
        message,
        algorithm,
    )
}

/// Cipher or decipher an EPS NAS message in place, with BEARER 0.
pub fn nas_cipher(
    key: &KNasEnc,
    count: NasCount,
    direction: Direction,
    data: &mut [u8],
    algorithm: CipheringAlgorithm,
) {
    nea_cipher(key, count.get(), Bearer::ZERO, direction, data, algorithm);
}

/// An EPS NAS message to cipher or decipher with others: what
/// [`nas_cipher`] takes, as a job of
/// [`nea_cipher_batch`](crate::nea_cipher_batch).
pub fn cipher_job<'a>(
    key: &'a KNasEnc,
    count: NasCount,
    direction: Direction,
    data: &'a mut [u8],
    algorithm: CipheringAlgorithm,
) -> CipherJob<'a> {
    CipherJob::new(key, count.get(), Bearer::ZERO, direction, data, algorithm)
}

/// An EPS NAS message whose MAC is computed with those of others: what
/// [`nas_mac`] takes, as a job of [`nia_mac_batch`](crate::nia_mac_batch).
pub fn mac_job<'a>(
    key: &'a KNasInt,
    count: NasCount,
    direction: Direction,
    message: &'a [u8],
    algorithm: IntegrityAlgorithm,
) -> MacJob<'a> {
    MacJob::new(
        key,
        count.get(),
        Bearer::ZERO,
        direction,
        message,
        algorithm,
    )
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
/// A `target_cell_id` above 28 bits is [`SecurityError::OutOfRange`].
pub fn re_establishment_nas_mac(
    key: &KNasInt,
    ul_count: NasCount,
    target_cell_id: u32,
    algorithm: IntegrityAlgorithm,
) -> Result<(u16, u16), SecurityError> {
    if target_cell_id > 0x0fff_ffff {
        return Err(SecurityError::OutOfRange {
            field: "E-UTRAN Cell Identifier",
            maximum: 0x0fff_ffff,
            got: target_cell_id.into(),
        });
    }
    let encoded = (target_cell_id << 4).to_be_bytes();
    let mac = nia_mac_bits(
        key,
        ul_count.get(),
        Bearer::ZERO,
        Direction::Uplink,
        &encoded,
        28,
        algorithm,
    )?;
    Ok(((mac >> 16) as u16, mac as u16))
}

/// Compute the short MAC of a SERVICE REQUEST: the two least significant
/// octets of the MAC over its first two octets (TS 24.301 §9.9.3.28).
///
/// `ksi_and_sequence_number` is the second octet: the 3-bit KSI and the
/// 5-bit NAS sequence number. The first octet is 0xC7, security header type
/// 12 with the protocol discriminator of EMM.
pub fn service_request_short_mac(
    key: &KNasInt,
    count: NasCount,
    direction: Direction,
    ksi_and_sequence_number: u8,
    algorithm: IntegrityAlgorithm,
) -> u16 {
    nas_mac(
        key,
        count,
        direction,
        &[0xc7, ksi_and_sequence_number],
        algorithm,
    ) as u16
}

/// Compute a short MAC with the first octet that a SERVICE REQUEST was
/// received with. TS 24.301 §9.3.1 reads the security header types 12 to
/// 15 as a SERVICE REQUEST, so the octet is 0xC7, 0xD7, 0xE7 or 0xF7.
///
/// Another `first_octet` is [`SecurityError::InvalidParameter`].
pub fn service_request_short_mac_with_header(
    key: &KNasInt,
    count: NasCount,
    direction: Direction,
    first_octet: u8,
    ksi_and_sequence_number: u8,
    algorithm: IntegrityAlgorithm,
) -> Result<u16, SecurityError> {
    if !matches!(first_octet, 0xc7 | 0xd7 | 0xe7 | 0xf7) {
        return Err(SecurityError::InvalidParameter(
            "the first octet is not that of a SERVICE REQUEST",
        ));
    }
    Ok(nas_mac(
        key,
        count,
        direction,
        &[first_octet, ksi_and_sequence_number],
        algorithm,
    ) as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn re_establishment_mac_authenticates_the_28_bit_cell_id() {
        let key = KNasInt::new(&[0x33; 16]);
        assert_eq!(
            re_establishment_nas_mac(
                &key,
                NasCount::from_parts(0, 7),
                0x0123_4567,
                IntegrityAlgorithm::EIA2
            ),
            Ok((0xe14e, 0xc9e7))
        );
        assert!(
            re_establishment_nas_mac(&key, NasCount::ZERO, 0x0fff_ffff, IntegrityAlgorithm::EIA2)
                .is_ok()
        );
        assert_eq!(
            re_establishment_nas_mac(&key, NasCount::ZERO, 0x1000_0000, IntegrityAlgorithm::EIA2),
            Err(SecurityError::OutOfRange {
                field: "E-UTRAN Cell Identifier",
                maximum: 0x0fff_ffff,
                got: 0x1000_0000
            })
        );
    }

    #[test]
    fn eps_nas_uses_the_algorithms_with_bearer_zero() {
        let (int, enc) = (KNasInt::new(&[0x23; 16]), KNasEnc::new(&[0x23; 16]));
        let mut payload = b"EPS NAS security".to_vec();
        let (count, uplink) = (NasCount::from_parts(0, 10), Direction::Uplink);
        for (integrity, ciphering) in [
            (IntegrityAlgorithm::EIA0, CipheringAlgorithm::EEA0),
            (IntegrityAlgorithm::EIA1, CipheringAlgorithm::EEA1),
            (IntegrityAlgorithm::EIA2, CipheringAlgorithm::EEA2),
            (IntegrityAlgorithm::EIA3, CipheringAlgorithm::EEA3),
        ] {
            let mac = nas_mac(&int, count, uplink, &payload, integrity);
            assert_eq!(
                mac,
                nia_mac(&int, 10, Bearer::ZERO, uplink, &payload, integrity)
            );
            let original = payload.clone();
            nas_cipher(&enc, count, uplink, &mut payload, ciphering);
            let mut expected = original.clone();
            nea_cipher(&enc, 10, Bearer::ZERO, uplink, &mut expected, ciphering);
            assert_eq!(payload, expected);
            nas_cipher(&enc, count, uplink, &mut payload, ciphering);
            assert_eq!(payload, original);
        }
    }

    /// TS 24.301 §9.9.3.28: the short MAC is the 2 least significant octets
    /// of the MAC over octets 1 and 2 of the SERVICE REQUEST.
    #[test]
    fn the_short_mac_covers_the_first_two_octets() {
        let key = KNasInt::new(&[0x23; 16]);
        let (count, uplink) = (NasCount::from_parts(0, 10), Direction::Uplink);
        let over = |octets: [u8; 2]| {
            nia_mac(
                &key,
                10,
                Bearer::ZERO,
                uplink,
                &octets,
                IntegrityAlgorithm::EIA2,
            ) as u16
        };
        assert_eq!(
            service_request_short_mac(&key, count, uplink, 0x2a, IntegrityAlgorithm::EIA2),
            over([0xc7, 0x2a])
        );
        for first_octet in [0xc7, 0xd7, 0xe7, 0xf7] {
            assert_eq!(
                service_request_short_mac_with_header(
                    &key,
                    count,
                    uplink,
                    first_octet,
                    0x2a,
                    IntegrityAlgorithm::EIA2
                ),
                Ok(over([first_octet, 0x2a]))
            );
        }
        for first_octet in [0x07, 0x17, 0xb7, 0xc0, 0xc2] {
            assert!(
                service_request_short_mac_with_header(
                    &key,
                    count,
                    uplink,
                    first_octet,
                    0x2a,
                    IntegrityAlgorithm::EIA2
                )
                .is_err()
            );
        }
    }
}
