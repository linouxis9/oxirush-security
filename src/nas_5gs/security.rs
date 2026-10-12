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

//! 5GS NAS integrity and ciphering (TS 33.501 §6.4.3 and §6.4.4).

use super::keys::{KNasEnc, KNasInt};
use crate::common::batch::{CipherJob, MacJob};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};
use crate::common::nea::nea_cipher;
use crate::common::nia::nia_mac;

/// The NAS connection of a 5GS NAS message, which gives the BEARER input of
/// the algorithms: the NAS connection identifier 0x01 for 3GPP access and
/// 0x02 for non-3GPP access (TS 33.501 §6.4.2.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum NasConnection {
    /// 3GPP access, NAS connection identifier 0x01.
    ThreeGpp = 1,
    /// Non-3GPP access, NAS connection identifier 0x02.
    Non3Gpp = 2,
}

impl TryFrom<u8> for NasConnection {
    type Error = SecurityError;

    fn try_from(identifier: u8) -> Result<Self, SecurityError> {
        match identifier {
            1 => Ok(Self::ThreeGpp),
            2 => Ok(Self::Non3Gpp),
            _ => Err(SecurityError::InvalidParameter(
                "NAS connection identifier must be 1 or 2",
            )),
        }
    }
}

impl From<NasConnection> for u8 {
    fn from(connection: NasConnection) -> u8 {
        connection as u8
    }
}

impl From<NasConnection> for Bearer {
    fn from(connection: NasConnection) -> Bearer {
        // 1 or 2, within the five bits of a BEARER
        Bearer(connection as u8)
    }
}

/// Compute the MAC of a 5GS NAS message (TS 33.501 §6.4.3).
///
/// `message` is what the MAC covers: the sequence number octet, then the
/// NAS message, ciphered when it is to be.
pub fn nas_mac(
    key: &KNasInt,
    count: NasCount,
    connection: NasConnection,
    direction: Direction,
    message: &[u8],
    algorithm: IntegrityAlgorithm,
) -> u32 {
    nia_mac(
        key,
        count.get(),
        connection.into(),
        direction,
        message,
        algorithm,
    )
}

/// Cipher or decipher a 5GS NAS message in place (TS 33.501 §6.4.4).
pub fn nas_cipher(
    key: &KNasEnc,
    count: NasCount,
    connection: NasConnection,
    direction: Direction,
    data: &mut [u8],
    algorithm: CipheringAlgorithm,
) {
    nea_cipher(
        key,
        count.get(),
        connection.into(),
        direction,
        data,
        algorithm,
    );
}

/// A 5GS NAS message to cipher or decipher with others: what
/// [`nas_cipher`] takes, as a job of
/// [`nea_cipher_batch`](crate::nea_cipher_batch).
pub fn cipher_job<'a>(
    key: &'a KNasEnc,
    count: NasCount,
    connection: NasConnection,
    direction: Direction,
    data: &'a mut [u8],
    algorithm: CipheringAlgorithm,
) -> CipherJob<'a> {
    CipherJob::new(
        key,
        count.get(),
        connection.into(),
        direction,
        data,
        algorithm,
    )
}

/// A 5GS NAS message whose MAC is computed with those of others: what
/// [`nas_mac`] takes, as a job of [`nia_mac_batch`](crate::nia_mac_batch).
pub fn mac_job<'a>(
    key: &'a KNasInt,
    count: NasCount,
    connection: NasConnection,
    direction: Direction,
    message: &'a [u8],
    algorithm: IntegrityAlgorithm,
) -> MacJob<'a> {
    MacJob::new(
        key,
        count.get(),
        connection.into(),
        direction,
        message,
        algorithm,
    )
}

/// Compute the MAC of a NAS Container (NASC) for N2 handover with a KAMF
/// change or for EPS to 5GS handover (TS 33.501 §6.9.2.3.3, §8.4.2).
///
/// `message` is the value of the container from its octet 7 on, the
/// octets after its message authentication code (TS 24.501 §4.4.3.3):
/// the three octets of an Intra N1 mode NAS transparent container, which
/// are the algorithms, the flags with the ngKSI and the sequence number
/// (§9.11.2.6), or the four of an S1 mode to N1 mode NAS transparent
/// container, which are the algorithms, the NCC with the ngKSI and two
/// spare octets (§9.11.2.9).
///
/// The inputs are fixed: COUNT is 2^32 - 1, DIRECTION is 1, and BEARER is
/// the NAS connection identifier for 3GPP access, 0x01. The COUNT is used
/// only for this MAC and does not change the NAS COUNTs.
pub fn nas_container_mac(key: &KNasInt, message: &[u8], algorithm: IntegrityAlgorithm) -> u32 {
    nia_mac(
        key,
        u32::MAX,
        NasConnection::ThreeGpp.into(),
        Direction::Downlink,
        message,
        algorithm,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 16] = [0x11; 16];

    fn bearer(value: u8) -> Bearer {
        Bearer::new(value).unwrap()
    }

    /// TS 33.501 §6.9.2.3.3. The message is octets 7 to 9 of an Intra N1
    /// mode NAS transparent container: 128-5G-EA2 and 128-5G-IA2, a new
    /// KAMF with ngKSI 5, and the sequence number 0x22.
    #[test]
    fn nas_container_mac_uses_the_reserved_count() {
        let key = KNasInt::new(KEY);
        let container = [0x22, 0x15, 0x22];
        let mac = |count| {
            nia_mac(
                &key,
                count,
                bearer(1),
                Direction::Downlink,
                &container,
                IntegrityAlgorithm::NIA2,
            )
        };
        assert_eq!(
            nas_container_mac(&key, &container, IntegrityAlgorithm::NIA2),
            mac(0xffff_ffff)
        );
        assert_ne!(
            nas_container_mac(&key, &container, IntegrityAlgorithm::NIA2),
            mac(0x00ff_ffff)
        );
    }

    /// TS 33.501 §6.4.2.2: "0x01" for 3GPP access and "0x02" for non-3GPP
    /// access, and §6.4.3.1: the BEARER input is that identifier.
    #[test]
    fn nas_connection_identifier_is_one_or_two() {
        assert_eq!(NasConnection::try_from(1), Ok(NasConnection::ThreeGpp));
        assert_eq!(NasConnection::try_from(2), Ok(NasConnection::Non3Gpp));
        assert!(NasConnection::try_from(0).is_err());
        assert!(NasConnection::try_from(3).is_err());
        assert_eq!(u8::from(NasConnection::Non3Gpp), 2);
        assert_eq!(Bearer::from(NasConnection::ThreeGpp), bearer(1));
        assert_eq!(Bearer::from(NasConnection::Non3Gpp), bearer(2));

        let key = KNasInt::new(KEY);
        let payload = [0x7e, 0x00, 0x41, 0x01];
        let count = NasCount::from_parts(0, 1);
        let mac = |connection| {
            nas_mac(
                &key,
                count,
                connection,
                Direction::Uplink,
                &payload,
                IntegrityAlgorithm::NIA2,
            )
        };
        assert_eq!(mac(NasConnection::ThreeGpp), 0x7f88_ff87);
        assert_eq!(
            mac(NasConnection::Non3Gpp),
            nia_mac(
                &key,
                1,
                bearer(2),
                Direction::Uplink,
                &payload,
                IntegrityAlgorithm::NIA2
            )
        );
    }

    /// The functions of NAS take a NAS COUNT, which has 24 bits; the
    /// algorithms take any 32-bit COUNT.
    #[test]
    fn nas_ciphering_is_the_algorithm_with_the_nas_connection() {
        let key = KNasEnc::new(KEY);
        let payload = [0x7e, 0x00, 0x41, 0x01];
        let (connection, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);
        assert!(NasCount::new(1 << 24).is_err());

        let mut ciphered = payload;
        nas_cipher(
            &key,
            NasCount::MAX,
            connection,
            uplink,
            &mut ciphered,
            CipheringAlgorithm::NEA2,
        );
        let mut expected = payload;
        nea_cipher(
            &key,
            0x00ff_ffff,
            bearer(1),
            uplink,
            &mut expected,
            CipheringAlgorithm::NEA2,
        );
        assert_eq!(ciphered, expected);
        assert_ne!(ciphered, payload);
    }
}
