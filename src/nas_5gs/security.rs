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

use crate::common::error::SecurityError;
use crate::common::input::{Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};
pub use crate::common::{
    nea_cipher, nea_cipher_bits, nea1_cipher, nea1_cipher_bits, nea2_cipher, nea2_cipher_bits,
    nea3_cipher, nea3_cipher_bits, nia_mac, nia_mac_bits, nia1_mac, nia1_mac_bits, nia2_mac,
    nia2_mac_bits, nia3_mac, nia3_mac_bits,
};

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
    key: &[u8; 16],
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
    key: &[u8; 16],
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

/// Compute the MAC of a NAS Container (NASC) for N2 handover with a KAMF
/// change or for EPS to 5GS handover (TS 33.501 §6.9.2.3.3, §8.4.2).
///
/// The inputs are fixed: COUNT is 2^32 - 1, DIRECTION is 1, and BEARER is
/// the NAS connection identifier for 3GPP access, 0x01. The COUNT is used
/// only for this MAC and does not change the NAS COUNTs.
pub fn nas_container_mac(key: &[u8; 16], message: &[u8], algorithm: IntegrityAlgorithm) -> u32 {
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

    #[test]
    fn nas_container_mac_uses_the_reserved_count() {
        let container = [0x01, 0x00, 0x00, 0x05, 0x22];
        let mac = |count| {
            nia_mac(
                &KEY,
                count,
                bearer(1),
                Direction::Downlink,
                &container,
                IntegrityAlgorithm::NIA2,
            )
        };
        assert_eq!(
            nas_container_mac(&KEY, &container, IntegrityAlgorithm::NIA2),
            mac(0xffff_ffff)
        );
        assert_ne!(
            nas_container_mac(&KEY, &container, IntegrityAlgorithm::NIA2),
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

        let payload = [0x7e, 0x00, 0x41, 0x01];
        let count = NasCount::from_parts(0, 1);
        let mac = |connection| {
            nas_mac(
                &KEY,
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
                &KEY,
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
    fn the_crate_root_has_the_functions_of_5gs_nas() {
        let payload = [0x7e, 0x00, 0x41, 0x01];
        let (connection, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);
        let algorithm = IntegrityAlgorithm::NIA2;

        assert_eq!(
            crate::nas_mac(
                &KEY,
                NasCount::from_parts(0, 1),
                connection,
                uplink,
                &payload,
                algorithm
            ),
            0x7f88_ff87
        );
        assert!(NasCount::new(1 << 24).is_err());

        let mut ciphered = payload;
        crate::nas_cipher(
            &KEY,
            NasCount::MAX,
            connection,
            uplink,
            &mut ciphered,
            CipheringAlgorithm::NEA2,
        );
        let mut expected = payload;
        crate::nea_cipher(
            &KEY,
            0x00ff_ffff,
            bearer(1),
            uplink,
            &mut expected,
            CipheringAlgorithm::NEA2,
        );
        assert_eq!(ciphered, expected);

        // The algorithm itself takes any 32-bit COUNT
        crate::nia_mac(&KEY, 1 << 24, bearer(1), uplink, &payload, algorithm);
    }
}
