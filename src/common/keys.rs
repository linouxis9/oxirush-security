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

//! The types of the keys and of the values of an authentication.
//!
//! A key is never printed. An identity and a value that travels in clear
//! always are, whole: a SUPI, a SUCI, a 5G-GUTI, a PLMN, RAND, AUTN, a
//! home network public key.
//!
//! A key has a type of its own, so that a function takes the key that its
//! clause names and no other: KNASenc does not compile where KNASint is
//! expected, nor CK where IK is. Each type:
//!
//! - is built from its octets with `new` or `from_slice`, and gives them
//!   back with `as_octets`, and in no other way. Each takes a reference:
//!   an array passed by value would leave a copy where the program cannot
//!   wipe it;
//! - is wiped when it is dropped, and is not `Copy`: a copy is a `clone`
//!   that the program writes, and that is wiped in its turn;
//! - prints as its name with `{:?}`, without its octets;
//! - compares in a time that does not depend on where two values differ.
//!
//! RAND and AUTN have types of the same shape, built, viewed and compared
//! in the same way. They are not keys: `{:?}` prints their octets, and
//! they are not wiped.
//!
//! The keys that both systems have are here. Those of the 5GS hierarchy are
//! in [`nas_5gs`](crate::nas_5gs) and those of the EPS one in
//! [`nas_eps`](crate::nas_eps), under the names of TS 33.501 and TS 33.401.

/// What a key type and the type of a public value share: the type, how it
/// is built from its octets and viewed as them, and its comparison.
macro_rules! octets_type {
    ($(#[$attribute:meta])* $name:ident, $octets:literal) => {
        $(#[$attribute])*
        #[derive(Clone)]
        pub struct $name([u8; $octets]);

        impl $name {
            #[doc = concat!("From its ", stringify!($octets), " octets.")]
            pub const fn new(octets: &[u8; $octets]) -> Self {
                Self(*octets)
            }

            #[doc = concat!(
                "From a slice of ", stringify!($octets), " octets. Another length is ",
                "[`SecurityError::InvalidKeyLength`](crate::SecurityError::InvalidKeyLength)."
            )]
            pub fn from_slice(octets: &[u8]) -> Result<Self, $crate::common::error::SecurityError> {
                match octets.try_into() {
                    Ok(octets) => Ok(Self(octets)),
                    Err(_) => Err($crate::common::error::SecurityError::InvalidKeyLength {
                        expected: $octets,
                        got: octets.len(),
                    }),
                }
            }

            /// Its octets.
            pub const fn as_octets(&self) -> &[u8; $octets] {
                &self.0
            }
        }

        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                $crate::common::ct::constant_time_eq(&self.0, &other.0)
            }
        }

        impl Eq for $name {}

        impl PartialEq<[u8; $octets]> for $name {
            fn eq(&self, octets: &[u8; $octets]) -> bool {
                $crate::common::ct::constant_time_eq(&self.0, octets)
            }
        }
    };
}
pub(crate) use octets_type;

/// Define a key type: wiped when it is dropped, and printed without its
/// octets.
macro_rules! key {
    ($(#[$attribute:meta])* $name:ident, $octets:literal) => {
        $crate::common::keys::octets_type! {
            $(#[$attribute])*
            $name, $octets
        }

        impl Drop for $name {
            fn drop(&mut self) {
                zeroize::Zeroize::zeroize(&mut self.0);
            }
        }

        impl zeroize::ZeroizeOnDrop for $name {}

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "(..)"))
            }
        }
    };
}
pub(crate) use key;

/// Name the keys of 128 bits that an integrity algorithm or a ciphering
/// algorithm takes.
macro_rules! algorithm_keys {
    ($role:ident: $($name:ident),+) => {$(
        impl $crate::common::keys::sealed::Key128 for $name {
            fn key_octets(&self) -> &[u8; 16] {
                self.as_octets()
            }
        }

        impl $crate::common::keys::$role for $name {}
    )+};
}
pub(crate) use algorithm_keys;

/// What the key traits rest on. A program outside the crate cannot name
/// it, and so cannot implement them for a type of its own.
pub(crate) mod sealed {
    pub trait Key128 {
        fn key_octets(&self) -> &[u8; 16];
    }

    pub trait Key256 {
        fn key_octets(&self) -> &[u8; 32];
    }
}

/// A key of an integrity algorithm: KNASint, KRRCint or KUPint, of 5GS or
/// of EPS. The types of [`nas_5gs`](crate::nas_5gs) and of
/// [`nas_eps`](crate::nas_eps) implement it, and no other type can.
pub trait IntegrityKey: sealed::Key128 {}

/// A key of a ciphering algorithm: KNASenc, KRRCenc or KUPenc, of 5GS or
/// of EPS. The types of [`nas_5gs`](crate::nas_5gs) and of
/// [`nas_eps`](crate::nas_eps) implement it, and no other type can.
pub trait CipheringKey: sealed::Key128 {}

// The unit tests of the algorithms take their keys as octets, which the
// test data of 3GPP is written in.
#[cfg(test)]
impl sealed::Key128 for [u8; 16] {
    fn key_octets(&self) -> &[u8; 16] {
        self
    }
}
#[cfg(test)]
impl IntegrityKey for [u8; 16] {}
#[cfg(test)]
impl CipheringKey for [u8; 16] {}

key! {
    /// CK, the ciphering key of an authentication (TS 33.102 §6.3).
    Ck, 16
}
key! {
    /// IK, the integrity key of an authentication (TS 33.102 §6.3).
    Ik, 16
}
/// Define the type of a value that a network sends in clear: printed with
/// its octets, and not wiped.
macro_rules! public_value {
    ($(#[$attribute:meta])* $name:ident, $octets:literal) => {
        octets_type! {
            $(#[$attribute])*
            $name, $octets
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "("))?;
                for octet in &self.0 {
                    write!(f, "{octet:02x}")?;
                }
                f.write_str(")")
            }
        }
    };
}

public_value! {
    /// RAND, the challenge of an authentication. A network sends it in
    /// clear: `{:?}` prints its octets, and it is not wiped.
    Rand, 16
}
public_value! {
    /// AUTN, the authentication token: SQN xor AK, AMF and MAC
    /// (TS 33.102 §6.3.2). A network sends it in clear: `{:?}` prints its
    /// octets, and it is not wiped.
    Autn, 16
}

impl Autn {
    /// SQN xor AK, the first six octets, which the derivations of KAUSF
    /// and of KASME take.
    pub fn sqn_xor_ak(&self) -> &[u8; 6] {
        self.0.first_chunk().expect("AUTN has sixteen octets")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::error::SecurityError;

    #[test]
    fn a_key_is_built_from_octets_and_shows_none() {
        let ck = Ck::new(&[0x11; 16]);
        assert_eq!(ck.as_octets(), &[0x11; 16]);
        assert_eq!(format!("{ck:?}"), "Ck(..)");
        assert_eq!(ck, ck.clone());
        assert_eq!(ck, [0x11; 16]);
        assert_ne!(ck, Ck::new(&[0x12; 16]));

        assert_eq!(Ik::from_slice(&[0x22; 16]), Ok(Ik::new(&[0x22; 16])));
        assert_eq!(
            Ik::from_slice(&[0x22; 15]),
            Err(SecurityError::InvalidKeyLength {
                expected: 16,
                got: 15
            })
        );
    }

    #[test]
    fn rand_and_autn_are_printed_whole() {
        let rand = Rand::new(&[
            0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47,
            0xbf, 0x35,
        ]);
        assert_eq!(
            format!("{rand:?}"),
            "Rand(23553cbe9637a89d218ae64dae47bf35)"
        );
        let autn = Autn::new(&[
            0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77, 0xb9, 0xb9, 0x4a, 0x9f, 0xfa, 0xc3, 0x54, 0xdf,
            0xaf, 0xb3,
        ]);
        assert_eq!(
            format!("{autn:?}"),
            "Autn(55f328b43577b9b94a9ffac354dfafb3)"
        );
        // Built, viewed and compared as a key is
        assert_eq!(Rand::from_slice(rand.as_octets()), Ok(rand.clone()));
        assert_eq!(autn, *autn.as_octets());
        assert_eq!(
            Autn::from_slice(&[0; 15]),
            Err(SecurityError::InvalidKeyLength {
                expected: 16,
                got: 15
            })
        );
    }

    #[test]
    fn autn_gives_sqn_xor_ak() {
        let autn = Autn::new(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]);
        assert_eq!(autn.sqn_xor_ak(), &[1, 2, 3, 4, 5, 6]);
    }
}
