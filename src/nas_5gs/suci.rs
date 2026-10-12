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

//! The SUCI, the concealed form of a SUPI (TS 33.501 §6.12.2 and Annex C,
//! TS 23.003 §2.2B).
//!
//! A [`Suci`] is a SUCI with its parts: the SUPI type, the home network,
//! the routing indicator, the protection scheme, the home network public
//! key identifier and the scheme output. It is read from the octets of a
//! 5GS mobile identity ([`Suci::from_nas`]) or from the NAI format
//! ([`Suci::from_nai`]), and written back to either.
//!
//! - A UE makes one with [`Suci::conceal_imsi`] or [`Suci::conceal_nai`]:
//!   the null scheme, which conceals nothing, or ECIES with a
//!   [`HomeNetworkPublicKey`] of Profile A (X25519) or Profile B
//!   (secp256r1).
//! - A SIDF reads the scheme and the key identifier of a SUCI, takes the
//!   [`HomeNetworkPrivateKey`] that they name, and has the [`Supi`] from
//!   [`Suci::deconceal`], or a [`SuciError`] that says which step failed.
//!
//! This module is the `suci` feature. The NAI format, and with it the
//! SUPIs that are not an IMSI, are the `nai` feature beside it.

mod ecies;
#[cfg(feature = "nai")]
mod nai;

pub use ecies::{HomeNetworkPrivateKey, HomeNetworkPublicKey};

use crate::common::plmn::{Plmn, decimal_tbcd_decode, tbcd_encode};
use crate::nas_5gs::guti::MobileIdentityType;
use crate::nas_5gs::supi::{Supi, SupiType};
use alloc::{string::String, vec::Vec};
use core::fmt;
use ecies::{MAC_LEN, PROFILE_A_PUBLIC_KEY_LEN, PROFILE_B_PUBLIC_KEY_LEN};

/// A protection scheme of a SUCI (TS 33.501 Annex C.1).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProtectionScheme {
    /// The null scheme, identifier 0: the scheme output is the identity in
    /// clear.
    Null,
    /// ECIES Profile A, identifier 1: X25519 (Annex C.3.4.1).
    ProfileA,
    /// ECIES Profile B, identifier 2: secp256r1 with point compression
    /// (Annex C.3.4.2).
    ProfileB,
    /// A scheme of the home operator, with its identifier, 12 to 15. The
    /// crate reads and writes a SUCI of one, and cannot de-conceal it.
    Proprietary(u8),
}

impl ProtectionScheme {
    /// The protection scheme identifier, 0 to 15.
    pub const fn identifier(self) -> u8 {
        match self {
            Self::Null => 0,
            Self::ProfileA => 1,
            Self::ProfileB => 2,
            Self::Proprietary(identifier) => identifier,
        }
    }
}

/// The scheme of an identifier. 3 to 11 are reserved, and a number above
/// 15 is no identifier: both are [`SuciError::UnknownScheme`].
impl TryFrom<u8> for ProtectionScheme {
    type Error = SuciError;

    fn try_from(identifier: u8) -> Result<Self, SuciError> {
        match identifier {
            0 => Ok(Self::Null),
            1 => Ok(Self::ProfileA),
            2 => Ok(Self::ProfileB),
            12..=15 => Ok(Self::Proprietary(identifier)),
            _ => Err(SuciError::UnknownScheme(identifier)),
        }
    }
}

impl From<ProtectionScheme> for u8 {
    fn from(scheme: ProtectionScheme) -> u8 {
        scheme.identifier()
    }
}

/// The home network identifier of a SUCI (TS 23.003 §2.2B).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HomeNetwork<'a> {
    /// The MCC and the MNC, of a SUCI whose SUPI is an IMSI.
    Plmn(Plmn),
    /// A realm: that of a network specific identifier, a GCI or a GLI,
    /// and that of an IMSI in a SUCI that came in the NAI format, which is
    /// `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`.
    Realm(&'a str),
}

/// The scheme output of a SUCI (TS 23.003 §2.2B).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchemeOutput<'a> {
    /// Of the null scheme: the digits of the MSIN, or the username of the
    /// NAI, in clear.
    Clear(&'a str),
    /// Of Profile A and of Profile B.
    Ecies {
        /// The ephemeral public key of the UE: 32 octets with Profile A,
        /// and the 33 of a compressed point with Profile B.
        ephemeral_public_key: &'a [u8],
        /// The ciphertext, as long as the MSIN in BCD or as the username.
        ciphertext: &'a [u8],
        /// The MAC tag, eight octets.
        mac_tag: &'a [u8],
    },
    /// Of a scheme of the home operator: its octets.
    Proprietary(&'a [u8]),
}

/// How a UE conceals its SUPI.
#[non_exhaustive]
#[derive(Clone, Copy, Debug)]
pub enum Protection<'a> {
    /// With the null scheme: not at all.
    Null,
    /// With ECIES, by the profile of the key.
    Ecies {
        /// The home network public key identifier that the home network
        /// gave the key, 1 to 254.
        key_id: u8,
        /// The home network public key.
        key: &'a HomeNetworkPublicKey,
    },
}

/// Why a SUCI was not read, concealed or de-concealed.
///
/// # What a SIDF tells its peers
///
/// The variant is for the log of the network function that de-conceals.
/// The network function that asked gets one of three causes
/// (TS 29.503 §6.3.7.3):
///
/// - `UNSUPPORTED_PROTECTION_SCHEME` for [`UnknownScheme`](Self::UnknownScheme)
///   and [`ProprietaryScheme`](Self::ProprietaryScheme);
/// - `INVALID_HN_PUBLIC_KEY_IDENTIFIER` for
///   [`KeyIdentifier`](Self::KeyIdentifier), [`MissingKey`](Self::MissingKey)
///   and [`WrongKeyType`](Self::WrongKeyType);
/// - `INVALID_SCHEME_OUTPUT` for every other one.
///
/// [`MalformedPoint`](Self::MalformedPoint),
/// [`MacMismatch`](Self::MacMismatch) and [`Plaintext`](Self::Plaintext)
/// must not be told apart outside the SIDF, to the UE least of all: they
/// say how far a forged SUCI went, which is what its sender wants to
/// learn. The UE is told that its registration is rejected, and no more.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SuciError {
    /// Fewer octets than the SUCI has to have: of the mobile identity, or
    /// of a scheme output of ECIES, which is an ephemeral public key, at
    /// least one octet of ciphertext and a MAC tag.
    Truncated,
    /// A mobile identity whose type of identity is not SUCI.
    NotASuci,
    /// A home network identifier that is not an MCC and an MNC of decimal
    /// digits.
    HomeNetwork,
    /// A routing indicator that is not 1 to 4 decimal digits, or that is
    /// not 0 with a GCI or a GLI.
    RoutingIndicator,
    /// A protection scheme identifier that names no scheme: 3 to 11,
    /// which are reserved, or a number above 15.
    UnknownScheme(u8),
    /// A home network public key identifier that the scheme cannot have:
    /// another than 0 with the null scheme, and 0 or 255 with any other.
    KeyIdentifier(u8),
    /// A scheme output of the null scheme that is not an identity of the
    /// SUPI type: an MSIN of decimal digits, a username, a GCI or a GLI.
    SchemeOutput,
    /// A SUPI type that is not defined: 4 to 7 in the NAI format.
    SupiType(u8),
    /// A SUCI in the NAI format whose SUPI type is not the one that the
    /// SUPI format of its mobile identity says.
    SupiTypeMismatch,
    /// A GCI or a GLI with another scheme than the null scheme, the only
    /// one that they have.
    NullSchemeRequired,
    /// A SUCI in the NAI format, or the NAI of a SUPI, that is not one.
    Nai(NaiError),
    /// A SUCI in the NAI format, in a build without the `nai` feature.
    NaiNotSupported,
    /// An IMSI of a SUCI that came in the NAI format: its realm writes the
    /// MNC with three digits, of which an MNC of two has one in front, so
    /// the IMSI is not known from it. Its home network, which knows its
    /// own MNC, reads the SUCI in the form of the mobile identity.
    MncLengthUnknown,
    /// A SUCI of Profile A or of Profile B, and no private key.
    MissingKey,
    /// A private key of another profile than the SUCI.
    WrongKeyType {
        /// The protection scheme of the SUCI.
        suci: ProtectionScheme,
        /// The profile of the key.
        key: ProtectionScheme,
    },
    /// A SUCI of a scheme of the home operator, with its identifier: the
    /// crate does not know how it is de-concealed.
    ProprietaryScheme(u8),
    /// An ephemeral public key that the profile does not accept: octets
    /// that are not a compressed point of secp256r1, or a point of small
    /// order of Curve25519.
    MalformedPoint,
    /// A MAC tag that is not the one of the ciphertext: the SUCI was not
    /// concealed for this key, or was changed.
    MacMismatch,
    /// A plaintext, under a MAC tag that is right, that is not an
    /// identity of the SUPI type.
    Plaintext,
    /// A home network key that is not one of its profile: octets that are
    /// not a point of secp256r1 in its compressed or uncompressed form, a
    /// private key that is zero or not below the order of that curve, or
    /// a public key of small order of Curve25519.
    InvalidKey,
    /// An identity that cannot be concealed: an MSIN that is not decimal
    /// digits or is too long for its IMSI, or a SUPI of another type than
    /// the function takes.
    Identity,
    /// The random number generator of the system failed, and no ephemeral
    /// key was drawn.
    RandomSource,
}

impl fmt::Display for SuciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => f.write_str("the SUCI is truncated"),
            Self::NotASuci => f.write_str("the mobile identity is not a SUCI"),
            Self::HomeNetwork => {
                f.write_str("the home network identifier is not an MCC and an MNC")
            }
            Self::RoutingIndicator => f.write_str("invalid routing indicator"),
            Self::UnknownScheme(identifier) => {
                write!(f, "unknown protection scheme identifier {identifier}")
            }
            Self::KeyIdentifier(identifier) => write!(
                f,
                "home network public key identifier {identifier} is not one of the scheme"
            ),
            Self::SchemeOutput => f.write_str("the scheme output is not an identity in clear"),
            Self::SupiType(kind) => write!(f, "undefined SUPI type {kind}"),
            Self::SupiTypeMismatch => {
                f.write_str("the SUPI type of the NAI is not that of the mobile identity")
            }
            Self::NullSchemeRequired => {
                f.write_str("a GCI or a GLI has the null scheme and no other")
            }
            Self::Nai(error) => write!(f, "{error}"),
            Self::NaiNotSupported => {
                f.write_str("a SUCI in the NAI format needs the `nai` feature")
            }
            Self::MncLengthUnknown => {
                f.write_str("the realm of an IMSI does not say how many digits its MNC has")
            }
            Self::MissingKey => f.write_str("no home network private key for the SUCI"),
            Self::WrongKeyType { suci, key } => write!(
                f,
                "a home network private key of {key:?} for a SUCI of {suci:?}"
            ),
            Self::ProprietaryScheme(identifier) => write!(
                f,
                "protection scheme {identifier} is one of the home operator"
            ),
            Self::MalformedPoint => f.write_str("malformed ephemeral public key"),
            Self::MacMismatch => f.write_str("MAC verification failed"),
            Self::Plaintext => f.write_str("the de-concealed plaintext is not an identity"),
            Self::InvalidKey => f.write_str("invalid home network key"),
            Self::Identity => f.write_str("the identity cannot be concealed"),
            Self::RandomSource => f.write_str("the system random number generator failed"),
        }
    }
}

impl core::error::Error for SuciError {}

/// Why a text is not a SUCI in the NAI format (TS 23.003 §28.7.3), or not
/// the NAI of a SUPI.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NaiError {
    /// Longer than the longest SUCI in the NAI format. Nothing else of it
    /// was looked at.
    TooLong,
    /// Octets of a mobile identity that are not a text in UTF-8.
    Encoding,
    /// No `@`: an NAI is a username, `@` and a realm.
    NoRealm,
    /// A realm that is not a domain name of RFC 7542 §2.2 and RFC 5891:
    /// two labels at least, of letters, digits and hyphens, normalized,
    /// and 253 octets at most.
    Realm,
    /// A username that is not one of RFC 7542 §2.2, is not normalized, is
    /// longer than 253 octets, or is not a GLI in base64.
    Username,
    /// A field of the username of a SUCI that is missing or is not as its
    /// format has it, by its name: `type`, `rid`, `schid`, `userid`,
    /// `hnkey`, `ecckey`, `cip`, `mac` or `out`.
    Field(&'static str),
    /// An IMSI whose realm is not `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`,
    /// with the NID of an SNPN or without it.
    ImsiRealm,
}

impl fmt::Display for NaiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLong => f.write_str("the NAI is longer than a SUCI can be"),
            Self::Encoding => f.write_str("the NAI is not a text in UTF-8"),
            Self::NoRealm => f.write_str("the NAI has no @ and no realm"),
            Self::Realm => f.write_str("the realm of the NAI is not a domain name"),
            Self::Username => f.write_str("the username of the NAI is not one"),
            Self::Field(field) => {
                write!(f, "the `{field}` field of the SUCI is missing or malformed")
            }
            Self::ImsiRealm => {
                f.write_str("the realm of an IMSI is 5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org")
            }
        }
    }
}

impl core::error::Error for NaiError {}

impl From<NaiError> for SuciError {
    fn from(error: NaiError) -> Self {
        Self::Nai(error)
    }
}

/// A routing indicator: 1 to 4 decimal digits, each of which counts
/// (TS 23.003 §2.2B).
#[derive(Clone, Copy, PartialEq, Eq)]
struct RoutingIndicator {
    digits: [u8; 4],
    len: u8,
}

impl RoutingIndicator {
    fn new(digits: &str) -> Result<Self, SuciError> {
        if !(1..=4).contains(&digits.len()) || !digits.bytes().all(|digit| digit.is_ascii_digit()) {
            return Err(SuciError::RoutingIndicator);
        }
        let mut indicator = Self {
            digits: [0; 4],
            len: digits.len() as u8,
        };
        indicator.digits[..digits.len()].copy_from_slice(digits.as_bytes());
        Ok(indicator)
    }

    /// From the two octets of a mobile identity: BCD digits, the first in
    /// the low four bits, and the filler 0xF after the last
    /// (TS 24.501 Table 9.11.3.4.1).
    fn from_octets(octets: [u8; 2]) -> Result<Self, SuciError> {
        let nibbles = [
            octets[0] & 0x0f,
            octets[0] >> 4,
            octets[1] & 0x0f,
            octets[1] >> 4,
        ];
        let len = nibbles.iter().take_while(|nibble| **nibble <= 9).count();
        if len == 0 || nibbles[len..].iter().any(|nibble| *nibble != 0x0f) {
            return Err(SuciError::RoutingIndicator);
        }
        let mut digits = [0; 4];
        for (digit, nibble) in digits.iter_mut().zip(&nibbles[..len]) {
            *digit = b'0' + nibble;
        }
        Ok(Self {
            digits,
            len: len as u8,
        })
    }

    fn to_octets(self) -> [u8; 2] {
        let nibble = |index: usize| {
            if index < usize::from(self.len) {
                self.digits[index] - b'0'
            } else {
                0x0f
            }
        };
        [(nibble(1) << 4) | nibble(0), (nibble(3) << 4) | nibble(2)]
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.digits[..usize::from(self.len)]).expect("decimal digits")
    }
}

/// The home network of a SUCI, with a realm of its own.
#[derive(Clone, PartialEq, Eq)]
enum Home {
    Plmn(Plmn),
    #[cfg_attr(not(feature = "nai"), allow(dead_code))]
    Realm(String),
}

/// A SUCI with its parts (TS 23.003 §2.2B).
///
/// ```
/// use oxirush_security::nas_5gs::{
///     HomeNetwork, HomeNetworkPrivateKey, Protection, ProtectionScheme, Suci, SuciError,
/// };
/// use oxirush_security::Plmn;
///
/// // The home network has a key pair of Profile A, and gives its
/// // subscribers the public key with the identifier 1
/// let private_key = HomeNetworkPrivateKey::profile_a(&[0x42; 32]);
/// let public_key = private_key.public_key();
///
/// // A UE conceals its IMSI, 208 93 0000000001
/// let protection = Protection::Ecies { key_id: 1, key: &public_key };
/// let suci = Suci::conceal_imsi(Plmn::new("208", "93")?, "0000000001", "0", protection)?;
/// let identity = suci.to_nas()?;
///
/// // The SIDF reads the mobile identity and chooses its key
/// let received = Suci::from_nas(&identity)?;
/// assert_eq!(received.home_network(), HomeNetwork::Plmn(Plmn::new("208", "93")?));
/// assert_eq!(received.routing_indicator(), "0");
/// assert_eq!(received.protection_scheme(), ProtectionScheme::ProfileA);
/// assert_eq!(received.home_network_public_key_id(), 1);
///
/// let supi = received.deconceal(Some(&private_key))?;
/// assert_eq!(supi.to_string(), "imsi-208930000000001");
///
/// // Without the key, and with a tag that was changed
/// assert_eq!(received.deconceal(None), Err(SuciError::MissingKey));
/// let mut changed = identity.clone();
/// *changed.last_mut().unwrap() ^= 1;
/// assert_eq!(
///     Suci::from_nas(&changed)?.deconceal(Some(&private_key)),
///     Err(SuciError::MacMismatch)
/// );
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Clone, PartialEq, Eq)]
pub struct Suci {
    supi_type: SupiType,
    home: Home,
    routing_indicator: RoutingIndicator,
    scheme: ProtectionScheme,
    key_id: u8,
    /// The scheme output: with the null scheme the characters of the
    /// identity in clear, and with another the octets of the output.
    output: Vec<u8>,
}

/// Whether `msin` is the MSIN of an IMSI of `plmn`: decimal digits, and
/// 15 at most with those of the PLMN (TS 23.003 §2.2).
fn valid_msin(plmn: Plmn, msin: &str) -> bool {
    let longest = 15 - plmn.mcc().len() - plmn.mnc().len();
    (1..=longest).contains(&msin.len()) && msin.bytes().all(|digit| digit.is_ascii_digit())
}

impl Suci {
    /// A SUCI of parts that are checked here, each against the others.
    fn checked(
        supi_type: SupiType,
        home: Home,
        routing_indicator: RoutingIndicator,
        scheme: ProtectionScheme,
        key_id: u8,
        output: Vec<u8>,
    ) -> Result<Self, SuciError> {
        // The identifier is 0 if and only if the scheme is the null one
        // (TS 23.003 §2.2B), and 255 is reserved (TS 24.501 §9.11.3.4)
        match (scheme, key_id) {
            (ProtectionScheme::Null, 0) => {}
            (ProtectionScheme::Null, _) | (_, 0 | 255) => {
                return Err(SuciError::KeyIdentifier(key_id));
            }
            _ => {}
        }
        // A GCI and a GLI have the null scheme and the routing indicator 0
        // (TS 23.003 §28.15.5 and §28.16.5)
        if matches!(supi_type, SupiType::Gci | SupiType::Gli) {
            if scheme != ProtectionScheme::Null {
                return Err(SuciError::NullSchemeRequired);
            }
            if routing_indicator.as_str() != "0" {
                return Err(SuciError::RoutingIndicator);
            }
        }
        let suci = Self {
            supi_type,
            home,
            routing_indicator,
            scheme,
            key_id,
            output,
        };
        #[cfg(feature = "nai")]
        nai::check(&suci)?;
        match scheme {
            ProtectionScheme::Null => {
                let clear =
                    core::str::from_utf8(&suci.output).map_err(|_| SuciError::SchemeOutput)?;
                if !suci.valid_identity(clear) {
                    return Err(SuciError::SchemeOutput);
                }
            }
            ProtectionScheme::ProfileA | ProtectionScheme::ProfileB => {
                if suci.output.len() < suci.public_key_len() + 1 + MAC_LEN {
                    return Err(SuciError::Truncated);
                }
            }
            ProtectionScheme::Proprietary(_) => {}
        }
        Ok(suci)
    }

    /// Octets of the ephemeral public key of the profile of the SUCI.
    fn public_key_len(&self) -> usize {
        match self.scheme {
            ProtectionScheme::ProfileB => PROFILE_B_PUBLIC_KEY_LEN,
            _ => PROFILE_A_PUBLIC_KEY_LEN,
        }
    }

    /// Whether `clear` is the identity of a SUPI of the type and the home
    /// network of the SUCI: its MSIN, or the username of its NAI.
    fn valid_identity(&self, clear: &str) -> bool {
        match (&self.home, self.supi_type) {
            (Home::Plmn(plmn), _) => valid_msin(*plmn, clear),
            #[cfg(feature = "nai")]
            (Home::Realm(_), kind) => nai::valid_identity(kind, clear),
            #[cfg(not(feature = "nai"))]
            (Home::Realm(_), _) => false,
        }
    }

    /// Read the SUCI of a 5GS mobile identity: its octets from the one
    /// that has the type of identity, after the length
    /// (TS 24.501 §9.11.3.4).
    ///
    /// The spare bits are ignored, and a SUPI format of 4 to 7 is read as
    /// an IMSI, as that clause has a receiver do. A SUCI in the NAI
    /// format is read as [`from_nai`](Self::from_nai) reads it, with the
    /// `nai` feature, and is [`SuciError::NaiNotSupported`] without it.
    pub fn from_nas(identity: &[u8]) -> Result<Self, SuciError> {
        let Some((first, rest)) = identity.split_first() else {
            return Err(SuciError::Truncated);
        };
        if MobileIdentityType::of(identity) != Some(MobileIdentityType::Suci) {
            return Err(SuciError::NotASuci);
        }
        let supi_type = match (first >> 4) & 0x07 {
            1 => SupiType::NetworkSpecific,
            // The SUPI format of NAS has GCI before GLI, and the SUPI
            // type of TS 23.003 the other way round
            2 => SupiType::Gci,
            3 => SupiType::Gli,
            _ => SupiType::Imsi,
        };
        if supi_type != SupiType::Imsi {
            #[cfg(feature = "nai")]
            {
                // The length first: a text that is too long is not read
                if rest.len() > nai::LONGEST_SUCI_NAI {
                    return Err(NaiError::TooLong.into());
                }
                let text = core::str::from_utf8(rest).map_err(|_| NaiError::Encoding)?;
                let suci = nai::parse(text)?;
                return if suci.supi_type == supi_type {
                    Ok(suci)
                } else {
                    Err(SuciError::SupiTypeMismatch)
                };
            }
            #[cfg(not(feature = "nai"))]
            return Err(SuciError::NaiNotSupported);
        }

        // The PLMN, the routing indicator, the scheme, the key identifier
        // and one octet of scheme output at least
        let [
            plmn_1,
            plmn_2,
            plmn_3,
            routing_1,
            routing_2,
            scheme,
            key_id,
            output @ ..,
        ] = rest
        else {
            return Err(SuciError::Truncated);
        };
        if output.is_empty() {
            return Err(SuciError::Truncated);
        }
        let plmn =
            Plmn::from_octets(&[*plmn_1, *plmn_2, *plmn_3]).map_err(|_| SuciError::HomeNetwork)?;
        let routing_indicator = RoutingIndicator::from_octets([*routing_1, *routing_2])?;
        // Bits 8 to 5 of the octet of the scheme are spare
        let scheme = ProtectionScheme::try_from(scheme & 0x0f)?;
        let output = match scheme {
            // The MSIN in BCD: its digits are kept
            ProtectionScheme::Null => decimal_tbcd_decode(output)
                .ok_or(SuciError::SchemeOutput)?
                .into_bytes(),
            _ => output.to_vec(),
        };
        Self::checked(
            SupiType::Imsi,
            Home::Plmn(plmn),
            routing_indicator,
            scheme,
            *key_id,
            output,
        )
    }

    /// The octets of the 5GS mobile identity of the SUCI, from the one
    /// that has the type of identity (TS 24.501 §9.11.3.4).
    ///
    /// An IMSI that came in the NAI format has no such form here: the
    /// result is [`SuciError::MncLengthUnknown`].
    pub fn to_nas(&self) -> Result<Vec<u8>, SuciError> {
        let plmn = match (&self.home, self.supi_type) {
            (Home::Plmn(plmn), _) => plmn,
            (Home::Realm(_), SupiType::Imsi) => return Err(SuciError::MncLengthUnknown),
            #[cfg(feature = "nai")]
            (Home::Realm(_), kind) => {
                let format = match kind {
                    SupiType::Gci => 2,
                    SupiType::Gli => 3,
                    _ => 1,
                };
                let mut identity = alloc::vec![(format << 4) | MobileIdentityType::Suci as u8];
                identity.extend_from_slice(nai::encode(self).as_bytes());
                return Ok(identity);
            }
            #[cfg(not(feature = "nai"))]
            (Home::Realm(_), _) => return Err(SuciError::NaiNotSupported),
        };
        let mut identity = Vec::with_capacity(8 + self.output.len());
        identity.push(MobileIdentityType::Suci as u8);
        identity.extend_from_slice(&plmn.to_octets());
        identity.extend_from_slice(&self.routing_indicator.to_octets());
        identity.push(self.scheme.identifier());
        identity.push(self.key_id);
        match self.scheme_output() {
            SchemeOutput::Clear(msin) => {
                let bcd = tbcd_encode(msin).expect("the MSIN is decimal digits");
                identity.extend_from_slice(&bcd);
            }
            _ => identity.extend_from_slice(&self.output),
        }
        Ok(identity)
    }

    /// Read a SUCI in the NAI format (TS 23.003 §28.7.3, §28.15.5 and
    /// §28.16.5), such as
    /// `type1.rid678.schid0.useriduser17@example.com`.
    ///
    /// A text longer than a SUCI can be is refused before anything else
    /// of it is looked at, and so is a realm of more than 253 octets.
    #[cfg(feature = "nai")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nai")))]
    pub fn from_nai(nai: &str) -> Result<Self, SuciError> {
        nai::parse(nai)
    }

    /// The SUCI in the NAI format (TS 23.003 §28.7.3). The octets of a
    /// scheme output are written in lower-case hexadecimal digits, and the
    /// realm of an IMSI is `5gc.mnc<MNC>.mcc<MCC>.3gppnetwork.org`.
    #[cfg(feature = "nai")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nai")))]
    pub fn to_nai(&self) -> String {
        nai::encode(self)
    }

    /// Conceal an IMSI: the PLMN of its home network, then its MSIN.
    ///
    /// `routing_indicator` is 1 to 4 decimal digits, `"0"` when the USIM
    /// has none (TS 23.003 §2.2B). With [`Protection::Ecies`], a fresh
    /// ephemeral key is drawn from the random number generator of the
    /// system, so two SUCIs of one IMSI are not alike.
    ///
    /// An `msin` that is not decimal digits, or that makes an IMSI of
    /// more than 15, is [`SuciError::Identity`].
    pub fn conceal_imsi(
        plmn: Plmn,
        msin: &str,
        routing_indicator: &str,
        protection: Protection<'_>,
    ) -> Result<Self, SuciError> {
        if !valid_msin(plmn, msin) {
            return Err(SuciError::Identity);
        }
        let routing_indicator = RoutingIndicator::new(routing_indicator)?;
        let (scheme, key_id, output) = match protection {
            Protection::Null => (ProtectionScheme::Null, 0, msin.as_bytes().to_vec()),
            Protection::Ecies { key_id, key } => {
                // The MSIN in BCD is the plaintext (TS 33.501 Annex C.3.1)
                let bcd = tbcd_encode(msin).expect("the MSIN is decimal digits");
                (key.scheme(), key_id, Self::protect(key_id, key, &bcd)?)
            }
        };
        let home = Home::Plmn(plmn);
        Self::checked(
            SupiType::Imsi,
            home,
            routing_indicator,
            scheme,
            key_id,
            output,
        )
    }

    /// Conceal a SUPI that has the form of a NAI: a network specific
    /// identifier, a GCI or a GLI.
    ///
    /// The username is what is concealed, and the realm stays in clear. A
    /// GCI and a GLI have the null scheme and the routing indicator `"0"`
    /// (TS 23.003 §28.15.5 and §28.16.5). An IMSI is
    /// [`SuciError::Identity`]: [`conceal_imsi`](Self::conceal_imsi) takes
    /// it with its PLMN.
    #[cfg(feature = "nai")]
    #[cfg_attr(docsrs, doc(cfg(feature = "nai")))]
    pub fn conceal_nai(
        supi: &Supi<'_>,
        routing_indicator: &str,
        protection: Protection<'_>,
    ) -> Result<Self, SuciError> {
        let kind = supi.supi_type();
        if kind == SupiType::Imsi {
            return Err(SuciError::Identity);
        }
        let (username, realm) = nai::username_and_realm(kind, supi.identity())?;
        let routing_indicator = RoutingIndicator::new(routing_indicator)?;
        let (scheme, key_id, output) = match protection {
            Protection::Null => (ProtectionScheme::Null, 0, username.as_bytes().to_vec()),
            Protection::Ecies { .. } if kind != SupiType::NetworkSpecific => {
                return Err(SuciError::NullSchemeRequired);
            }
            // A scheme output without ciphertext is none
            Protection::Ecies { .. } if username.is_empty() => {
                return Err(NaiError::Username.into());
            }
            Protection::Ecies { key_id, key } => {
                let output = Self::protect(key_id, key, username.as_bytes())?;
                (key.scheme(), key_id, output)
            }
        };
        let home = Home::Realm(String::from(realm));
        Self::checked(kind, home, routing_indicator, scheme, key_id, output)
    }

    /// The scheme output of a plaintext under a key and its identifier.
    fn protect(
        key_id: u8,
        key: &HomeNetworkPublicKey,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, SuciError> {
        // Before a key is drawn for an identifier that no SUCI has
        if matches!(key_id, 0 | 255) {
            return Err(SuciError::KeyIdentifier(key_id));
        }
        ecies::conceal(key, plaintext)
    }

    /// The SUPI type.
    pub fn supi_type(&self) -> SupiType {
        self.supi_type
    }

    /// The home network identifier.
    pub fn home_network(&self) -> HomeNetwork<'_> {
        match &self.home {
            Home::Plmn(plmn) => HomeNetwork::Plmn(*plmn),
            Home::Realm(realm) => HomeNetwork::Realm(realm),
        }
    }

    /// The routing indicator: 1 to 4 decimal digits, each of which
    /// counts, so `"012"` is not `"12"`.
    pub fn routing_indicator(&self) -> &str {
        self.routing_indicator.as_str()
    }

    /// The protection scheme.
    pub fn protection_scheme(&self) -> ProtectionScheme {
        self.scheme
    }

    /// The home network public key identifier: 0 with the null scheme,
    /// and 1 to 254 with another. With the protection scheme, it names
    /// the private key that de-conceals the SUCI.
    pub fn home_network_public_key_id(&self) -> u8 {
        self.key_id
    }

    /// The scheme output.
    pub fn scheme_output(&self) -> SchemeOutput<'_> {
        match self.scheme {
            ProtectionScheme::Null => SchemeOutput::Clear(
                core::str::from_utf8(&self.output).expect("checked when the SUCI was made"),
            ),
            ProtectionScheme::ProfileA | ProtectionScheme::ProfileB => {
                let (ephemeral_public_key, rest) = self.output.split_at(self.public_key_len());
                let (ciphertext, mac_tag) = rest.split_at(rest.len() - MAC_LEN);
                SchemeOutput::Ecies {
                    ephemeral_public_key,
                    ciphertext,
                    mac_tag,
                }
            }
            ProtectionScheme::Proprietary(_) => SchemeOutput::Proprietary(&self.output),
        }
    }

    /// De-conceal the SUCI: the SUPI of the subscriber.
    ///
    /// `key` is the private key that the protection scheme and the home
    /// network public key identifier of the SUCI name. The null scheme
    /// needs none, and ignores one.
    ///
    /// The checks follow TS 33.501 Annex C.3.3 in this order, and the
    /// error says which one failed: the key ([`SuciError::MissingKey`],
    /// [`SuciError::WrongKeyType`]), the ephemeral public key
    /// ([`SuciError::MalformedPoint`]), the MAC tag
    /// ([`SuciError::MacMismatch`]), which is compared in a time that does
    /// not depend on where it differs, and then the plaintext, which is
    /// decrypted only under a tag that is right
    /// ([`SuciError::Plaintext`]). See [`SuciError`] for what a peer may
    /// be told of them.
    ///
    /// The SUPI is what [`derive_kamf`](crate::nas_5gs::derive_kamf)
    /// takes.
    pub fn deconceal(
        &self,
        key: Option<&HomeNetworkPrivateKey>,
    ) -> Result<Supi<'static>, SuciError> {
        if matches!(
            (&self.home, self.supi_type),
            (Home::Realm(_), SupiType::Imsi)
        ) {
            return Err(SuciError::MncLengthUnknown);
        }
        let identity = match self.scheme {
            ProtectionScheme::Null => {
                String::from_utf8(self.output.clone()).expect("checked when the SUCI was made")
            }
            ProtectionScheme::ProfileA | ProtectionScheme::ProfileB => {
                let key = key.ok_or(SuciError::MissingKey)?;
                if key.scheme() != self.scheme {
                    return Err(SuciError::WrongKeyType {
                        suci: self.scheme,
                        key: key.scheme(),
                    });
                }
                let plaintext = ecies::deconceal(key, &self.output)?;
                let identity = match self.home {
                    // The MSIN in BCD
                    Home::Plmn(_) => decimal_tbcd_decode(&plaintext),
                    Home::Realm(_) => String::from_utf8(plaintext.to_vec()).ok(),
                };
                identity
                    .filter(|identity| self.valid_identity(identity))
                    .ok_or(SuciError::Plaintext)?
            }
            ProtectionScheme::Proprietary(identifier) => {
                return Err(SuciError::ProprietaryScheme(identifier));
            }
        };
        Ok(match &self.home {
            Home::Plmn(plmn) => {
                let imsi = alloc::format!("{}{}{identity}", plmn.mcc(), plmn.mnc());
                Supi::owned(SupiType::Imsi, imsi)
            }
            Home::Realm(realm) => Supi::owned(self.supi_type, alloc::format!("{identity}@{realm}")),
        })
    }
}

/// The SUCI as the service based interfaces write it (TS 29.571 §5.3.2):
/// `suci-`, then the SUPI type, the home network, the routing indicator,
/// the protection scheme identifier, the home network public key
/// identifier and the scheme output, with hyphens between them. The home
/// network of an IMSI is its MCC and its MNC, and a scheme output that is
/// not in clear is in hexadecimal digits:
/// `suci-0-208-93-0-0-0-0000000001`.
///
/// An IMSI that came in the NAI format has its realm in the place of the
/// MCC and the MNC, which the realm does not tell apart.
impl fmt::Display for Suci {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self.supi_type {
            SupiType::Imsi => 0,
            SupiType::NetworkSpecific => 1,
            SupiType::Gli => 2,
            SupiType::Gci => 3,
        };
        write!(f, "suci-{kind}-")?;
        match &self.home {
            Home::Plmn(plmn) => write!(f, "{}-{}", plmn.mcc(), plmn.mnc())?,
            Home::Realm(realm) => f.write_str(realm)?,
        }
        let (routing_indicator, scheme) = (self.routing_indicator(), self.scheme.identifier());
        write!(f, "-{routing_indicator}-{scheme}-{}-", self.key_id)?;
        match self.scheme_output() {
            SchemeOutput::Clear(clear) => f.write_str(clear),
            _ => self
                .output
                .iter()
                .try_for_each(|octet| write!(f, "{octet:02x}")),
        }
    }
}

impl fmt::Debug for Suci {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Suci({self})")
    }
}

#[cfg(test)]
pub(crate) mod test_keys {
    //! The home network keys of TS 33.501 Annex C.4.
    use super::{HomeNetworkPrivateKey, HomeNetworkPublicKey};

    pub(crate) const PROFILE_A_PRIV: &str =
        "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    pub(crate) const PROFILE_A_PUB: &str =
        "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
    pub(crate) const PROFILE_B_PRIV: &str =
        "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA";
    pub(crate) const PROFILE_B_PUB: &str = "0472DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD15A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4";

    fn octets<const N: usize>(hexadecimal: &str) -> [u8; N] {
        hex::decode(hexadecimal).unwrap().try_into().unwrap()
    }

    pub(crate) fn private_a() -> HomeNetworkPrivateKey {
        HomeNetworkPrivateKey::profile_a(&octets(PROFILE_A_PRIV))
    }

    pub(crate) fn public_a() -> HomeNetworkPublicKey {
        HomeNetworkPublicKey::profile_a(&octets(PROFILE_A_PUB))
    }

    pub(crate) fn private_b() -> HomeNetworkPrivateKey {
        HomeNetworkPrivateKey::profile_b(&octets(PROFILE_B_PRIV)).unwrap()
    }

    pub(crate) fn public_b() -> HomeNetworkPublicKey {
        HomeNetworkPublicKey::profile_b(&hex::decode(PROFILE_B_PUB).unwrap()).unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::test_keys::*;
    use super::*;

    fn plmn(mcc: &str, mnc: &str) -> Plmn {
        Plmn::new(mcc, mnc).unwrap()
    }

    /// The mobile identity of a SUCI of an IMSI of 208 93, with the
    /// routing indicator 0.
    fn identity(scheme: u8, key_id: u8, scheme_output: &[u8]) -> Vec<u8> {
        let mut identity = vec![0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, scheme, key_id];
        identity.extend_from_slice(scheme_output);
        identity
    }

    fn ecies(key_id: u8, key: &HomeNetworkPublicKey) -> Protection<'_> {
        Protection::Ecies { key_id, key }
    }

    /// The keys of Annex C.4 are a pair.
    #[test]
    fn the_public_key_of_a_private_key_is_the_one_of_annex_c4() {
        assert_eq!(private_a().public_key(), public_a());
        assert_eq!(private_b().public_key(), public_b());
        assert_eq!(hex::encode(public_a().to_octets()), PROFILE_A_PUB);
        // The compressed form of the point that Annex C.4.4 writes whole
        assert_eq!(
            hex::encode(public_b().to_octets()),
            "0272da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1"
        );
    }

    /// TS 24.501 Figure 9.11.3.4.3: the MSIN of the null scheme in BCD,
    /// the first digit of each pair in the low four bits, and the filler
    /// 0xF after an odd number of digits.
    #[test]
    fn the_null_scheme_writes_the_msin_in_bcd() {
        for (msin, bcd) in [
            ("00007487", &[0x00, 0x00, 0x47, 0x78][..]),
            ("001002086", &[0x00, 0x01, 0x20, 0x80, 0xf6]),
            ("0123456789", &[0x10, 0x32, 0x54, 0x76, 0x98]),
            ("0000000001", &[0x00, 0x00, 0x00, 0x00, 0x10]),
        ] {
            let suci = Suci::conceal_imsi(plmn("208", "93"), msin, "0", Protection::Null).unwrap();
            assert_eq!(suci.scheme_output(), SchemeOutput::Clear(msin));
            let nas = suci.to_nas().unwrap();
            assert_eq!(nas, identity(0, 0, bcd), "{msin}");
            let read = Suci::from_nas(&nas).unwrap();
            assert_eq!(read, suci);
            assert_eq!(
                read.deconceal(None).unwrap().to_string(),
                format!("imsi-20893{msin}")
            );
        }
    }

    /// TS 33.501 Annex C.4.2.1: with the null scheme, the scheme output of
    /// the IMSI 274012001002086 is its MSIN, 001002086.
    #[test]
    fn annex_c4_null_scheme_vector() {
        let suci =
            Suci::conceal_imsi(plmn("274", "012"), "001002086", "0", Protection::Null).unwrap();
        assert_eq!(suci.to_string(), "suci-0-274-012-0-0-0-001002086");
        assert_eq!(hex::encode(&suci.to_nas().unwrap()[8..]), "00012080f6");
        assert_eq!(
            suci.deconceal(None).unwrap(),
            Supi::imsi("274012001002086").unwrap()
        );
    }

    #[test]
    fn a_suci_is_de_concealed_by_the_key_of_its_profile() {
        for msin in [
            "0010020862",
            "00007487",
            "001002086",
            "0123456789",
            "0000000001",
            "1",
        ] {
            for (public, private, scheme, key_len) in [
                (public_a(), private_a(), ProtectionScheme::ProfileA, 32),
                (public_b(), private_b(), ProtectionScheme::ProfileB, 33),
            ] {
                let suci =
                    Suci::conceal_imsi(plmn("208", "93"), msin, "0", ecies(7, &public)).unwrap();
                assert_eq!(suci.supi_type(), SupiType::Imsi);
                assert_eq!(suci.home_network(), HomeNetwork::Plmn(plmn("208", "93")));
                assert_eq!(suci.protection_scheme(), scheme);
                assert_eq!(suci.home_network_public_key_id(), 7);
                let SchemeOutput::Ecies {
                    ephemeral_public_key,
                    ciphertext,
                    mac_tag,
                } = suci.scheme_output()
                else {
                    panic!("the scheme output of a profile");
                };
                assert_eq!(ephemeral_public_key.len(), key_len);
                assert_eq!(ciphertext.len(), msin.len().div_ceil(2));
                assert_eq!(mac_tag.len(), 8);

                let received = Suci::from_nas(&suci.to_nas().unwrap()).unwrap();
                assert_eq!(received, suci);
                assert_eq!(
                    received.deconceal(Some(&private)).unwrap().to_string(),
                    format!("imsi-20893{msin}"),
                );
            }
        }
        // Each concealment draws a key of its own
        let conceal = || {
            Suci::conceal_imsi(plmn("208", "93"), "0000000001", "0", ecies(1, &public_a())).unwrap()
        };
        assert_ne!(conceal(), conceal());
    }

    /// The scheme outputs of TS 33.501 Annex C.4.3.1 and C.4.4.1, of the
    /// IMSI 274012001002086, and one that another implementation made for
    /// the MSIN 0123456789 of 001 01 with the key of Profile B.
    #[test]
    fn known_scheme_outputs_are_de_concealed() {
        let profile_a = hex::decode(
            "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d\
             cb02352410\
             cddd9e730ef3fa87",
        )
        .unwrap();
        let mut nas = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
        nas.extend_from_slice(&profile_a);
        let suci = Suci::from_nas(&nas).unwrap();
        assert_eq!(suci.home_network(), HomeNetwork::Plmn(plmn("274", "012")));
        assert_eq!(
            suci.to_string(),
            format!("suci-0-274-012-0-1-27-{}", hex::encode(&profile_a))
        );
        assert_eq!(
            suci.deconceal(Some(&private_a())).unwrap().to_string(),
            "imsi-274012001002086"
        );

        let profile_b = hex::decode(
            "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1\
             46a33fc271\
             6ac7dae96aa30a4d",
        )
        .unwrap();
        let mut nas = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x02, 27];
        nas.extend_from_slice(&profile_b);
        assert_eq!(
            Suci::from_nas(&nas)
                .unwrap()
                .deconceal(Some(&private_b()))
                .unwrap()
                .to_string(),
            "imsi-274012001002086"
        );

        // 33 octets of key, 5 of ciphertext and 8 of tag
        let ten_digits = hex::decode(
            "03a7b1db2a9db9d44112b59d03d8243dc6089fd91d2ecb78f5d16298634682e94\
             373888b22bdc9293d1681922e17",
        )
        .unwrap();
        let mut nas = vec![0x01, 0x00, 0xf1, 0x10, 0xf0, 0xff, 0x02, 2];
        nas.extend_from_slice(&ten_digits);
        assert_eq!(
            Suci::from_nas(&nas)
                .unwrap()
                .deconceal(Some(&private_b()))
                .unwrap()
                .to_string(),
            "imsi-001010123456789"
        );
    }

    /// Each step of a de-concealment has its error.
    #[test]
    fn a_de_concealment_says_which_step_failed() {
        let suci =
            Suci::conceal_imsi(plmn("208", "93"), "001002086", "0", ecies(1, &public_a())).unwrap();
        let nas = suci.to_nas().unwrap();

        // The key: none, and one of the other profile
        assert_eq!(suci.deconceal(None), Err(SuciError::MissingKey));
        assert_eq!(
            suci.deconceal(Some(&private_b())),
            Err(SuciError::WrongKeyType {
                suci: ProtectionScheme::ProfileA,
                key: ProtectionScheme::ProfileB
            })
        );
        // Another key of the same profile: the tag is not the one it gives
        let other = HomeNetworkPrivateKey::profile_a(&[0x42; 32]);
        assert_eq!(suci.deconceal(Some(&other)), Err(SuciError::MacMismatch));

        // A tag and a ciphertext that were changed
        for changed in [nas.len() - 1, nas.len() - 8, nas.len() - 9] {
            let mut nas = nas.clone();
            nas[changed] ^= 0x01;
            assert_eq!(
                Suci::from_nas(&nas).unwrap().deconceal(Some(&private_a())),
                Err(SuciError::MacMismatch)
            );
        }
        // An ephemeral public key of small order: the point of order 1,
        // whose shared secret is zero whatever the private key
        let mut small_order = nas.clone();
        small_order[8..40].fill(0);
        small_order[8] = 1;
        assert_eq!(
            Suci::from_nas(&small_order)
                .unwrap()
                .deconceal(Some(&private_a())),
            Err(SuciError::MalformedPoint)
        );
        // Too few octets for a key, one octet of ciphertext and a tag
        assert_eq!(
            Suci::from_nas(&nas[..8 + 32 + 8]),
            Err(SuciError::Truncated)
        );
        assert!(Suci::from_nas(&nas[..8 + 32 + 1 + 8]).is_ok());

        // A plaintext that is no MSIN, under a tag that is right
        let not_digits = super::ecies::conceal(&public_a(), &[0xab, 0xcd]).unwrap();
        assert_eq!(
            Suci::from_nas(&identity(1, 1, &not_digits))
                .unwrap()
                .deconceal(Some(&private_a())),
            Err(SuciError::Plaintext)
        );
        // An MSIN that makes an IMSI of more than fifteen digits
        let too_long = super::ecies::conceal(&public_a(), &[0x21, 0x43, 0x65, 0x87, 0x09, 0xf1]);
        assert_eq!(
            Suci::from_nas(&identity(1, 1, &too_long.unwrap()))
                .unwrap()
                .deconceal(Some(&private_a())),
            Err(SuciError::Plaintext)
        );

        // A scheme of the operator is read, and not de-concealed
        let proprietary = Suci::from_nas(&identity(12, 1, &[0xaa, 0xbb])).unwrap();
        assert_eq!(
            proprietary.protection_scheme(),
            ProtectionScheme::Proprietary(12)
        );
        assert_eq!(
            proprietary.scheme_output(),
            SchemeOutput::Proprietary(&[0xaa, 0xbb])
        );
        assert_eq!(proprietary.to_string(), "suci-0-208-93-0-12-1-aabb");
        assert_eq!(
            proprietary.deconceal(Some(&private_a())),
            Err(SuciError::ProprietaryScheme(12))
        );
    }

    /// TS 33.514 §4.2.1.3: an uncompressed ephemeral point is refused,
    /// even with a ciphertext and a tag that are right for it. The one of
    /// Annex C.4.4.1 is used.
    #[test]
    fn profile_b_takes_a_compressed_ephemeral_key_alone() {
        let scheme_output = hex::decode(
            "049AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1\
             D1F44EA1C87AA7478B954537BDE79951E748A43294A4F4CF86EAFF1789C9C81F\
             46A33FC2716AC7DAE96AA30A4D",
        )
        .unwrap();
        let suci = Suci::from_nas(&identity(2, 2, &scheme_output)).unwrap();
        assert_eq!(
            suci.deconceal(Some(&private_b())),
            Err(SuciError::MalformedPoint)
        );
        // The x of the point under the tag of the encoding that leaves the
        // choice of y to the reader, which is no compressed point
        let mut x_only = hex::decode(
            "039aab8376597021e855679a9778ea0b67396e68c66df32c0f41e9acca2da9b9d1\
             46a33fc271\
             6ac7dae96aa30a4d",
        )
        .unwrap();
        assert!(
            Suci::from_nas(&identity(2, 2, &x_only))
                .unwrap()
                .deconceal(Some(&private_b()))
                .is_ok()
        );
        x_only[0] = 0x05;
        assert_eq!(
            Suci::from_nas(&identity(2, 2, &x_only))
                .unwrap()
                .deconceal(Some(&private_b())),
            Err(SuciError::MalformedPoint)
        );
        // 33 octets that begin as a compressed point, with an x that no
        // point of the curve has
        let mut no_point = scheme_output[..33 + 5 + 8].to_vec();
        no_point[0] = 0x02;
        no_point[1..33].fill(0x01);
        assert_eq!(
            Suci::from_nas(&identity(2, 2, &no_point))
                .unwrap()
                .deconceal(Some(&private_b())),
            Err(SuciError::MalformedPoint)
        );
    }

    /// TS 24.501 §9.11.3.4: what a mobile identity has to have.
    #[test]
    fn a_mobile_identity_that_is_no_suci_is_refused_with_its_reason() {
        let read = |octets: &[u8]| Suci::from_nas(octets).unwrap_err();
        let null = identity(0, 0, &[0x00, 0x00, 0x00, 0x00, 0x10]);
        assert!(Suci::from_nas(&null).is_ok());

        assert_eq!(read(&[]), SuciError::Truncated);
        assert_eq!(read(&null[..8]), SuciError::Truncated);
        // A 5G-GUTI and an IMEI
        assert_eq!(read(&[0xf2; 11]), SuciError::NotASuci);
        assert_eq!(read(&[0x03; 9]), SuciError::NotASuci);

        let with = |index: usize, octet: u8| {
            let mut identity = null.clone();
            identity[index] = octet;
            read(&identity)
        };
        // An MCC digit above 9, and the filler in the place of a digit
        assert_eq!(with(1, 0x0a), SuciError::HomeNetwork);
        assert_eq!(with(3, 0xf9), SuciError::HomeNetwork);
        // A routing indicator without a digit, with a filler before a
        // digit, and with a digit above 9
        assert_eq!(with(4, 0xff), SuciError::RoutingIndicator);
        assert_eq!(with(4, 0x0f), SuciError::RoutingIndicator);
        assert_eq!(with(4, 0xfa), SuciError::RoutingIndicator);
        // A digit after the filler of a shorter one, and after a
        // character that is no digit
        assert_eq!(with(5, 0xf2), SuciError::RoutingIndicator);
        assert_eq!(with(5, 0x2f), SuciError::RoutingIndicator);
        assert_eq!(with(4, 0xa0), SuciError::RoutingIndicator);
        // The schemes 3 to 11 are reserved
        for scheme in 3..=11 {
            assert_eq!(with(6, scheme), SuciError::UnknownScheme(scheme));
        }
        // The null scheme has the key identifier 0, and no other has it,
        // nor 255
        assert_eq!(with(7, 1), SuciError::KeyIdentifier(1));
        for key_id in [0, 255] {
            let mut identity = identity(1, key_id, &[0x42; 32 + 5 + 8]);
            assert_eq!(read(&identity), SuciError::KeyIdentifier(key_id));
            identity[6] = 12;
            assert_eq!(read(&identity), SuciError::KeyIdentifier(key_id));
        }
        // An MSIN with a character that is no digit, with a filler before
        // its end, and of more digits than an IMSI of 208 93 has
        assert_eq!(with(8, 0x0a), SuciError::SchemeOutput);
        assert_eq!(with(8, 0xf0), SuciError::SchemeOutput);
        let long = identity(0, 0, &[0x00, 0x00, 0x00, 0x00, 0x00, 0xf1]);
        assert_eq!(read(&long), SuciError::SchemeOutput);
    }

    /// TS 24.501 §9.11.3.4: bits 8 and 4 of the first octet and bits 8 to
    /// 5 of the octet of the protection scheme are spare, and the SUPI
    /// formats 4 to 7 are read as IMSI by a receiver.
    #[test]
    fn a_receiver_ignores_the_spare_bits_and_reads_a_spare_format_as_imsi() {
        let canonical = [0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00];
        let expected = Suci::from_nas(&canonical).unwrap();
        assert_eq!(expected.to_string(), "suci-0-208-93-0-0-0-00");
        assert_eq!(expected.to_nas().unwrap(), canonical);
        for received in [
            [0x81, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x09, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x41, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x71, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x00, 0x00, 0x00],
            [0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0xf0, 0x00, 0x00],
        ] {
            assert_eq!(Suci::from_nas(&received), Ok(expected.clone()));
        }
    }

    /// TS 24.501 Table 9.11.3.4.1, NOTE 2: the routing indicator 567 has
    /// 5 in bits 1 to 4 of its first octet, 6 in bits 5 to 8, 7 in bits 1
    /// to 4 of its second, and "1111" in bits 5 to 8. Each digit counts
    /// (TS 23.003 §2.2B).
    #[test]
    fn a_routing_indicator_keeps_each_of_its_digits() {
        for (digits, octets) in [
            ("567", [0x65, 0xf7]),
            ("0", [0xf0, 0xff]),
            ("012", [0x10, 0xf2]),
            ("12", [0x21, 0xff]),
            ("0000", [0x00, 0x00]),
            ("9876", [0x89, 0x67]),
        ] {
            let suci =
                Suci::conceal_imsi(plmn("208", "93"), "0000000001", digits, Protection::Null)
                    .unwrap();
            assert_eq!(suci.routing_indicator(), digits);
            let nas = suci.to_nas().unwrap();
            assert_eq!(nas[4..6], octets, "{digits}");
            assert_eq!(Suci::from_nas(&nas).unwrap().routing_indicator(), digits);
        }
        for digits in ["", "12345", "1a", "-1", " 1"] {
            assert_eq!(
                Suci::conceal_imsi(plmn("208", "93"), "1", digits, Protection::Null),
                Err(SuciError::RoutingIndicator),
                "{digits:?}"
            );
        }
    }

    #[test]
    fn what_cannot_be_concealed_is_refused_with_its_reason() {
        fn conceal(msin: &str, protection: Protection<'_>) -> Result<Suci, SuciError> {
            Suci::conceal_imsi(Plmn::new("208", "93").unwrap(), msin, "0", protection)
        }
        // No MSIN, one that is not digits, and one too long for 208 93
        for msin in ["", "12a4", "12345678901", " 1"] {
            assert_eq!(conceal(msin, Protection::Null), Err(SuciError::Identity));
        }
        assert!(conceal("1234567890", Protection::Null).is_ok());
        // An MNC of three digits leaves nine for the MSIN
        let three = |msin| Suci::conceal_imsi(plmn("274", "012"), msin, "0", Protection::Null);
        assert!(three("123456789").is_ok());
        assert_eq!(three("1234567890"), Err(SuciError::Identity));

        // The key identifiers that no key has
        for key_id in [0, 255] {
            assert_eq!(
                conceal("1", ecies(key_id, &public_a())),
                Err(SuciError::KeyIdentifier(key_id))
            );
        }
        // A public key of small order of Curve25519
        let mut small_order = [0u8; 32];
        small_order[0] = 1;
        let key = HomeNetworkPublicKey::profile_a(&small_order);
        assert_eq!(conceal("1", ecies(1, &key)), Err(SuciError::InvalidKey));
        assert_eq!(
            conceal("1", ecies(1, &HomeNetworkPublicKey::profile_a(&[0; 32]))),
            Err(SuciError::InvalidKey)
        );
    }

    /// A SUCI in the NAI format needs the `nai` feature.
    #[cfg(not(feature = "nai"))]
    #[test]
    fn a_nai_suci_is_not_read_without_the_nai_feature() {
        let mut suci = vec![0x11];
        suci.extend_from_slice(b"type1.rid0.schid0.useriduser17@example.com");
        assert_eq!(Suci::from_nas(&suci), Err(SuciError::NaiNotSupported));
    }

    #[test]
    fn each_error_says_what_failed() {
        for (error, text) in [
            (SuciError::Truncated, "the SUCI is truncated"),
            (
                SuciError::UnknownScheme(3),
                "unknown protection scheme identifier 3",
            ),
            (
                SuciError::KeyIdentifier(255),
                "home network public key identifier 255 is not one of the scheme",
            ),
            (
                SuciError::WrongKeyType {
                    suci: ProtectionScheme::ProfileA,
                    key: ProtectionScheme::ProfileB,
                },
                "a home network private key of ProfileB for a SUCI of ProfileA",
            ),
            (SuciError::MacMismatch, "MAC verification failed"),
            (
                SuciError::Nai(NaiError::Field("mac")),
                "the `mac` field of the SUCI is missing or malformed",
            ),
        ] {
            assert_eq!(error.to_string(), text);
        }
        fn is_an_error<T: core::error::Error + Send + Sync + Copy + 'static>() {}
        is_an_error::<SuciError>();
        is_an_error::<NaiError>();
        // The identifiers of the schemes
        for identifier in 0..=255u8 {
            match ProtectionScheme::try_from(identifier) {
                Ok(scheme) => assert_eq!(u8::from(scheme), identifier),
                Err(error) => assert_eq!(error, SuciError::UnknownScheme(identifier)),
            }
        }
        assert!(ProtectionScheme::try_from(15).is_ok());
        assert!(ProtectionScheme::try_from(16).is_err());
    }

    /// One data set of TS 33.501 Annex C.4 step by step on the UE side:
    /// the keying data of a shared secret as an encryption key, an ICB
    /// and a MAC key, then the ciphertext and the MAC tag.
    fn check_annex_c4(
        shared_secret: &[u8],
        ephemeral_public_key: &[u8],
        [encryption_key, icb, mac_key, plaintext, ciphertext, mac_tag]: [&str; 6],
    ) {
        let plaintext = hex::decode(plaintext).unwrap();
        let steps = super::ecies::tests::steps(shared_secret, ephemeral_public_key, &plaintext);
        assert_eq!(
            hex::encode(steps.encryption_key),
            encryption_key.to_lowercase()
        );
        // Annex C.4 gives the ICB of the IMSI-based data sets
        if !icb.is_empty() {
            assert_eq!(hex::encode(steps.icb), icb.to_lowercase());
        }
        assert_eq!(hex::encode(steps.mac_key), mac_key.to_lowercase());
        assert_eq!(hex::encode(&steps.ciphertext), ciphertext.to_lowercase());
        assert_eq!(hex::encode(steps.mac_tag), mac_tag.to_lowercase());
    }

    #[test]
    fn annex_c4_profile_a_intermediate_values() {
        use x25519_dalek::{PublicKey, StaticSecret};

        let home_network_public_key =
            PublicKey::from(<[u8; 32]>::try_from(hex::decode(PROFILE_A_PUB).unwrap()).unwrap());
        for (ephemeral_private_key, ephemeral_public_key, shared_key, steps) in [
            // C.4.3.1, IMSI-based SUPI.
            (
                "c80949f13ebe61af4ebdbd293ea4f942696b9e815d7e8f0096bbf6ed7de62256",
                "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d",
                "028ddf890ec83cdf163947ce45f6ec1a0e3070ea5fe57e2b1f05139f3e82422a",
                [
                    "2ba342cabd2b3b1e5e4e890da11b65f6",
                    "e2622cb0cdd08204e721c8ea9b95a7c6",
                    "d9846966fb7cf5fcf11266c5957dea60b83fff2b7c940690a4bfe57b1eb52bd2",
                    "00012080f6",
                    "cb02352410",
                    "cddd9e730ef3fa87",
                ],
            ),
            // C.4.3.2, network specific identifier-based SUPI; the
            // 17-octet plaintext spans two counter blocks.
            (
                "BE9EFF3E9F22A4B42A3D236E7A6C500B3F2E7E0C7449988BA800D664BF4FCD97",
                "977D8B2FDAA7B64AA700D04227D5B440630EA4EC50F9082273A26BB678C92222",
                "511C1DF473BB88317F923501F8BA944FD3B667D25699DCB552DBCEF60BBDC56D",
                [
                    "FE77B87D87F40428EDD71BCA69D79059",
                    "",
                    "D87B69F4FE8CD6B211264EA5E69F682F151A82252684CDB15A047E6EF0595028",
                    "766572796C6F6E67757365726E616D6531",
                    "8E358A1582ADB15322C10E515141D2039A",
                    "12E1D7783A97F1AC",
                ],
            ),
        ] {
            let secret = StaticSecret::from(
                <[u8; 32]>::try_from(hex::decode(ephemeral_private_key).unwrap()).unwrap(),
            );
            let public = PublicKey::from(&secret);
            assert_eq!(
                hex::encode(public.as_bytes()),
                ephemeral_public_key.to_lowercase()
            );
            let shared = secret.diffie_hellman(&home_network_public_key);
            assert_eq!(hex::encode(shared.as_bytes()), shared_key.to_lowercase());
            check_annex_c4(shared.as_bytes(), public.as_bytes(), steps);
        }
    }

    #[test]
    fn annex_c4_profile_b_intermediate_values() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        use p256::{PublicKey, SecretKey};

        let home_network_public_key =
            PublicKey::from_sec1_bytes(&hex::decode(PROFILE_B_PUB).unwrap()).unwrap();
        for (ephemeral_private_key, ephemeral_public_key, shared_key, steps) in [
            // C.4.4.1, IMSI-based SUPI.
            (
                "99798858A1DC6A2C68637149A4B1DBFD1FDFF5ADDD62A2142F06699ED7602529",
                "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
                "6C7E6518980025B982FBB2FF746E3C2E85A196D252099A7AD23EA7B4C0959CAE",
                [
                    "8A65C3AED80295C12BD55087E965702A",
                    "EF285B4061C3BAEE858AB6EC68487DAE",
                    "A5EBAC0BC48D9CF7AE5CE39CD840AC6C761AEC04078FAB954D634F923E901C64",
                    "00012080F6",
                    "46A33FC271",
                    "6AC7DAE96AA30A4D",
                ],
            ),
            // C.4.4.2, network specific identifier-based SUPI.
            (
                "90A5898BD29FFA3F261E00E980067C70A2B1B992A21F5B4FEF6D4DF69FE804AD",
                "03759BB22C563D9F4A6B3C1419E543FC2F39D6823F02A9D71162B39399218B244B",
                "BC3529ED79541CF8C007CE9806330F4A5FF15064D7CF4B16943EF8F007597872",
                [
                    "84F9A78995D39E6968047547ECC12C4F",
                    "",
                    "39D5517E965F8E1252B61345ED45226C5F1A8C69F03D6C91437591F0B8E48FA0",
                    "766572796C6F6E67757365726E616D6531",
                    "BE22D8B9F856A52ED381CD7EAF4CF2D525",
                    "3CDDC61A0A7882EB",
                ],
            ),
        ] {
            let secret =
                SecretKey::from_slice(&hex::decode(ephemeral_private_key).unwrap()).unwrap();
            // Profile B applies point compression to the ephemeral public
            // key, and that octet string is SharedInfo1 of the KDF.
            let public = secret.public_key().to_sec1_point(true);
            assert_eq!(
                hex::encode(public.as_bytes()),
                ephemeral_public_key.to_lowercase()
            );
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                secret.to_nonzero_scalar(),
                home_network_public_key.as_affine(),
            );
            assert_eq!(
                hex::encode(shared.raw_secret_bytes()),
                shared_key.to_lowercase()
            );
            check_annex_c4(shared.raw_secret_bytes(), public.as_bytes(), steps);
        }
    }
}
