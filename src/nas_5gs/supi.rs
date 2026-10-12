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

//! The SUPI, the permanent identity of a subscription (TS 23.003 §2.2A).
//!
//! A SUPI is an IMSI, or an identity in the form of a NAI: a network
//! specific identifier, a GCI or a GLI. It has two written forms, which
//! are not the same string:
//!
//! - the identity itself, the digits of the IMSI or the NAI, which is what
//!   the derivation of KAMF takes (TS 33.501 Annex A.7.0);
//! - the form of the service based interfaces, with the type in front:
//!   `imsi-208930000000001`, `nai-user@example.com` (TS 29.571).
//!
//! [`Supi`] holds the identity with its type and gives each form by name,
//! so that neither is taken for the other.

use crate::common::error::SecurityError;
use core::fmt;

/// The type of a SUPI (TS 23.003 §2.2A and §2.2B).
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SupiType {
    /// IMSI.
    Imsi,
    /// Network specific identifier, a NAI (TS 23.003 §28.7.2).
    NetworkSpecific,
    /// Global Line Identifier, in the form of a NAI (TS 23.003 §28.16.2).
    Gli,
    /// Global Cable Identifier, in the form of a NAI (TS 23.003 §28.15.2).
    Gci,
}

impl SupiType {
    /// The prefix of the form of the service based interfaces.
    const fn prefix(self) -> &'static str {
        match self {
            Self::Imsi => "imsi-",
            Self::NetworkSpecific => "nai-",
            Self::Gli => "gli-",
            Self::Gci => "gci-",
        }
    }
}

/// The longest NAI that is taken for a SUPI, in octets: a username and a
/// realm of 253 octets each, the length that RFC 7542 §2.5 asks a system
/// to support for a whole NAI.
pub(crate) const LONGEST_NAI: usize = 253 + 1 + 253;

/// A SUPI: an IMSI, a network specific identifier, a GLI or a GCI.
///
/// ```
/// use oxirush_security::nas_5gs::{Supi, SupiType};
///
/// // From the service based interfaces, with its type in front
/// let supi = Supi::parse("imsi-208930000000001")?;
/// assert_eq!(supi.supi_type(), SupiType::Imsi);
/// // What the derivation of KAMF takes
/// assert_eq!(supi.identity(), "208930000000001");
/// assert_eq!(supi.to_string(), "imsi-208930000000001");
///
/// assert_eq!(Supi::imsi("208930000000001")?, supi);
/// assert!(Supi::imsi("imsi-208930000000001").is_err());
/// # Ok::<(), oxirush_security::SecurityError>(())
/// ```
#[derive(Clone)]
pub struct Supi<'a> {
    kind: SupiType,
    identity: Text<'a>,
}

/// The text of an identity: that of the caller, or one that the crate
/// made.
#[derive(Clone)]
enum Text<'a> {
    Borrowed(&'a str),
    #[cfg(feature = "alloc")]
    Owned(alloc::string::String),
}

impl<'a> Supi<'a> {
    /// The SUPI that is an IMSI, from its 6 to 15 decimal digits: MCC, MNC
    /// and MSIN (TS 23.003 §2.2). Anything else is
    /// [`SecurityError::InvalidParameter`].
    pub fn imsi(imsi: &'a str) -> Result<Self, SecurityError> {
        if !(6..=15).contains(&imsi.len()) || !imsi.bytes().all(|digit| digit.is_ascii_digit()) {
            return Err(SecurityError::InvalidParameter(
                "an IMSI is 6 to 15 decimal digits",
            ));
        }
        Ok(Self {
            kind: SupiType::Imsi,
            identity: Text::Borrowed(imsi),
        })
    }

    /// The SUPI that is a network specific identifier, from its NAI,
    /// `username@realm`. The username of an anonymous one may be empty
    /// (TS 23.003 §2.2B).
    ///
    /// A text without `@` or without a realm, or longer than 507 octets,
    /// is [`SecurityError::InvalidParameter`]. The grammar of the NAI is
    /// not checked here: the `nai` feature checks it where a SUPI is
    /// concealed or de-concealed.
    pub fn network_specific(nai: &'a str) -> Result<Self, SecurityError> {
        Self::nai(SupiType::NetworkSpecific, nai)
    }

    /// The SUPI that is a GLI, from its form as a NAI.
    pub fn gli(nai: &'a str) -> Result<Self, SecurityError> {
        Self::nai(SupiType::Gli, nai)
    }

    /// The SUPI that is a GCI, from its form as a NAI.
    pub fn gci(nai: &'a str) -> Result<Self, SecurityError> {
        Self::nai(SupiType::Gci, nai)
    }

    fn nai(kind: SupiType, nai: &'a str) -> Result<Self, SecurityError> {
        if nai.len() > LONGEST_NAI {
            return Err(SecurityError::InvalidParameter(
                "a SUPI in the form of a NAI is at most 507 octets",
            ));
        }
        match nai.rsplit_once('@') {
            Some((_, realm)) if !realm.is_empty() => Ok(Self {
                kind,
                identity: Text::Borrowed(nai),
            }),
            _ => Err(SecurityError::InvalidParameter(
                "a SUPI in the form of a NAI is a username, @ and a realm",
            )),
        }
    }

    /// The SUPI from the form of the service based interfaces: `imsi-`,
    /// `nai-`, `gli-` or `gci-`, then the identity (TS 29.571
    /// §5.3.2).
    ///
    /// A text without one of these in front is
    /// [`SecurityError::InvalidParameter`]: the bare digits of an IMSI go
    /// through [`imsi`](Self::imsi).
    pub fn parse(supi: &'a str) -> Result<Self, SecurityError> {
        let kinds = [
            SupiType::Imsi,
            SupiType::NetworkSpecific,
            SupiType::Gli,
            SupiType::Gci,
        ];
        for kind in kinds {
            if let Some(identity) = supi.strip_prefix(kind.prefix()) {
                return match kind {
                    SupiType::Imsi => Self::imsi(identity),
                    kind => Self::nai(kind, identity),
                };
            }
        }
        Err(SecurityError::InvalidParameter(
            "a SUPI begins with imsi-, nai-, gli- or gci-",
        ))
    }

    /// Its type.
    pub fn supi_type(&self) -> SupiType {
        self.kind
    }

    /// The identity without its type: the digits of the IMSI, or the NAI.
    /// It is P0 of the derivation of KAMF (TS 33.501 Annex A.7.0).
    pub fn identity(&self) -> &str {
        match &self.identity {
            Text::Borrowed(identity) => identity,
            #[cfg(feature = "alloc")]
            Text::Owned(identity) => identity,
        }
    }

    /// The same SUPI, with a text of its own.
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub fn into_owned(self) -> Supi<'static> {
        Supi {
            kind: self.kind,
            identity: Text::Owned(alloc::string::String::from(self.identity())),
        }
    }
}

#[cfg(feature = "suci")]
impl Supi<'static> {
    /// A SUPI of a type and a text that the crate has checked.
    pub(crate) fn owned(kind: SupiType, identity: alloc::string::String) -> Self {
        Self {
            kind,
            identity: Text::Owned(identity),
        }
    }
}

/// The form of the service based interfaces, with the type in front.
impl fmt::Display for Supi<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.kind.prefix(), self.identity())
    }
}

impl fmt::Debug for Supi<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Supi({self})")
    }
}

impl PartialEq for Supi<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.kind == other.kind && self.identity() == other.identity()
    }
}

impl Eq for Supi<'_> {}

impl core::hash::Hash for Supi<'_> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.kind.hash(state);
        self.identity().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_supi_has_its_identity_and_its_sbi_form() {
        let supi = Supi::parse("imsi-208930000000001").unwrap();
        assert_eq!(supi.supi_type(), SupiType::Imsi);
        assert_eq!(supi.identity(), "208930000000001");
        assert_eq!(supi.to_string(), "imsi-208930000000001");
        assert_eq!(format!("{supi:?}"), "Supi(imsi-208930000000001)");
        assert_eq!(supi, Supi::imsi("208930000000001").unwrap());

        for (text, kind, identity) in [
            (
                "nai-bob@example.com",
                SupiType::NetworkSpecific,
                "bob@example.com",
            ),
            (
                "gci-AAAA@5gc.mnc012.mcc345.3gppnetwork.org",
                SupiType::Gci,
                "AAAA@5gc.mnc012.mcc345.3gppnetwork.org",
            ),
            (
                "gli-AAAA@5gc.mnc012.mcc345.3gppnetwork.org",
                SupiType::Gli,
                "AAAA@5gc.mnc012.mcc345.3gppnetwork.org",
            ),
        ] {
            let supi = Supi::parse(text).unwrap();
            assert_eq!((supi.supi_type(), supi.identity()), (kind, identity));
            assert_eq!(supi.to_string(), text);
        }
        #[cfg(feature = "alloc")]
        assert_eq!(supi.clone().into_owned(), supi);
        // A SUPI is the key of a map, whichever text it has
        let subscribers = std::collections::HashSet::from([Supi::imsi("208930000000001").unwrap()]);
        assert!(subscribers.contains(&Supi::parse("imsi-208930000000001").unwrap()));
        assert!(!subscribers.contains(&Supi::parse("imsi-208930000000002").unwrap()));
        // An anonymous SUPI has no username
        assert_eq!(
            Supi::parse("nai-@example.com").unwrap().identity(),
            "@example.com"
        );
    }

    #[test]
    fn what_is_not_a_supi_is_refused() {
        for text in [
            "",
            "208930000000001",
            "imsi-",
            "imsi-20893",
            "imsi-2089300000000012",
            "imsi-20893000000000a",
            "nai-bob",
            "nai-bob@",
            "suci-0-208-93-0-0-0-0000000001",
        ] {
            assert!(Supi::parse(text).is_err(), "{text:?}");
        }
        // The form of the interfaces is not the identity
        assert!(Supi::imsi("imsi-208930000000001").is_err());
        let long = "a".repeat(LONGEST_NAI - "@b.c".len() + 1);
        assert!(Supi::network_specific(&format!("{long}@b.c")).is_err());
    }
}
