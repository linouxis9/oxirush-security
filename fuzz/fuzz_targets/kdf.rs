//! The key derivation function of TS 33.220 Annex B.2 on any key, any FC and any
//! parameters: `build_s` lays out FC, then each parameter with its length in two octets,
//! and refuses one longer than 65535 octets; `kdf` is HMAC-SHA-256 of the key and S, as
//! the `hmac` crate computes it; `extract_128` takes the 128 least significant bits. The
//! derivations of KAUSF, KSEAF and KAMF (TS 33.501 Annex A.2, A.6 and A.7), which take a
//! serving network name, a SUPI and an ABBA of any length, are the KDF of their FC and
//! parameters, or refuse what their clause does not have.
#![no_main]

use hmac::{Hmac, KeyInit, Mac};
use libfuzzer_sys::fuzz_target;
use oxirush_security::kdf::{build_s, extract_128, kdf};
use oxirush_security::nas_5gs::{KAusf, KSeaf, derive_kamf, derive_kausf, derive_kseaf};
use oxirush_security::{Autn, Ck, Ik, SecurityError};
use sha2::Sha256;

/// The longest parameter: its length has two octets.
const LONGEST: usize = 65_535;

/// S as TS 33.220 Annex B.2 lays it out, or none for a parameter too long.
fn s(fc: u8, parameters: &[&[u8]]) -> Option<Vec<u8>> {
    let mut s = vec![fc];
    for parameter in parameters {
        let length = u16::try_from(parameter.len()).ok()?;
        s.extend_from_slice(parameter);
        s.extend_from_slice(&length.to_be_bytes());
    }
    Some(s)
}

fn hmac_sha256(key: &[u8], s: &[u8]) -> [u8; 32] {
    let mut mac =
        <Hmac<Sha256> as KeyInit>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(s);
    mac.finalize().into_bytes().into()
}

/// The parameters of the octets: each a length of two octets and that many octets, the
/// last one what is left; a length of 0xffff is a parameter of 65536 octets, one too many.
fn parameters(mut rest: &[u8]) -> Vec<Vec<u8>> {
    let mut parameters = Vec::new();
    while let [high, low, more @ ..] = rest
        && parameters.len() < 6
    {
        let length = usize::from(u16::from_be_bytes([*high, *low]));
        if length == LONGEST {
            parameters.push(vec![*high; LONGEST + 1]);
            rest = more;
            continue;
        }
        let (parameter, after) = more.split_at(length.min(more.len()));
        parameters.push(parameter.to_vec());
        rest = after;
    }
    parameters
}

fuzz_target!(|bytes: &[u8]| {
    let [fc, key_length, rest @ ..] = bytes else {
        return;
    };
    let (key, rest) = rest.split_at(usize::from(*key_length).min(rest.len()));
    let parameters = parameters(rest);
    let views: Vec<&[u8]> = parameters.iter().map(Vec::as_slice).collect();

    // S, and the KDF over it
    let expected = s(*fc, &views);
    match (build_s(*fc, &views), &expected) {
        (Ok(built), Some(expected)) => {
            assert_eq!(&built, expected, "S");
            let derived = kdf(key, &built);
            assert_eq!(*derived, hmac_sha256(key, &built), "KDF");
            assert_eq!(
                *extract_128(&derived),
                derived[16..],
                "the 128 least significant bits"
            );
        }
        (Err(SecurityError::InputTooLong { .. }), None) => {}
        (built, expected) => panic!("build_s gives {built:?} where S is {expected:?}"),
    }

    // KAUSF, KSEAF and KAMF of the octets of the key, a serving network name, a SUPI and
    // an ABBA
    let mut octets = [0u8; 48];
    octets[..key.len().min(48)].copy_from_slice(&key[..key.len().min(48)]);
    let (ck, ik) = (
        Ck::new(octets[..16].try_into().unwrap()),
        Ik::new(octets[16..32].try_into().unwrap()),
    );
    let autn = Autn::new(octets[32..48].try_into().unwrap());
    let sn_name = views.first().copied().unwrap_or_default();
    let kausf = derive_kausf(&ck, &ik, sn_name, &autn);
    match s(0x6a, &[sn_name, autn.sqn_xor_ak()]) {
        Some(s) => assert_eq!(
            kausf.as_ref().map(|kausf| *kausf.as_octets()),
            Ok(hmac_sha256(&octets[..32], &s)),
            "KAUSF"
        ),
        None => assert!(
            matches!(kausf, Err(SecurityError::InputTooLong { .. })),
            "KAUSF of a name too long"
        ),
    }
    let kausf = KAusf::new(&hmac_sha256(key, b"KAUSF"));
    let kseaf = derive_kseaf(&kausf, sn_name);
    match s(0x6c, &[sn_name]) {
        Some(s) => assert_eq!(
            kseaf.as_ref().map(|kseaf| *kseaf.as_octets()),
            Ok(hmac_sha256(kausf.as_octets(), &s)),
            "KSEAF"
        ),
        None => assert!(
            matches!(kseaf, Err(SecurityError::InputTooLong { .. })),
            "KSEAF of a name too long"
        ),
    }
    let kseaf = KSeaf::new(&hmac_sha256(key, b"KSEAF"));
    let supi = String::from_utf8_lossy(views.get(1).copied().unwrap_or_default());
    let abba = views.get(2).copied().unwrap_or(&[0, 0]);
    let kamf = derive_kamf(&kseaf, &supi, abba);
    match s(0x6d, &[supi.as_bytes(), abba]) {
        Some(s) if (2..=255).contains(&abba.len()) => {
            assert_eq!(
                kamf.as_ref().map(|kamf| *kamf.as_octets()),
                Ok(hmac_sha256(kseaf.as_octets(), &s)),
                "KAMF"
            )
        }
        _ => assert!(
            kamf.is_err(),
            "KAMF of an ABBA or a SUPI that its clause does not have"
        ),
    }
});
