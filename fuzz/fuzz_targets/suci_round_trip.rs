//! What one side conceals, the other de-conceals: an IMSI in a mobile
//! identity, and a network specific identifier in a mobile identity and in
//! the NAI format, with the null scheme, Profile A and Profile B.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::Plmn;
use oxirush_security::nas_5gs::{
    HomeNetworkPrivateKey, Protection, ProtectionScheme, RoutingIndicator, SchemeOutput, Suci, Supi,
};

// The home network private keys of TS 33.501 Annex C.4
const PRIVATE_A: [u8; 32] = [
    0xc5, 0x3c, 0x22, 0x20, 0x8b, 0x61, 0x86, 0x0b, 0x06, 0xc6, 0x2e, 0x54, 0x06, 0xa7, 0xb3, 0x30,
    0xc2, 0xb5, 0x77, 0xaa, 0x55, 0x58, 0x98, 0x15, 0x10, 0xd1, 0x28, 0x24, 0x7d, 0x38, 0xbd, 0x1d,
];
const PRIVATE_B: [u8; 32] = [
    0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7, 0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
    0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac, 0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
];

fuzz_target!(|bytes: &[u8]| {
    let private_a = HomeNetworkPrivateKey::profile_a(&PRIVATE_A);
    let private_b = HomeNetworkPrivateKey::profile_b(&PRIVATE_B).expect("a key of Profile B");
    let (public_a, public_b) = (private_a.public_key(), private_b.public_key());
    let Some((head, rest)) = bytes.split_at_checked(4) else {
        return;
    };
    // A key identifier that a key has, 1 to 254, and a routing indicator
    // of one to four digits
    let key_id = 1 + head[0] % 254;
    let routing_indicator = format!("{:04}", u16::from_be_bytes([head[1], head[2]]) % 10_000);
    let routing_indicator = &routing_indicator[usize::from(head[3] % 4)..];
    let routing_indicator = RoutingIndicator::new(routing_indicator).expect("one to four digits");
    let protections = [
        (Protection::Null, None),
        (
            Protection::Ecies {
                key_id,
                key: &public_a,
            },
            Some(&private_a),
        ),
        (
            Protection::Ecies {
                key_id,
                key: &public_b,
            },
            Some(&private_b),
        ),
    ];

    // An IMSI: the PLMN and the MSIN are digits that the octets give
    let digits: String = (rest.iter().take(16))
        .map(|octet| char::from(b'0' + octet % 10))
        .collect();
    if let Some((plmn, msin)) = digits.split_at_checked(5 + usize::from(head[3] >> 7))
        && let Ok(plmn) = Plmn::new(&plmn[..3], &plmn[3..])
    {
        for (protection, private) in &protections {
            let Ok(suci) = Suci::conceal_imsi(plmn, msin, routing_indicator, *protection) else {
                // No MSIN, or one that makes more than fifteen digits
                assert!(msin.is_empty() || digits.len() > 15);
                continue;
            };
            assert_eq!(suci.routing_indicator(), routing_indicator);
            if let SchemeOutput::Ecies { ciphertext, .. } = suci.scheme_output() {
                assert_eq!(ciphertext.len(), msin.len().div_ceil(2));
                assert_eq!(suci.home_network_public_key_id(), key_id);
            }
            let identity = suci.to_nas_octets().expect("an IMSI with its PLMN");
            let received = Suci::from_nas_octets(&identity).expect("a SUCI that was written");
            assert_eq!(received, suci);
            let supi = received.deconceal(*private).expect("the key of the SUCI");
            assert_eq!(supi.identity(), digits);
            // The NAI format has the same parts, and its realm for the PLMN
            let nai = Suci::from_nai(&suci.to_nai().expect("an IMSI in the NAI format"))
                .expect("a SUCI that was written");
            assert_eq!(nai.scheme_output(), suci.scheme_output());
        }
    }

    // A network specific identifier, when the octets are one: concealed,
    // written in both forms, read and de-concealed
    let Ok(nai) = std::str::from_utf8(rest) else {
        return;
    };
    let Ok(supi) = Supi::network_specific(nai) else {
        return;
    };
    for (protection, private) in &protections {
        let Ok(suci) = Suci::conceal_nai(&supi, routing_indicator, *protection) else {
            continue;
        };
        if let SchemeOutput::Ecies { ciphertext, .. } = suci.scheme_output() {
            let username = nai.rsplit_once('@').expect("a NAI").0;
            assert_eq!(ciphertext.len(), username.len());
        } else {
            assert_eq!(suci.protection_scheme(), ProtectionScheme::NULL);
        }
        let text = suci.to_nai().expect("a NAI");
        assert_eq!(Suci::from_nai(&text).as_ref(), Ok(&suci));
        let identity = suci.to_nas_octets().expect("a network specific identifier");
        assert_eq!(Suci::from_nas_octets(&identity).as_ref(), Ok(&suci));
        assert_eq!(suci.deconceal(*private).as_ref(), Ok(&supi));
    }
});
