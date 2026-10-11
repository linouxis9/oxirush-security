//! What one side conceals, the other deconceals: a scheme input of any
//! octets with Profile A and Profile B, and a network specific identifier
//! through its NAI.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::nas_5gs::{
    NaiProtectionScheme, conceal_network_specific_supi, deconceal_network_specific_suci,
    encode_nai_suci, parse_nai_suci, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b,
};

// The home network keys of TS 33.501 Annex C.4
const PRIVATE_A: [u8; 32] = [
    0xc5, 0x3c, 0x22, 0x20, 0x8b, 0x61, 0x86, 0x0b, 0x06, 0xc6, 0x2e, 0x54, 0x06, 0xa7, 0xb3, 0x30,
    0xc2, 0xb5, 0x77, 0xaa, 0x55, 0x58, 0x98, 0x15, 0x10, 0xd1, 0x28, 0x24, 0x7d, 0x38, 0xbd, 0x1d,
];
const PUBLIC_A: [u8; 32] = [
    0x5a, 0x8d, 0x38, 0x86, 0x48, 0x20, 0x19, 0x7c, 0x33, 0x94, 0xb9, 0x26, 0x13, 0xb2, 0x0b, 0x91,
    0x63, 0x3c, 0xbd, 0x89, 0x71, 0x19, 0x27, 0x3b, 0xf8, 0xe4, 0xa6, 0xf4, 0xee, 0xc0, 0xa6, 0x50,
];
const PRIVATE_B: [u8; 32] = [
    0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7, 0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
    0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac, 0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
];
const PUBLIC_B: [u8; 33] = [
    0x02, 0x72, 0xda, 0x71, 0x97, 0x62, 0x34, 0xce, 0x83, 0x3a, 0x69, 0x07, 0x42, 0x58, 0x67, 0xb8,
    0x2e, 0x07, 0x4d, 0x44, 0xef, 0x90, 0x7d, 0xfb, 0x4b, 0x3e, 0x21, 0xc1, 0xc2, 0x25, 0x6e, 0xbc,
    0xd1,
];

fuzz_target!(|bytes: &[u8]| {
    // A scheme input of any octets; an empty one is refused
    if bytes.is_empty() {
        assert!(suci_scheme_output_a(bytes, &PUBLIC_A).is_err());
        assert!(suci_scheme_output_b(bytes, &PUBLIC_B).is_err());
        return;
    }
    let output = suci_scheme_output_a(bytes, &PUBLIC_A).expect("Profile A conceals");
    assert_eq!(output.len(), 32 + bytes.len() + 8);
    assert_eq!(suci_decrypt_a(&output, &PRIVATE_A).as_deref(), Ok(bytes));
    let output = suci_scheme_output_b(bytes, &PUBLIC_B).expect("Profile B conceals");
    assert_eq!(output.len(), 33 + bytes.len() + 8);
    assert_eq!(suci_decrypt_b(&output, &PRIVATE_B).as_deref(), Ok(bytes));

    // A network specific identifier, when the octets are one: concealed,
    // written as a NAI, parsed and deconcealed
    let Ok(supi) = std::str::from_utf8(bytes) else {
        return;
    };
    for (scheme, key) in [
        (NaiProtectionScheme::Null, None),
        (
            NaiProtectionScheme::ProfileA {
                home_network_public_key_id: 1,
                home_network_public_key: &PUBLIC_A,
            },
            Some(&PRIVATE_A[..]),
        ),
        (
            NaiProtectionScheme::ProfileB {
                home_network_public_key_id: 255,
                home_network_public_key: &PUBLIC_B,
            },
            Some(&PRIVATE_B[..]),
        ),
    ] {
        let Ok(suci) = conceal_network_specific_supi(supi, "0", scheme) else {
            continue;
        };
        let text = encode_nai_suci(&suci).expect("a concealed SUCI encodes");
        assert_eq!(parse_nai_suci(&text).as_ref(), Ok(&suci));
        assert_eq!(
            deconceal_network_specific_suci(&suci, key).as_deref(),
            Ok(supi)
        );
    }
});
