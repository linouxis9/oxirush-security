//! A SUCI from a peer never panics the functions that read it, and a SUCI
//! in the NAI format that parses encodes back to the same thing.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::nas_5gs::{
    deconceal_nai_suci, encode_nai_suci, parse_nai_suci, suci_decrypt_a, suci_decrypt_b,
    suci_to_string, suci_to_supi,
};

// The home network keys of TS 33.501 Annex C.4
const PRIVATE_A: [u8; 32] = [
    0xc5, 0x3c, 0x22, 0x20, 0x8b, 0x61, 0x86, 0x0b, 0x06, 0xc6, 0x2e, 0x54, 0x06, 0xa7, 0xb3, 0x30,
    0xc2, 0xb5, 0x77, 0xaa, 0x55, 0x58, 0x98, 0x15, 0x10, 0xd1, 0x28, 0x24, 0x7d, 0x38, 0xbd, 0x1d,
];
const PRIVATE_B: [u8; 32] = [
    0xf1, 0xab, 0x10, 0x74, 0x47, 0x7e, 0xbc, 0xc7, 0xf5, 0x54, 0xea, 0x1c, 0x5f, 0xc3, 0x68, 0xb1,
    0x61, 0x67, 0x30, 0x15, 0x5e, 0x00, 0x41, 0xac, 0x44, 0x7d, 0x63, 0x01, 0x97, 0x5f, 0xec, 0xda,
];
fuzz_target!(|bytes: &[u8]| {
    // The SUCI mobile identity of a NAS message, with each key and with none
    let _ = suci_to_supi(bytes, None);
    let _ = suci_to_supi(bytes, Some(&PRIVATE_A));
    let _ = suci_to_supi(bytes, Some(&PRIVATE_B));
    let _ = suci_to_string(bytes);

    // A scheme output, and a home network private key of any length
    let _ = suci_decrypt_a(bytes, &PRIVATE_A);
    let _ = suci_decrypt_b(bytes, &PRIVATE_B);
    let _ = suci_decrypt_b(&[0x02; 42], bytes);

    // A SUCI in the NAI format: what parses encodes to a text that parses
    // to the same value
    if let Ok(text) = std::str::from_utf8(bytes)
        && let Ok(suci) = parse_nai_suci(text)
    {
        let encoded = encode_nai_suci(&suci).expect("a parsed SUCI encodes");
        assert_eq!(parse_nai_suci(&encoded).as_ref(), Ok(&suci));
        let _ = deconceal_nai_suci(&suci, None);
        let _ = deconceal_nai_suci(&suci, Some(&PRIVATE_A));
        let _ = deconceal_nai_suci(&suci, Some(&PRIVATE_B));
    }
});
