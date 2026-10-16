//! A SUCI from a peer never panics the functions that read it, and a SUCI
//! that is read is written back to a form that reads as the same SUCI.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::nas_5gs::{
    HomeNetworkPrivateKey, HomeNetworkPublicKey, ProtectionScheme, Suci, SuciError,
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
    // De-conceal with each key and with none: an error or a SUPI. A key is
    // missing or of the other profile exactly when the error says so
    let deconceal = |suci: &Suci| {
        for key in [None, Some(&private_a), Some(&private_b)] {
            let result = suci.deconceal(key);
            let wrong_key = matches!(
                result,
                Err(SuciError::MissingKey | SuciError::WrongKeyType { .. })
            );
            let scheme = suci.protection_scheme();
            let needs = matches!(
                scheme,
                ProtectionScheme::PROFILE_A | ProtectionScheme::PROFILE_B
            );
            let has = key.is_some_and(|key| key.scheme() == scheme);
            let unknown = result == Err(SuciError::MncLengthUnknown);
            assert!(
                unknown || wrong_key == (needs && !has),
                "{suci}: {result:?}"
            );
        }
    };

    // The SUCI mobile identity of a NAS message
    if let Ok(suci) = Suci::from_nas_octets(bytes) {
        let _ = suci.to_string();
        let identity = suci.to_nas_octets().expect("a SUCI of a mobile identity");
        assert_eq!(Suci::from_nas_octets(&identity).as_ref(), Ok(&suci));
        deconceal(&suci);
    }

    // A SUCI in the NAI format: what is read is written as a text that
    // reads as the same SUCI
    if let Ok(text) = std::str::from_utf8(bytes)
        && let Ok(suci) = Suci::from_nai(text)
    {
        assert_eq!(
            Suci::from_nai(&suci.to_nai().expect("a NAI")).as_ref(),
            Ok(&suci)
        );
        let _ = suci.to_string();
        deconceal(&suci);
    }

    // The keys of a home network, from any octets
    let _ = HomeNetworkPublicKey::profile_b(bytes);
    if let Some(octets) = bytes.first_chunk::<32>() {
        if let Ok(key) = HomeNetworkPrivateKey::profile_b(octets) {
            let public = key.public_key().to_octets();
            assert!(HomeNetworkPublicKey::profile_b(&public).is_ok());
        }
        let _ = HomeNetworkPrivateKey::profile_a(octets).public_key();
    }
});
