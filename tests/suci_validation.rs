/*
   OxiRush
   Copyright 2025 - 2026 Valentin D'Emmanuele

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

use oxirush_security::{
    SecurityError, suci_conceal, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b, suci_to_supi,
};

// Home network keys of TS 33.501 Annex C.4.
const PROFILE_A_PRIVATE: &str = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
const PROFILE_A_PUBLIC: &str = "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
const PROFILE_B_PRIVATE: &str = "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA";
const PROFILE_B_PUBLIC_X: &str = "72DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1";
const PROFILE_B_PUBLIC_Y: &str = "5A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4";

#[test]
fn profile_b_invalid_private_key_lengths_return_error() {
    for length in [0, 31, 33] {
        let result = std::panic::catch_unwind(|| suci_decrypt_b(&[0; 42], &vec![1; length]));
        assert!(result.is_ok(), "private key length {length} panicked");
        assert!(result.unwrap().is_err());
        let mut suci = vec![0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x02, 0x02];
        suci.extend_from_slice(&[0; 42]);
        assert!(suci_to_supi(&suci, Some(&vec![1; length])).is_none());
    }
}

/// TS 33.514 v19.1.0 §4.2.1.3 requires rejection even when the
/// uncompressed point is curve-valid and the ciphertext MAC is correct.
#[test]
fn profile_b_rejects_uncompressed_ephemeral_public_key() {
    let private_key =
        hex::decode("F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA").unwrap();
    let scheme_output = hex::decode(concat!(
        "049AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
        "D1F44EA1C87AA7478B954537BDE79951E748A43294A4F4CF86EAFF1789C9C81F",
        "46A33FC2716AC7DAE96AA30A4D",
    ))
    .unwrap();
    assert!(suci_decrypt_b(&scheme_output, &private_key).is_err());
    let mut suci = vec![0x01, 0x02, 0xf8, 0x39, 0xf0, 0xff, 0x02, 0x02];
    suci.extend_from_slice(&scheme_output);
    assert!(suci_to_supi(&suci, Some(&private_key)).is_none());

    // The same authenticated output with its standardized compressed point
    // remains accepted through the public SUPI wrapper.
    let compressed = hex::decode(concat!(
        "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
        "46A33FC2716AC7DAE96AA30A4D",
    ))
    .unwrap();
    suci.truncate(8);
    suci.extend_from_slice(&compressed);
    assert_eq!(
        suci_to_supi(&suci, Some(&private_key)).as_deref(),
        Some("imsi-20893001002086")
    );
}

#[test]
fn profile_a_rejects_non_contributory_public_keys() {
    for first_octet in [0, 1] {
        let mut public_key = [0; 32];
        public_key[0] = first_octet;
        assert!(suci_scheme_output_a(&[0x21], &public_key).is_err());
        let mut output = public_key.to_vec();
        output.extend_from_slice(&[0; 9]);
        assert!(suci_decrypt_a(&output, &[0x55; 32]).is_err());
    }
}

/// TS 33.501 Annex C.4.4 gives the home network public key of Profile B as a
/// compressed and as an uncompressed point. SEC1 has other encodings, which
/// are not keys of the profile.
#[test]
fn profile_b_takes_a_compressed_or_an_uncompressed_home_network_key_only() {
    let private_key = hex::decode(PROFILE_B_PRIVATE).unwrap();
    let (x, y) = (PROFILE_B_PUBLIC_X, PROFILE_B_PUBLIC_Y);
    for accepted in [format!("02{x}"), format!("04{x}{y}")] {
        let public_key = hex::decode(&accepted).unwrap();
        let output = suci_scheme_output_b(&[0x21, 0x43], &public_key).unwrap();
        assert_eq!(
            suci_decrypt_b(&output, &private_key).unwrap(),
            [0x21, 0x43],
            "{accepted}"
        );
    }
    for refused in [
        // The x-only encoding, which leaves the choice of Y to the reader.
        format!("05{x}"),
        // The point at infinity.
        "00".to_owned(),
        // A tag that does not go with the length.
        format!("04{x}"),
        format!("02{x}{y}"),
        // No key.
        String::new(),
    ] {
        let public_key = hex::decode(&refused).unwrap();
        assert!(
            matches!(
                suci_scheme_output_b(&[0x21, 0x43], &public_key),
                Err(SecurityError::Ecies(_))
            ),
            "{refused}"
        );
        assert!(
            matches!(
                suci_conceal(&[0x21, 0x43], 2, &public_key),
                Err(SecurityError::Ecies(_))
            ),
            "{refused}"
        );
    }
}

/// Deconcealment refuses a scheme output without ciphertext, so concealment
/// refuses an empty scheme input, with the same kind of error.
#[test]
fn ecies_profiles_refuse_an_empty_scheme_input_and_its_output() {
    let public_a: [u8; 32] = hex::decode(PROFILE_A_PUBLIC).unwrap().try_into().unwrap();
    let private_a: [u8; 32] = hex::decode(PROFILE_A_PRIVATE).unwrap().try_into().unwrap();
    let public_b = hex::decode(format!("04{PROFILE_B_PUBLIC_X}{PROFILE_B_PUBLIC_Y}")).unwrap();
    let private_b = hex::decode(PROFILE_B_PRIVATE).unwrap();

    assert!(matches!(
        suci_scheme_output_a(&[], &public_a),
        Err(SecurityError::Ecies(_))
    ));
    assert!(matches!(
        suci_scheme_output_b(&[], &public_b),
        Err(SecurityError::Ecies(_))
    ));
    assert!(matches!(
        suci_conceal(&[], 1, &public_a),
        Err(SecurityError::Ecies(_))
    ));
    assert!(matches!(
        suci_conceal(&[], 2, &public_b),
        Err(SecurityError::Ecies(_))
    ));

    // The ephemeral key and the MAC tag of a real output, with its one
    // octet of ciphertext taken out.
    let mut output_a = suci_scheme_output_a(&[0x21], &public_a).unwrap();
    assert_eq!(suci_decrypt_a(&output_a, &private_a).unwrap(), [0x21]);
    output_a.remove(32);
    assert!(matches!(
        suci_decrypt_a(&output_a, &private_a),
        Err(SecurityError::Ecies(_))
    ));
    let mut output_b = suci_scheme_output_b(&[0x21], &public_b).unwrap();
    assert_eq!(suci_decrypt_b(&output_b, &private_b).unwrap(), [0x21]);
    output_b.remove(33);
    assert!(matches!(
        suci_decrypt_b(&output_b, &private_b),
        Err(SecurityError::Ecies(_))
    ));
}
