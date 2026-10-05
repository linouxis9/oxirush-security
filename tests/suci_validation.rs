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

use oxirush_security::{suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a, suci_to_supi};

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
