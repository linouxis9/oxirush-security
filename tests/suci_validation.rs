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

//! The SUCI through the public API, as a SIDF and a UE use it.

use oxirush_security::Plmn;
use oxirush_security::nas_5gs::{
    HomeNetwork, HomeNetworkPrivateKey, HomeNetworkPublicKey, KSeaf, Protection, ProtectionScheme,
    RoutingIndicator, SchemeOutput, Suci, SuciError, SupiType, derive_kamf,
};

// Home network keys of TS 33.501 Annex C.4.
const PROFILE_A_PRIVATE: &str = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
const PROFILE_A_PUBLIC: &str = "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
const PROFILE_B_PRIVATE: &str = "F1AB1074477EBCC7F554EA1C5FC368B1616730155E0041AC447D6301975FECDA";
const PROFILE_B_PUBLIC_X: &str = "72DA71976234CE833A6907425867B82E074D44EF907DFB4B3E21C1C2256EBCD1";
const PROFILE_B_PUBLIC_Y: &str = "5A7DED52FCBB097A4ED250E036C7B9C8C7004C4EEDC4F068CD7BF8D3F900E3B4";

fn octets<const N: usize>(hexadecimal: &str) -> [u8; N] {
    hex::decode(hexadecimal).unwrap().try_into().unwrap()
}

fn private_a() -> HomeNetworkPrivateKey {
    HomeNetworkPrivateKey::profile_a(&octets(PROFILE_A_PRIVATE))
}

fn private_b() -> HomeNetworkPrivateKey {
    HomeNetworkPrivateKey::profile_b(&octets(PROFILE_B_PRIVATE)).unwrap()
}

/// The mobile identity of a SUCI of an IMSI of 274 012 with the routing
/// indicator 0, as TS 33.501 Annex C.4 has it.
fn identity(scheme: u8, key_id: u8, scheme_output: &[u8]) -> Vec<u8> {
    let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, scheme, key_id];
    identity.extend_from_slice(scheme_output);
    identity
}

/// The scheme output of Annex C.4.3.1: Profile A, MSIN 001002086.
fn annex_c4_profile_a() -> Vec<u8> {
    hex::decode(concat!(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d",
        "cb02352410",
        "cddd9e730ef3fa87",
    ))
    .unwrap()
}

/// A SIDF reads the parts of the SUCI, chooses the private key that the
/// scheme and the key identifier name, and gives the SUPI to the
/// derivation of KAMF.
///
/// KSEAF and KAMF are those that Open5GS and Python's `hmac` give for the
/// IMSI of Annex C.4, as the second review of this crate recorded them.
/// The SUPI goes from the de-concealment to the derivation as it is: the
/// `imsi-` of its text is not part of what is hashed (TS 33.501
/// Annex A.7.0).
#[test]
fn a_sidf_chooses_its_key_and_the_supi_gives_kamf() {
    let keys = [
        (ProtectionScheme::PROFILE_A, 27, private_a()),
        (ProtectionScheme::PROFILE_B, 27, private_b()),
        (
            ProtectionScheme::PROFILE_A,
            28,
            HomeNetworkPrivateKey::profile_a(&[0x42; 32]),
        ),
    ];
    let suci = Suci::from_nas_octets(&identity(1, 27, &annex_c4_profile_a())).unwrap();
    assert_eq!(suci.supi_type(), SupiType::Imsi);
    assert_eq!(
        suci.home_network(),
        HomeNetwork::Plmn(Plmn::new("274", "012").unwrap())
    );
    assert_eq!(suci.routing_indicator().as_str(), "0");
    assert_eq!(suci.protection_scheme(), ProtectionScheme::PROFILE_A);
    assert_eq!(suci.home_network_public_key_id(), 27);
    let SchemeOutput::Ecies {
        ephemeral_public_key,
        ciphertext,
        mac_tag,
    } = suci.scheme_output()
    else {
        panic!("the scheme output of a profile");
    };
    assert_eq!(ephemeral_public_key.len(), 32);
    assert_eq!(hex::encode(ciphertext), "cb02352410");
    assert_eq!(hex::encode(mac_tag), "cddd9e730ef3fa87");
    assert_eq!(
        suci.to_string(),
        format!(
            "suci-0-274-012-0-1-27-{}",
            hex::encode(annex_c4_profile_a())
        )
    );

    let key = keys
        .iter()
        .find(|(scheme, key_id, _)| {
            (*scheme, *key_id) == (suci.protection_scheme(), suci.home_network_public_key_id())
        })
        .map(|(_, _, key)| key);
    let supi = suci.deconceal(key).unwrap();
    assert_eq!(supi.to_string(), "imsi-274012001002086");
    assert_eq!(supi.identity(), "274012001002086");

    let kseaf = KSeaf::new(&octets(
        "e51039fe94eee5044488cde4ffd610ece389153baf7f6736ef41d998df11a149",
    ));
    let kamf = derive_kamf(&kseaf, &supi, &[0x00, 0x00]).unwrap();
    assert_eq!(
        hex::encode(kamf.as_octets()),
        "1df794e8213a60c9a9c80e4eb0d6132f86275620f455b323832d859dda7d7dfb"
    );
}

/// A tag that was changed, no key, a SUCI that was cut and a scheme that
/// is not known gave the same `None` in 0.2.0. Each has its error.
#[test]
fn each_failure_of_a_sidf_has_its_error() {
    let nas = identity(1, 27, &annex_c4_profile_a());
    let suci = Suci::from_nas_octets(&nas).unwrap();

    let mut tampered = nas.clone();
    *tampered.last_mut().unwrap() ^= 0x01;
    assert_eq!(
        Suci::from_nas_octets(&tampered)
            .unwrap()
            .deconceal(Some(&private_a())),
        Err(SuciError::MacMismatch)
    );
    assert_eq!(suci.deconceal(None), Err(SuciError::MissingKey));
    assert_eq!(
        suci.deconceal(Some(&private_b())),
        Err(SuciError::WrongKeyType {
            suci: ProtectionScheme::PROFILE_A,
            key: ProtectionScheme::PROFILE_B,
        })
    );
    for length in [0, 1, 7, 8, 20, nas.len() - 5] {
        assert_eq!(
            Suci::from_nas_octets(&nas[..length]),
            Err(SuciError::Truncated),
            "{length} octets"
        );
    }
    let mut unknown = nas.clone();
    unknown[6] = 3;
    assert_eq!(
        Suci::from_nas_octets(&unknown),
        Err(SuciError::UnknownScheme(3))
    );
    // A SUCI of a scheme of the operator is read, for the SIDF that
    // knows the scheme
    let mut proprietary = nas.clone();
    proprietary[6] = 13;
    assert_eq!(
        Suci::from_nas_octets(&proprietary)
            .unwrap()
            .deconceal(Some(&private_a())),
        Err(SuciError::ProprietaryScheme(13))
    );
}

/// TS 33.514 v19.1.0 §4.2.1.3 requires rejection even when the
/// uncompressed point is curve-valid and the ciphertext MAC is correct.
#[test]
fn profile_b_rejects_uncompressed_ephemeral_public_key() {
    let uncompressed = hex::decode(concat!(
        "049AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
        "D1F44EA1C87AA7478B954537BDE79951E748A43294A4F4CF86EAFF1789C9C81F",
        "46A33FC2716AC7DAE96AA30A4D",
    ))
    .unwrap();
    let suci = Suci::from_nas_octets(&identity(2, 2, &uncompressed)).unwrap();
    assert_eq!(
        suci.deconceal(Some(&private_b())),
        Err(SuciError::MalformedPoint)
    );

    // The same authenticated output with its standardized compressed point
    // is accepted.
    let compressed = hex::decode(concat!(
        "039AAB8376597021E855679A9778EA0B67396E68C66DF32C0F41E9ACCA2DA9B9D1",
        "46A33FC2716AC7DAE96AA30A4D",
    ))
    .unwrap();
    let suci = Suci::from_nas_octets(&identity(2, 2, &compressed)).unwrap();
    assert_eq!(
        suci.deconceal(Some(&private_b())).unwrap().to_string(),
        "imsi-274012001002086"
    );
}

/// The points of order 1 and of order 2... of Curve25519 whose shared
/// secret does not depend on the private key: zero and one.
#[test]
fn profile_a_rejects_non_contributory_public_keys() {
    let plmn = Plmn::new("274", "012").unwrap();
    for first_octet in [0, 1] {
        let mut point = [0; 32];
        point[0] = first_octet;
        let key = HomeNetworkPublicKey::profile_a(&point);
        let protection = Protection::Ecies {
            key_id: 1,
            key: &key,
        };
        assert_eq!(
            Suci::conceal_imsi(plmn, "001002086", RoutingIndicator::default(), protection),
            Err(SuciError::InvalidKey)
        );
        let mut output = point.to_vec();
        output.extend_from_slice(&[0; 9]);
        assert_eq!(
            Suci::from_nas_octets(&identity(1, 1, &output))
                .unwrap()
                .deconceal(Some(&HomeNetworkPrivateKey::profile_a(&[0x55; 32]))),
            Err(SuciError::MalformedPoint)
        );
    }
}

/// TS 33.501 Annex C.4.4 gives the home network public key of Profile B as a
/// compressed and as an uncompressed point. SEC1 has other encodings, which
/// are not keys of the profile.
#[test]
fn profile_b_takes_a_compressed_or_an_uncompressed_home_network_key_only() {
    let plmn = Plmn::new("274", "012").unwrap();
    let (x, y) = (PROFILE_B_PUBLIC_X, PROFILE_B_PUBLIC_Y);
    for accepted in [format!("02{x}"), format!("04{x}{y}")] {
        let key = HomeNetworkPublicKey::profile_b(&hex::decode(&accepted).unwrap()).unwrap();
        assert_eq!(key, private_b().public_key(), "{accepted}");
        assert_eq!(key.scheme(), ProtectionScheme::PROFILE_B);
        let protection = Protection::Ecies {
            key_id: 2,
            key: &key,
        };
        let suci =
            Suci::conceal_imsi(plmn, "001002086", RoutingIndicator::default(), protection).unwrap();
        assert_eq!(
            suci.deconceal(Some(&private_b())).unwrap().identity(),
            "274012001002086",
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
        // x and y without a tag, and the key of Profile A.
        format!("{x}{y}"),
        PROFILE_A_PUBLIC.to_owned(),
        // No key.
        String::new(),
    ] {
        assert_eq!(
            HomeNetworkPublicKey::profile_b(&hex::decode(&refused).unwrap()),
            Err(SuciError::InvalidKey),
            "{refused}"
        );
    }
}

/// De-concealment refuses a scheme output without ciphertext, and
/// concealment an identity without a digit.
#[test]
fn ecies_profiles_refuse_an_empty_identity_and_its_output() {
    let plmn = Plmn::new("274", "012").unwrap();
    let public_a = HomeNetworkPublicKey::profile_a(&octets(PROFILE_A_PUBLIC));
    let public_b = private_b().public_key();
    for (public, private, scheme, key_len) in [
        (&public_a, private_a(), 1, 32),
        (&public_b, private_b(), 2, 33),
    ] {
        let protection = Protection::Ecies {
            key_id: 1,
            key: public,
        };
        assert_eq!(
            Suci::conceal_imsi(plmn, "", RoutingIndicator::default(), protection),
            Err(SuciError::Identity)
        );
        // The ephemeral key and the MAC tag of a real output, with its one
        // octet of ciphertext taken out.
        let suci = Suci::conceal_imsi(plmn, "1", RoutingIndicator::default(), protection).unwrap();
        assert_eq!(
            suci.deconceal(Some(&private)).unwrap().identity(),
            "2740121"
        );
        let mut nas = suci.to_nas_octets().unwrap();
        assert_eq!(nas[6], scheme);
        nas.remove(8 + key_len);
        assert_eq!(Suci::from_nas_octets(&nas), Err(SuciError::Truncated));
    }
}
