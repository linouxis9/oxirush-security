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

//! What `{}` and `{:?}` print: an identity and a value that travels in
//! clear whole, and no octet of a key.

use oxirush_security::nas_5gs::{Guti, KAmf, KNasInt, ResStar, STmsi, Supi, XresStar};
use oxirush_security::{Autn, Ck, Ik, Plmn, Rand};

#[test]
fn an_identity_is_printed_whole() {
    let supi = Supi::imsi("208930000000001").unwrap();
    assert_eq!(format!("{supi}"), "imsi-208930000000001");
    assert_eq!(format!("{supi:?}"), "Supi(imsi-208930000000001)");
    let supi = Supi::parse("nai-user17@example.com").unwrap();
    assert_eq!(format!("{supi}"), "nai-user17@example.com");
    assert_eq!(format!("{supi:?}"), "Supi(nai-user17@example.com)");

    let plmn = Plmn::new("208", "93").unwrap();
    assert_eq!(format!("{plmn}"), "208-93");
    assert_eq!(format!("{plmn:?}"), "Plmn(208-93)");

    let guti = Guti::new(plmn, 0xca, 0x3fe, 0x01, 0x1234_5678).unwrap();
    assert_eq!(
        format!("{guti:?}"),
        "Guti { plmn: Plmn(208-93), amf_region_id: 202, \
         s_tmsi: STmsi { amf_set_id: 1022, amf_pointer: 1, tmsi: 305419896 } }"
    );
    let s_tmsi = STmsi::new(0x3fe, 0x01, 0x1234_5678).unwrap();
    assert_eq!(
        format!("{s_tmsi:?}"),
        "STmsi { amf_set_id: 1022, amf_pointer: 1, tmsi: 305419896 }"
    );
}

#[cfg(feature = "suci")]
#[test]
fn a_suci_and_a_home_network_public_key_are_printed_whole() {
    use oxirush_security::nas_5gs::{HomeNetworkPrivateKey, HomeNetworkPublicKey, Suci};

    // The SUCI of TS 33.501 Annex C.4.3.1, concealed with Profile A
    let output = concat!(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457d",
        "cb02352410cddd9e730ef3fa87",
    );
    let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
    identity.extend(hex::decode(output).unwrap());
    let suci = Suci::from_nas(&identity).unwrap();
    assert_eq!(format!("{suci}"), format!("suci-0-274-012-0-1-27-{output}"));
    assert_eq!(
        format!("{suci:?}"),
        format!("Suci(suci-0-274-012-0-1-27-{output})")
    );

    let public = "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650";
    let octets = <[u8; 32]>::try_from(hex::decode(public).unwrap()).unwrap();
    let key = HomeNetworkPublicKey::profile_a(&octets);
    assert_eq!(
        format!("{key:?}"),
        format!("HomeNetworkPublicKey(ProfileA, {public})")
    );

    // The private key is a key
    let private = HomeNetworkPrivateKey::profile_a(&[0x5a; 32]);
    assert_eq!(
        format!("{private:?}"),
        "HomeNetworkPrivateKey(ProfileA, ..)"
    );
}

#[test]
fn rand_and_autn_are_printed_whole() {
    let octets = [
        0x23, 0x55, 0x3c, 0xbe, 0x96, 0x37, 0xa8, 0x9d, 0x21, 0x8a, 0xe6, 0x4d, 0xae, 0x47, 0xbf,
        0x35,
    ];
    assert_eq!(
        format!("{:?}", Rand::new(&octets)),
        "Rand(23553cbe9637a89d218ae64dae47bf35)"
    );
    assert_eq!(
        format!("{:?}", Autn::new(&octets)),
        "Autn(23553cbe9637a89d218ae64dae47bf35)"
    );
}

#[test]
fn a_key_is_not_printed() {
    let (short, long) = ([0x5a; 16], [0x5a; 32]);
    let printed = [
        format!("{:?}", Ck::new(&short)),
        format!("{:?}", Ik::new(&short)),
        format!("{:?}", KAmf::new(&long)),
        format!("{:?}", KNasInt::new(&short)),
        format!("{:?}", ResStar::new(&short)),
        format!("{:?}", XresStar::new(&short)),
    ];
    assert_eq!(
        printed,
        [
            "Ck(..)",
            "Ik(..)",
            "KAmf(..)",
            "KNasInt(..)",
            "ResStar(..)",
            "XresStar(..)"
        ]
    );
    assert!(printed.iter().all(|text| !text.contains("5a")));
}
