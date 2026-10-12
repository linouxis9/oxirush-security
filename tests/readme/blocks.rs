// The Rust blocks of the README and of the documentation, each as a function.
// `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what its page shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    ($($argument:tt)*) => {
        PRINTED.with(|printed| {
            let line = format!($($argument)*);
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    };
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

pub const BLOCKS: &[fn()] = &[
    block_1,
    block_2,
    block_3,
    block_4,
    block_5,
    block_6,
    block_7,
    block_8,
    block_9,
    block_10,
    block_11,
];

/// The Rust block 1 of README.md.
fn block_1() {
    use oxirush_security::nas_5gs::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, derive_knas_enc,
        derive_knas_int, nas_cipher, nas_mac,
    };

    // KAMF, the key of the AMF, as the 5G AKA example below derives it
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();

    // The NAS keys of the algorithms that the AMF selected
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let k_nas_enc = derive_knas_enc(&k_amf, nea2);
    let k_nas_int = derive_knas_int(&k_amf, nia2);
    println!("KNASenc {}", hex::encode(k_nas_enc));
    println!("KNASint {}", hex::encode(k_nas_int));

    // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
    // it, then compute the MAC over the sequence number and the ciphertext
    let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
    let mut message = [0x7e, 0x00, 0x43];
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    println!("ciphered {}, MAC {mac:08x}", hex::encode(message));
}

/// The Rust block 2 of README.md.
fn block_2() {
    use oxirush_security::constant_time_eq;
    use oxirush_security::nas_5gs::{
        compute_hres_star, compute_xres_star, derive_kamf, derive_kausf, derive_kseaf,
    };

    let hex16 = |s: &str| <[u8; 16]>::try_from(hex::decode(s).unwrap()).unwrap();
    let ck = hex16("b40ba9a3c58b2a05bbf0d987b21bf8cb");
    let ik = hex16("f769bcd751044604127672711c6d3441");
    let rand = hex16("23553cbe9637a89d218ae64dae47bf35");
    let res = hex::decode("a54211d5e3ba50bf").unwrap();
    let sqn_xor_ak = [0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77];
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

    // UDM: KAUSF and XRES*
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak).unwrap();
    let xres_star = compute_xres_star(&ck, &ik, sn_name, &rand, &res).unwrap();
    println!("KAUSF  {}", hex::encode(k_ausf));
    println!("XRES*  {}", hex::encode(xres_star));

    // AUSF: HXRES* and KSEAF
    let hxres_star = compute_hres_star(&rand, &xres_star);
    let k_seaf = derive_kseaf(&k_ausf, sn_name).unwrap();
    println!("HXRES* {}", hex::encode(hxres_star));
    println!("KSEAF  {}", hex::encode(k_seaf));

    // SEAF: KAMF, from the SUPI and the ABBA
    let k_amf = derive_kamf(&k_seaf, "208930000000001", &[0x00, 0x00]).unwrap();
    println!("KAMF   {}", hex::encode(k_amf));

    // The RES* of the UE is compared in constant time
    let res_star = xres_star;
    println!("RES* accepted: {}", constant_time_eq(&res_star, &xres_star));
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_security::nas_5gs::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, nas_cipher,
        nas_mac,
    };

    let key = |s: &str| <[u8; 16]>::try_from(hex::decode(s).unwrap()).unwrap();
    let k_nas_enc = key("f47ae570afde775373d1b313d2176f54");
    let k_nas_int = key("28ddb5356880149b9fee22f2367522a4");
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);

    // What came after the security header: the MAC, the sequence number and
    // the ciphered message
    let (received_mac, sequence_number) = (0x83e4_d009, 0);
    let mut message = [0xb5, 0x7d, 0xd5];

    // The NAS COUNT is the overflow counter that the receiver keeps and the
    // sequence number
    let count = NasCount::from_parts(0, sequence_number);
    let (access, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);

    let protected = [&[sequence_number][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    println!("MAC {mac:08x}, as received: {}", mac == received_mac);

    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    println!("deciphered {}", hex::encode(message));
}

/// The Rust block 4 of README.md.
fn block_4() {
    use oxirush_security::nas_eps::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, derive_kasme, derive_knas_enc,
        derive_knas_int, nas_cipher, nas_mac, service_request_short_mac,
    };
    use oxirush_security::plmn_to_bytes;

    // KASME from CK, IK, the serving network identity and SQN xor AK
    let (ck, ik, sqn_xor_ak) = ([0x11; 16], [0x22; 16], [0; 6]);
    let sn_id = plmn_to_bytes("208", "93").unwrap();
    let kasme = derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak);

    // The NAS keys of the selected algorithms
    let (eea2, eia2) = (CipheringAlgorithm::EEA2, IntegrityAlgorithm::EIA2);
    let knas_enc = derive_knas_enc(&kasme, eea2);
    let knas_int = derive_knas_int(&kasme, eia2);

    // An uplink EMM STATUS with cause #3 and NAS COUNT 0
    let (count, uplink) = (NasCount::ZERO, Direction::Uplink);
    let mut message = [0x07, 0x60, 0x03];
    nas_cipher(&knas_enc, count, uplink, &mut message, eea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&knas_int, count, uplink, &protected, eia2);
    println!("ciphered {}, MAC {mac:08x}", hex::encode(message));

    // The MME computes the same MAC over what it received, then deciphers
    let received = [&[count.sequence_number()][..], &message].concat();
    println!("MAC as sent: {}", nas_mac(&knas_int, count, uplink, &received, eia2) == mac);
    nas_cipher(&knas_enc, count, uplink, &mut message, eea2);
    println!("deciphered {}", hex::encode(message));

    // The short MAC of a SERVICE REQUEST with NAS COUNT 1: KSI 0 and sequence
    // number 1 in its second octet
    let count = NasCount::new(1).unwrap();
    let short_mac = service_request_short_mac(&knas_int, count, uplink, 0x01, eia2);
    println!("short MAC {short_mac:04x}");
}

/// The Rust block 5 of README.md.
fn block_5() {
    use oxirush_security::nas_5gs::{
        NasCount, derive_kamf_prime_handover, derive_kgnb, derive_kng_ran_star, derive_nh,
    };

    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();

    // KgNB from the uplink NAS COUNT of the message that set the context up,
    // then the chain of NH: the first from KgNB, the next from the one before
    let k_gnb = derive_kgnb(&k_amf, NasCount::ZERO);
    let nh_1 = derive_nh(&k_amf, &k_gnb);
    let nh_2 = derive_nh(&k_amf, &nh_1);
    println!("KgNB     {}", hex::encode(k_gnb));
    println!("NH 1     {}", hex::encode(nh_1));
    println!("NH 2     {}", hex::encode(nh_2));

    // KNG-RAN* of a target cell, from its PCI and its downlink ARFCN: from the
    // current KgNB, or from an NH that the target has not used
    let (pci, arfcn_dl) = (501, 632_628);
    let horizontal = derive_kng_ran_star(&k_gnb, pci, arfcn_dl).unwrap();
    let vertical = derive_kng_ran_star(&nh_2, pci, arfcn_dl).unwrap();
    println!("KNG-RAN* {}", hex::encode(horizontal));
    println!("KNG-RAN* {}", hex::encode(vertical));

    // KAMF' for a target AMF, from the downlink NAS COUNT
    let count = NasCount::new(5).unwrap();
    println!("KAMF'    {}", hex::encode(derive_kamf_prime_handover(&k_amf, count)));
}

/// The Rust block 6 of README.md.
fn block_6() {
    use oxirush_security::nas_5gs::{
        msin_to_bcd, suci_decrypt_a, suci_scheme_output_a, suci_to_string, suci_to_supi,
    };
    use oxirush_security::plmn_to_bytes;

    let key = |s: &str| <[u8; 32]>::try_from(hex::decode(s).unwrap()).unwrap();
    let public = key("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");
    let private = key("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");

    // UE: the scheme output is an ephemeral public key, the ciphered MSIN and a
    // MAC tag. The key is drawn at each call
    let msin = msin_to_bcd("001002086").unwrap();
    let output = suci_scheme_output_a(&msin, &public).unwrap();
    println!("scheme output of {} octets", output.len());

    // Home network: the MSIN again
    let deconcealed = suci_decrypt_a(&output, &private).unwrap();
    println!("MSIN {}", hex::encode(deconcealed));

    // The SUCI of a NAS message, with the scheme output of Annex C.4.3.1
    let mut suci = vec![0x01]; // SUPI format IMSI, type of identity SUCI
    suci.extend(plmn_to_bytes("274", "012").unwrap());
    suci.extend([0xf0, 0xff, 0x01, 0x01]); // routing indicator 0, Profile A, key 1
    suci.extend(hex::decode(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
    ).unwrap());
    println!("{}", suci_to_string(&suci).unwrap());
    println!("{:?}", suci_to_supi(&suci, Some(&private)));
    println!("{:?}", suci_to_supi(&suci, None));
}

/// The Rust block 7 of README.md.
fn block_7() {
    use oxirush_security::nas_5gs::{
        NaiProtectionScheme, conceal_network_specific_supi, deconceal_network_specific_suci,
        encode_nai_suci, parse_nai_suci,
    };

    let key = |s: &str| <[u8; 32]>::try_from(hex::decode(s).unwrap()).unwrap();
    let public = key("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");
    let private = key("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");

    // UE: the username is concealed, the realm is not
    let scheme = NaiProtectionScheme::ProfileA {
        home_network_public_key_id: 1,
        home_network_public_key: &public,
    };
    let suci = conceal_network_specific_supi("sensor-17@example.net", "0", scheme).unwrap();
    let text = encode_nai_suci(&suci).unwrap();
    println!("{}...", &text[..31]);

    // Home network
    let parsed = parse_nai_suci(&text).unwrap();
    let supi = deconceal_network_specific_suci(&parsed, Some(&private)).unwrap();
    println!("{supi}");
}

/// The Rust block 8 of README.md.
fn block_8() {
    use oxirush_security::{
        Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher_bits, nia_mac_bits,
    };

    let key = |s: &str| <[u8; 16]>::try_from(hex::decode(s).unwrap()).unwrap();

    // 128-EEA2 test set 1 of TS 33.401 Annex C.1.1: 253 bits
    let k = key("d3c5d592327fb11c4035c6680af8c6d1");
    let mut data =
        hex::decode("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0").unwrap();
    let (count, bearer, downlink) = (0x398a_59b4, Bearer::new(0x15).unwrap(), Direction::Downlink);
    nea_cipher_bits(&k, count, bearer, downlink, &mut data, 253, CipheringAlgorithm::EEA2).unwrap();
    println!("{}", hex::encode(&data));

    // 128-EIA2 test set 1 of Annex C.2.1: 58 bits
    let k = key("2bd6459f82c5b300952c49104881ff48");
    let message = hex::decode("3332346263393840").unwrap();
    let (count, bearer, uplink) = (0x38a6_f056, Bearer::new(0x18).unwrap(), Direction::Uplink);
    let mac = nia_mac_bits(&k, count, bearer, uplink, &message, 58, IntegrityAlgorithm::EIA2);
    println!("{:08x}", mac.unwrap());
}

/// The Rust block 9 of README.md.
fn block_9() {
    use oxirush_security::nas_5gs::{
        CipheringAlgorithm, IntegrityAlgorithm, select_ciphering_algo, select_integrity_algo,
        select_integrity_algo_with_preference,
    };

    // The EA and IA octets of a UE security capability: EA0, EA1 and EA2, and
    // IA1 and IA2. 128-NEA2 and 128-NIA2 are AES, 128-NEA1 and 128-NIA1 SNOW 3G
    println!("{:?}", select_ciphering_algo(0xe0));
    println!("{:?}", select_integrity_algo(0x60));

    // An operator's order in the place of NIA2, NIA1, NIA3
    let order = [IntegrityAlgorithm::NIA1, IntegrityAlgorithm::NIA2];
    println!("{:?}", select_integrity_algo_with_preference(0x60, &order));

    // An identifier from a message: 4 to 7 are reserved
    println!("{:?}", CipheringAlgorithm::try_from(2));
    println!("{:?}", IntegrityAlgorithm::try_from(5));
}

/// The Rust block 10 of README.md.
fn block_10() {
    use oxirush_security::{
        build_guti_bytes, parse_guti_tmsi, plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode,
    };

    // MCC 208 and MNC 93
    let plmn = plmn_to_bytes("208", "93").unwrap();
    println!("{} is {:?}", hex::encode(plmn), plmn_from_bytes(&plmn).unwrap());

    // AMF region 1, set 1 and pointer 2, and a 5G-TMSI
    let guti = build_guti_bytes(&plmn, 0x01, 0x001, 0x02, 0x1122_3344).unwrap();
    println!("{} has 5G-TMSI {:08x}", hex::encode(guti), parse_guti_tmsi(&guti).unwrap());

    // The digits of an IMSI
    let imsi = tbcd_encode("208930000000001").unwrap();
    println!("{} is {}", hex::encode(&imsi), tbcd_decode(&imsi));
}

/// The Rust block 1 of src/lib.rs.
fn block_11() {
    use oxirush_security::nas_5gs::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, derive_knas_enc,
        derive_knas_int, nas_cipher, nas_mac,
    };

    // KAMF, the key of the AMF
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();

    // The NAS keys of the algorithms that the AMF selected
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let k_nas_enc = derive_knas_enc(&k_amf, nea2);
    let k_nas_int = derive_knas_int(&k_amf, nia2);
    println!("KNASenc {}", hex::encode(k_nas_enc));
    println!("KNASint {}", hex::encode(k_nas_int));

    // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
    // it, then compute the MAC over the sequence number and the ciphertext
    let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
    let mut message = [0x7e, 0x00, 0x43];
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    println!("ciphered {}, MAC {mac:08x}", hex::encode(message));
}
