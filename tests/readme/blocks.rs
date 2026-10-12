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
    block_12,
    block_13,
];

/// The Rust block 1 of README.md.
fn block_1() {
    use oxirush_security::nas_5gs::{
        KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
    };
    use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};

    // KAMF, the key of the AMF, as the 5G AKA example below derives it
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf).unwrap()).unwrap();

    // The NAS keys of the algorithms that the AMF selected
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let k_nas_enc = derive_knas_enc(&k_amf, nea2);
    let k_nas_int = derive_knas_int(&k_amf, nia2);
    println!("KNASenc {}", hex::encode(k_nas_enc.as_octets()));
    println!("KNASint {}", hex::encode(k_nas_int.as_octets()));

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
    use oxirush_security::nas_5gs::{
        Supi, compute_hxres_star, compute_res_star, compute_xres_star, derive_kamf, derive_kausf,
        derive_kseaf,
    };
    use oxirush_security::{Autn, Ck, Ik, Rand};

    let octets = |s: &str| hex::decode(s).unwrap();
    let ck = Ck::from_slice(&octets("b40ba9a3c58b2a05bbf0d987b21bf8cb")).unwrap();
    let ik = Ik::from_slice(&octets("f769bcd751044604127672711c6d3441")).unwrap();
    let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
    // SQN xor AK, the AMF field and MAC-A
    let autn = Autn::from_slice(&octets("55f328b43577b9b94a9ffac354dfafb3")).unwrap();
    let res = octets("a54211d5e3ba50bf");
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

    // UDM: KAUSF and XRES*
    let k_ausf = derive_kausf(&ck, &ik, sn_name, &autn).unwrap();
    let xres_star = compute_xres_star(&ck, &ik, sn_name, &rand, &res).unwrap();
    println!("KAUSF  {}", hex::encode(k_ausf.as_octets()));
    println!("XRES*  {}", hex::encode(xres_star.as_octets()));

    // AUSF: HXRES* and KSEAF
    let hxres_star = compute_hxres_star(&rand, &xres_star);
    let k_seaf = derive_kseaf(&k_ausf, sn_name).unwrap();
    println!("HXRES* {}", hex::encode(hxres_star.as_octets()));
    println!("KSEAF  {}", hex::encode(k_seaf.as_octets()));

    // SEAF: KAMF, from the SUPI and the ABBA. The SUPI is the one that a SUCI
    // de-conceals to, or the text of a service based interface
    let supi = Supi::parse("imsi-208930000000001").unwrap();
    let k_amf = derive_kamf(&k_seaf, &supi, &[0x00, 0x00]).unwrap();
    println!("KAMF   {}", hex::encode(k_amf.as_octets()));

    // UE: RES*, which the AUSF compares with XRES* in constant time
    let res_star = compute_res_star(&ck, &ik, sn_name, &rand, &res).unwrap();
    println!("RES* accepted: {}", xres_star.accepts(&res_star));
}

/// The Rust block 3 of README.md.
fn block_3() {
    use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection, nas_cipher, nas_mac};
    use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};

    let octets = |s: &str| hex::decode(s).unwrap();
    let k_nas_enc = KNasEnc::from_slice(&octets("f47ae570afde775373d1b313d2176f54")).unwrap();
    let k_nas_int = KNasInt::from_slice(&octets("28ddb5356880149b9fee22f2367522a4")).unwrap();
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);

    // What came after the security header: the MAC, the sequence number and
    // the ciphered message
    let (received_mac, sequence_number) = (0x83e4_d009, 0);
    let mut message = [0xb5, 0x7d, 0xd5];

    // The receiver keeps the lowest uplink NAS COUNT that it still accepts,
    // zero in a new security context, and estimates the NAS COUNT of the
    // message from its sequence number
    let lowest = NasCount::ZERO;
    let count = lowest.estimate(sequence_number).unwrap();
    let (access, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);

    let protected = [&[sequence_number][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    println!("MAC {mac:08x}, as received: {}", mac == received_mac);

    // The MAC is right: the message is deciphered, and its NAS COUNT is not
    // accepted again
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let lowest = count.next().unwrap();
    println!("deciphered {}, then from NAS COUNT {}", hex::encode(message), lowest.get());
}

/// The Rust block 4 of README.md.
fn block_4() {
    use oxirush_security::nas_eps::{
        derive_kasme, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
        service_request_short_mac,
    };
    use oxirush_security::{
        Autn, CipheringAlgorithm, Ck, Direction, Ik, IntegrityAlgorithm, NasCount, Plmn,
    };

    // KASME from CK, IK, the serving network and the AUTN of the
    // authentication, whose SQN xor AK the derivation takes
    let (ck, ik, autn) = (Ck::new([0x11; 16]), Ik::new([0x22; 16]), Autn::new([0; 16]));
    let kasme = derive_kasme(&ck, &ik, Plmn::new("208", "93").unwrap(), &autn);

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
    let count = count.next().unwrap();
    let short_mac = service_request_short_mac(&knas_int, count, uplink, 0x01, eia2);
    println!("short MAC {short_mac:04x}");
}

/// The Rust block 5 of README.md.
fn block_5() {
    use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection, cipher_job, mac_job};
    use oxirush_security::{
        CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, nea_cipher_batch, nia_mac_batch,
    };

    // Three UEs: the NAS keys, the downlink NAS COUNT and the algorithms of each
    let k_nas_enc = [[0x11; 16], [0x22; 16], [0x33; 16]].map(KNasEnc::new);
    let k_nas_int = [[0x44; 16], [0x55; 16], [0x66; 16]].map(KNasInt::new);
    let counts = [7, 0, 41].map(|count| NasCount::new(count).unwrap());
    let nea = [CipheringAlgorithm::NEA2, CipheringAlgorithm::NEA1, CipheringAlgorithm::NEA2];
    let nia = [IntegrityAlgorithm::NIA2, IntegrityAlgorithm::NIA1, IntegrityAlgorithm::NIA2];
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);

    // The sequence number and the message of each
    let mut messages = [
        vec![7, 0x7e, 0x00, 0x54, 0x43, 0x90],
        vec![0, 0x7e, 0x00, 0x5d, 0x02],
        vec![41, 0x7e, 0x00, 0x68, 0x01, 0x00, 0x2e],
    ];

    let mut jobs: Vec<_> = (messages.iter_mut().enumerate())
        .map(|(ue, message)| {
            let (key, count) = (&k_nas_enc[ue], counts[ue]);
            cipher_job(key, count, access, downlink, &mut message[1..], nea[ue])
        })
        .collect();
    nea_cipher_batch(&mut jobs);

    // The MAC is over the sequence number and the ciphered message
    let mut jobs: Vec<_> = (messages.iter().enumerate())
        .map(|(ue, message)| {
            let (key, count) = (&k_nas_int[ue], counts[ue]);
            mac_job(key, count, access, downlink, message, nia[ue])
        })
        .collect();
    nia_mac_batch(&mut jobs);
    for (job, message) in jobs.iter().zip(&messages) {
        println!("MAC {:08x} of {}", job.mac().unwrap(), hex::encode(message));
    }
}

/// The Rust block 6 of README.md.
fn block_6() {
    use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection};
    use oxirush_security::{
        CipheringAlgorithm, CipheringContext, Direction, IntegrityAlgorithm, IntegrityContext,
        NasCount,
    };

    // The contexts of a UE, made once, when its NAS keys are derived
    let ciphering = CipheringContext::new(&KNasEnc::new([0x11; 16]), CipheringAlgorithm::NEA2);
    let integrity = IntegrityContext::new(&KNasInt::new([0x44; 16]), IntegrityAlgorithm::NIA2);
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);

    // Each downlink message takes the next NAS COUNT
    let mut count = NasCount::new(7).unwrap();
    for plain in [&[0x7e, 0x00, 0x54, 0x43, 0x90][..], &[0x7e, 0x00, 0x5d, 0x02]] {
        let mut message = [&[count.sequence_number()][..], plain].concat();
        ciphering.cipher(count, access, downlink, &mut message[1..]);
        let mac = integrity.mac(count, access, downlink, &message);
        println!("NAS COUNT {}: MAC {mac:08x} of {}", count.get(), hex::encode(&message));
        count = count.next().unwrap();
    }
}

/// The Rust block 7 of README.md.
fn block_7() {
    use oxirush_security::NasCount;
    use oxirush_security::nas_5gs::{
        KAmf, derive_kamf_prime_handover, derive_kgnb, derive_kng_ran_star, derive_nh,
    };

    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf).unwrap()).unwrap();

    // KgNB from the uplink NAS COUNT of the message that set the context up,
    // then the chain of NH: the first from KgNB, the next from the one before
    let k_gnb = derive_kgnb(&k_amf, NasCount::ZERO);
    let nh_1 = derive_nh(&k_amf, &k_gnb);
    let nh_2 = derive_nh(&k_amf, &nh_1);
    println!("KgNB     {}", hex::encode(k_gnb.as_octets()));
    println!("NH 1     {}", hex::encode(nh_1.as_octets()));
    println!("NH 2     {}", hex::encode(nh_2.as_octets()));

    // KNG-RAN* of a target cell, from its PCI and its downlink ARFCN: from the
    // current KgNB, or from an NH that the target has not used
    let (pci, arfcn_dl) = (501, 632_628);
    let horizontal = derive_kng_ran_star(&k_gnb, pci, arfcn_dl).unwrap();
    let vertical = derive_kng_ran_star(&nh_2, pci, arfcn_dl).unwrap();
    println!("KNG-RAN* {}", hex::encode(horizontal.as_octets()));
    println!("KNG-RAN* {}", hex::encode(vertical.as_octets()));

    // KAMF' for a target AMF, from the downlink NAS COUNT
    let k_amf_prime = derive_kamf_prime_handover(&k_amf, NasCount::new(5).unwrap());
    println!("KAMF'    {}", hex::encode(k_amf_prime.as_octets()));
}

/// The Rust block 8 of README.md.
fn block_8() {
    use oxirush_security::Plmn;
    use oxirush_security::nas_5gs::{HomeNetworkPrivateKey, Protection, Suci};

    // Home network: its private key, and the public key that its subscribers
    // have under the identifier 27
    let private = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    let private = <[u8; 32]>::try_from(hex::decode(private).unwrap()).unwrap();
    let private = HomeNetworkPrivateKey::profile_a(&private);
    let public = private.public_key();
    println!("public key {}", hex::encode(public.to_octets()));

    // UE: conceal the IMSI 274 012 001002086. The scheme output is an
    // ephemeral public key, drawn at each call, the ciphered MSIN and a MAC tag
    let protection = Protection::Ecies { key_id: 27, key: &public };
    let plmn = Plmn::new("274", "012").unwrap();
    let suci = Suci::conceal_imsi(plmn, "001002086", "0", protection).unwrap();
    let identity = suci.to_nas().unwrap();
    println!("mobile identity of {} octets", identity.len());

    // SIDF: read the SUCI, take the private key that its scheme and its key
    // identifier name, and de-conceal
    let received = Suci::from_nas(&identity).unwrap();
    println!("{:?}, key {}", received.protection_scheme(), received.home_network_public_key_id());
    let supi = received.deconceal(Some(&private)).unwrap();
    println!("{supi}, of which KAMF takes {}", supi.identity());

    // The SUCI of Annex C.4.3.1, and what a SIDF without the key is told
    let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
    identity.extend(hex::decode(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
    ).unwrap());
    let annex = Suci::from_nas(&identity).unwrap();
    println!("{annex}");
    println!("{:?}", annex.deconceal(Some(&private)));
    println!("{:?}", annex.deconceal(None));
}

/// The Rust block 9 of README.md.
fn block_9() {
    use oxirush_security::nas_5gs::{HomeNetworkPrivateKey, Protection, Suci, Supi};

    let private = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    let private = <[u8; 32]>::try_from(hex::decode(private).unwrap()).unwrap();
    let private = HomeNetworkPrivateKey::profile_a(&private);
    let public = private.public_key();

    // UE: the username is concealed, the realm is not
    let supi = Supi::network_specific("sensor-17@example.net").unwrap();
    let protection = Protection::Ecies { key_id: 1, key: &public };
    let suci = Suci::conceal_nai(&supi, "0", protection).unwrap();
    let text = suci.to_nai();
    println!("{}...", &text[..31]);

    // Home network
    let received = Suci::from_nai(&text).unwrap();
    println!("{}", received.deconceal(Some(&private)).unwrap());

    // A text that is no SUCI says what is wrong with it
    println!("{:?}", Suci::from_nai("type1.rid0.schid1.hnkey1@example.net"));
}

/// The Rust block 10 of README.md.
fn block_10() {
    use oxirush_security::nas_eps::{KNasEnc, KNasInt};
    use oxirush_security::{
        Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher_bits, nia_mac_bits,
    };

    let octets = |s: &str| hex::decode(s).unwrap();

    // 128-EEA2 test set 1 of TS 33.401 Annex C.1.1: 253 bits. A key type
    // takes the octets of a test set with `from_slice`
    let k = KNasEnc::from_slice(&octets("d3c5d592327fb11c4035c6680af8c6d1")).unwrap();
    let mut data = octets("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0");
    let (count, bearer, downlink) = (0x398a_59b4, Bearer::new(0x15).unwrap(), Direction::Downlink);
    nea_cipher_bits(&k, count, bearer, downlink, &mut data, 253, CipheringAlgorithm::EEA2).unwrap();
    println!("{}", hex::encode(&data));

    // 128-EIA2 test set 1 of Annex C.2.1: 58 bits
    let k = KNasInt::from_slice(&octets("2bd6459f82c5b300952c49104881ff48")).unwrap();
    let message = octets("3332346263393840");
    let (count, bearer, uplink) = (0x38a6_f056, Bearer::new(0x18).unwrap(), Direction::Uplink);
    let mac = nia_mac_bits(&k, count, bearer, uplink, &message, 58, IntegrityAlgorithm::EIA2);
    println!("{:08x}", mac.unwrap());
}

/// The Rust block 11 of README.md.
fn block_11() {
    use oxirush_security::{
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

    // The name of an algorithm in each system, for a log
    let selected = select_integrity_algo(0x60).unwrap();
    println!("{} in 5GS, {} in EPS", selected.name_5gs(), selected.name_eps());
}

/// The Rust block 12 of README.md.
fn block_12() {
    use oxirush_security::nas_5gs::Guti;
    use oxirush_security::{Plmn, tbcd_decode, tbcd_encode};

    // MCC 208 and MNC 93
    let plmn = Plmn::new("208", "93").unwrap();
    println!("{} is {plmn}", hex::encode(plmn.to_octets()));

    // AMF region 1, set 1 and pointer 2, and a 5G-TMSI
    let guti = Guti::new(plmn, 0x01, 0x001, 0x02, 0x1122_3344).unwrap();
    let octets = guti.to_octets();
    let read = Guti::from_octets(&octets).unwrap();
    println!("{} has 5G-TMSI {:08x}", hex::encode(octets), read.tmsi());

    // The digits of an IMSI
    let imsi = tbcd_encode("208930000000001").unwrap();
    println!("{} is {}", hex::encode(&imsi), tbcd_decode(&imsi).unwrap());
}

/// The Rust block 1 of src/lib.rs.
fn block_13() {
    use oxirush_security::nas_5gs::{
        KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
    };
    use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};

    // KAMF, the key of the AMF
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf).unwrap()).unwrap();

    // The NAS keys of the algorithms that the AMF selected
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let k_nas_enc = derive_knas_enc(&k_amf, nea2);
    let k_nas_int = derive_knas_int(&k_amf, nia2);
    println!("KNASenc {}", hex::encode(k_nas_enc.as_octets()));
    println!("KNASint {}", hex::encode(k_nas_int.as_octets()));

    // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
    // it, then compute the MAC over the sequence number and the ciphertext
    let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
    let mut message = [0x7e, 0x00, 0x43];
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    println!("ciphered {}, MAC {mac:08x}", hex::encode(message));
}
