# oxirush-security

[![Crates.io](https://img.shields.io/crates/v/oxirush-security.svg)](https://crates.io/crates/oxirush-security)
[![Documentation](https://docs.rs/oxirush-security/badge.svg)](https://docs.rs/oxirush-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

MILENAGE, 5G AKA and EAP-AKA', key derivation, NAS integrity and ciphering,
and SUCI concealment for 5GS and EPS, in Rust (3GPP TS 35.206, TS 33.102,
TS 33.501 and TS 33.401).

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_5gs::{
    KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
};
use oxirush_security::{Direction, NasCount};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KAMF, the key of the AMF, as the 5G AKA example below derives it
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;

    // The NAS keys of the algorithms that the AMF selected
    let (nea2, nia2) = (Algorithm::Aes, Algorithm::Aes);
    let k_nas_enc = derive_knas_enc(&k_amf, nea2);
    let k_nas_int = derive_knas_int(&k_amf, nia2);
    assert_eq!(hex::encode(k_nas_enc.as_octets()), "f47ae570afde775373d1b313d2176f54");
    assert_eq!(hex::encode(k_nas_int.as_octets()), "28ddb5356880149b9fee22f2367522a4");

    // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
    // it, then compute the MAC over the sequence number and the ciphertext
    let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
    let mut message = [0x7e, 0x00, 0x43];
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    assert_eq!((hex::encode(message), mac), ("b57dd5".to_string(), 0x83e4_d009));
    Ok(())
}
```

## Installation

```toml
[dependencies]
oxirush-security = { version = "0.5", features = ["suci"] }
hex = "0.4" # for the examples of this page
```

| Feature | Adds | Needs |
|---------|------|-------|
| none | The algorithms, MILENAGE, the key derivations, NAS integrity and ciphering | Nothing: `no_std`, no allocator |
| `std` (default) | Run-time CPU detection on AArch64 targets other than Linux, Android and Apple | The standard library |
| `alloc` | The functions that return a `Vec` or a `String` | An allocator |
| `batch` | Many messages, or many subscribers' MILENAGE, in one call | |
| `suci` | SUCI concealment and deconcealment: null scheme, Profile A and Profile B | `alloc`, and a `getrandom` source |
| `idna` | NAI realms and usernames checked as internationalized names | `suci` |

The identities (`Plmn`, `Supi`, `Guti5g`, …) are those of oxirush-utils, in
`oxirush_security::identity`. The minimum supported Rust version is 1.88.

## Protect and check a NAS message

This is the receiving side of the first example: it checks the MAC before
it deciphers.

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection, nas_cipher, nas_mac};
use oxirush_security::{Direction, NasCount, constant_time_eq};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k_nas_enc = KNasEnc::from_slice(&hex::decode("f47ae570afde775373d1b313d2176f54")?)?;
    let k_nas_int = KNasInt::from_slice(&hex::decode("28ddb5356880149b9fee22f2367522a4")?)?;
    let (nea2, nia2) = (Algorithm::Aes, Algorithm::Aes);

    // What came after the security header: the MAC, the sequence number and
    // the ciphered message
    let (received_mac, sequence_number) = (0x83e4_d009_u32, 0);
    let mut message = [0xb5, 0x7d, 0xd5];

    // The receiver keeps the lowest uplink NAS COUNT that it still accepts,
    // zero in a new security context, and estimates the NAS COUNT of the
    // message from its sequence number
    let lowest = NasCount::ZERO;
    let count = lowest.estimate(sequence_number)?;
    let (access, uplink) = (NasConnection::ThreeGpp, Direction::Uplink);

    let protected = [&[sequence_number][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
    // Compare in constant time
    let right = constant_time_eq(&mac.to_be_bytes(), &received_mac.to_be_bytes());
    assert!(right);

    // The MAC is right: the message is deciphered, and its NAS COUNT is not
    // accepted again
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let lowest = count.next()?;
    assert_eq!((message, lowest.get()), ([0x7e, 0x00, 0x43], 1));
    Ok(())
}
```

In EPS the functions are in `nas_eps`, and take no NAS connection: the
BEARER of EPS NAS is zero.

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_eps::{
    derive_kasme, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
    service_request_short_mac,
};
use oxirush_security::{Autn, Ck, Direction, Ik, NasCount};
use oxirush_security::identity::Plmn;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KASME from CK, IK, the serving network and the AUTN, then the NAS keys
    let (ck, ik, autn) = (Ck::new(&[0x11; 16]), Ik::new(&[0x22; 16]), Autn::new(&[0; 16]));
    let kasme = derive_kasme(&ck, &ik, Plmn::new("208", "93")?, &autn);
    let (eea2, eia2) = (Algorithm::Aes, Algorithm::Aes);
    let (knas_enc, knas_int) = (derive_knas_enc(&kasme, eea2), derive_knas_int(&kasme, eia2));

    // An uplink EMM STATUS with cause #3 and NAS COUNT 0
    let (count, uplink) = (NasCount::ZERO, Direction::Uplink);
    let mut message = [0x07, 0x60, 0x03];
    nas_cipher(&knas_enc, count, uplink, &mut message, eea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&knas_int, count, uplink, &protected, eia2);
    assert_eq!((hex::encode(message), mac), ("b02c47".to_string(), 0x190a_f1e7));

    // The short MAC of a SERVICE REQUEST with NAS COUNT 1: its first octet,
    // then KSI 0 and sequence number 1 in its second
    let next = count.next()?;
    let short_mac = service_request_short_mac(&knas_int, next, uplink, 0xc7, 0x01, eia2)?;
    assert_eq!(short_mac, 0x7e95);
    Ok(())
}
```

[oxirush-nas](https://github.com/linouxis9/oxirush-nas) writes the security
header of a protected message, and its security context calls these
functions.

## Run 5G AKA, from MILENAGE to KAMF

The subscriber of TS 35.208 test set 1: its K, its OPc, and the RAND, the
SQN and the AMF of a challenge.

```rust
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
use oxirush_security::nas_5gs::{compute_hxres_star, derive_kamf, derive_kausf, derive_kseaf};
use oxirush_security::identity::Supi;
use oxirush_security::Rand;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k = K::from_slice(&hex::decode("465b5ce8b199b49faa5f0a2ee238a6bc")?)?;
    let opc = Opc::from_slice(&hex::decode("cd63cb71954a9f4e48a5994e37a02baf")?)?;
    let subscriber = Milenage::new(&k, &opc);
    let rand = Rand::from_slice(&hex::decode("23553cbe9637a89d218ae64dae47bf35")?)?;
    let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607)?, Amf::new(&[0xb9, 0xb9]));
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

    // UDM: the authentication vector of MILENAGE, then KAUSF and XRES*
    let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
    let k_ausf = derive_kausf(vector.ck(), vector.ik(), sn_name, vector.autn())?;
    let xres_star = vector.xres_star(sn_name)?;
    assert_eq!(hex::encode(vector.autn().as_octets()), "55f328b43577b9b94a9ffac354dfafb3");
    assert_eq!(
        hex::encode(k_ausf.as_octets()),
        "f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9",
    );
    assert_eq!(hex::encode(xres_star.as_octets()), "5cc9527f4d21c43bee83a15443acf1c4");

    // AUSF: HXRES* and KSEAF
    let hxres_star = compute_hxres_star(vector.rand(), &xres_star);
    let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
    assert_eq!(hex::encode(hxres_star.as_octets()), "6970075e3c8245fdc2073003cf166279");
    assert_eq!(
        hex::encode(k_seaf.as_octets()),
        "cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa",
    );

    // SEAF: KAMF, from the SUPI and the ABBA. The SUPI is the one that a SUCI
    // de-conceals to, or the text of a service based interface
    let supi = Supi::parse("imsi-208930000000001")?;
    let k_amf = derive_kamf(&k_seaf, supi.identity(), &[0x00, 0x00])?;
    assert_eq!(
        hex::encode(k_amf.as_octets()),
        "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4",
    );

    // UE: the USIM checks the MAC of AUTN. The ME judges the SQN and the
    // separation bit of the AMF, then sends RES*, which the AUSF compares with
    // XRES* in constant time
    let response = subscriber.check_autn(&rand, vector.autn())?;
    assert_eq!(response.sqn().get(), 0xff9b_b4d0_b607);
    assert!(response.amf().separation_bit());
    let res_star = response.res_star(sn_name)?;
    assert!(xres_star.accepts(&res_star));
    Ok(())
}
```

`Opc::from_op` derives OPc from OP. `nas_eps::derive_kasme` takes the CK,
the IK and the AUTN of a vector for EPS AKA.

## Derive the keys of EAP-AKA'

EAP-AKA' is the other primary authentication of 5GS (TS 33.501 §6.1.3.1).
CK' and IK' bind the vector to the network name. PRF' over them and the
identity gives K_aut, which keys AT_MAC, and the EMSK, whose first 256 bits
are KAUSF. The values are those of RFC 9048 Appendix D.

```rust
use oxirush_security::eap_aka_prime::{Keys, derive_ck_ik_prime};
use oxirush_security::{Autn, Ck, Ik, constant_time_eq};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ck = Ck::from_slice(&hex::decode("5349fbe098649f948f5d2e973a81c00f")?)?;
    let ik = Ik::from_slice(&hex::decode("9744871ad32bf9bbd1dd5ce54e3e2e5a")?)?;
    let autn = Autn::from_slice(&hex::decode("bb52e91c747ac3ab2a5c23d15ee351d5")?)?;
    let (ck_prime, ik_prime) = derive_ck_ik_prime(&ck, &ik, b"WLAN", &autn)?;
    let keys = Keys::derive(&ck_prime, &ik_prime, b"0555444333222111");
    assert_eq!(
        hex::encode(keys.k_aut().as_octets()),
        "0842ea722ff6835bfa2032499fc3ec23c2f0e388b4f07543ffc677f1696d71ea",
    );
    assert_eq!(
        hex::encode(keys.kausf().as_octets()),
        "f861703cd775590e16c7679ea3874ada866311de290764d760cf76df647ea01c",
    );

    // The server: an EAP-Request/AKA'-Challenge with its AT_MAC alone. The
    // MAC is computed over the packet with a zero AT_MAC value, then written there
    let mut packet = [0; 28];
    packet[..12].copy_from_slice(&[1, 7, 0, 28, 50, 1, 0, 0, 11, 5, 0, 0]);
    let mac = keys.k_aut().mac(&packet);
    assert_eq!(hex::encode(mac), "b97e71d83feb98764385f6fb57fed122");
    packet[12..].copy_from_slice(&mac);

    // The peer: it zeros the value that it received, and compares
    let received: [u8; 16] = packet[12..].try_into()?;
    packet[12..].fill(0);
    assert!(constant_time_eq(&keys.k_aut().mac(&packet), &received));
    Ok(())
}
```

## Re-synchronise a USIM

When a challenge's SQN is out of range, the USIM answers with an AUTS that
carries its own highest SQN (SQNMS). The home network checks the AUTS, reads
SQNMS, and starts again from the next SEQ.

```rust
use oxirush_security::milenage::{Amf, Auts, ChallengeAnswer, K, Milenage, Opc, Sqn};
use oxirush_security::Rand;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = Milenage::new(&K::new(&[0x46; 16]), &Opc::new(&[0xcd; 16]));
    let rand = Rand::new(&[0x23; 16]);
    let (sqn, amf) = (Sqn::try_from(32)?, Amf::new(&[0x80, 0]));
    let vector = subscriber.authentication_vector(&rand, &sqn, &amf);

    // UE: its SQNMS is 64, so the SQN 32 of the AUTN is not fresh
    let sqn_ms = Sqn::try_from(64)?;
    let answer = subscriber.answer_challenge(&rand, vector.autn(), &sqn_ms);
    let ChallengeAnswer::SynchFailure { auts, .. } = answer else {
        panic!("{answer:?}");
    };
    assert_eq!(hex::encode(auts.as_octets()), "5ef40417ef4cb9ac9e76640b820d");

    // Home network: check the AUTS against the RAND of the challenge, read
    // SQNMS, and take the next SEQ (with 5 bits of IND)
    let read = subscriber.verify_auts(&rand, &auts)?;
    assert_eq!(read.get(), 64);
    let next = Sqn::from_seq_ind(read.seq(5) + 1, 0, 5)?;
    assert_eq!(next.get(), 96);

    // An AUTS with one bit changed, or for another RAND, is refused
    let mut changed = *auts.as_octets();
    changed[13] ^= 1;
    let refused = subscriber.verify_auts(&rand, &Auts::new(&changed));
    assert_eq!(format!("{refused:?}"), "Err(MacFailure)");
    Ok(())
}
```

## Keep the keys of a UE between its messages

A context keeps a key, its algorithm and what can be precomputed from it
(AES round keys, CMAC subkeys). One context serves both directions, and
`job()` makes a batch job from it.

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection};
use oxirush_security::{CipheringContext, Direction, IntegrityContext, NasCount};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The contexts of a UE, made once, when its NAS keys are derived
    let ciphering = CipheringContext::new(&KNasEnc::new(&[0x11; 16]), Algorithm::Aes);
    let integrity = IntegrityContext::new(&KNasInt::new(&[0x44; 16]), Algorithm::Aes);
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);

    // Each downlink message takes the next NAS COUNT
    let mut count = NasCount::new(7)?;
    let mut sent = Vec::new();
    for plain in [&[0x7e, 0x00, 0x54, 0x43, 0x90][..], &[0x7e, 0x00, 0x5d, 0x02]] {
        let mut message = [&[count.sequence_number()][..], plain].concat();
        ciphering.cipher(count, access, downlink, &mut message[1..]);
        let mac = integrity.mac(count, access, downlink, &message);
        sent.push((count.get(), mac, hex::encode(&message)));
        count = count.next()?;
    }
    assert_eq!(
        sent,
        [(7, 0xafc5_3a82, "076b4a2c14c2".to_string()), (8, 0x5a27_e0ff, "08cc23803c".to_string())],
    );
    Ok(())
}
```

## Derive the keys of a handover

```rust
use oxirush_security::NasCount;
use oxirush_security::nas_5gs::{
    KAmf, derive_kamf_prime_handover, derive_kgnb, derive_kng_ran_star, derive_nh,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;

    // KgNB from the uplink NAS COUNT of the message that set the context up,
    // then the chain of NH: the first from KgNB, the next from the one before
    let k_gnb = derive_kgnb(&k_amf, NasCount::ZERO);
    let nh_1 = derive_nh(&k_amf, &k_gnb);
    let nh_2 = derive_nh(&k_amf, &nh_1);
    assert_eq!(
        hex::encode(k_gnb.as_octets()),
        "c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005",
    );
    assert_eq!(
        hex::encode(nh_1.as_octets()),
        "383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b",
    );
    assert_eq!(
        hex::encode(nh_2.as_octets()),
        "ab2e99ac759e44b2f31665b1593ac74dcf175b095956668d00a838a3f6505fb8",
    );

    // KNG-RAN* of a target cell, from its PCI and its downlink ARFCN: from the
    // current KgNB, or from an NH that the target has not used
    let (pci, arfcn_dl) = (501, 632_628);
    let horizontal = derive_kng_ran_star(&k_gnb, pci, arfcn_dl)?;
    let vertical = derive_kng_ran_star(&nh_2, pci, arfcn_dl)?;
    assert_eq!(
        hex::encode(horizontal.as_octets()),
        "58c111d9277e1e1aeeba2f9893fde7b5e855f42759ca5e46647004852d59b744",
    );
    assert_eq!(
        hex::encode(vertical.as_octets()),
        "563d8aba7015f1ad77af632104b023d51c1cd410ef2ff46886aa2e02887e71d1",
    );

    // KAMF' for a target AMF, from the downlink NAS COUNT
    let k_amf_prime = derive_kamf_prime_handover(&k_amf, NasCount::new(5)?);
    assert_eq!(
        hex::encode(k_amf_prime.as_octets()),
        "ae5e2cb9cda5b1687556e9c3d889d0edb0aa4e7317d409e0315dac5597ad438a",
    );
    Ok(())
}
```

`nas_eps` has `derive_kenb`, `derive_nh` and `derive_kenb_star` for EPS.
The keys of a change of system are in `nas_5gs`: `derive_mapped_kasme_idle`
and `derive_mapped_kamf_idle`, and those of a handover.

## Conceal and deconceal a SUCI

The home network's key pair is the one of Profile A in TS 33.501
Annex C.4. `HomeNetworkPrivateKey::profile_b` makes one of Profile B, and
the rest is the same. A SIDF with several keys picks one by the protection
scheme and the home network public key identifier of the SUCI it read. A
SUPI that is a NAI is concealed as a NAI (TS 23.003, 28.7.3). This needs the
`suci` feature.

```rust
use oxirush_security::identity::{NaiSuci, Plmn, RoutingIndicator, Suci, Supi};
use oxirush_security::nas_5gs::{
    HomeNetworkPrivateKey, Protection, conceal_imsi, conceal_nai, deconceal,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Home network: its private key, and the public key that its subscribers
    // have under the identifier 27
    let mut private = [0; 32];
    let text = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    hex::decode_to_slice(text, &mut private)?;
    let private = HomeNetworkPrivateKey::profile_a(&private);
    let public = private.public_key();
    assert_eq!(
        hex::encode(public.to_octets()),
        "5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650",
    );

    // UE: conceal the IMSI 274 012 001002086. The scheme output is an
    // ephemeral public key, drawn at each call, the ciphered MSIN and a MAC tag
    let protection = Protection::Ecies { key_id: 27, key: &public };
    let plmn = Plmn::new("274", "012")?;
    let routing = RoutingIndicator::default();
    let suci = conceal_imsi(plmn, "001002086", routing, protection)?;
    let identity = suci.to_nas_octets()?;
    assert_eq!(identity.len(), 53);

    // SIDF: read the SUCI, take the private key that its scheme and its key
    // identifier name, and de-conceal
    let (received, _) = Suci::from_nas_octets_tolerant(&identity)?;
    let key_id = received.home_network_public_key_identifier();
    assert_eq!(format!("{:?}", received.protection_scheme()), "ProtectionScheme(1: profile A)");
    assert_eq!(key_id, 27);
    let supi = deconceal(&received, Some(&private))?;
    assert_eq!(supi.to_string(), "imsi-274012001002086");
    assert_eq!(supi.identity(), "274012001002086");

    // The SUCI of Annex C.4.3.1, and what a SIDF without the key is told
    let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
    let output = "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d84\
                  57dcb02352410cddd9e730ef3fa87";
    identity.extend(hex::decode(output)?);
    let annex = Suci::from_nas_octets(&identity)?;
    assert_eq!(annex.to_string(), format!("suci-0-274-012-0-1-27-{output}"));
    assert_eq!(deconceal(&annex, Some(&private))?.to_string(), "imsi-274012001002086");
    assert_eq!(format!("{:?}", deconceal(&annex, None)), "Err(MissingKey)");

    // A SUPI that is a NAI: the username is concealed, the realm is not
    let supi = Supi::network_specific("sensor-17@example.net")?;
    let protection = Protection::Ecies { key_id: 1, key: &public };
    let text = conceal_nai(&supi, RoutingIndicator::default(), protection)?.to_nai()?.to_string();
    assert!(text.starts_with("type1.rid0.schid1.hnkey1.ecckey"));
    let read = Suci::Nai(NaiSuci::parse(&text)?);
    assert_eq!(deconceal(&read, Some(&private))?.to_string(), "nai-sensor-17@example.net");
    Ok(())
}
```

## Run an algorithm on a 3GPP test set

A keyed context takes what the algorithms take: any 32-bit COUNT, a 5-bit
BEARER and a length in bits.

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_eps::{KNasEnc, KNasInt};
use oxirush_security::{Bearer, CipheringContext, Direction, IntegrityContext};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 128-EEA2 test set 1 of TS 33.401 Annex C.1.1: 253 bits. A key type
    // takes the octets of a test set with `from_slice`
    let k = KNasEnc::from_slice(&hex::decode("d3c5d592327fb11c4035c6680af8c6d1")?)?;
    let mut data = hex::decode("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0")?;
    let (count, bearer, downlink) = (0x398a_59b4_u32, Bearer::new(0x15)?, Direction::Downlink);
    let context = CipheringContext::new(&k, Algorithm::Aes);
    context.cipher_bits(count, bearer, downlink, &mut data, 253)?;
    let ciphered = "e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78";
    assert_eq!(hex::encode(&data), ciphered);

    // 128-EIA2 test set 1 of Annex C.2.1: 58 bits
    let k = KNasInt::from_slice(&hex::decode("2bd6459f82c5b300952c49104881ff48")?)?;
    let message = hex::decode("3332346263393840")?;
    let (count, bearer, uplink) = (0x38a6_f056_u32, Bearer::new(0x18)?, Direction::Uplink);
    let context = IntegrityContext::new(&k, Algorithm::Aes);
    let mac = context.mac_bits(count, bearer, uplink, &message, 58)?;
    assert_eq!(mac, 0x118c_6eb8);
    Ok(())
}
```

## Select the algorithms

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::{
    DEFAULT_CIPHERING_PREFERENCE, DEFAULT_INTEGRITY_PREFERENCE, select_ciphering_algorithm,
    select_integrity_algorithm,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The EA and IA octets of a UE security capability: EA0, EA1 and EA2, and
    // IA1 and IA2. 128-NEA2 and 128-NIA2 are AES, 128-NEA1 and 128-NIA1 SNOW 3G
    let ciphering = select_ciphering_algorithm(0xe0, DEFAULT_CIPHERING_PREFERENCE);
    assert_eq!(ciphering, Some(Algorithm::Aes));
    let integrity = select_integrity_algorithm(0x60, DEFAULT_INTEGRITY_PREFERENCE);
    assert_eq!(integrity, Some(Algorithm::Aes));

    // An operator's order in the place of NIA2, NIA1, NIA3
    let order = [Algorithm::Snow3g, Algorithm::Aes];
    assert_eq!(select_integrity_algorithm(0x60, &order), Some(Algorithm::Snow3g));

    // An identity from a message, which ciphering and integrity share: 4 to 7
    // are reserved, and given back
    assert_eq!(Algorithm::try_from(2), Ok(Algorithm::Aes));
    assert_eq!(Algorithm::try_from(5), Err(5));
    Ok(())
}
```

## Make the vectors of many subscribers in one call

With the `batch` feature, a job is one subscriber with the inputs of its
call. On the AES instructions, a batch works on eight subscribers side by
side.

```rust
use oxirush_security::Rand;
use oxirush_security::batch::{self, AutnJob, VectorJob};
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A thousand subscribers, each with its K, its RAND and its next SQN
    let subscribers: Vec<Milenage> = (0..1000u16)
        .map(|n| {
            let mut k = [0x46; 16];
            k[..2].copy_from_slice(&n.to_be_bytes());
            Milenage::new(&K::new(&k), &Opc::new(&[0xcd; 16]))
        })
        .collect();
    let rands: Vec<Rand> = (0..1000u16).map(|n| Rand::new(&[n as u8; 16])).collect();
    let sqns = (0..1000u64).map(|n| Sqn::try_from(32 + n)).collect::<Result<Vec<_>, _>>()?;
    let amf = Amf::new(&[0x80, 0x00]);

    // Home network: the vectors, each in its job
    let mut jobs: Vec<_> = (0..1000)
        .map(|n| VectorJob::new(&subscribers[n], &rands[n], &sqns[n], &amf))
        .collect();
    batch::authentication_vectors(&mut jobs);
    let vectors: Vec<_> = jobs.into_iter().filter_map(VectorJob::into_vector).collect();
    assert_eq!(hex::encode(vectors[999].autn().as_octets()), "a8ea63cde1078000cad3a5b1943c2ec3");

    // The UEs: the check of each AUTN
    let mut jobs: Vec<_> = (0..1000)
        .map(|n| AutnJob::new(&subscribers[n], &rands[n], vectors[n].autn()))
        .collect();
    batch::check_autn(&mut jobs);
    let accepted = jobs.iter().filter(|job| matches!(job.response(), Some(Ok(_)))).count();
    assert_eq!(accepted, 1000);
    Ok(())
}
```

## Protect the messages of many UEs in one call

With the `batch` feature, a job is one message with its key, its NAS COUNT
and its algorithm. A batch gives each job what `nas_cipher` or `nas_mac`
would give it, and runs the keystream generators and the MAC chains of
several jobs side by side.

```rust
use oxirush_security::identity::Algorithm;
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection};
use oxirush_security::batch::{self, CipherJob, MacJob};
use oxirush_security::{Direction, NasCount};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Three UEs: the NAS keys, the downlink NAS COUNT and the algorithms of each
    let k_nas_enc = [[0x11; 16], [0x22; 16], [0x33; 16]].each_ref().map(KNasEnc::new);
    let k_nas_int = [[0x44; 16], [0x55; 16], [0x66; 16]].each_ref().map(KNasInt::new);
    let counts = [NasCount::new(7)?, NasCount::new(0)?, NasCount::new(41)?];
    let nea = [Algorithm::Aes, Algorithm::Snow3g, Algorithm::Aes];
    let nia = [Algorithm::Aes, Algorithm::Snow3g, Algorithm::Aes];
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);

    // The sequence number and the message of each
    let mut messages = [
        vec![7, 0x7e, 0x00, 0x54, 0x43, 0x90],
        vec![0, 0x7e, 0x00, 0x5d, 0x02],
        vec![41, 0x7e, 0x00, 0x68, 0x01, 0x00, 0x2e],
    ];

    let mut jobs: Vec<_> = (messages.iter_mut().enumerate())
        .map(|(ue, message)| {
            let (key, count) = (&k_nas_enc[ue], counts[ue].get());
            CipherJob::new(key, count, access.into(), downlink, &mut message[1..], nea[ue])
        })
        .collect();
    batch::cipher(&mut jobs);

    // The MAC is over the sequence number and the ciphered message
    let mut jobs: Vec<_> = (messages.iter().enumerate())
        .map(|(ue, message)| {
            let (key, count) = (&k_nas_int[ue], counts[ue].get());
            MacJob::new(key, count, access.into(), downlink, message, nia[ue])
        })
        .collect();
    batch::mac(&mut jobs);
    let macs: Vec<_> = jobs.iter().map(|job| job.mac()).collect();
    assert_eq!(macs, [Some(0xafc5_3a82), Some(0x6a11_a04f), Some(0xc48d_481a)]);
    assert_eq!(hex::encode(&messages[0]), "076b4a2c14c2");
    assert_eq!(hex::encode(&messages[1]), "00e17ff3e0");
    assert_eq!(hex::encode(&messages[2]), "295c7b75e6ac69");
    Ok(())
}
```

A job also takes any 32-bit COUNT and BEARER, for data that is not NAS.

## Wipe keys after use

Keys, contexts and generators are wiped when they are dropped, and `{:?}`
of a key prints only its name, as `KAmf(..)`. RES, RES\*, XRES, XRES\*,
HRES\* and HXRES\* are keys too: whoever has one can answer the challenge.
Identities, and RAND, AUTN, SQN and AUTS, which travel in clear, are printed
whole.

When an operation that uses a key returns, the crate also zeroes the stack
that it used and, on x86-64 and AArch64, the registers. A batch pays for it
once, and `RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the crate
without it ([`benches/`](benches/README.md#what-the-clearing-costs) has what
it costs). A key that is moved leaves its octets where it was, so make a key
where it stays and pass references.

## Limits

- AKA: it has MILENAGE, not TUAK. `answer_challenge` is a USIM that keeps
  one SQNMS; a UE with the array of SQNs of TS 33.102 Annex C judges the
  result of `check_autn` itself.
- State: it stores no key and keeps no NAS COUNT or SQN. The caller passes
  them, and `NasCount` gives the next one and that of a received message.
- NAS messages: it protects octets.
  [oxirush-nas](https://github.com/linouxis9/oxirush-nas) encodes the
  messages and their security header.
- It has had no security audit.
- On a target without an operating system, the vector and AES code runs only
  where the build enables those instructions; `implementation()` says which
  code runs.
- Under Cargo's resolver 2, `aes` 0.9.3 needs Rust 1.89: keep 0.9.2 with
  `cargo update -p aes --precise 0.9.2`.

## Performance

| Operation | This crate | Closest Rust crate | Open5GS v2.8.0 | free5GC (util v1.3.2, nas v1.2.3) |
|---|---|---|---|---|
| MILENAGE, an authentication vector | 294 ns | milenage 0.1.6: 2.0× slower | 2.5× slower | 4.5× slower |
| 128-NEA1 (SNOW 3G), 1,500 octets | 5.4 µs | cryptography-rs 0.8.0: 1.2× slower | about the same | 200× slower |
| 128-NEA2 (AES-CTR), 1,500 octets | 660 ns | aes 0.8.4 and ctr: about the same | 11× slower | 1.9× slower |
| 128-NEA3 (ZUC), 1,500 octets | 6.1 µs | zuc 0.4.1: about the same | 2.2× slower | 3.6× slower |
| 128-NIA1 (SNOW 3G), 1,500 octets | 876 ns | none | 1,200× slower | 1,100× slower |
| 128-NIA2 (AES-CMAC), 1,500 octets | 2.6 µs | aes 0.8.4 and cmac: about the same | 2.6× slower | 1.6× slower |
| 128-NIA3 (ZUC), 1,500 octets | 6.5 µs | zuc 0.4.1: 1.7× slower | 9.6× slower | 9.2× slower |

Medians of ten rounds in turns on one core of an Intel Xeon E5-2680 v4 (a
KVM guest, Linux 7.0, Rust 1.100.0), at 39b3491 on 2026-11-15. A cell of
another implementation says how much slower or faster it is than this crate:
"about the same" when the two medians are within 10 % or their ten times
overlap. [`benches/README.md`](benches/README.md) has every figure, the
method and the commands.

In a batch of sixteen, 128-NEA1 takes 1.8 µs a message. SUCI concealment
takes 100 µs with Profile A.

## Tests and fuzzing

```sh
cargo test --all-features
```

Each example of this page checks what it gives with `assert_eq!`, and runs
as a documentation test. The algorithms, MILENAGE and SUCI are tested on the
3GPP test data. TS 33.501 has none for its key derivations, so two Python
programs in `tests/` derive them a second time: the 5G AKA chain, and the
keys of a change between 5GS and EPS over four handovers back and forth.
MILENAGE is compared with the `milenage` crate, Open5GS and free5GC on a
million random subscribers, and the memory is searched for keys after each
operation. [The documentation](https://docs.rs/oxirush-security) has each
function with its clause and its test values, and how the code was checked
for a time that does not depend on a secret.

[CONTRIBUTING.md](CONTRIBUTING.md) has the other test programs, the fuzz
targets, and how to contribute. [SECURITY.md](SECURITY.md) says how to
report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, the JSON tree with its paths, and the fields and tables that the codecs are laid out on.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a user-plane test peer.
- [oxirush-pfcp](https://github.com/linouxis9/oxirush-pfcp): PFCP, between the control plane and the user plane.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2025-2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
