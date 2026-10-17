# oxirush-security

[![Crates.io](https://img.shields.io/crates/v/oxirush-security.svg)](https://crates.io/crates/oxirush-security)
[![Documentation](https://docs.rs/oxirush-security/badge.svg)](https://docs.rs/oxirush-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The security functions of 5GS and EPS in Rust, per 3GPP TS 35.206,
TS 33.102, TS 33.501 and TS 33.401: MILENAGE, key derivation, NAS integrity
and ciphering, and SUCI concealment.

```rust
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
```

```text
KNASenc f47ae570afde775373d1b313d2176f54
KNASint 28ddb5356880149b9fee22f2367522a4
ciphered b57dd5, MAC 83e4d009
```

The text under a block is what the block prints.

> This page describes the unreleased 0.3.0. crates.io has 0.2.0, and the
> [changelog](CHANGELOG.md) lists each change.

## Install

```toml
[dependencies]
oxirush-security = "0.3"
hex = "0.4" # for the examples of this page
```

Until 0.3.0 is on crates.io, the repository has it:
`oxirush-security = { git = "https://github.com/linouxis9/oxirush-security" }`.

## Run 5G AKA, from MILENAGE to KAMF

The subscriber of TS 35.208 test set 1: its K, its OPc, and the RAND, the
SQN and the AMF of a challenge.

```rust
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
use oxirush_security::nas_5gs::{
    Supi, compute_hxres_star, derive_kamf, derive_kausf, derive_kseaf,
};
use oxirush_security::Rand;

let octets = |s: &str| hex::decode(s).unwrap();
let k = K::from_slice(&octets("465b5ce8b199b49faa5f0a2ee238a6bc")).unwrap();
let opc = Opc::from_slice(&octets("cd63cb71954a9f4e48a5994e37a02baf")).unwrap();
let subscriber = Milenage::new(&k, &opc);
let rand = Rand::from_slice(&octets("23553cbe9637a89d218ae64dae47bf35")).unwrap();
let (sqn, amf) = (Sqn::try_from(0xff9b_b4d0_b607).unwrap(), Amf::new(&[0xb9, 0xb9]));
let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

// UDM: the authentication vector of MILENAGE, then KAUSF and XRES*
let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
let k_ausf = derive_kausf(vector.ck(), vector.ik(), sn_name, vector.autn()).unwrap();
let xres_star = vector.xres_star(sn_name).unwrap();
println!("AUTN   {}", hex::encode(vector.autn().as_octets()));
println!("KAUSF  {}", hex::encode(k_ausf.as_octets()));
println!("XRES*  {}", hex::encode(xres_star.as_octets()));

// AUSF: HXRES* and KSEAF
let hxres_star = compute_hxres_star(vector.rand(), &xres_star);
let k_seaf = derive_kseaf(&k_ausf, sn_name).unwrap();
println!("HXRES* {}", hex::encode(hxres_star.as_octets()));
println!("KSEAF  {}", hex::encode(k_seaf.as_octets()));

// SEAF: KAMF, from the SUPI and the ABBA. The SUPI is the one that a SUCI
// de-conceals to, or the text of a service based interface
let supi = Supi::parse("imsi-208930000000001").unwrap();
let k_amf = derive_kamf(&k_seaf, &supi, &[0x00, 0x00]).unwrap();
println!("KAMF   {}", hex::encode(k_amf.as_octets()));

// UE: the USIM checks the MAC of AUTN. The ME judges the SQN and the
// separation bit of the AMF, then sends RES*, which the AUSF compares with
// XRES* in constant time
let response = subscriber.check_autn(&rand, vector.autn()).unwrap();
println!("SQN {:x}, separation bit {}", response.sqn().get(), response.amf().separation_bit());
let res_star = response.res_star(sn_name).unwrap();
println!("RES* accepted: {}", xres_star.accepts(&res_star));
```

```text
AUTN   55f328b43577b9b94a9ffac354dfafb3
KAUSF  f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9
XRES*  5cc9527f4d21c43bee83a15443acf1c4
HXRES* 6970075e3c8245fdc2073003cf166279
KSEAF  cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa
KAMF   9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4
SQN ff9bb4d0b607, separation bit true
RES* accepted: true
```

`Opc::from_op` derives OPc from OP. `nas_eps::derive_kasme` takes the CK,
the IK and the AUTN of a vector for EPS AKA.

## Re-synchronise a USIM

A USIM that finds the SQN of a challenge out of range answers with an
AUTS of its own SQN, SQNMS. The home network reads SQNMS back from it.

```rust
use oxirush_security::milenage::{Amf, Auts, K, Milenage, Opc, Sqn};
use oxirush_security::Rand;

let subscriber = Milenage::new(&K::new(&[0x46; 16]), &Opc::new(&[0xcd; 16]));
let rand = Rand::new(&[0x23; 16]);
let vector = subscriber.authentication_vector(&rand, &Sqn::try_from(32).unwrap(), &Amf::new(&[0x80, 0]));

// UE: its SQNMS is 64, ahead of the 32 of the AUTN, which is no longer
// fresh. Whether a SQN is fresh is the UE's policy (TS 33.102 Annex C)
let response = subscriber.check_autn(&rand, vector.autn()).unwrap();
let sqn_ms = Sqn::try_from(64).unwrap();
println!("SQN {} after SQNMS {}", response.sqn().get(), sqn_ms.get());
let auts = subscriber.auts(&rand, &sqn_ms);
println!("{auts:?}");

// Home network: the AUTS answers the RAND of the challenge, which the
// serving network gives with it. Its MAC-S is checked, and SQNMS read
let read = subscriber.verify_auts(&rand, &auts).unwrap();
println!("SQNMS {}", read.get());

// An AUTS with one bit changed, or for another RAND, is refused
let mut changed = *auts.as_octets();
changed[13] ^= 1;
println!("{:?}", subscriber.verify_auts(&rand, &Auts::new(&changed)));
```

```text
SQN 32 after SQNMS 64
Auts(5ef40417ef4cb9ac9e76640b820d)
SQNMS 64
Err(MacFailure)
```

## Make the vectors of many subscribers in one call

A job is a subscriber with the inputs of its call. On the AES instructions
a batch runs the key expansions and the encryptions of eight subscribers
side by side.

```rust
use oxirush_security::milenage::{
    Amf, AutnJob, K, Milenage, Opc, Sqn, VectorJob, authentication_vector_batch,
    check_autn_batch,
};
use oxirush_security::Rand;

// A thousand subscribers, each with its K, its RAND and its next SQN
let subscribers: Vec<Milenage> = (0..1000u16)
    .map(|n| {
        let mut k = [0x46; 16];
        k[..2].copy_from_slice(&n.to_be_bytes());
        Milenage::new(&K::new(&k), &Opc::new(&[0xcd; 16]))
    })
    .collect();
let rands: Vec<Rand> = (0..1000u16).map(|n| Rand::new(&[n as u8; 16])).collect();
let sqns: Vec<Sqn> = (0..1000u64).map(|n| Sqn::try_from(32 + n).unwrap()).collect();
let amf = Amf::new(&[0x80, 0x00]);

// Home network: the vectors
let mut jobs: Vec<_> = (0..1000)
    .map(|n| VectorJob::new(&subscribers[n], &rands[n], &sqns[n], &amf))
    .collect();
authentication_vector_batch(&mut jobs);
let vectors: Vec<_> = jobs.into_iter().map(|job| job.into_vector().unwrap()).collect();
println!("AUTN of the last {}", hex::encode(vectors[999].autn().as_octets()));

// The UEs: the check of each AUTN
let mut jobs: Vec<_> = (0..1000)
    .map(|n| AutnJob::new(&subscribers[n], &rands[n], vectors[n].autn()))
    .collect();
check_autn_batch(&mut jobs);
let accepted = jobs.iter().filter(|job| matches!(job.response(), Some(Ok(_)))).count();
println!("{accepted} AUTNs accepted");
```

```text
AUTN of the last a8ea63cde1078000cad3a5b1943c2ec3
1000 AUTNs accepted
```

## Protect and check a NAS message

The first block of the page is the sender. The receiver computes the MAC
before it deciphers.

```rust
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
```

```text
MAC 83e4d009, as received: true
deciphered 7e0043, then from NAS COUNT 1
```

## Protect and check a NAS message in EPS

The EPS functions are in `nas_eps`. Its `nas_mac` and `nas_cipher` take no
NAS connection: the BEARER of EPS NAS is zero.

```rust
use oxirush_security::nas_eps::{
    derive_kasme, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
    service_request_short_mac,
};
use oxirush_security::{
    Autn, CipheringAlgorithm, Ck, Direction, Ik, IntegrityAlgorithm, NasCount, Plmn,
};

// KASME from CK, IK, the serving network and the AUTN of the
// authentication, whose SQN xor AK the derivation takes
let (ck, ik, autn) = (Ck::new(&[0x11; 16]), Ik::new(&[0x22; 16]), Autn::new(&[0; 16]));
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
```

```text
ciphered b02c47, MAC 190af1e7
MAC as sent: true
deciphered 076003
short MAC 7e95
```

## Protect the messages of many UEs in one call

A job is one message with its key, its NAS COUNT and its algorithm. A batch
gives each job the result of `nas_cipher` or `nas_mac`, and runs the
keystream generators and the MAC chains of several jobs side by side.

```rust
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection, cipher_job, mac_job};
use oxirush_security::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, nea_cipher_batch, nia_mac_batch,
};

// Three UEs: the NAS keys, the downlink NAS COUNT and the algorithms of each
let k_nas_enc = [[0x11; 16], [0x22; 16], [0x33; 16]].each_ref().map(KNasEnc::new);
let k_nas_int = [[0x44; 16], [0x55; 16], [0x66; 16]].each_ref().map(KNasInt::new);
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
```

```text
MAC afc53a82 of 076b4a2c14c2
MAC 6a11a04f of 00e17ff3e0
MAC c48d481a of 295c7b75e6ac69
```

`CipherJob::new` and `MacJob::new` take any 32-bit COUNT and a BEARER, for
a message that is not a NAS message.

## Keep the keys of a UE between its messages

A context holds a key with its algorithm and what the algorithm computes
from the key alone: the round keys of AES and the subkeys of CMAC. It
serves both directions, and its `job` goes in a batch.

```rust
use oxirush_security::nas_5gs::{KNasEnc, KNasInt, NasConnection};
use oxirush_security::{
    CipheringAlgorithm, CipheringContext, Direction, IntegrityAlgorithm, IntegrityContext,
    NasCount,
};

// The contexts of a UE, made once, when its NAS keys are derived
let ciphering = CipheringContext::new(&KNasEnc::new(&[0x11; 16]), CipheringAlgorithm::NEA2);
let integrity = IntegrityContext::new(&KNasInt::new(&[0x44; 16]), IntegrityAlgorithm::NIA2);
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
```

```text
NAS COUNT 7: MAC afc53a82 of 076b4a2c14c2
NAS COUNT 8: MAC 5a27e0ff of 08cc23803c
```

## Derive the keys of a handover

```rust
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
```

```text
KgNB     c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005
NH 1     383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b
NH 2     ab2e99ac759e44b2f31665b1593ac74dcf175b095956668d00a838a3f6505fb8
KNG-RAN* 58c111d9277e1e1aeeba2f9893fde7b5e855f42759ca5e46647004852d59b744
KNG-RAN* 563d8aba7015f1ad77af632104b023d51c1cd410ef2ff46886aa2e02887e71d1
KAMF'    ae5e2cb9cda5b1687556e9c3d889d0edb0aa4e7317d409e0315dac5597ad438a
```

`nas_eps` has `derive_kenb`, `derive_nh` and `derive_kenb_star` for EPS. The
keys of a change of system are in `nas_5gs`: `derive_mapped_kasme_idle` and
`derive_mapped_kamf_idle`, and those of a handover.

## Conceal and deconceal a SUCI

The home network key pair is that of Profile A in TS 33.501 Annex C.4.
`HomeNetworkPrivateKey::profile_b` makes one of Profile B, and the rest is
the same. A SIDF with several keys chooses by the protection scheme and the
home network public key identifier of the SUCI that it read.

```rust
use oxirush_security::Plmn;
use oxirush_security::nas_5gs::{HomeNetworkPrivateKey, Protection, RoutingIndicator, Suci};

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
let routing = RoutingIndicator::default();
let suci = Suci::conceal_imsi(plmn, "001002086", routing, protection).unwrap();
let identity = suci.to_nas_octets().unwrap();
println!("mobile identity of {} octets", identity.len());

// SIDF: read the SUCI, take the private key that its scheme and its key
// identifier name, and de-conceal
let received = Suci::from_nas_octets(&identity).unwrap();
println!("{:?}, key {}", received.protection_scheme(), received.home_network_public_key_id());
let supi = received.deconceal(Some(&private)).unwrap();
println!("{supi}, of which KAMF takes {}", supi.identity());

// The SUCI of Annex C.4.3.1, and what a SIDF without the key is told
let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
identity.extend(hex::decode(
    "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
).unwrap());
let annex = Suci::from_nas_octets(&identity).unwrap();
println!("{annex}");
println!("{:?}", annex.deconceal(Some(&private)));
println!("{:?}", annex.deconceal(None));
```

```text
public key 5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650
mobile identity of 53 octets
ProtectionScheme(1: profile A), key 27
imsi-274012001002086, of which KAMF takes 274012001002086
suci-0-274-012-0-1-27-b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87
Ok(Supi(imsi-274012001002086))
Err(MissingKey)
```

## Conceal a network specific identifier

A SUPI that is a NAI is concealed as a NAI (TS 23.003 §28.7.3), with the
`nai` feature.

```rust
use oxirush_security::nas_5gs::{HomeNetworkPrivateKey, Protection, RoutingIndicator, Suci, Supi};

let private = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
let private = <[u8; 32]>::try_from(hex::decode(private).unwrap()).unwrap();
let private = HomeNetworkPrivateKey::profile_a(&private);
let public = private.public_key();

// UE: the username is concealed, the realm is not
let supi = Supi::network_specific("sensor-17@example.net").unwrap();
let protection = Protection::Ecies { key_id: 1, key: &public };
let suci = Suci::conceal_nai(&supi, RoutingIndicator::default(), protection).unwrap();
let text = suci.to_nai().unwrap();
println!("{}...", &text[..31]);

// Home network
let received = Suci::from_nai(&text).unwrap();
println!("{}", received.deconceal(Some(&private)).unwrap());

// A text that is no SUCI says what is wrong with it
println!("{}", Suci::from_nai("type1.rid0.schid1.hnkey1@example.net").unwrap_err());
```

```text
type1.rid0.schid1.hnkey1.ecckey...
nai-sensor-17@example.net
the NAI is not one: `ecckey` is written as ecckey and the ephemeral public key in hexadecimal digits
```

## Run an algorithm on a 3GPP test set

`nea_cipher_bits` and `nia_mac_bits` take what the algorithms take: any
32-bit COUNT, a 5-bit BEARER and a length in bits.

```rust
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
```

```text
e9fed8a63d155304d71df20bf3e82214b20ed7dad2f233dc3c22d7bdeeed8e78
118c6eb8
```

## Select the algorithms

```rust
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
```

```text
Some(Aes)
Some(Aes)
Some(Snow3g)
Ok(Aes)
Err(UnsupportedAlgorithm(5))
128-NIA2 in 5GS, 128-EIA2 in EPS
```

## Encode a PLMN identity, a 5G-GUTI and TBCD digits

The identities are the values of
[oxirush-utils](https://github.com/linouxis9/oxirush-utils), which
`oxirush_security::identity` is.

```rust
use oxirush_security::nas_5gs::Guti;
use oxirush_security::{Plmn, tbcd};

// MCC 208 and MNC 93
let plmn = Plmn::new("208", "93").unwrap();
println!("{} is {plmn}", hex::encode(plmn.to_nas_octets()));

// AMF region 1, set 1 and pointer 2, and a 5G-TMSI
let guti = Guti::new(plmn, 0x01, 0x001, 0x02, 0x1122_3344).unwrap();
let octets = guti.to_nas_octets();
let read = Guti::from_nas_octets(&octets).unwrap();
println!("{} has 5G-TMSI {:08x}", hex::encode(octets), read.tmsi());

// The digits of an IMSI
let imsi = tbcd::encode("208930000000001").unwrap();
println!("{} is {}", hex::encode(&imsi), tbcd::decode(&imsi).unwrap());
```

```text
02f839 is 208-93
f202f83901004211223344 has 5G-TMSI 11223344
02980300000000f1 is 208930000000001
```

`examples/` has five programs: `key_derivation_nas_5gs`,
`key_derivation_nas_eps`, `integrity_nas_5gs`, `integrity_nas_eps` and
`suci_conceal`. Run one with `cargo run --example suci_conceal`.

## What an operation leaves

A key, a context and a generator are wiped when they are dropped, and
`{:?}` prints no octet of a key. An identity and RAND and AUTN, which travel
in clear, are printed whole.

When an operation that computes with a key returns, the crate also sets to
zero the stack that the work used and, on x86-64 and AArch64, the registers.
[`leftovers/`](https://github.com/linouxis9/oxirush-security/tree/master/leftovers) looks for
the keys, the round keys and the keystream after each operation and finds
none. A copy that the program makes is its own: a key that is moved leaves
its octets where it was, so make a key where it stays and pass references.

The clearing takes 10 to 33 ns for a message, and a batch pays it once.
`RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the crate without it.

## Features

| Feature | The crate has | Needs |
|---------|---------------|-------|
| none | the algorithms, the contexts and the batches, MILENAGE, the keys and their derivations, NAS integrity and ciphering, the selection of the algorithms, the SUPI, the 5G-GUTI and the PLMN | `core` alone: no allocator |
| `alloc` | and what returns a `Vec` or a `String`: `kdf::build_s`, `tbcd::encode`, `tbcd::decode`, `Supi::into_owned` | an allocator |
| `std` | and, on an AArch64 system other than Linux, Android and Apple's, the choice of the code on the vector and AES instructions when the program runs | the standard library |
| `suci` | and the SUCI of an IMSI, with the null scheme, Profile A (X25519) and Profile B (secp256r1) | `alloc`, and a source of random numbers that `getrandom` has for the target |
| `nai` | and the SUCI in the NAI format and that of a SUPI that is a NAI, with Unicode normalization and IDNA | `suci` |

`std`, `suci` and `nai` are the default. Without `std` the crate is
`no_std`, and it still asks the processor what it has: by CPUID on x86-64,
through the auxiliary vector on AArch64 Linux and Android. On a target
without an operating system the code on the vector and AES instructions
runs when the build enables them
(`-C target-feature=+ssse3,+sse4.1,+aes,+pclmulqdq`, or `+neon,+aes`).

`oxirush_security::implementation()` says which code runs for each
algorithm, scalar or on the instructions: log it when the program starts.

```toml
# no_std, without an allocator
oxirush-security = { version = "0.3", default-features = false }
```

The minimum supported Rust version is 1.88. A project that is built with it
needs Cargo's resolver 3, the default of edition 2024, which keeps each
dependency at a version that 1.88 builds.

## What it does not do

- AKA: it has MILENAGE and not TUAK. Whether a SQN is fresh and whether
  an AMF has the separation bit are the caller's to decide.
- State: it stores no key and keeps no NAS COUNT or SQN. The caller passes
  them, and `NasCount` gives the next one and the one of a received
  message.
- NAS messages: it protects octets.
  [oxirush-nas](https://github.com/linouxis9/oxirush-nas) encodes the
  messages and their security header.
- It has had no security audit.

## Performance

On one core of an AMD Ryzen 7 5700G, a message of 1500 octets, alone and
as one of sixteen in a call of `nea_cipher_batch` or `nia_mac_batch`:

| | Cipher | MAC | Cipher, one of sixteen | MAC, one of sixteen |
|---|---|---|---|---|
| 128-NEA2, 128-NIA2 (AES) | 0.19 µs | 0.98 µs | 0.18 µs | 0.26 µs |
| 128-NEA1, 128-NIA1 (SNOW 3G) | 2.3 µs | 0.41 µs | 0.65 µs | 0.24 µs |
| 128-NEA3, 128-NIA3 (ZUC) | 3.2 µs | 3.6 µs | 0.87 µs | 1.2 µs |

MILENAGE makes an authentication vector in 0.13 µs, and in 0.06 µs as one
of a thousand in a call of `authentication_vector_batch`, where the
`milenage` crate 0.1.6 takes 0.26 µs. A key derivation takes 0.24 µs, and
SUCI concealment 59 µs with Profile A and 286 µs with Profile B.
[`benches/`](https://github.com/linouxis9/oxirush-security/tree/master/benches)
has the benchmarks, the other figures and how to profile.

## Tests and fuzzing

The algorithms, MILENAGE and SUCI are tested on the 3GPP test data, MILENAGE
on every set of TS 35.207 and TS 35.208. TS 33.501 has none for its
key derivations: the 5G AKA chain is compared with a second implementation,
[`tests/five_g_aka_chain.py`](tests/five_g_aka_chain.py), and the other
derivations with values that the tests calculate.

SNOW 3G, ZUC, AES and MILENAGE run on the AES, vector and carry-less
multiplication instructions of an x86-64 or AArch64 processor that has
them, and on scalar code elsewhere. The source has no index into memory and no branch that
depends on a secret, and the compiled code of one x86-64 build was read
for it; no timing was measured. The tests compare the two forms, and a
batch with its messages one by one. CI runs them on x86-64, AArch64 and
32-bit x86, builds each set of features for two targets without the
standard library, and runs the AArch64 code on an emulated processor
([`emulated-aarch64/`](https://github.com/linouxis9/oxirush-security/tree/master/emulated-aarch64)).
The crate's only `unsafe` code is the calls of the vector code and the
instructions that clear the stack and the registers.

CI fuzzes the four `cargo fuzz` targets of
[`fuzz/`](https://github.com/linouxis9/oxirush-security/tree/master/fuzz) for a minute at each
push and for half an hour each week.

[The documentation](https://docs.rs/oxirush-security) has the terms, and
each function with its clause and the values that it is tested against. It
also has the types of the inputs with their errors, what an operation
leaves, and how the timing was checked. Until the release,
`cargo doc --open` in a clone builds it.

## The OxiRush family

[oxirush-nas](https://github.com/linouxis9/oxirush-nas) (NAS messages),
[oxirush-ngap](https://github.com/linouxis9/oxirush-ngap) (NGAP),
[oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap) (S1AP),
[oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u) (GTP-U) and
[oxirush-sctp](https://github.com/linouxis9/oxirush-sctp) (SCTP).

## Contributing

Open a pull request with a test for what it changes. A Rust block of this
page is checked with what it prints: [`tests/readme.rs`](tests/readme.rs)
says how. Sign off your commits (`git commit -s`): by contributing you
agree to the [Developer Certificate of Origin](https://developercertificate.org/).
[SECURITY.md](SECURITY.md) says how to report a vulnerability.

## License

Copyright 2025-2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
