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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KAMF, the key of the AMF, as the 5G AKA example below derives it
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;

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
    Ok(())
}
```

```text
KNASenc f47ae570afde775373d1b313d2176f54
KNASint 28ddb5356880149b9fee22f2367522a4
ciphered b57dd5, MAC 83e4d009
```

The text under a block is what the block prints.

This page describes oxirush-security 0.3.0, which is not on crates.io yet.

## Installation

```toml
[dependencies]
oxirush-security = "0.3"
hex = "0.4" # for the examples of this page
```

| Feature | The crate has | Needs |
|---------|---------------|-------|
| none | the algorithms, the contexts and the batches, MILENAGE, the keys and their derivations, NAS integrity and ciphering, the selection of the algorithms, the SUPI, the 5G-GUTI and the PLMN | `core` alone: no allocator |
| `alloc` | and what returns a `Vec` or a `String`: `kdf::build_s`, `tbcd::encode`, `tbcd::decode`, `Supi::into_owned` | an allocator |
| `std` | and, on an AArch64 system other than Linux, Android and Apple's, the choice of the code on the vector and AES instructions when the program runs | the standard library |
| `suci` | and the SUCI of an IMSI, with the null scheme, Profile A (X25519) and Profile B (secp256r1) | `alloc`, and a source of random numbers that `getrandom` has for the target |
| `nai` | and the SUCI in the NAI format and that of a SUPI that is a NAI, by the grammar of RFC 7542 | `suci` |
| `idna` | and the realm and the username of a NAI are also checked as internationalized names: Unicode normalization and IDNA | `nai`; the Unicode tables of `idna` and `unicode-normalization` |

`std`, `suci` and `nai` are the default, without IDNA. Without `std` the crate is
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

Until 0.3.0 is on crates.io, a program takes the crate from its
repository, and oxirush-utils at the revision that it is tested with:

```toml
[dependencies]
oxirush-security = { git = "https://github.com/linouxis9/oxirush-security" }

[patch.crates-io]
oxirush-utils = { git = "https://github.com/linouxis9/oxirush-utils", rev = "1fb4d2720fa0b1c036e54d3e9907b278adac0f80" }
```

In a clone, cargo takes oxirush-utils from `.cargo/config.toml`, as CI does:

```sh
cargo test
```

The minimum supported Rust version is 1.88. Cargo's resolver 3, the
default of edition 2024, keeps each dependency at a version that 1.88
builds. Under resolver 2, `aes` 0.9.3 needs 1.89, and a project keeps 0.9.2:

```sh
cargo update -p aes --precise 0.9.2
```

## Run 5G AKA, from MILENAGE to KAMF

The subscriber of TS 35.208 test set 1: its K, its OPc, and the RAND, the
SQN and the AMF of a challenge.

```rust
use oxirush_security::milenage::{Amf, K, Milenage, Opc, Sqn};
use oxirush_security::nas_5gs::{
    Supi, compute_hxres_star, derive_kamf, derive_kausf, derive_kseaf,
};
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
    println!("AUTN   {}", hex::encode(vector.autn().as_octets()));
    println!("KAUSF  {}", hex::encode(k_ausf.as_octets()));
    println!("XRES*  {}", hex::encode(xres_star.as_octets()));

    // AUSF: HXRES* and KSEAF
    let hxres_star = compute_hxres_star(vector.rand(), &xres_star);
    let k_seaf = derive_kseaf(&k_ausf, sn_name)?;
    println!("HXRES* {}", hex::encode(hxres_star.as_octets()));
    println!("KSEAF  {}", hex::encode(k_seaf.as_octets()));

    // SEAF: KAMF, from the SUPI and the ABBA. The SUPI is the one that a SUCI
    // de-conceals to, or the text of a service based interface
    let supi = Supi::parse("imsi-208930000000001")?;
    let k_amf = derive_kamf(&k_seaf, &supi, &[0x00, 0x00])?;
    println!("KAMF   {}", hex::encode(k_amf.as_octets()));

    // UE: the USIM checks the MAC of AUTN. The ME judges the SQN and the
    // separation bit of the AMF, then sends RES*, which the AUSF compares with
    // XRES* in constant time
    let response = subscriber.check_autn(&rand, vector.autn())?;
    println!("SQN {:x}, separation bit {}", response.sqn().get(), response.amf().separation_bit());
    let res_star = response.res_star(sn_name)?;
    println!("RES* accepted: {}", xres_star.accepts(&res_star));
    Ok(())
}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let subscriber = Milenage::new(&K::new(&[0x46; 16]), &Opc::new(&[0xcd; 16]));
    let rand = Rand::new(&[0x23; 16]);
    let vector = subscriber.authentication_vector(&rand, &Sqn::try_from(32)?, &Amf::new(&[0x80, 0]));

    // UE: its SQNMS is 64, ahead of the 32 of the AUTN, which is no longer
    // fresh. Whether a SQN is fresh is the UE's policy (TS 33.102 Annex C)
    let response = subscriber.check_autn(&rand, vector.autn())?;
    let sqn_ms = Sqn::try_from(64)?;
    println!("SQN {} after SQNMS {}", response.sqn().get(), sqn_ms.get());
    let auts = subscriber.auts(&rand, &sqn_ms);
    println!("{auts:?}");

    // Home network: the AUTS answers the RAND of the challenge, which the
    // serving network gives with it. Its MAC-S is checked, and SQNMS read
    let read = subscriber.verify_auts(&rand, &auts)?;
    println!("SQNMS {}", read.get());

    // An AUTS with one bit changed, or for another RAND, is refused
    let mut changed = *auts.as_octets();
    changed[13] ^= 1;
    println!("{:?}", subscriber.verify_auts(&rand, &Auts::new(&changed)));
    Ok(())
}
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
    authentication_vector_batch(&mut jobs);
    let vectors: Vec<_> = jobs.into_iter().filter_map(VectorJob::into_vector).collect();
    println!("AUTN of the last {}", hex::encode(vectors[999].autn().as_octets()));

    // The UEs: the check of each AUTN
    let mut jobs: Vec<_> = (0..1000)
        .map(|n| AutnJob::new(&subscribers[n], &rands[n], vectors[n].autn()))
        .collect();
    check_autn_batch(&mut jobs);
    let accepted = jobs.iter().filter(|job| matches!(job.response(), Some(Ok(_)))).count();
    println!("{accepted} AUTNs accepted");
    Ok(())
}
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
use oxirush_security::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, constant_time_eq,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k_nas_enc = KNasEnc::from_slice(&hex::decode("f47ae570afde775373d1b313d2176f54")?)?;
    let k_nas_int = KNasInt::from_slice(&hex::decode("28ddb5356880149b9fee22f2367522a4")?)?;
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);

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
    // In a time that does not tell how much of a forged MAC is right
    let right = constant_time_eq(&mac.to_be_bytes(), &received_mac.to_be_bytes());
    println!("MAC {mac:08x}, as received: {right}");

    // The MAC is right: the message is deciphered, and its NAS COUNT is not
    // accepted again
    nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
    let lowest = count.next()?;
    println!("deciphered {}, then from NAS COUNT {}", hex::encode(message), lowest.get());
    Ok(())
}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // KASME from CK, IK, the serving network and the AUTN of the
    // authentication, whose SQN xor AK the derivation takes
    let (ck, ik, autn) = (Ck::new(&[0x11; 16]), Ik::new(&[0x22; 16]), Autn::new(&[0; 16]));
    let kasme = derive_kasme(&ck, &ik, Plmn::new("208", "93")?, &autn);

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
    let count = count.next()?;
    let short_mac = service_request_short_mac(&knas_int, count, uplink, 0x01, eia2);
    println!("short MAC {short_mac:04x}");
    Ok(())
}
```

```text
ciphered b02c47, MAC 190af1e7
MAC as sent: true
deciphered 076003
short MAC 7e95
```

## Protect a message that oxirush-nas encodes

[oxirush-nas](https://github.com/linouxis9/oxirush-nas) encodes the
message, and its security context calls these functions. Under the
security header of TS 24.501 §9.1.1 are the extended protocol
discriminator, the security header type, the MAC and the sequence number,
then the ciphered message.

```rust,ignore
use oxirush_nas::nas_5gs::{self, GmmCause, Nas5gsMessage, NasFGmmCause, NasFGmmStatus};
use oxirush_security::nas_5gs::{
    KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
};
use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;
    let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
    let (k_nas_enc, k_nas_int) = (derive_knas_enc(&k_amf, nea2), derive_knas_int(&k_amf, nia2));

    // A 5GMM STATUS with cause #22, which oxirush-nas encodes
    let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
    let status = Nas5gsMessage::new_5gmm(NasFGmmStatus::new(cause));
    let mut message = status.encode()?;

    // The AMF ciphers it, computes the MAC over the sequence number and the
    // ciphertext, and puts the security header before them: header type 2
    let (count, access, downlink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Downlink);
    nas_cipher(&k_nas_enc, count, access, downlink, &mut message, nea2);
    let protected = [&[count.sequence_number()][..], &message].concat();
    let mac = nas_mac(&k_nas_int, count, access, downlink, &protected, nia2);
    let octets = [&[0x7e, 0x02][..], &mac.to_be_bytes(), &protected].concat();
    println!("{}", hex::encode(&octets));

    // The UE: oxirush-nas reads the security header, and its security
    // context checks the MAC and deciphers with the same functions
    println!("{}", Nas5gsMessage::decode(&octets)?);
    let (nia, nea) = (nas_5gs::IntegrityAlgorithm::NIA2, nas_5gs::CipheringAlgorithm::NEA2);
    let mut ue = nas_5gs::NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;
    println!("{}", ue.unprotect(&octets, nas_5gs::Direction::Downlink)?.message);
    Ok(())
}
```

```text
7e02cbbc4fbb00e793fe4e
SecurityProtected (SHT=IntegrityProtectedAndCiphered, MAC=0xcbbc4fbb, SN=0) Opaque (4 octets)
5GMM Status (cause=#22 (Congestion))
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Three UEs: the NAS keys, the downlink NAS COUNT and the algorithms of each
    let k_nas_enc = [[0x11; 16], [0x22; 16], [0x33; 16]].each_ref().map(KNasEnc::new);
    let k_nas_int = [[0x44; 16], [0x55; 16], [0x66; 16]].each_ref().map(KNasInt::new);
    let counts = [NasCount::new(7)?, NasCount::new(0)?, NasCount::new(41)?];
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
        if let Some(mac) = job.mac() {
            println!("MAC {mac:08x} of {}", hex::encode(message));
        }
    }
    Ok(())
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // The contexts of a UE, made once, when its NAS keys are derived
    let ciphering = CipheringContext::new(&KNasEnc::new(&[0x11; 16]), CipheringAlgorithm::NEA2);
    let integrity = IntegrityContext::new(&KNasInt::new(&[0x44; 16]), IntegrityAlgorithm::NIA2);
    let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);

    // Each downlink message takes the next NAS COUNT
    let mut count = NasCount::new(7)?;
    for plain in [&[0x7e, 0x00, 0x54, 0x43, 0x90][..], &[0x7e, 0x00, 0x5d, 0x02]] {
        let mut message = [&[count.sequence_number()][..], plain].concat();
        ciphering.cipher(count, access, downlink, &mut message[1..]);
        let mac = integrity.mac(count, access, downlink, &message);
        println!("NAS COUNT {}: MAC {mac:08x} of {}", count.get(), hex::encode(&message));
        count = count.next()?;
    }
    Ok(())
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
    let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;

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
    let horizontal = derive_kng_ran_star(&k_gnb, pci, arfcn_dl)?;
    let vertical = derive_kng_ran_star(&nh_2, pci, arfcn_dl)?;
    println!("KNG-RAN* {}", hex::encode(horizontal.as_octets()));
    println!("KNG-RAN* {}", hex::encode(vertical.as_octets()));

    // KAMF' for a target AMF, from the downlink NAS COUNT
    let k_amf_prime = derive_kamf_prime_handover(&k_amf, NasCount::new(5)?);
    println!("KAMF'    {}", hex::encode(k_amf_prime.as_octets()));
    Ok(())
}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Home network: its private key, and the public key that its subscribers
    // have under the identifier 27
    let mut private = [0; 32];
    let text = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    hex::decode_to_slice(text, &mut private)?;
    let private = HomeNetworkPrivateKey::profile_a(&private);
    let public = private.public_key();
    println!("public key {}", hex::encode(public.to_octets()));

    // UE: conceal the IMSI 274 012 001002086. The scheme output is an
    // ephemeral public key, drawn at each call, the ciphered MSIN and a MAC tag
    let protection = Protection::Ecies { key_id: 27, key: &public };
    let plmn = Plmn::new("274", "012")?;
    let routing = RoutingIndicator::default();
    let suci = Suci::conceal_imsi(plmn, "001002086", routing, protection)?;
    let identity = suci.to_nas_octets()?;
    println!("mobile identity of {} octets", identity.len());

    // SIDF: read the SUCI, take the private key that its scheme and its key
    // identifier name, and de-conceal
    let received = Suci::from_nas_octets(&identity)?;
    println!("{:?}, key {}", received.protection_scheme(), received.home_network_public_key_id());
    let supi = received.deconceal(Some(&private))?;
    println!("{supi}, of which KAMF takes {}", supi.identity());

    // The SUCI of Annex C.4.3.1, and what a SIDF without the key is told
    let mut identity = vec![0x01, 0x72, 0x24, 0x10, 0xf0, 0xff, 0x01, 27];
    identity.extend(hex::decode(
        "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
    )?);
    let annex = Suci::from_nas_octets(&identity)?;
    println!("{annex}");
    println!("{:?}", annex.deconceal(Some(&private)));
    println!("{:?}", annex.deconceal(None));
    Ok(())
}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut private = [0; 32];
    let text = "c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d";
    hex::decode_to_slice(text, &mut private)?;
    let private = HomeNetworkPrivateKey::profile_a(&private);
    let public = private.public_key();

    // UE: the username is concealed, the realm is not
    let supi = Supi::network_specific("sensor-17@example.net")?;
    let protection = Protection::Ecies { key_id: 1, key: &public };
    let suci = Suci::conceal_nai(&supi, RoutingIndicator::default(), protection)?;
    let text = suci.to_nai()?;
    println!("{}...", &text[..31]);

    // Home network
    let received = Suci::from_nai(&text)?;
    println!("{}", received.deconceal(Some(&private))?);

    // A text that is no SUCI says what is wrong with it
    if let Err(error) = Suci::from_nai("type1.rid0.schid1.hnkey1@example.net") {
        println!("{error}");
    }
    Ok(())
}
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 128-EEA2 test set 1 of TS 33.401 Annex C.1.1: 253 bits. A key type
    // takes the octets of a test set with `from_slice`
    let k = KNasEnc::from_slice(&hex::decode("d3c5d592327fb11c4035c6680af8c6d1")?)?;
    let mut data = hex::decode("981ba6824c1bfb1ab485472029b71d808ce33e2cc3c0b5fc1f3de8a6dc66b1f0")?;
    let (count, bearer, downlink) = (0x398a_59b4, Bearer::new(0x15)?, Direction::Downlink);
    nea_cipher_bits(&k, count, bearer, downlink, &mut data, 253, CipheringAlgorithm::EEA2)?;
    println!("{}", hex::encode(&data));

    // 128-EIA2 test set 1 of Annex C.2.1: 58 bits
    let k = KNasInt::from_slice(&hex::decode("2bd6459f82c5b300952c49104881ff48")?)?;
    let message = hex::decode("3332346263393840")?;
    let (count, bearer, uplink) = (0x38a6_f056, Bearer::new(0x18)?, Direction::Uplink);
    let mac = nia_mac_bits(&k, count, bearer, uplink, &message, 58, IntegrityAlgorithm::EIA2)?;
    println!("{mac:08x}");
    Ok(())
}
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

fn main() {
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
    if let Some(selected) = select_integrity_algo(0x60) {
        println!("{} in 5GS, {} in EPS", selected.name_5gs(), selected.name_eps());
    }
}
```

```text
Some(Aes (128-NEA2/128-EEA2))
Some(Aes (128-NIA2/128-EIA2))
Some(Snow3g (128-NIA1/128-EIA1))
Ok(Aes (128-NEA2/128-EEA2))
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // MCC 208 and MNC 93
    let plmn = Plmn::new("208", "93")?;
    println!("{} is {plmn}", hex::encode(plmn.to_nas_octets()));

    // AMF region 1, set 1 and pointer 2, and a 5G-TMSI
    let guti = Guti::new(plmn, 0x01, 0x001, 0x02, 0x1122_3344)?;
    let octets = guti.to_nas_octets();
    let read = Guti::from_nas_octets(&octets)?;
    println!("{} has 5G-TMSI {:08x}", hex::encode(octets), read.tmsi());

    // The digits of an IMSI
    let imsi = tbcd::encode("208930000000001")?;
    println!("{} is {}", hex::encode(&imsi), tbcd::decode(&imsi)?);
    Ok(())
}
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
`{:?}` prints no octet of a key. RES, RES\*, XRES, XRES\*, HRES\* and
HXRES\* are keys: whoever has one answers the challenge. An identity, and
RAND, AUTN, SQN and AUTS, which travel in clear, are printed whole.

When an operation that computes with a key returns, the crate also sets to
zero the stack that the work used and, on x86-64 and AArch64, the registers.
[`leftovers/`](https://github.com/linouxis9/oxirush-security/tree/master/leftovers) looks for
the keys, the round keys and the keystream after each operation and finds
none. A copy that the program makes is its own: a key that is moved leaves
its octets where it was, so make a key where it stays and pass references.

The clearing takes 13 to 34 ns for a message, and a batch pays it once.
`RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the crate without it.

## Limits

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

On one core of an AMD Ryzen 7 5700G (16 threads, Linux 7.0, Rust 1.98.1),
measured at 9dc28da on a quiet machine on 2026-10-18, a message of 1,500
octets, alone and as one of sixteen in a call of `nea_cipher_batch` or
`nia_mac_batch`, the lowest of five runs:

| | Cipher | MAC | Cipher, one of sixteen | MAC, one of sixteen |
|---|---|---|---|---|
| 128-NEA2, 128-NIA2 (AES) | 0.18 µs | 0.94 µs | 0.17 µs | 0.25 µs |
| 128-NEA1, 128-NIA1 (SNOW 3G) | 2.2 µs | 0.39 µs | 0.62 µs | 0.23 µs |
| 128-NEA3, 128-NIA3 (ZUC) | 3.1 µs | 3.4 µs | 0.82 µs | 1.1 µs |

MILENAGE makes an authentication vector in 0.12 µs, and in 0.06 µs as one
of a thousand in a call of `authentication_vector_batch`. A key
derivation takes 0.22 µs, and SUCI concealment 55 µs with Profile A and
268 µs with Profile B.
[`benches/`](https://github.com/linouxis9/oxirush-security/tree/master/benches)
has the benchmarks, the other figures and how to profile.

### Against other implementations

The same inputs to each, a call for each operation, on core 2 of the same
machine (Go 1.27), at 9dc28da. Times are the lowest of three runs, and each
figure the median of three runs of the script; cycles and instructions are
per operation, from `perf stat`, in user mode; peak memory is that of the
whole program. A ratio within 10 % is "about the same": the layout of the
code alone moves a time by 7 to 15 % between two builds. cryptography-rs
has the keystream generators, which the program runs with the IV of
128-NEA1 and 128-NEA3; its `Ct` types read no table at an index from the
state, as this crate does. Open5GS is called through `ogs_nas_encrypt` and
`ogs_nas_mac_calculate`, which its AMF and MME call.

| Operation | | ns | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Other / this crate |
|---|---|---|---|---|---|---|---|---|
| MILENAGE, an authentication vector | oxirush-security | 120.9 | 554 | 1,013 | 0 | 0 | 2.5 MiB | |
| | milenage 0.3.1 | 713.7 | 3,253 | 7,965 | 0 | 0 | 2.4 MiB | 5.9x |
| | milenage 0.1.6 | 246.4 | 1,124 | 2,952 | 0 | 0 | 2.4 MiB | 2.0x |
| | Open5GS v2.8.0 | 416.9 | 1,897 | 6,115 | 0 | 0 | 2.1 MiB | 3.4x |
| | free5GC util v1.3.2 | 537.9 | 2,376 | 8,682 | 19 | 1,248 | 7.5 MiB | 4.4x |
| 128-NEA1 (SNOW 3G), 1,500 octets | oxirush-security | 2,193 | 9,980 | 32,706 | 0 | 0 | 2.5 MiB | |
| | cryptography-rs 0.8.0, Snow3g | 3,172 | 14,434 | 66,230 | 0 | 0 | 2.5 MiB | 1.4x |
| | cryptography-rs 0.8.0, Snow3gCt | 42,846 | 195,420 | 853,943 | 0 | 0 | 2.5 MiB | 20x |
| | Open5GS v2.8.0 | 2,798 | 12,352 | 42,136 | 0 | 0 | 2.1 MiB | 1.3x |
| | free5GC nas v1.2.3 | 438,584 | 1,987,513 | 5,359,230 | 3 | 3,152 | 5.0 MiB | 200x |
| 128-NEA2 (AES-CTR), 1,500 octets | oxirush-security | 178.3 | 822 | 2,440 | 0 | 0 | 2.5 MiB | |
| | aes 0.8.4, ctr 0.9.2 | 187.6 | 857 | 2,972 | 0 | 0 | 2.4 MiB | about the same |
| | Open5GS v2.8.0 | 4,336 | 19,775 | 69,722 | 0 | 0 | 2.1 MiB | 24x |
| | free5GC nas v1.2.3 | 451.8 | 2,014 | 6,403 | 4 | 2,576 | 7.6 MiB | 2.5x |
| 128-NEA3 (ZUC), 1,500 octets | oxirush-security | 3,102 | 14,242 | 51,537 | 0 | 0 | 2.5 MiB | |
| | zuc 0.4.1 | 3,116 | 14,144 | 55,504 | 0 | 0 | 2.4 MiB | about the same |
| | cryptography-rs 0.8.0, Zuc128 | 3,383 | 15,384 | 60,783 | 0 | 0 | 2.5 MiB | about the same |
| | cryptography-rs 0.8.0, Zuc128Ct | 41,669 | 190,702 | 795,415 | 0 | 0 | 2.5 MiB | 13x |
| | Open5GS v2.8.0 | 7,422 | 33,735 | 126,029 | 1 | 1,596 | 2.1 MiB | 2.4x |
| | free5GC nas v1.2.3 | 10,843 | 48,746 | 203,237 | 2 | 3,072 | 7.5 MiB | 3.5x |
| 128-NIA1 (SNOW 3G), 1,500 octets | oxirush-security | 389.1 | 1,794 | 4,947 | 0 | 0 | 2.5 MiB | |
| | Open5GS v2.8.0 | 546,014 | 2,278,205 | 5,514,519 | 0 | 0 | 2.1 MiB | 1,400x |
| | free5GC nas v1.2.3 | 410,815 | 1,803,541 | 4,688,036 | 3 | 108 | 2.9 MiB | 1,100x |
| 128-NIA2 (AES-CMAC), 1,500 octets | oxirush-security | 938.3 | 4,323 | 2,704 | 0 | 0 | 2.5 MiB | |
| | aes 0.8.4, cmac 0.7.2 | 946.1 | 4,357 | 2,603 | 0 | 0 | 2.4 MiB | about the same |
| | Open5GS v2.8.0 | 4,144 | 18,926 | 60,224 | 0 | 0 | 2.1 MiB | 4.4x |
| | free5GC nas v1.2.3 | 1,825 | 8,173 | 21,030 | 8 | 2,240 | 7.7 MiB | 1.9x |
| 128-NIA3 (ZUC), 1,500 octets | oxirush-security | 3,417 | 15,672 | 56,569 | 0 | 0 | 2.5 MiB | |
| | zuc 0.4.1 | 5,381 | 24,593 | 116,125 | 0 | 0 | 2.4 MiB | 1.6x |
| | Open5GS v2.8.0 | 35,626 | 161,648 | 443,082 | 1 | 1,604 | 2.1 MiB | 10x |

`benches/compare/compare.sh 3` runs every row on core 3. It fetches each
implementation at the version that it pins, and builds Open5GS's libraries
of NAS security; perf may need `PERF="sudo -n perf"`.

## Tests and fuzzing

```sh
cargo test --all-features
python3 -I tests/five_g_aka_chain.py
cargo +nightly fuzz run algorithms -- -max_total_time=60
```

The algorithms, MILENAGE and SUCI are tested on the 3GPP test data, and
MILENAGE on every set of TS 35.207 and TS 35.208. TS 33.501 has no test
data for its key derivations: a second implementation,
[`tests/five_g_aka_chain.py`](tests/five_g_aka_chain.py), derives the 5G
AKA chain.
[`differential/`](https://github.com/linouxis9/oxirush-security/tree/master/differential)
compares MILENAGE with the `milenage` crate, Open5GS and free5GC on a
million random subscribers. CI compares the vector code with the scalar
code on x86-64, AArch64 and an emulated AArch64 processor
([`emulated-aarch64/`](https://github.com/linouxis9/oxirush-security/tree/master/emulated-aarch64)),
and fuzzes the four targets of
[`fuzz/`](https://github.com/linouxis9/oxirush-security/tree/master/fuzz).
The only `unsafe` code calls the vector code and clears the stack and the
registers.

The Rust blocks of this page are checked with what they print
([`tests/readme.rs`](tests/readme.rs) says how), and the block that uses
oxirush-nas runs in the package of [`family/`](family/).
[The documentation](https://docs.rs/oxirush-security) has the terms, each
function with its clause and the values that it is tested against, what an
operation leaves, and how the code was checked for a time that does not
depend on a secret.

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.

## The OxiRush family

- [oxirush-utils](https://github.com/linouxis9/oxirush-utils): the 3GPP identities, and the JSON tree with its paths that the others share.
- [oxirush-aper](https://github.com/linouxis9/oxirush-aper): aligned PER, the runtime of the NGAP and S1AP codecs.
- [oxirush-nas](https://github.com/linouxis9/oxirush-nas): the NAS messages of 5GS and EPS.
- [oxirush-security](https://github.com/linouxis9/oxirush-security): NAS security, AKA and the derivation of keys.
- [oxirush-ngap](https://github.com/linouxis9/oxirush-ngap): NGAP, between a gNB and an AMF.
- [oxirush-s1ap](https://github.com/linouxis9/oxirush-s1ap): S1AP, between an eNB and an MME.
- [oxirush-gtp-u](https://github.com/linouxis9/oxirush-gtp-u): GTP-U tunnels, with a test UPF.
- [oxirush-sctp](https://github.com/linouxis9/oxirush-sctp): SCTP sockets, which carry NGAP and S1AP.

## License

Copyright 2025-2026 Valentin D'Emmanuele. Licensed under the Apache License,
Version 2.0: see [LICENSE](LICENSE).
