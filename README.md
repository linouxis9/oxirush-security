# oxirush-security

[![Crates.io](https://img.shields.io/crates/v/oxirush-security.svg)](https://crates.io/crates/oxirush-security)
[![Documentation](https://docs.rs/oxirush-security/badge.svg)](https://docs.rs/oxirush-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

The security functions of 5GS and EPS in Rust, per 3GPP TS 33.501 and
TS 33.401: key derivation, NAS integrity and ciphering with SNOW 3G, AES and
ZUC, and SUCI concealment. They are functions over octets. The crate stores no
key, keeps no NAS COUNT and has no `unsafe` code.

```rust
use oxirush_security::nas_5gs::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, derive_knas_enc,
    derive_knas_int, nas_cipher, nas_mac,
};

// KAMF, as the 5G AKA example below derives it
let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
let k_amf: [u8; 32] = hex::decode(k_amf).unwrap().try_into().unwrap();

// The NAS keys of the algorithms that the network selected
let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
let k_nas_enc = derive_knas_enc(&k_amf, nea2);
let k_nas_int = derive_knas_int(&k_amf, nia2);
assert_eq!(hex::encode(k_nas_enc), "f47ae570afde775373d1b313d2176f54");
assert_eq!(hex::encode(k_nas_int), "28ddb5356880149b9fee22f2367522a4");

// An uplink message on 3GPP access with NAS COUNT 0: cipher it, then compute
// the MAC over the sequence number and the ciphertext
let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
let mut message = vec![0x7e, 0x00, 0x43]; // REGISTRATION COMPLETE
nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
let protected = [&[count.sequence_number()][..], &message].concat();
let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
assert_eq!((hex::encode(&message), mac), ("b57dd5".to_string(), 0x83e4_d009));

// The same call deciphers
nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
assert_eq!(message, [0x7e, 0x00, 0x43]);
```

The block needs the `hex` crate beside this one. Like every Rust block of
this page it runs as a documentation test: it asserts what it computes and
prints nothing.

[Installation](#installation) ·
[What it implements](#what-it-implements) ·
[Examples by task](#examples-by-task) ·
[Inputs and errors](#inputs-and-errors) ·
[Key material and timing](#key-material-and-timing) ·
[Test evidence](#test-evidence) ·
[What it does not do](#what-it-does-not-do) ·
[Modules](#modules-and-example-programs) ·
[Specifications](#specifications)

## Installation

```toml
[dependencies]
oxirush-security = "0.3"

# For the examples of this page:
hex = "0.4"
```

Two features, both on by default, bring what only part of the crate needs:

| Features | What the crate has | Crates in its tree |
|----------|--------------------|--------------------|
| none | The key derivations, the algorithms, NAS integrity and ciphering, 5G-GUTI, PLMN and TBCD | 15 |
| `suci` | And SUCI concealment and deconcealment with the null scheme, Profile A and Profile B, which bring X25519 and P-256 | 41 |
| `suci` and `nai`, the default | And the SUCI and SUPI of the NAI format, which bring Unicode normalization and IDNA | 71 |

```toml
# The key derivations and the algorithms alone
oxirush-security = { version = "0.3", default-features = false }
```

The minimum supported Rust version is 1.88. On 1.88 itself Cargo has to
choose the dependencies by Rust version, as resolver 3 does, the default of
edition 2024: `aes` 0.9.3 needs Rust 1.89 and 0.9.2 takes its place.

## What it implements

The last column names the kind of reference value that the tests have, which
[Test evidence](#test-evidence) explains.

| What | Functions | Specification | Reference values |
|------|-----------|---------------|------------------|
| NAS ciphering | `nas_cipher`; the algorithms `nea_cipher`, `nea1_cipher`, `nea2_cipher`, `nea3_cipher` and their `*_bits` forms | NEA0 (null), NEA1 (SNOW 3G, 128-EEA1), NEA2 (AES-128-CTR, 128-EEA2), NEA3 (ZUC, 128-EEA3): TS 33.401 Annex B.1 | 3GPP |
| NAS integrity | `nas_mac`; the algorithms `nia_mac`, `nia1_mac`, `nia2_mac`, `nia3_mac` and their `*_bits` forms | NIA1 (SNOW 3G, 128-EIA1), NIA2 (AES-CMAC, 128-EIA2), NIA3 (ZUC, 128-EIA3): TS 33.401 Annex B.2 | 3GPP |
| Keystream generators | `Snow3G`, `Zuc` | TS 35.216, TS 35.222 | 3GPP |
| 5G AKA | `derive_kausf`, `compute_xres_star`, `compute_hres_star`, `derive_kseaf`, `derive_kamf`, `derive_knas_enc`, `derive_knas_int`, `derive_kgnb`, `derive_nh` | TS 33.501 Annex A.2 and A.4 to A.10 | other implementations |
| Other 5GS derivations | KAMF', KN3IWF, KNG-RAN\*, KSN, the RRC and UP keys, the SoR and UPU MACs, the TNAP usage keys, KIAB | TS 33.501 Annex A | calculated |
| EPS derivations | KASME, KNASint and KNASenc, KeNB, NH, KeNB\*, the AS keys, the NAS token, the CK'/IK' mapping, SRVCC, S-KeNB, LWIP-PSK, S-KWT, K_n | TS 33.401 Annex A | calculated |
| HASHMME | `nas_eps::compute_hash_mme` | TS 33.401 Annex I.2 | other implementations |
| 5GS/EPS key mapping | Idle mobility and connected handover in both directions, and KASME_SRVCC | TS 33.501 Annexes A.14, A.15 and A.21 | calculated |
| Other NAS MACs | `nas_container_mac`; `nas_eps::re_establishment_nas_mac` for UL_NAS_MAC and XDL_NAS_MAC; `nas_eps::service_request_short_mac` | TS 33.501 §6.9.2.3.3; TS 33.401 §7.4.4; TS 24.301 §9.9.3.28 | calculated |
| SUCI | IMSI and NAI identities with the null scheme, Profile A (X25519 ECIES) and Profile B (P-256 ECIES), and proprietary outputs kept as they are | TS 33.501 Annex C | 3GPP |
| 5G-GUTI, 5G-S-TMSI | `build_guti_bytes`, `parse_guti_tmsi`, `parse_s_tmsi` | TS 24.501 §9.11.3.4 | calculated |
| PLMN and TBCD | `plmn_to_bytes`, `plmn_from_bytes`, `tbcd_encode`, `tbcd_decode` | TS 24.501 §9.11.3.4, TS 29.002 | calculated |
| Algorithm selection | `select_integrity_algo`, `select_ciphering_algo` with NIA2 > NIA1 > NIA3 (never NIA0) and NEA2 > NEA1 > NEA3 > NEA0, the default order; their `*_with_preference` forms with an operator's order | TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1 | calculated |

EPS and 5GS share the 128-bit EEA/EIA algorithm cores, and the whole-octet
NAS wrappers delegate to them. The `*_bits` functions take a length in bits:
they preserve the unused low bits of the final octet when ciphering and
ignore them for integrity.

## Examples by task

### 5G AKA

```rust
use oxirush_security::constant_time_eq;
use oxirush_security::nas_5gs::*;

// CK, IK, RAND, RES and SQN xor AK: the MILENAGE outputs of TS 35.208 test set 1
let hex16 = |s: &str| <[u8; 16]>::try_from(hex::decode(s).unwrap()).unwrap();
let ck = hex16("b40ba9a3c58b2a05bbf0d987b21bf8cb");
let ik = hex16("f769bcd751044604127672711c6d3441");
let rand = hex16("23553cbe9637a89d218ae64dae47bf35");
let res = hex::decode("a54211d5e3ba50bf").unwrap();
let sqn_xor_ak = [0x55, 0xf3, 0x28, 0xb4, 0x35, 0x77];
let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

// UDM: KAUSF and XRES*
let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak)?;
let xres_star = compute_xres_star(&ck, &ik, sn_name, &rand, &res)?;

// AUSF: HXRES* and KSEAF
let hxres_star = compute_hres_star(&rand, &xres_star);
let k_seaf = derive_kseaf(&k_ausf, sn_name)?;

// SEAF: KAMF
let (supi, abba) = ("208930000000001", [0x00, 0x00]);
let k_amf = derive_kamf(&k_seaf, supi, &abba)?;

// Access stratum: KgNB from the uplink NAS COUNT, then NH for a handover
let uplink_nas_count = NasCount::ZERO;
let k_gnb = derive_kgnb(&k_amf, uplink_nas_count);
let nh = derive_nh(&k_amf, &k_gnb);

// The values of the chain
assert_eq!(hex::encode(k_ausf), "f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9");
assert_eq!(hex::encode(xres_star), "5cc9527f4d21c43bee83a15443acf1c4");
assert_eq!(hex::encode(hxres_star), "6970075e3c8245fdc2073003cf166279");
assert_eq!(hex::encode(k_seaf), "cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa");
assert_eq!(hex::encode(k_amf), "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4");
assert_eq!(hex::encode(k_gnb), "c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005");
assert_eq!(hex::encode(nh), "383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b");

// What a peer sent is compared in constant time, not with `==`
let res_star_of_the_ue = xres_star;
assert!(constant_time_eq(&res_star_of_the_ue, &xres_star));
# Ok::<(), oxirush_security::SecurityError>(())
```

free5GC and CryptoMobile give the same values for these inputs.

### NAS integrity and ciphering

The first example of this page ciphers a message and computes its MAC.

```rust
use oxirush_security::nas_5gs::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasConnection, NasCount, nas_mac,
    select_ciphering_algo, select_integrity_algo, select_integrity_algo_with_preference,
};
use oxirush_security::{SecurityError, nia_mac_bits};

// Selection from the EA and IA octets of a UE security capability:
// here EA0, EA1 and EA2, and IA1 and IA2
assert_eq!(select_ciphering_algo(0xe0), Some(CipheringAlgorithm::NEA2)); // NEA2 > NEA1 > NEA3 > NEA0
assert_eq!(select_integrity_algo(0x60), Some(IntegrityAlgorithm::NIA2)); // NIA2 > NIA1 > NIA3, never NIA0
let operator = [IntegrityAlgorithm::NIA1, IntegrityAlgorithm::NIA2];
assert_eq!(select_integrity_algo_with_preference(0x60, &operator), Some(IntegrityAlgorithm::NIA1));

// An algorithm identifier from a message is checked once: 4 to 7 are reserved
let algorithm = IntegrityAlgorithm::try_from(2)?;
assert_eq!(algorithm, IntegrityAlgorithm::NIA2);
assert_eq!(IntegrityAlgorithm::try_from(5), Err(SecurityError::UnsupportedAlgorithm(5)));

// So is a NAS COUNT, which has 24 bits
let count = NasCount::new(5)?;
assert!(NasCount::new(1 << 24).is_err());

// One call for every algorithm. `message` is the sequence number, then the
// NAS message
let key = [0x2b; 16];
let message = [count.sequence_number(), 0x7e, 0x00, 0x43];
let (access, downlink) = (NasConnection::ThreeGpp, Direction::Downlink);
let mac = |algorithm| nas_mac(&key, count, access, downlink, &message, algorithm);
assert_eq!(mac(IntegrityAlgorithm::NIA0), 0); // the null algorithm
assert_ne!(mac(IntegrityAlgorithm::NIA1), mac(IntegrityAlgorithm::NIA3));

// The algorithms as the 3GPP test sets use them: any 32-bit COUNT, a 5-bit
// BEARER and a length in bits. This is 128-EIA2 test set 1 of TS 33.401
// Annex C.2.1, a message of 58 bits
let key = hex::decode("2bd6459f82c5b300952c49104881ff48").unwrap().try_into().unwrap();
let message = hex::decode("3332346263393840").unwrap();
let (count, bearer, uplink, bits) = (0x38a6_f056, Bearer::new(0x18)?, Direction::Uplink, 58);

let mac = nia_mac_bits(&key, count, bearer, uplink, &message, bits, IntegrityAlgorithm::EIA2)?;
assert_eq!(mac, 0x118c_6eb8);

// A length that the message does not have is an error
assert!(nia_mac_bits(&key, count, bearer, uplink, &message, 65, IntegrityAlgorithm::EIA2).is_err());
# Ok::<(), SecurityError>(())
```

### EPS

`nas_eps` fixes the NAS bearer to zero and accepts the 24-bit EPS NAS COUNT.

```rust
use oxirush_security::nas_eps::{
    CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount, derive_kasme, derive_knas_enc,
    derive_knas_int, nas_cipher, nas_mac, service_request_short_mac,
};
use oxirush_security::plmn_to_bytes;

// KASME from CK, IK, the serving network identity and SQN xor AK
let ck = [0x11; 16];
let ik = [0x22; 16];
let sn_id = plmn_to_bytes("208", "93")?;
let sqn_xor_ak = [0; 6];
let kasme = derive_kasme(&ck, &ik, &sn_id, &sqn_xor_ak);

// The NAS keys of the selected algorithms
let (eea2, eia2) = (CipheringAlgorithm::EEA2, IntegrityAlgorithm::EIA2);
let knas_enc = derive_knas_enc(&kasme, eea2);
let knas_int = derive_knas_int(&kasme, eia2);

// Uplink EMM STATUS with cause #3, NAS COUNT 0: cipher it, then compute the
// MAC over the sequence number and the ciphertext
let (count, uplink) = (NasCount::ZERO, Direction::Uplink);
let mut payload = vec![0x07, 0x60, 0x03];
nas_cipher(&knas_enc, count, uplink, &mut payload, eea2);
let protected = [&[count.sequence_number()][..], &payload].concat();
let mac = nas_mac(&knas_int, count, uplink, &protected, eia2);
assert_eq!((hex::encode(&payload), mac), ("b02c47".to_string(), 0x190a_f1e7));

// The 16-bit short MAC of a SERVICE REQUEST: NAS COUNT 1, KSI 0 and sequence number 1
let (count, ksi_and_sequence_number) = (NasCount::new(1)?, 0x01);
let short_mac =
    service_request_short_mac(&knas_int, count, uplink, ksi_and_sequence_number, eia2);
assert_eq!(short_mac, 0x7e95);
# Ok::<(), oxirush_security::SecurityError>(())
```

### SUCI: conceal and deconceal

```rust
use oxirush_security::{nas_5gs::*, plmn_to_bytes};

let hex = |s: &str| hex::decode(s).unwrap();

// MSIN 001002086, and the home network keys of TS 33.501 Annex C.4
let msin = msin_to_bcd("001002086")?;
assert_eq!(msin, [0x00, 0x01, 0x20, 0x80, 0xf6]);

// The home network key pair of Profile A, X25519
let public_a = hex("5a8d38864820197c3394b92613b20b91633cbd897119273bf8e4a6f4eec0a650");
let private_a = hex("c53c22208b61860b06c62e5406a7b330c2b577aa5558981510d128247d38bd1d");
let (public_a, private_a): ([u8; 32], [u8; 32]) =
    (public_a.try_into().unwrap(), private_a.try_into().unwrap());

// Its scheme output: ephemeral public key (32) || ciphertext || MAC tag (8)
let output = suci_scheme_output_a(&msin, &public_a)?;
assert_eq!(output.len(), 32 + msin.len() + 8);
assert_eq!(suci_decrypt_a(&output, &private_a)?, msin);

// The home network key pair of Profile B, P-256
let public_b = hex("0272da71976234ce833a6907425867b82e074d44ef907dfb4b3e21c1c2256ebcd1");
let private_b = hex("f1ab1074477ebcc7f554ea1c5fc368b1616730155e0041ac447d6301975fecda");

// Its scheme output: compressed ephemeral public key (33) || ciphertext || MAC tag (8)
let output = suci_scheme_output_b(&msin, &public_b)?;
assert_eq!(output.len(), 33 + msin.len() + 8);
assert_eq!(suci_decrypt_b(&output, &private_b)?, msin);

// The Profile A scheme output of Annex C.4.3.1, in the SUCI of a NAS message
let output = hex(
    "b2e92f836055a255837debf850b528997ce0201cb82adfe4be1f587d07d8457dcb02352410cddd9e730ef3fa87",
);
let mut suci = vec![0x01]; // SUPI format IMSI, type of identity SUCI
suci.extend(plmn_to_bytes("274", "012")?);
suci.extend([0xf0, 0xff, 0x01, 0x01]); // routing indicator 0, Profile A, key identifier 1
suci.extend(&output);

// It is deconcealed with the private key, and not without it
assert_eq!(suci_to_supi(&suci, Some(&private_a)).as_deref(), Some("imsi-274012001002086"));
assert_eq!(suci_to_supi(&suci, None), None);

// A network specific identifier is concealed as a NAI (TS 23.003 §28.7.3):
// type1.rid0.schid1.hnkey1.ecckey<key>.cip<ciphertext>.mac<tag>@example.net
let scheme = NaiProtectionScheme::ProfileA {
    home_network_public_key_id: 1,
    home_network_public_key: &public_a,
};
let suci = conceal_network_specific_supi("sensor-17@example.net", "0", scheme)?;
let text = encode_nai_suci(&suci)?;

// The home network parses the NAI and deconceals the identifier
let parsed = parse_nai_suci(&text)?;
let supi = deconceal_network_specific_suci(&parsed, Some(&private_a))?;
assert_eq!(supi, "sensor-17@example.net");
# Ok::<(), SecurityError>(())
```

Concealment draws a fresh ephemeral key, so two outputs for one MSIN differ.
Profile B always applies point compression (TS 33.501 Annex C.3.4), and
deconcealment rejects an uncompressed ephemeral point, as TS 33.514 §4.2.1.3
requires.

### 5G-GUTI, PLMN and TBCD

```rust
use oxirush_security::{
    build_guti_bytes, parse_guti_tmsi, parse_s_tmsi, plmn_from_bytes, plmn_to_bytes, tbcd_decode,
    tbcd_encode,
};

// A PLMN identity: MCC 208 and MNC 93
let plmn = plmn_to_bytes("208", "93")?;
assert_eq!(plmn, [0x02, 0xf8, 0x39]);
assert_eq!(plmn_from_bytes(&plmn), Some(("208".to_string(), "93".to_string())));
assert!(plmn_to_bytes("208", "9").is_err());

// A 5G-GUTI: AMF region 1, set 1 and pointer 2, and a 5G-TMSI
let (region, set, pointer, tmsi) = (0x01, 0x001, 0x02, 0x1122_3344);
let guti = build_guti_bytes(&plmn, region, set, pointer, tmsi)?;
assert_eq!(hex::encode(guti), "f202f83901004211223344");
assert_eq!(parse_guti_tmsi(&guti), Some(tmsi));

// The 5G-TMSI of a 5G-S-TMSI
let s_tmsi = [0xf4, 0x00, 0x42, 0x11, 0x22, 0x33, 0x44];
assert_eq!(parse_s_tmsi(&s_tmsi), Some(tmsi));

// The digits of an IMSI as a TBCD string
let imsi = tbcd_encode("208930000000001")?;
assert_eq!(hex::encode(&imsi), "02980300000000f1");
assert_eq!(tbcd_decode(&imsi), "208930000000001");
# Ok::<(), oxirush_security::SecurityError>(())
```

## Inputs and errors

No public function panics on its arguments. A value that a specification
bounds has a type that holds only the values in range, and a value from a
peer or from a configuration enters through `TryFrom` or `new`, which
return a `SecurityError`. The functions that take these types then cannot
fail. What a type cannot say is a `Result` or an `Option`.

| Input | Type or check |
|-------|---------------|
| Algorithm of a MAC, a cipher or a key | `IntegrityAlgorithm` and `CipheringAlgorithm`: the four of each that 5GS and EPS share, under both names (`NIA2` and `EIA2`). `try_from(u8)` reads an identifier and refuses 4 and above; `u8::from` gives it back |
| NAS COUNT | `NasCount`, 24 bits: `new`, `try_from(u32)` or `from_parts(overflow, sequence_number)` |
| COUNT of the KgNB and KeNB derivations | A `NasCount`, or `AccessKeyCount::Handover` for the 2^32 - 1 of a handover |
| NAS connection of 5GS | `NasConnection::ThreeGpp` (identifier 1) or `Non3Gpp` (2) |
| DIRECTION | `Direction::Uplink` or `Downlink` |
| COUNT and BEARER of the algorithms themselves | Any `u32`, and `Bearer`, 5 bits |
| Length in bits | `Err(BitLengthExceedsData)` when the buffer is shorter |
| PCI, ARFCN, AMF Set ID, AMF Pointer, cell identity | `Err(OutOfRange)` above the largest value |
| MCC, MNC, MSIN and TBCD string | `Err(InvalidParameter)` for a wrong length or character |
| KDF parameter of variable length | `Err(InputTooLong)` above 65535 octets |
| SUCI, 5G-GUTI and 5G-S-TMSI from a peer | `None` or an `Err` for what cannot be read or deconcealed |

`nas_mac` and `nas_cipher` are the functions of NAS. They exist in `nas_5gs`
and in `nas_eps`, and the crate root re-exports those of `nas_5gs`. The
functions named after an algorithm (`nia_mac`, `nea_cipher`, `nia2_mac` and
the others of `common`) take what the algorithm takes.

## Key material and timing

| Subject | What the crate does |
|---------|---------------------|
| Wiped after use | Explicit buffers and owned state: CK‖IK buffers, key-bearing KDF input buffers, the SHA-256 state and the key block and inner hash of HMAC-SHA-256, SUCI ECIES KDF buffers, cipher state including the AES key schedule, and keystream buffers. The hasher and the AES cipher are those of the `sha2` and `aes` crates, built with their `zeroize` features: the crate does not compile without them. |
| Not wiped | Temporary copies and compiler-generated spills, which the wiping above does not all cover. Returned keys and deconcealed identities belong to the caller, who clears them when their lifetime ends. |
| Secret-dependent indexing and branches | In the source, the SNOW 3G and ZUC S-boxes, the MULα/DIVα tables, and the 128-EIA1 and AES-CMAC field arithmetic neither index memory nor branch on secret values. AES comes from the `aes` crate. |
| Comparison | `constant_time_eq` compares RES\* with XRES\*, or HRES\* with HXRES\*, through `subtle`: its time depends on the lengths and not on where the values differ. |
| Not measured | Compiled-code timing has not been audited across supported targets. |

## Test evidence

The unit tests and `tests/spec_vectors.rs` rest on three kinds of reference
values, which do not carry the same weight.

| Kind | What is tested against it |
|------|---------------------------|
| **3GPP** test data | 128-EEA1/2/3 and 128-EIA1/2/3 on the TS 33.401 Annex C, TS 35.217, TS 35.218 and TS 35.223 sets, including non-byte-aligned EEA1, EEA2, EEA3, EIA1, EIA2 and EIA3 inputs; the SNOW 3G and ZUC keystreams; SUCI on every TS 33.501 Annex C.4 data set. |
| Values of **other implementations** | The 5G AKA chain from the TS 35.208 test set 1 MILENAGE outputs through KAUSF, XRES\*, HXRES\*, KSEAF, KAMF, the NAS keys, KgNB and NH, which free5GC and CryptoMobile both give; HASHMME on ATTACH REQUESTs and the values a network returned for them. |
| Values **calculated** in the tests | The other 5GS KDFs, the EPS and interworking KDFs, and the NAS container, short and re-establishment MACs are compared with HMAC-SHA-256 or the MAC over the parameter layout as the test writes it. The identity encodings and the algorithm selection are compared with what the test writes too. These tests keep a layout from changing unnoticed; they are not independent vectors. |

## What it does not do

| Subject | Limit |
|---------|-------|
| Audit | The crate has not had a security audit, and its timing has been read in the source, not measured. |
| State | It stores no keys, and it keeps neither the NAS COUNT nor replay state: those belong to the caller. |
| AKA | It has no MILENAGE or TUAK: CK, IK, RES and SQN xor AK come from the caller. |
| NAS messages | It protects octets. It does not encode a NAS message or its security header. |
| Re-establishment MAC | The 28-bit reading of the target Cell-ID is this crate's: no test data or other implementation exists to check it against. |

## Modules and example programs

| Module | Contents |
|--------|----------|
| [`nas_5gs`](src/nas_5gs/mod.rs) | TS 33.501 `kdf`, `security`, and `algo`; GUTI and SUCI |
| [`nas_eps`](src/nas_eps/mod.rs) | TS 33.401 `kdf`, `security`, and `algo` |
| [`common`](src/common/mod.rs) | HMAC KDF framing (TS 33.220), EEA/EIA cores, SNOW 3G, ZUC, algorithm selection, and PLMN utilities |

The crate root has the functions of `nas_5gs` and of `common`. EPS functions
are under `oxirush_security::nas_eps`.

Each 5GS example has an EPS counterpart; SUCI concealment is 5GS only.

```bash
cargo run --example key_derivation_nas_5gs   # KAUSF -> KSEAF -> KAMF -> NAS keys -> KgNB -> NH
cargo run --example key_derivation_nas_eps   # CK || IK -> KASME -> NAS keys -> KeNB -> NH
cargo run --example integrity_nas_5gs        # NIA1/NIA2/NIA3 MAC computation
cargo run --example integrity_nas_eps        # EIA1/EIA2/EIA3 MAC and SERVICE REQUEST short MAC
cargo run --example suci_conceal             # SUCI concealment with Profile A
```

## Specifications

| Specification | For |
|---------------|-----|
| TS 33.501 | 5G security architecture: key derivation, algorithm IDs, SUCI |
| TS 33.401 | EPS security architecture: key derivation, NAS COUNT, EIA/EEA |
| TS 35.215, 35.216, 35.217, 35.218 | SNOW 3G modes, core, and test data |
| TS 35.221, 35.222, 35.223 | ZUC modes, core, and test data |

Full API reference: **<https://docs.rs/oxirush-security>**

## Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Sign off your commits (`git commit -s`)
4. Open a Pull Request

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2025 - 2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.
