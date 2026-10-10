# oxirush-security

[![Crates.io](https://img.shields.io/crates/v/oxirush-security.svg)](https://crates.io/crates/oxirush-security)
[![Documentation](https://docs.rs/oxirush-security/badge.svg)](https://docs.rs/oxirush-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

5GS and EPS security algorithms in Rust — key derivation, integrity, ciphering, and SUCI concealment per 3GPP TS 33.501 and TS 33.401.

## Features

- **5GS key derivation** (TS 33.501 Annex A) — KAUSF, KSEAF, KAMF/KAMF', KNASint/KNASenc, K_gNB, KN3IWF, NH, KNG-RAN*, KSN, SoR/UPU MACs, TNAP usage keys, KIAB, and the RRC/UP keys
- **EPS key derivation** (TS 33.401 Annex A) — KASME, KNASint/KNASenc, KeNB, NH, KeNB*, AS keys, NAS token, CK'/IK' mapping, SRVCC, and HASHMME (Annex I.2)
- **5GS/EPS key mapping** (TS 33.501 Annexes A.14, A.15, A.21) — idle mobility and connected handover in both directions, and KASME_SRVCC
- **Mobility MACs** — the NAS Container MAC of TS 33.501 §6.9.2.3.3 and the UL_NAS_MAC/XDL_NAS_MAC of TS 33.401 §7.4.4
- **NAS integrity** — NIA1 (SNOW 3G / 128-EIA1), NIA2 (AES-CMAC / 128-EIA2), NIA3 (ZUC / 128-EIA3)
- **NAS ciphering** — NEA0 (null), NEA1 (SNOW 3G / 128-EEA1), NEA2 (AES-128-CTR / 128-EEA2), NEA3 (ZUC / 128-EEA3)
- **SUCI concealment** (TS 33.501 Annex C.4) — IMSI and NAI identities with the null scheme, Profile A (X25519 ECIES), Profile B (P-256 ECIES), plus preserved proprietary outputs
- **XRES\* / HXRES\* computation** — for AMF-side 5G-AKA verification
- **5G-GUTI / 5G-S-TMSI** — construction and parsing
- **PLMN encoding** — TBCD encode/decode for MCC/MNC
- **Algorithm selection** — configurable operator preference order, with NIA2 > NIA1 > NIA3 (never NIA0) and NEA2 > NEA1 > NEA3 > NEA0 as the compatibility defaults

The EEA/EIA functions are tested against the TS 33.401 Annex C and
TS 35.217/35.218/35.223 test sets, including non-byte-aligned EEA1, EEA2,
EEA3, EIA1, EIA2, and EIA3 inputs. The `*_bits` APIs preserve unused low bits in
the final ciphering octet and ignore them for integrity. Whole-octet NAS
wrappers delegate to the same cores. [Test evidence](#test-evidence) says
which reference values each part of the crate is tested against.

Explicit buffers and owned state are wiped after use: CK‖IK buffers,
key-bearing KDF input buffers, SHA-256 and HMAC-SHA-256 state owned by this
crate, SUCI ECIES KDF buffers, cipher state, and keystream buffers. This
does not cover every temporary copy or compiler-generated spill. Returned
keys and deconcealed identities belong to the caller, who clears them when
their lifetime ends.

AES comes from the `aes` crate. In the source,
the SNOW 3G and ZUC S-boxes, the MULα/DIVα tables, and the 128-EIA1 and
AES-CMAC field arithmetic neither index memory nor branch on secret values.
Compiled-code timing has not been audited across supported targets.

EPS and 5GS share the 128-bit EEA/EIA algorithm cores. The `nas_eps` module fixes
the NAS bearer to zero and accepts the 24-bit EPS NAS COUNT. It also computes
the 16-bit short MAC for a SERVICE REQUEST and the 28-bit target Cell-ID
re-establishment MAC of TS 33.401 §7.4.4.

## Quick start

```toml
[dependencies]
oxirush-security = "0.3"
```

### 5GS key derivation

```rust
use oxirush_security::nas_5gs::*;

// Full 5G key derivation chain per TS 33.501 Annex A
let ck = [0x11; 16];       // from 5G-AKA
let ik = [0x22; 16];       // from 5G-AKA
let sqn_xor_ak = [0u8; 6]; // AUTN field
let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

let k_ausf = derive_kausf(&ck, &ik, sn_name, &sqn_xor_ak);
let k_seaf = derive_kseaf(&k_ausf, sn_name);
let k_amf  = derive_kamf(&k_seaf, "208930000000001", &[0x00, 0x00]);

// NAS keys (distinguisher: 0x01=ciphering, 0x02=integrity; algo_id: 1=NIA1/NEA1, 2=NIA2/NEA2, 3=NIA3/NEA3)
let k_nas_int = extract_128(&derive_nas_key(&k_amf, 0x02, 2)); // integrity, NIA2
let k_nas_enc = extract_128(&derive_nas_key(&k_amf, 0x01, 2)); // ciphering, NEA2

// K_gNB for initial context setup
let k_gnb = derive_kgnb(&k_amf, 0); // UL NAS COUNT = 0

// NH for handover (NCC=1)
let nh = derive_nh(&k_amf, &k_gnb);
```

### 5GS NAS integrity and ciphering

```rust
use oxirush_security::nas_5gs::*;

let key = [0u8; 16]; // KNASint or KNASenc (128-bit)
let inner_message = [0x7e, 0x00, 0x41];
let sequence_number = 0u8;
let mut payload = inner_message.to_vec();

// Cipher the inner NAS message, then MAC the sequence number and ciphertext.
nas_cipher(&key, /*count=*/0, /*bearer=*/1, /*direction=*/0, &mut payload, /*algo=*/0x02);
let mut mac_input = vec![sequence_number];
mac_input.extend_from_slice(&payload);
let mac: u32 = nas_mac(&key, /*count=*/0, /*bearer=*/1, /*direction=*/0, &mac_input, /*algo=*/0x02);
```

### EPS key derivation and NAS protection

```rust
use oxirush_security::{common::plmn_to_bytes, nas_eps};

let ck = [0x11; 16];
let ik = [0x22; 16];
let sn_id: [u8; 3] = plmn_to_bytes("208", "93").try_into().unwrap();
let kasme = nas_eps::derive_kasme(&ck, &ik, &sn_id, &[0; 6]);
let knas_int = nas_eps::extract_128(&nas_eps::derive_nas_key(&kasme, 0x02, 2)); // EIA2
let knas_enc = nas_eps::extract_128(&nas_eps::derive_nas_key(&kasme, 0x01, 2)); // EEA2

let mut payload = vec![0x07, 0x60, 0x03]; // EPS EMM STATUS, cause 3
nas_eps::nas_cipher(&knas_enc, 0, 0, &mut payload, 2);
let mac = nas_eps::nas_mac(&knas_int, 0, 0, &[&[0], payload.as_slice()].concat(), 2);
let short_mac = nas_eps::service_request_short_mac(&knas_int, 1, 0, 0x01, 2);
```

### SUCI concealment

```rust
use oxirush_security::{SecurityError, nas_5gs::*};

fn conceal_with_operator_keys(
    home_network_pub_key_a: &[u8; 32],
    home_network_pub_key_b: &[u8],
) -> Result<(), SecurityError> {
    let msin_bcd = msin_to_bcd("0000000001");

    let output_a = suci_scheme_output_a(&msin_bcd, home_network_pub_key_a)?;
    let ephemeral_pub_key_a = &output_a[..32]; // X25519

    let output_b = suci_scheme_output_b(&msin_bcd, home_network_pub_key_b)?;
    let ephemeral_pub_key_b = &output_b[..33]; // compressed P-256
    assert_eq!(ephemeral_pub_key_a.len(), 32);
    assert_eq!(ephemeral_pub_key_b.len(), 33);
    Ok(())
}
```

## Modules

| Module | Description |
|--------|-------------|
| [`nas_5gs`](src/nas_5gs/mod.rs) | TS 33.501 `kdf`, `security`, and `algo`; GUTI and SUCI |
| [`nas_eps`](src/nas_eps/mod.rs) | TS 33.401 `kdf`, `security`, and `algo` |
| [`common`](src/common/mod.rs) | HMAC KDF framing, EEA/EIA cores, algorithm selection, and PLMN utilities |

The crate root re-exports the existing 5GS and common functions for backward
compatibility. EPS functions are under `oxirush_security::nas_eps`.

Functions that take protocol values documented as bounded (for example an
algorithm identifier above 3, a NAS COUNT above 2^24 - 1, or a PCI above 503)
panic on out-of-range input; each lists its conditions under `# Panics`.
The raw algorithm cores also reject a bearer above 31, a direction above 1,
or a bit length larger than the supplied buffer. Check values received from a
peer before passing them.

## Architecture

```text
src/
├── common/     KDF framing (TS 33.220), EEA/EIA cores, SNOW 3G, ZUC, PLMN
├── nas_5gs/    TS 33.501 key hierarchy, NAS security, algorithm selection,
│               GUTI, and SUCI
└── nas_eps/    TS 33.401 key hierarchy, NAS security, algorithm selection
```

## Examples

Each 5GS example has an EPS counterpart; SUCI concealment is 5GS only.

```bash
cargo run --example key_derivation_nas_5gs   # KAUSF -> KSEAF -> KAMF -> NAS keys -> KgNB -> NH
cargo run --example key_derivation_nas_eps   # CK || IK -> KASME -> NAS keys -> KeNB -> NH
cargo run --example integrity_nas_5gs        # NIA1/NIA2/NIA3 MAC computation
cargo run --example integrity_nas_eps        # EIA1/EIA2/EIA3 MAC and SERVICE REQUEST short MAC
cargo run --example suci_conceal             # SUCI concealment with Profile A
```

## 3GPP references

- **TS 33.501** — 5G security architecture (key derivation, algorithm IDs, SUCI)
- **TS 33.401** — EPS security architecture (key derivation, NAS COUNT, EIA/EEA)
- **TS 35.215/35.216/35.217/35.218** — SNOW 3G modes, core, and test data
- **TS 35.221/35.222/35.223** — ZUC modes, core, and test data

## Test evidence

The unit tests and `tests/spec_vectors.rs` rest on three kinds of reference
values, which do not carry the same weight:

- **3GPP test data** — 128-EEA1/2/3 and 128-EIA1/2/3 on the TS 33.401
  Annex C, TS 35.217, TS 35.218, and TS 35.223 sets, the SNOW 3G and ZUC
  keystreams, and SUCI on every TS 33.501 Annex C.4 data set.
- **Values of other implementations** — the 5G AKA chain from the TS 35.208
  test set 1 MILENAGE outputs through KAUSF, XRES\*, HXRES\*, KSEAF, KAMF, the
  NAS keys, KgNB, and NH, which free5GC and CryptoMobile both give, and
  HASHMME on ATTACH REQUESTs and the values a network returned for them.
- **Values calculated in the tests** — the other 5GS KDFs, the EPS and
  interworking KDFs, and the NAS container, short, and re-establishment MACs
  are compared with HMAC-SHA-256 or the MAC over the parameter layout as the
  test writes it. These tests keep a layout from changing unnoticed; they are
  not independent vectors.

Profile B always applies point compression (TS 33.501 Annex C.3.4), and
deconcealment rejects uncompressed ephemeral points as TS 33.514 §4.2.1.3
requires.

The crate has not had a security audit, and its timing has been read in the
source, not measured. It stores no keys, and it keeps neither the NAS COUNT
nor replay state: those belong to the caller.

## Documentation

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
