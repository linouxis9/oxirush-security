# oxirush-security

[![Crates.io](https://img.shields.io/crates/v/oxirush-security.svg)](https://crates.io/crates/oxirush-security)
[![Documentation](https://docs.rs/oxirush-security/badge.svg)](https://docs.rs/oxirush-security)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

5G NAS security algorithms in Rust — key derivation, integrity, ciphering, and SUCI concealment per 3GPP TS 33.501.

Part of the [OxiRush](https://github.com/linouxis9/oxirush) project — a 5G Core Network testing framework.

## Features

- **Key derivation chain** (TS 33.501 Annex A) — KAUSF, KSEAF, KAMF, KNASint/KNASenc, K_gNB, NH (for handover)
- **NAS integrity** — NIA1 (SNOW 3G / 128-EIA1), NIA2 (AES-CMAC / 128-EIA2), NIA3 (ZUC / 128-EIA3)
- **NAS ciphering** — NEA0 (null), NEA1 (SNOW 3G / 128-EEA1), NEA2 (AES-128-CTR / 128-EEA2), NEA3 (ZUC / 128-EEA3)
- **SUCI concealment** (TS 33.501 Annex C.4) — null scheme, Profile A (X25519 ECIES), Profile B (P-256 ECIES)
- **XRES\* / HXRES\* computation** — for AMF-side 5G-AKA verification
- **5G-GUTI / 5G-S-TMSI** — construction and parsing
- **PLMN encoding** — TBCD encode/decode for MCC/MNC
- **Algorithm selection** — NIA2 > NIA1 > NIA3 (never NIA0); NEA2 > NEA1 > NEA3 > NEA0

All algorithms verified against 3GPP test vectors (TS 35.201, TS 35.215, TS 35.221) and free5GC interop.

## Quick start

```toml
[dependencies]
oxirush-security = "0.1"
```

### Key derivation

```rust
use oxirush_security::*;

// Full 5G key derivation chain per TS 33.501 Annex A
let k_ausf = [0xAA; 32]; // from AUSF via 5G-AKA
let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";

let k_seaf = derive_kseaf(&k_ausf, sn_name);
let k_amf  = derive_kamf(&k_seaf, "208930000000001", &[0x00, 0x00]);

// NAS keys (distinguisher: 0x01=ciphering, 0x02=integrity; algo_id: 1=NIA1/NEA1, 2=NIA2/NEA2, 3=NIA3/NEA3)
let k_nas_int = derive_nas_key(&k_amf, 0x02, 2); // integrity, NIA2
let k_nas_enc = derive_nas_key(&k_amf, 0x01, 2); // ciphering, NEA2

// K_gNB for initial context setup
let k_gnb = derive_kgnb(&k_amf, 0); // UL NAS COUNT = 0

// NH for handover (NCC=1)
let nh = derive_nh(&k_amf, &k_gnb);
```

### NAS integrity and ciphering

```rust
use oxirush_security::*;

let key = [0u8; 16]; // KNASint or KNASenc (128-bit)

// Compute NAS integrity MAC (NIA2 = AES-CMAC)
let mac: u32 = nas_mac(&key, /*count=*/0, /*bearer=*/1, /*direction=*/0, &message, /*algo=*/0x02);

// Cipher/decipher NAS payload in-place (NEA2 = AES-128-CTR)
nas_cipher(&key, /*count=*/0, /*bearer=*/1, /*direction=*/0, &mut payload, /*algo=*/0x02);
```

### SUCI concealment

```rust
use oxirush_security::*;

// Null scheme — MSIN in cleartext BCD
let msin_bcd = msin_to_bcd("0000000001");

// Profile A — X25519 ECIES
let (ephemeral_pub_key, scheme_output) = suci_scheme_output_a(&home_network_pub_key, &msin_bcd);

// Profile B — P-256 ECIES
let (ephemeral_pub_key, scheme_output) = suci_scheme_output_b(&home_network_pub_key, &msin_bcd);
```

## Modules

| Module | Description |
|--------|-------------|
| [`kdf`](src/kdf.rs) | Key derivation functions (HMAC-SHA-256 based) per TS 33.501 Annex A |
| [`nia`](src/nia.rs) | NAS integrity algorithms: NIA1 (SNOW 3G), NIA2 (AES-CMAC), NIA3 (ZUC) |
| [`nea`](src/nea.rs) | NAS ciphering algorithms: NEA0/1/2/3 — all stream ciphers, encrypt = decrypt |
| [`suci`](src/suci.rs) | SUCI concealment: null scheme, Profile A (X25519), Profile B (P-256) |
| [`algo`](src/algo.rs) | Algorithm selection from UE capability bitmask |
| [`guti`](src/guti.rs) | 5G-GUTI and 5G-S-TMSI construction/parsing |
| [`plmn`](src/plmn.rs) | PLMN TBCD encoding/decoding |
| [`snow3g`](src/snow3g.rs) | SNOW 3G stream cipher (TS 35.201/35.202) |
| [`zuc`](src/zuc.rs) | ZUC stream cipher (TS 35.221/35.222) |

## Examples

```bash
cargo run --example key_derivation    # Full KDF chain demo
cargo run --example integrity         # NIA1/NIA2/NIA3 MAC computation
cargo run --example suci_conceal      # SUCI concealment with Profile A
```

## 3GPP references

- **TS 33.501** — 5G security architecture (key derivation, algorithm IDs, SUCI)
- **TS 33.102** — 3G security (Milenage, SQN management)
- **TS 35.201/35.202** — SNOW 3G specification
- **TS 35.215/35.216** — NIA1/NEA1 (SNOW 3G mode of operation)
- **TS 35.221/35.222** — ZUC specification + NIA3/NEA3

### Developer Certificate of Origin (DCO)

By contributing to this project, you agree to the [Developer Certificate of Origin (DCO)](https://developercertificate.org/). This means that you have the right to submit your contributions and you agree to license them according to the project's license.

All commits should be signed-off with `git commit -s` to indicate your agreement to the DCO.

## License

Copyright 2026 Valentin D'Emmanuele

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for details.