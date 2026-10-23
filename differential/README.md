# MILENAGE beside three other implementations

```sh
git clone --depth 1 --branch v2.8.0 https://github.com/open5gs/open5gs ../../open5gs
(cd free5gc && go build -o ../target/free5gc-milenage .)
OPEN5GS=../../open5gs FREE5GC=target/free5gc-milenage cargo run --release -- 1000000
```

```text
1000000 random subscribers of seed 11400714819323198485:
  milenage 0.1.6: 8000000 values compared, 0 cases differ
  Open5GS: 13000000 values compared, 0 cases differ
  free5GC: 14000000 values compared, 0 cases differ
```

Each case draws K, OP, RAND, SQN, AMF and SQNMS. oxirush-security computes
OPc, an authentication vector, the check of its AUTN by a USIM, an AUTS and
its reading by the home network, RES\*, and the refusal of the AUTN and of
the AUTS with one bit changed. Each other implementation computes what it
has of these with its own functions:

| Implementation | Revision | Functions |
|----------------|----------|-----------|
| [`milenage`](https://crates.io/crates/milenage) | 0.1.6 | `Milenage::new_with_op`, `f1`, `f1star`, `f2345`, `f5star`, `compute_res_star` |
| Open5GS, `lib/crypt/milenage.c` | v2.8.0 | `milenage_opc`, `milenage_generate`, `milenage_check`, `milenage_f1`, `milenage_f2345`, `milenage_auts` |
| free5GC, `github.com/free5gc/util/milenage` | util v1.3.2, that of free5GC v4.2.3 | `GenerateOPc`, `GenerateAKAParameters`, `GenerateKeysWithAUTN`, `GenerateAUTS`, `ValidateAUTS` |

`OPEN5GS` names a source tree of Open5GS when the program is built: its
`build.rs` compiles `milenage.c` and `ogs-aes.c` from there beside
[`open5gs/ogs-crypt.h`](open5gs/ogs-crypt.h), which stands for the rest of
Open5GS. `FREE5GC` names the program of [`free5gc/`](free5gc) when it runs.
The run fails when a value differs, or when one of the two is missing and
`--without open5gs` or `--without free5gc` does not say so. A case that
differs is printed by its number and the seed (`--seed`), not by its keys.

This package is a test tool: it is not published, and the crate depends on
none of these implementations. CI runs it on a million subscribers.
