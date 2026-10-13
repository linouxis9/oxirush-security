# The AArch64 code on an emulated processor

```bash
rustup target add aarch64-unknown-none
./run.sh
```

`run.sh` builds the crate and [`workload.rs`](workload.rs) as a program
for a bare AArch64 processor: `aarch64-unknown-none`, without the standard
library, with NEON and the AES instructions enabled by the build. It then
runs the program on the `max` processor of
[Unicorn](https://www.unicorn-engine.org), which the `unicorn-engine` crate
builds from its source with cmake, a C compiler and libclang.

For each case of the workload the host calls the program twice, for its
vector code and for its scalar code, and computes the case on the processor
that it runs on itself. The three must give the same:

| Case | What it reaches |
|---|---|
| Known answers | The six algorithms on a 3GPP test set each |
| SNOW 3G and ZUC keystream, 200 keys each | The generators of one message, in pieces of every length |
| Ciphering at 170 lengths, in octets and in bits | 128-EEA1, 128-EEA3, and the key expansion and counter mode of AES |
| Integrity at 170 lengths, in octets and in bits | The carry-less products of 128-EIA1 and 128-EIA3, and the CBC-MAC of AES |
| Batches of 1 to 9 messages | Four generators side by side, and one to eight CBC-MAC chains |
| Keyed contexts at 170 lengths, alone and in batches | The counter mode and the CBC-MAC of AES with the round keys and the subkeys of a context |

The program must also say that its vector code is the one that runs:
`Implementation::Vector128` from the instructions that the build enables,
and `Scalar` once they are turned off.

The host then looks at what 22 operations of [`leftovers.rs`](leftovers.rs)
leave on the emulated processor, in the vector code and in the scalar code:
the algorithms on one message, the keyed contexts, the batches, the
generators, a derivation and a comparison. It paints the stack of the
program, runs an operation, and reads the stack and X0 to X17 and V0 to V31
when it has returned. As [`leftovers/`](../leftovers) does on x86-64, it
runs each operation without the clearing that follows its work, to measure
how deep the work goes, and then as a program has it:

```text
operation                                                          form  depth  cleared  areas
nea_cipher 128-EEA2, 64 octets                              vector code   1088     2304      1   nothing left (8 without the clearing)
nia_mac_batch of 128-EIA2, 8 x 300 octets, from contexts    vector code   8304    18432      1   nothing left
```

The run fails when a key, a round key, a subkey of CMAC, keystream or a
value of HMAC is on the stack or in a register, when an area that the crate
cleared is not zero, when a vector register is not zero, or when the work
used more than three quarters of what is cleared. SUCI is not in the
program, which has no allocator.

An emulator is not a processor of silicon: the AArch64 job of CI runs the
tests of the crate on one. Unicorn is under the GNU GPL, version 2. This
package is a test tool, is not published, and nothing of the crate depends
on it.
