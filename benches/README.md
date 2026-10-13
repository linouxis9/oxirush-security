# Benchmarks of oxirush-security

A package of its own, which the published crate does not have. It times the
algorithms, the key derivations and SUCI with
[criterion](https://crates.io/crates/criterion), and profiles them with
[pprof](https://crates.io/crates/pprof).

```bash
cargo bench --bench algorithms                # every benchmark of one message
cargo bench --bench algorithms -- 128-EEA2    # those whose name has it
cargo bench --bench batch -- 16x64            # sixteen messages of 64 octets

# Ten seconds of one benchmark under the profiler, then where the time went
cargo bench --bench algorithms -- --profile-time 10 cipher/128-EEA1/1500
go tool pprof -top target/criterion/cipher/128-EEA1/1500/profile/profile.pb
```

The profile is one that Go's `pprof` reads. With `PROFILE=flamegraph` in
the environment it is `flamegraph.svg`, in the same directory.

## Figures

The time of one call, on one core of an AMD Ryzen 7 5700G with Rust 1.98.1,
as a program has the crate: with the clearing of the stack and of the
registers that follows each operation. Each is the lowest median of two to
four runs of the benchmark on a core that was idle, as its hyper-thread
was, while other cores of the machine did other work. The figures of 0.2.0
are those of the same benchmark on that version.

The first two columns are what this processor runs, which has the vector
and AES instructions. The next two are the code that a processor without
them runs:

```bash
RUSTFLAGS="--cfg oxirush_security_hooks" FORM=scalar cargo bench --bench algorithms
```

| | 64 octets | 1500 octets | scalar code, 64 | scalar code, 1500 | 0.2.0, 64 | 0.2.0, 1500 |
|---|---|---|---|---|---|---|
| 128-EEA1, 128-NEA1 (SNOW 3G) | 0.35 µs | 2.3 µs | 2.1 µs | 17.2 µs | 0.53 µs | 5.1 µs |
| 128-EEA2, 128-NEA2 (AES-CTR) | 0.052 µs | 0.19 µs | 0.23 µs | 0.75 µs | 0.15 µs | 2.8 µs |
| 128-EEA3, 128-NEA3 (ZUC) | 0.46 µs | 3.2 µs | 1.4 µs | 11.4 µs | 0.61 µs | 5.2 µs |
| 128-EIA1, 128-NIA1 (SNOW 3G) | 0.31 µs | 0.41 µs | 1.8 µs | 4.5 µs | 0.75 µs | 8.4 µs |
| 128-EIA2, 128-NIA2 (AES-CMAC) | 0.12 µs | 0.98 µs | 0.31 µs | 1.9 µs | 0.24 µs | 2.8 µs |
| 128-EIA3, 128-NIA3 (ZUC) | 0.50 µs | 3.6 µs | 1.6 µs | 14.3 µs | 0.99 µs | 13.8 µs |

On the vector instructions SNOW 3G and ZUC are 1.3 to 2.2 times as fast as
in 0.2.0 for ciphering, and 2 to 20 times for the MACs. 0.2.0 read its
S-boxes from tables, at indices taken from the state of the generator. No
memory access depends on a secret here, in either form, and the scalar
code pays for it: the S-box SQ of SNOW 3G, which it reads whole, is most of
its time. Its MACs are as fast as those of 0.2.0 on a long message,
because their multiplications are carry-less products. On the carry-less
multiplication instruction, 128-EIA1 evaluates its polynomial four blocks
at a time, with the powers of P, and 128-EIA3 takes four groups of 32 bits
at a time.

A SNOW 3G that reads its S-boxes at indices taken from its state can be
faster on one short message: Open5GS's took 230 ns for 64 octets of
128-EEA1 on this processor, measured once with a harness that is not in
the repository. The difference is the S-box SQ, which this crate reads
through sixteen shuffles and four choices for each three clocks, so that
no address depends on the state, and a message of 64 octets is 49 clocks,
33 of them its initialization. On 1500 octets the two are within a tenth.

AES is the crate's own key expansion and rounds on the AES instruction:
eight counter blocks at a time for 128-EEA2, and a block after the other
for 128-EIA2. Without the instructions of the first two columns AES is the
`aes` crate, whose time is in the scalar columns: on this processor that
crate finds the AES instruction itself, and its bitsliced code, which a
processor without the instruction runs, was not measured. The counter mode
gives `aes` eight counter blocks one after the other there, and not
together: its code for several blocks follows the processor, up to 64 on
AVX-512F with a frame for as many, and 128-EEA2 took 0.19 µs and 0.61 µs
with it.

A key derivation, one HMAC-SHA-256, takes 0.24 µs, and 0.16 µs in 0.2.0,
whose HMAC did not wipe its state. SUCI concealment takes 59 µs with
Profile A and 286 µs with Profile B, and deconcealment 45 µs and 151 µs.

## A key kept between messages

`cipher-context` and `mac-context` time a `CipheringContext` and an
`IntegrityContext`, which keep the round keys of AES and the subkeys of
CMAC from one message to the next. The time of one call, in nanoseconds:

| | 64 octets, from a key | 64 octets, with a context | 1500 octets, from a key | 1500 octets, with a context |
|---|---|---|---|---|
| 128-EEA2 | 52 | 29 | 183 | 160 |
| 128-EIA2 | 117 | 81 | 937 | 928 |

A context of SNOW 3G or ZUC has nothing to keep but the key, and takes the
time of the function.

## What the clearing costs

After each operation the crate sets to zero the stack that the work used
and the registers. `RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the
crate without it, and the benchmarks with it:

```bash
cargo bench --bench algorithms
RUSTFLAGS="--cfg oxirush_security_unwiped" cargo bench --bench algorithms
```

The time of one call on 64 octets in nanoseconds, without the clearing and
with it, on the same processor: the lowest median of three runs or more of
each.

| | Without | With |
|---|---|---|
| 128-EEA2 with a keyed context | 12.7 | 28.7 |
| 128-EEA2 from a key | 34.3 | 52.3 |
| 128-EIA2 with a keyed context | 68.7 | 80.6 |
| 128-EIA2 from a key | 105 | 117 |
| 128-EEA1 | 320 | 349 |
| 128-EEA3 | 430 | 460 |
| 128-EIA1 | 276 | 309 |
| 128-EIA3 | 471 | 504 |

The clearing does not grow with the message: on 1500 octets it is the same
10 to 33 ns, which is less than the 3 % by which two runs of one benchmark
differ on this machine. A derivation takes 204 to 208 ns without the
clearing and 235 to 241 ns with it; SUCI changes by less than the runs
differ.

Sixteen messages of 64 octets in one call:

| | Without | With |
|---|---|---|
| 128-EEA1 | 1752 | 1871 |
| 128-EEA2 from keys | 631 | 633 |
| 128-EEA2 with keyed contexts | 256 | 276 |
| 128-EIA1 | 2094 | 2070 |
| 128-EIA2 from keys | 940 | 1077 |
| 128-EIA2 with keyed contexts | 727 | 836 |
| 128-EIA3 | 2617 | 2780 |

Two runs of a batch differ by up to 5 % here, under the load of the other
work of the machine: that is more than the clearing for SNOW 3G and ZUC,
and 128-EIA1 came out lower with it than without.

The cost is that of the stores: 1792 octets after AES with a keyed
context, 2304 after AES from a key, 4096 after a message of SNOW 3G or ZUC
and after a derivation, 18432 after each algorithm of a batch that runs
side by side. Each figure is twice what the deepest work of its kind uses.
On 64 octets the clearing is 7 to 12 % of SNOW 3G and of ZUC, 11 % of
128-EIA2, and it more than doubles 128-EEA2 with a keyed context, which a
batch avoids: sixteen such messages take 478 ns one by one and 276 ns in
one call.

## Several messages in one call

`batch` times N messages, each with its own key and COUNT: `single` is a
call of `nea_cipher` or `nia_mac` for each, and `batch` one call of
`nea_cipher_batch` or `nia_mac_batch` for all; `single-context` and
`batch-context` do the same with a keyed context for each message. The
times are for the N messages, on the same processor: the lowest median of
two runs, on a core that was idle with its hyper-thread while other cores
of the machine did other work.

64 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 1.4 µs | 0.78 µs | 2.8 µs | 1.1 µs | 5.6 µs | 1.8 µs |
| 128-EEA2 | 0.21 µs | 0.17 µs | 0.42 µs | 0.33 µs | 0.85 µs | 0.64 µs |
| 128-EEA3 | 1.8 µs | 0.93 µs | 3.7 µs | 1.2 µs | 7.4 µs | 2.2 µs |
| 128-EIA1 | 1.2 µs | 0.82 µs | 2.4 µs | 1.2 µs | 4.9 µs | 2.2 µs |
| 128-EIA2 | 0.48 µs | 0.38 µs | 0.94 µs | 0.60 µs | 1.9 µs | 1.1 µs |
| 128-EIA3 | 2.0 µs | 1.1 µs | 3.9 µs | 1.5 µs | 7.8 µs | 2.8 µs |

1500 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 9.2 µs | 4.4 µs | 18.5 µs | 5.4 µs | 36.9 µs | 10.4 µs |
| 128-EEA2 | 0.74 µs | 0.71 µs | 1.5 µs | 1.4 µs | 3.0 µs | 2.8 µs |
| 128-EEA3 | 13.1 µs | 5.8 µs | 26.1 µs | 7.0 µs | 51.6 µs | 13.9 µs |
| 128-EIA1 | 1.6 µs | 1.2 µs | 3.2 µs | 2.0 µs | 6.6 µs | 3.8 µs |
| 128-EIA2 | 3.9 µs | 1.3 µs | 7.5 µs | 2.1 µs | 15.6 µs | 4.2 µs |
| 128-EIA3 | 14.1 µs | 7.0 µs | 28.3 µs | 9.8 µs | 57.8 µs | 19.3 µs |

Four messages have four SNOW 3G or ZUC generators in the words of a
128-bit vector: ciphering is 1.8 to 2.3 times as fast as one message after
the other. From five messages on, this processor has eight generators in
a 256-bit vector (AVX2), and ciphering is 2.5 to 3.7 times as fast. The
MACs of SNOW 3G and of ZUC gain 1.3 to 3.0 times: their keystream comes
from the generators side by side, and the evaluation of 128-EIA1 and the
sums of 128-EIA3 stay one message after the other. 128-EIA2 gains 1.3 to
3.7 times from CBC-MAC chains that advance together, eight at most.

128-EEA2 has nothing to run side by side: its counter blocks are
encrypted eight at a time for one message already. Its batch saves the
clearing, which follows the batch and not each message.

Not built, and not measured: sixteen generators in an AVX-512 vector, with
the S-box SQ of SNOW 3G read by permutations of 64 octets where AVX-512
VBMI is; the S-box S1 of ZUC as GFNI instructions, in place of the AES
instruction and the shuffles around it; and AES on VAES, two or four blocks
to an instruction.
