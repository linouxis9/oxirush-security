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

The time of one call, on one core of an AMD Ryzen 7 5700G with Rust 1.98.1.
Each is the lowest median of four runs of the benchmark, and of two for the
scalar code and for 0.2.0, on a core that was idle, as its hyper-thread was;
other cores of the machine did other work in some of the runs.

The first two columns are what this processor runs, which has the vector
and AES instructions. The next two are the code that a processor without
them runs, and the last two 0.2.0 in the same benchmark.

| | 64 octets | 1500 octets | scalar code, 64 | scalar code, 1500 | 0.2.0, 64 | 0.2.0, 1500 |
|---|---|---|---|---|---|---|
| 128-EEA1, 128-NEA1 (SNOW 3G) | 0.34 µs | 2.5 µs | 2.0 µs | 16.8 µs | 0.53 µs | 5.1 µs |
| 128-EEA2, 128-NEA2 (AES-CTR) | 0.034 µs | 0.17 µs | 0.15 µs | 0.64 µs | 0.15 µs | 2.8 µs |
| 128-EEA3, 128-NEA3 (ZUC) | 0.41 µs | 3.2 µs | 1.4 µs | 11.7 µs | 0.61 µs | 5.2 µs |
| 128-EIA1, 128-NIA1 (SNOW 3G) | 0.30 µs | 0.40 µs | 1.7 µs | 4.6 µs | 0.75 µs | 8.4 µs |
| 128-EIA2, 128-NIA2 (AES-CMAC) | 0.10 µs | 0.94 µs | 0.20 µs | 1.8 µs | 0.24 µs | 2.8 µs |
| 128-EIA3, 128-NIA3 (ZUC) | 0.45 µs | 3.4 µs | 1.6 µs | 14.1 µs | 0.99 µs | 13.8 µs |

On the vector instructions SNOW 3G and ZUC are 1.5 to 2 times as fast as
in 0.2.0 for ciphering, and 2 to 21 times for the MACs. 0.2.0 read its
S-boxes from tables, at indices taken from the state of the generator. No
memory access depends on a secret here, in either form, and the scalar
code pays for it: the S-box SQ of SNOW 3G, which it reads whole, is most of
its time. Its MACs are as fast as those of 0.2.0 on a long message,
because their multiplications are carry-less products. On the carry-less
multiplication instruction, 128-EIA1 evaluates its polynomial four blocks
at a time, with the powers of P, and 128-EIA3 takes four groups of 32 bits
at a time.

AES is the crate's own key expansion and rounds on the AES instruction:
eight counter blocks at a time for 128-EEA2, and a block after the other
for 128-EIA2. Without the instructions of the first two columns AES is the
`aes` crate, whose time is in the scalar columns: on this processor that
crate finds the AES instruction itself, and its bitsliced code, which a
processor without the instruction runs, was not measured.

A key derivation, one HMAC-SHA-256, takes 0.22 µs, and 0.16 µs in 0.2.0,
whose HMAC did not wipe its state. SUCI concealment takes 55 µs with
Profile A and 284 µs with Profile B, and deconcealment 43 µs and 147 µs.

## What the clearing costs

After each operation the crate sets to zero the stack that the work used
and the registers. `RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the
crate without it, and the benchmarks with it:

```bash
cargo bench --bench algorithms
RUSTFLAGS="--cfg oxirush_security_unwiped" cargo bench --bench algorithms
```

The time of one call in nanoseconds, without the clearing and with it, on
the same processor: the lowest median of two runs with it and of four
without, while other cores of the machine did other work. The figures of
the other sections are without it.

| | 64 octets | 1500 octets |
|---|---|---|
| 128-EEA2 with a keyed context | 12.7, 26.4 | 152, 164 |
| 128-EEA2 from a key | 35.4, 52.8 | 172, 189 |
| 128-EIA2 with a keyed context | 68.7, 80.2 | 905, 948 |
| 128-EIA2 from a key | 105, 126 | 974, 996 |
| 128-EEA1 | 352, 383 | 2584, 2645 |
| 128-EEA3 | 421, 460 | 3222, 3275 |
| 128-EIA1 | 303, 336 | 407, 439 |
| 128-EIA3 | 466, 498 | 3570, 3614 |

A derivation takes 205 to 246 ns without the clearing and 233 to 244 ns
with it; SUCI changes by less than the runs differ.

Sixteen messages of 64 octets in one call:

| | Without | With |
|---|---|---|
| 128-EEA1 | 1911 | 2078 |
| 128-EEA2 from keys | 647 | 649 |
| 128-EEA2 with keyed contexts | 265 | 290 |
| 128-EEA3 | 2163 | 2375 |
| 128-EIA1 | 2166 | 2355 |
| 128-EIA2 from keys | 940 | 1078 |
| 128-EIA2 with keyed contexts | 735 | 846 |
| 128-EIA3 | 2617 | 2853 |

The cost is that of the stores: 1280 octets after AES with a keyed
context, 2048 after AES from a key, 4096 after a message of SNOW 3G or ZUC
and after a derivation, 16384 after each algorithm of a batch that runs
side by side. It does not grow with the message. On 64 octets it is 5 to
12 % of SNOW 3G and of ZUC, 17 to 20 % of 128-EIA2, and it doubles
128-EEA2 with a keyed context, which a batch avoids: sixteen such messages
take 427 ns one by one and 290 ns in one call.

## Several messages in one call

`batch` times N messages, each with its own key and COUNT: `single` is a
call of `nea_cipher` or `nia_mac` for each, and `batch` one call of
`nea_cipher_batch` or `nia_mac_batch` for all. The times are for the N
messages, on the same processor: the lowest median of three runs, on a
core that was idle with its hyper-thread while other cores of the machine
did other work.

64 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 1.3 µs | 0.71 µs | 2.8 µs | 0.97 µs | 5.7 µs | 1.8 µs |
| 128-EEA2 | 0.13 µs | 0.15 µs | 0.27 µs | 0.30 µs | 0.57 µs | 0.61 µs |
| 128-EEA3 | 1.6 µs | 0.76 µs | 3.4 µs | 1.1 µs | 6.7 µs | 2.1 µs |
| 128-EIA1 | 1.2 µs | 0.74 µs | 2.4 µs | 1.2 µs | 4.9 µs | 2.2 µs |
| 128-EIA2 | 0.41 µs | 0.26 µs | 0.83 µs | 0.47 µs | 1.7 µs | 0.92 µs |
| 128-EIA3 | 1.8 µs | 0.95 µs | 3.7 µs | 1.3 µs | 7.5 µs | 2.7 µs |

1500 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 10.0 µs | 4.7 µs | 20.6 µs | 5.8 µs | 41.3 µs | 11.5 µs |
| 128-EEA2 | 0.67 µs | 0.69 µs | 1.4 µs | 1.4 µs | 2.8 µs | 2.8 µs |
| 128-EEA3 | 12.7 µs | 5.6 µs | 25.2 µs | 7.0 µs | 51.4 µs | 13.6 µs |
| 128-EIA1 | 1.6 µs | 1.1 µs | 3.2 µs | 2.0 µs | 6.5 µs | 3.9 µs |
| 128-EIA2 | 3.8 µs | 1.2 µs | 7.7 µs | 2.0 µs | 15.3 µs | 4.0 µs |
| 128-EIA3 | 13.9 µs | 6.8 µs | 28.5 µs | 9.5 µs | 56.9 µs | 18.5 µs |

Four messages have four SNOW 3G or ZUC generators in the words of a
128-bit vector: ciphering is 1.9 to 2.3 times as fast as one message after
the other. From five messages on, this processor has eight generators in
a 256-bit vector (AVX2), and ciphering is 2.8 to 3.8 times as fast. The
MACs of SNOW 3G and of ZUC gain 1.4 to 3.1 times: their keystream comes
from the generators side by side, and the evaluation of 128-EIA1 and the
sums of 128-EIA3 stay one message after the other. 128-EIA2 gains 1.6 to
3.8 times from CBC-MAC chains that advance together, eight at most.

128-EEA2 gains nothing. Its counter blocks are encrypted eight at a time
for one message already, so the batch function calls the function of one
message, and a job costs about 4 ns more than the call.

Not built, and not measured: sixteen generators in an AVX-512 vector, with
the S-box SQ of SNOW 3G read by permutations of 64 octets where AVX-512
VBMI is; the S-box S1 of ZUC as GFNI instructions, in place of the AES
instruction and the shuffles around it; and AES on VAES, two or four blocks
to an instruction.
