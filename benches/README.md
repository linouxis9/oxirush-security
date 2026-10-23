# Benchmarks of oxirush-security

A package of its own, which the published crate does not have. It times the
algorithms, the key derivations and SUCI with
[criterion](https://crates.io/crates/criterion), and profiles them with
[pprof](https://crates.io/crates/pprof).

```sh
cargo bench --bench algorithms                # every benchmark of one message
cargo bench --bench algorithms -- 128-EEA2    # those whose name has it
cargo bench --bench batch -- 16x64            # sixteen messages of 64 octets
cargo bench --bench milenage                  # MILENAGE, beside the milenage crate
cargo bench --bench version_0_2               # the algorithms of 0.2.0, from crates.io

# Ten seconds of one benchmark under the profiler, then where the time went
cargo bench --bench algorithms -- --profile-time 10 cipher/128-EEA1/1500
go tool pprof -top target/criterion/cipher/128-EEA1/1500/profile/profile.pb
```

The profile is one that Go's `pprof` reads. With `PROFILE=flamegraph` in
the environment it is `flamegraph.svg`, in the same directory.

## Figures

The time of one call, on core 2 of an AMD Ryzen 7 5700G (16 threads,
Linux 7.0) with Rust 1.98.1, as a program has the crate: with the clearing
of the stack and of the registers that follows each operation. Each
figure is the lowest of five runs of its benchmark at 472c9e1 on
2026-10-18, on a machine that ran nothing else (a load average of 0.79 to
1.31 with the benchmark's own), and each configuration is one build, whose
binaries ran all five times. The figures of 0.2.0 are those of `version_0_2`, the same
benchmarks on that version, built with the others.

The first two columns are what this processor runs, which has the vector
and AES instructions. The next two are the code that a processor without
them runs:

```sh
RUSTFLAGS="--cfg oxirush_security_hooks" FORM=scalar cargo bench --bench algorithms
```

| | 64 octets | 1,500 octets | scalar code, 64 | scalar code, 1,500 | 0.2.0, 64 | 0.2.0, 1,500 |
|---|---|---|---|---|---|---|
| 128-EEA1, 128-NEA1 (SNOW 3G) | 0.33 µs | 2.2 µs | 2.0 µs | 16.4 µs | 0.50 µs | 4.8 µs |
| 128-EEA2, 128-NEA2 (AES-CTR) | 0.051 µs | 0.18 µs | 0.22 µs | 0.69 µs | 0.15 µs | 2.7 µs |
| 128-EEA3, 128-NEA3 (ZUC) | 0.44 µs | 3.1 µs | 1.3 µs | 10.7 µs | 0.60 µs | 5.2 µs |
| 128-EIA1, 128-NIA1 (SNOW 3G) | 0.29 µs | 0.39 µs | 1.7 µs | 4.3 µs | 0.75 µs | 8.3 µs |
| 128-EIA2, 128-NIA2 (AES-CMAC) | 0.12 µs | 0.94 µs | 0.28 µs | 1.8 µs | 0.24 µs | 2.8 µs |
| 128-EIA3, 128-NIA3 (ZUC) | 0.48 µs | 3.4 µs | 1.5 µs | 13.4 µs | 0.98 µs | 13.5 µs |

On the vector instructions SNOW 3G and ZUC are 1.4 to 2.2 times as fast as
in 0.2.0 for ciphering, and 2 to 21 times for the MACs. 0.2.0 read its
S-boxes from tables, at indices taken from the state of the generator. No
memory access depends on a secret here, in either form, and the scalar
code pays for it: the S-box SQ of SNOW 3G, which it reads whole, is most
of its time. Its MACs are as fast as those of 0.2.0 on a long message,
because their multiplications are carry-less products. On the carry-less
multiplication instruction, 128-EIA1 evaluates its polynomial four blocks
at a time, with the powers of P, and 128-EIA3 takes four groups of 32 bits
at a time.

A SNOW 3G that reads its S-boxes at indices taken from its state can be
faster on a short message. The S-box SQ is the difference: this crate reads
it through sixteen shuffles and four choices for each three clocks, so that
no address depends on the state, and a message of 64 octets is 49 clocks,
33 of them its initialization. The README compares 1,500 octets with
Open5GS's.

AES is the crate's own key expansion and rounds on the AES instruction:
eight counter blocks at a time for 128-EEA2, and a block after the other
for 128-EIA2. Without the instructions of the first two columns AES is the
`aes` crate, whose time is in the scalar columns: on this processor that
crate finds the AES instruction itself, and its bitsliced code, which a
processor without the instruction runs, was not measured. The counter mode
gives `aes` eight counter blocks one after the other there, and not
together.

A key derivation, one HMAC-SHA-256, takes 0.22 µs, and 0.16 µs in 0.2.0,
whose HMAC did not wipe its state. SUCI deconcealment takes 43 µs with
Profile A and 142 µs with Profile B; the README has the time of
concealment.

## A key kept between messages

`cipher-context` and `mac-context` time a `CipheringContext` and an
`IntegrityContext`, which keep the round keys of AES and the subkeys of
CMAC from one message to the next. The time of one call, in nanoseconds:

| | 64 octets, from a key | 64 octets, with a context | 1,500 octets, from a key | 1,500 octets, with a context |
|---|---|---|---|---|
| 128-EEA2 | 51 | 28 | 178 | 158 |
| 128-EIA2 | 116 | 79 | 937 | 899 |

A context of SNOW 3G or ZUC has nothing to keep but the key, and takes the
time of the function.

## What the clearing costs

After each operation the crate sets to zero the stack that the work used
and the registers. `RUSTFLAGS="--cfg oxirush_security_unwiped"` builds the
crate without it, and the benchmarks with it:

```sh
cargo bench --bench algorithms
RUSTFLAGS="--cfg oxirush_security_unwiped" cargo bench --bench algorithms
```

The time of one call on 64 octets in nanoseconds, without the clearing and
with it:

| | Without | With |
|---|---|---|
| 128-EEA2 with a keyed context | 12.1 | 28.2 |
| 128-EEA2 from a key | 33.0 | 50.8 |
| 128-EIA2 with a keyed context | 66.0 | 79.2 |
| 128-EIA2 from a key | 98.7 | 116 |
| 128-EEA1 | 302 | 331 |
| 128-EEA3 | 407 | 437 |
| 128-EIA1 | 260 | 294 |
| 128-EIA3 | 446 | 476 |

The clearing does not grow with the message: it adds 13 to 34 ns to a
message of 64 octets, and 15 to 32 ns to one of 1500. A derivation takes
193 to 198 ns without the clearing and 221 to 227 ns with it; SUCI changes
by 0.6 % at most, which is within what its runs differ by (1.5 %).

Sixteen messages of 64 octets in one call:

| | Without | With |
|---|---|---|
| 128-EEA1 | 1,637 | 1,774 |
| 128-EEA2 from keys | 599 | 605 |
| 128-EEA2 with keyed contexts | 245 | 262 |
| 128-EIA1 | 1,962 | 2,119 |
| 128-EIA2 from keys | 900 | 1,029 |
| 128-EIA2 with keyed contexts | 696 | 825 |
| 128-EIA3 | 2,509 | 2,654 |

A batch of SNOW 3G, ZUC or 128-EIA2 pays 129 to 157 ns for the clearing, 5
to 16 % of its time, once for its sixteen messages. 128-EEA2 from keys
changes by 0.9 %, less than its runs differ by (1.9 %); with keyed
contexts it pays 18 ns.

The cost is that of the stores: 1,792 octets after AES with a keyed
context, 2,304 after AES from a key, 4,096 after a message of SNOW 3G or ZUC
and after a derivation, 18,432 after each algorithm of a batch that runs
side by side. Each figure is twice what the deepest work of its kind uses.
On 64 octets the clearing is 6 to 12 % of SNOW 3G and of ZUC, 15 % of
128-EIA2, and it more than doubles 128-EEA2 with a keyed context, which a
batch avoids: sixteen such messages take 462 ns one by one and 262 ns in
one call.

## Several messages in one call

`batch` times N messages, each with its own key and COUNT: `single` is a
call of `nea_cipher` or `nia_mac` for each, and `batch` one call of
`nea_cipher_batch` or `nia_mac_batch` for all; `single-context` and
`batch-context` do the same with a keyed context for each message. The
times are for the N messages.

64 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 1.3 µs | 0.76 µs | 2.6 µs | 1.0 µs | 5.3 µs | 1.8 µs |
| 128-EEA2 | 0.20 µs | 0.17 µs | 0.41 µs | 0.31 µs | 0.82 µs | 0.60 µs |
| 128-EEA3 | 1.8 µs | 0.89 µs | 3.5 µs | 1.2 µs | 7.0 µs | 2.1 µs |
| 128-EIA1 | 1.2 µs | 0.78 µs | 2.3 µs | 1.2 µs | 4.7 µs | 2.1 µs |
| 128-EIA2 | 0.46 µs | 0.37 µs | 0.93 µs | 0.58 µs | 1.9 µs | 1.0 µs |
| 128-EIA3 | 1.9 µs | 1.0 µs | 3.8 µs | 1.4 µs | 7.6 µs | 2.7 µs |

1,500 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 8.7 µs | 4.1 µs | 17.4 µs | 5.1 µs | 34.8 µs | 10.0 µs |
| 128-EEA2 | 0.72 µs | 0.68 µs | 1.4 µs | 1.3 µs | 2.9 µs | 2.7 µs |
| 128-EEA3 | 12.3 µs | 5.5 µs | 24.7 µs | 6.6 µs | 49.4 µs | 13.2 µs |
| 128-EIA1 | 1.5 µs | 1.2 µs | 3.1 µs | 1.9 µs | 6.2 µs | 3.7 µs |
| 128-EIA2 | 3.7 µs | 1.2 µs | 7.5 µs | 2.1 µs | 15.0 µs | 4.0 µs |
| 128-EIA3 | 13.6 µs | 6.7 µs | 27.2 µs | 9.2 µs | 54.4 µs | 18.2 µs |

Four messages have four SNOW 3G or ZUC generators in the words of a
128-bit vector: ciphering is 1.7 to 2.2 times as fast as one message after
the other. From five messages on, this processor has eight generators in a
256-bit vector (AVX2), and ciphering is 2.6 to 3.8 times as fast. The MACs
of SNOW 3G and of ZUC gain 1.3 to 3.0 times: their keystream comes from
the generators side by side, and the evaluation of 128-EIA1 and the sums
of 128-EIA3 stay one message after the other. 128-EIA2 gains 1.2 to
3.7 times from CBC-MAC chains that advance together, eight at most.

128-EEA2 has nothing to run side by side: its counter blocks are
encrypted eight at a time for one message already. Its batch saves the
clearing, which follows the batch and not each message.

Not built, and not measured: sixteen generators in an AVX-512 vector, with
the S-box SQ of SNOW 3G read by permutations of 64 octets where AVX-512
VBMI is; the S-box S1 of ZUC as GFNI instructions, in place of the AES
instruction and the shuffles around it; and AES on VAES, two or four blocks
to an instruction.

## MILENAGE

`milenage` times MILENAGE for one subscriber, from its K and its OPc at
each call, beside the [`milenage`](https://crates.io/crates/milenage) crate
0.1.6, whose AES is that of the `aes` crate 0.8 and finds the AES
instructions itself. The time of one call in nanoseconds:

| | This crate | Without the clearing | `milenage` 0.1.6 | This crate, `aes` crate | This crate, bitsliced AES | `milenage` 0.1.6, bitsliced AES |
|---|---:|---:|---:|---:|---:|---:|
| OPc from OP | 74 | 56 | 53 | 202 | 777 | 582 |
| f1 | 89 | 69 | 88 | 221 | 1,041 | 1,153 |
| f2345 | 114 | 94 | 185 | 248 | 1,063 | 2,323 |
| An authentication vector | 117 | 99 | 276 | 249 | 1,070 | 3,476 |
| The check of an AUTN | 149 | 135 |  | 276 | 1,343 |  |
| An AUTS | 97 | 79 | 168 | 231 | 1,052 | 2,310 |
| The reading of an AUTS | 119 | 117 |  | 256 | 1,314 |  |

The first three columns run on the AES instructions. The fourth is the
code of a processor without the instructions of the vector code, with the
hooks of the crate and `FORM=scalar`: the `aes` crate 0.9, which finds AES-NI
itself here. The last two are this crate and the `milenage` crate with the
bitsliced AES of their `aes` crates, built with
`--cfg aes_backend="soft" --cfg aes_force_soft`. The `milenage` crate has
no function for the vector, the AUTS or their checks: the benchmark builds
the first two from its functions as its users do.

A vector is the key expansion, TEMP, then OUT1 to OUT4 side by side; the
`milenage` crate expands the key for each of its five encryptions. The
`milenage` crate is faster for OPc, 53 ns against 74, by about what the
clearing costs: this crate takes 56 without it. For f1 the two take about
the same, 88 ns and 89, and this crate 69 without the clearing. On the
`aes` crate 0.9 this crate pays the clearing and the wiping of the 704
octets of a key of that crate, which the `milenage` crate does not wipe.
With the bitsliced AES the encryptions of one key run four at a time.

`milenage/N/function/form` times N subscribers, each with its K: a call for
each, or one call of `authentication_vector_batch` or `check_autn_batch`.
The time for the N, in microseconds:

| | 1 | 4 | 8 | 64 | 1,024 |
|---|---:|---:|---:|---:|---:|
| Vectors, a call for each | 0.113 | 0.45 | 0.90 | 7.2 | 116 |
| Vectors, one batch | 0.27 | 0.43 | 0.62 | 4.0 | 61 |
| Checks of an AUTN, a call for each | 0.138 | 0.55 | 1.10 | 8.8 | 141 |
| Checks of an AUTN, one batch | 0.29 | 0.49 | 0.76 | 5.1 | 78 |

A batch runs the key expansions and the encryptions of eight subscribers
side by side, and clears the stack once over 18,432 octets, which takes
longer than a vector: for one or two subscribers, a call for each is
faster. On the `aes` crate a batch of a thousand vectors takes 198 µs,
where a call for each takes 249 µs: the jobs run one after the other, and
the stack is cleared once.

## Against other implementations

The same inputs to each, a call for each operation, on core 2 of the
machine above (Go 1.27), at 9dc28da. Times are the lowest of three runs, and
each figure the median of three runs of the script; cycles and instructions are
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
