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

The time of one call, on core 2 of an Intel Xeon E5-2680 v4 (Broadwell,
2.4 GHz; a KVM guest of 56 vCPUs, bound to NUMA node 0; Linux 7.0) with
Rust 1.100.0, as a program has the crate: with the clearing of the stack
and of the registers that follows each operation. Each figure is the
median of ten runs of its benchmark at 39b3491 on 2026-11-15, a run being
the median of criterion's samples; each configuration is one build, and
the binaries of the configurations ran in turns, ten rounds. The ten runs
of 181 of the 261 figures were within 5 % of each other (3.7 % for the
median figure); a few batches had one slow run, up to 59 % (sixteen
messages of 1,500 octets of 128-EIA3). The guest lost 0.02 % of the time
of its core to the host, and does not see its CPU frequency. The figures of
0.2.0 are those of `version_0_2`, the same benchmarks on that version,
built with the others.

The first two columns are what this processor runs, which has the vector
and AES instructions. The next two are the code that a processor without
them runs:

```sh
RUSTFLAGS="--cfg oxirush_security_hooks" FORM=scalar cargo bench --bench algorithms
```

| | 64 octets | 1,500 octets | scalar code, 64 | scalar code, 1,500 | 0.2.0, 64 | 0.2.0, 1,500 |
|---|---|---|---|---|---|---|
| 128-EEA1, 128-NEA1 (SNOW 3G) | 0.81 µs | 5.3 µs | 3.6 µs | 28.9 µs | 1.0 µs | 9.7 µs |
| 128-EEA2, 128-NEA2 (AES-CTR) | 0.18 µs | 0.66 µs | 0.45 µs | 1.3 µs | 0.28 µs | 4.3 µs |
| 128-EEA3, 128-NEA3 (ZUC) | 0.89 µs | 6.1 µs | 2.6 µs | 20.3 µs | 1.0 µs | 9.8 µs |
| 128-EIA1, 128-NIA1 (SNOW 3G) | 0.70 µs | 0.88 µs | 3.1 µs | 7.8 µs | 1.4 µs | 15.1 µs |
| 128-EIA2, 128-NIA2 (AES-CMAC) | 0.34 µs | 2.6 µs | 0.52 µs | 3.2 µs | 0.40 µs | 3.6 µs |
| 128-EIA3, 128-NIA3 (ZUC) | 0.97 µs | 6.6 µs | 2.9 µs | 24.7 µs | 2.0 µs | 70.2 µs |

On the vector instructions SNOW 3G and ZUC are 1.2 to 1.8 times as fast as
in 0.2.0 for ciphering, and 2.0 to 17 times for the MACs. 0.2.0 read its
S-boxes from tables, at indices taken from the state of the generator. No
memory access depends on a secret here, in either form, and the scalar
code pays for it: the S-box SQ of SNOW 3G, which it reads whole, is most
of its time. Its MACs are faster than those of 0.2.0 on a long message,
1.9 times for 128-EIA1 and 2.8 times for 128-EIA3, because their
multiplications are carry-less products. On the carry-less
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

A key derivation, one HMAC-SHA-256, takes 1.7 µs on this processor, which
has no SHA instructions, and 1.6 µs in 0.2.0, whose HMAC did not wipe its
state. SUCI deconcealment takes 76 µs with Profile A and 356 µs with
Profile B; the README has the time of concealment.

## A key kept between messages

`cipher-context` and `mac-context` time a `CipheringContext` and an
`IntegrityContext`, which keep the round keys of AES and the subkeys of
CMAC from one message to the next. The time of one call, in nanoseconds:

| | 64 octets, from a key | 64 octets, with a context | 1,500 octets, from a key | 1,500 octets, with a context |
|---|---|---|---|---|
| 128-EEA2 | 184 | 132 | 661 | 604 |
| 128-EIA2 | 341 | 250 | 2,602 | 2,510 |

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
| 128-EEA2 with a keyed context | 38.6 | 132 |
| 128-EEA2 from a key | 87.9 | 184 |
| 128-EIA2 with a keyed context | 162 | 250 |
| 128-EIA2 from a key | 235 | 341 |
| 128-EEA1 | 700 | 808 |
| 128-EEA3 | 787 | 890 |
| 128-EIA1 | 581 | 704 |
| 128-EIA3 | 856 | 968 |

The clearing does not grow with the message: it adds 88 to 123 ns to a
message of 64 octets, and 81 to 120 ns to one of 1500 (for 128-EEA1,
128-EEA3 and 128-EIA3 on 1500 octets the runs of the two builds overlap).
A derivation takes 1,593 to 1,604 ns without the clearing and 1,712 to
1,725 ns with it; SUCI changes by 0.2 % at most, within what its runs
differ by (2.0 to 4.6 %).

Sixteen messages of 64 octets in one call:

| | Without | With |
|---|---|---|
| 128-EEA1 | 4,497 | 4,791 |
| 128-EEA2 from keys | 1,497 | 1,598 |
| 128-EEA2 with keyed contexts | 722 | 807 |
| 128-EEA3 | 4,500 | 4,794 |
| 128-EIA1 | 4,895 | 5,250 |
| 128-EIA2 from keys | 1,951 | 2,237 |
| 128-EIA2 with keyed contexts | 1,476 | 1,820 |
| 128-EIA3 | 5,636 | 5,919 |

A batch of 128-EEA1, 128-EIA1 or 128-EIA2 pays 286 to 355 ns for the
clearing, 6 to 19 % of its time, once for its sixteen messages; for
128-EEA3 and 128-EIA3 the runs of the two builds overlap. 128-EEA2 pays
100 ns from keys and 86 ns with keyed contexts.

The cost is that of the stores: 1,792 octets after AES with a keyed
context, 2,304 after AES from a key, 4,096 after a message of SNOW 3G or ZUC
and after a derivation, 18,432 after each algorithm of a batch that runs
side by side. Each figure is twice what the deepest work of its kind uses.
On 64 octets the clearing is 12 to 17 % of SNOW 3G and of ZUC, 31 to 35 %
of 128-EIA2, and it more than triples 128-EEA2 with a keyed context, which
a batch avoids: sixteen such messages take 2,139 ns one by one and 807 ns
in one call.

## Several messages in one call

`batch` times N messages, each with its own key and COUNT: `single` is a
call of `nas_cipher` or `nas_mac` for each, and `batch` one call of
`batch::cipher` or `batch::mac` for all; `single-context` and
`batch-context` do the same with a keyed context for each message. The
times are for the N messages.

64 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 3.2 µs | 2.0 µs | 6.4 µs | 2.7 µs | 12.8 µs | 4.8 µs |
| 128-EEA2 | 0.74 µs | 0.48 µs | 1.5 µs | 0.85 µs | 3.0 µs | 1.6 µs |
| 128-EEA3 | 3.5 µs | 1.9 µs | 7.0 µs | 2.7 µs | 14.1 µs | 4.8 µs |
| 128-EIA1 | 2.8 µs | 1.9 µs | 5.6 µs | 2.9 µs | 11.2 µs | 5.2 µs |
| 128-EIA2 | 1.4 µs | 0.82 µs | 2.7 µs | 1.2 µs | 5.5 µs | 2.2 µs |
| 128-EIA3 | 3.9 µs | 2.1 µs | 7.7 µs | 3.2 µs | 15.5 µs | 5.9 µs |

1,500 octets:

| | 4, one by one | 4, a batch | 8, one by one | 8, a batch | 16, one by one | 16, a batch |
|---|---|---|---|---|---|---|
| 128-EEA1 | 21.0 µs | 12.4 µs | 42.1 µs | 15.0 µs | 83.9 µs | 29.3 µs |
| 128-EEA2 | 2.6 µs | 2.4 µs | 5.3 µs | 4.6 µs | 10.5 µs | 9.2 µs |
| 128-EEA3 | 24.5 µs | 11.4 µs | 48.8 µs | 15.8 µs | 97.9 µs | 30.6 µs |
| 128-EIA1 | 3.5 µs | 2.7 µs | 7.0 µs | 4.4 µs | 14.0 µs | 8.2 µs |
| 128-EIA2 | 10.4 µs | 3.2 µs | 20.9 µs | 4.7 µs | 41.8 µs | 9.3 µs |
| 128-EIA3 | 26.4 µs | 13.3 µs | 52.9 µs | 20.3 µs | 105.7 µs | 39.8 µs |

Four messages have four SNOW 3G or ZUC generators in the words of a
128-bit vector: ciphering is 1.6 to 2.1 times as fast as one message after
the other. From five messages on, this processor has eight generators in a
256-bit vector (AVX2), and ciphering is 2.4 to 3.2 times as fast. The MACs
of SNOW 3G and of ZUC gain 1.3 to 2.7 times: their keystream comes from
the generators side by side, and the evaluation of 128-EIA1 and the sums
of 128-EIA3 stay one message after the other. 128-EIA2 gains 1.7 to
4.5 times from CBC-MAC chains that advance together, eight at most.

128-EEA2 has nothing to run side by side: its counter blocks are
encrypted eight at a time for one message already. Its batch saves the
clearing, which follows the batch and not each message: 1.6 to 1.9 times
as fast on 64 octets, 1.1 times on 1,500.

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
| OPc from OP | 203 | 121 | 117 | 403 | 1,348 | 1,085 |
| f1 | 245 | 130 | 210 | 457 | 2,012 | 2,127 |
| f2345 | 282 | 195 | 456 | 502 | 2,062 | 4,330 |
| An authentication vector | 288 | 203 | 663 | 519 | 2,088 | 6,399 |
| The check of an AUTN | 340 | 253 |  | 569 | 2,755 |  |
| An AUTS | 258 | 171 | 416 | 479 | 2,036 | 4,274 |
| The reading of an AUTS | 299 | 221 |  | 516 | 2,677 |  |

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
`milenage` crate is faster for OPc, 117 ns against 203, and for f1, 210 ns
against 245, by what the clearing costs: this crate takes 121 and 130
without it. For f2345, a vector and an AUTS this crate is 1.6 to 2.3 times
as fast. On the
`aes` crate 0.9 this crate pays the clearing and the wiping of the 704
octets of a key of that crate, which the `milenage` crate does not wipe.
With the bitsliced AES the encryptions of one key run four at a time.

`milenage/N/function/form` times N subscribers, each with its K: a call for
each, or one call of `batch::authentication_vectors` or `batch::check_autn`.
The time for the N, in microseconds:

| | 1 | 4 | 8 | 64 | 1,024 |
|---|---:|---:|---:|---:|---:|
| Vectors, a call for each | 0.268 | 1.08 | 2.14 | 17.0 | 276 |
| Vectors, one batch | 0.581 | 0.844 | 1.34 | 8.94 | 144 |
| Checks of an AUTN, a call for each | 0.327 | 1.30 | 2.58 | 20.7 | 333 |
| Checks of an AUTN, one batch | 0.602 | 0.936 | 1.53 | 10.4 | 166 |

A batch runs the key expansions and the encryptions of eight subscribers
side by side, and clears the stack once over 18,432 octets, which takes
longer than a vector: for one subscriber a call is faster, and from four
the batch. On the `aes` crate a batch of 1,024 vectors takes 305 µs, where
a call for each takes 518 µs: the jobs run one after the other, and the
stack is cleared once.

## Against other implementations

The same inputs to each, a call for each operation, on core 3 of the
machine above (Go 1.27.4, GCC 15.2), at 39b3491 on 2026-11-15. Each
implementation ran once a round, in turns, ten rounds of about 0.3 s each:
a time is the median of the ten, beside the lowest and the highest.
Cycles and instructions are per operation, the median of those of
`perf stat` in user mode, between a run of N operations and one of 2N;
peak memory is that of the whole program. A ratio is that of the medians,
given where the ten times of the two do not overlap, and "about the same"
where they do; the layout of the code alone moves a time by 7 to 15 %
between two builds, so that a ratio between 0.9 and 1.1 says little.
cryptography-rs has the keystream generators, which the program runs with
the IV of 128-NEA1 and 128-NEA3; its `Ct` types read no table at an index
from the state, as this crate does. Open5GS is called through
`ogs_nas_encrypt` and `ogs_nas_mac_calculate`, which its AMF and MME call.

| Operation | | ns | Lowest and highest | Cycles | Instructions | Allocations | Octets allocated | Peak memory | Other / this crate |
|---|---|---|---|---|---|---|---|---|---|
| MILENAGE, an authentication vector | oxirush-security | 294.4 | 292.3 to 333.1 | 846 | 1,012 | 0 | 0 | 2.5 MiB | |
| | milenage 0.3.1 | 1,294 | 1,287 to 1,356 | 3,691 | 4,833 | 0 | 0 | 2.5 MiB | 4.4x |
| | milenage 0.1.6 | 592.1 | 581.9 to 665.4 | 1,689 | 2,988 | 0 | 0 | 2.5 MiB | 2.0x |
| | Open5GS v2.8.0 | 730.9 | 728 to 771.5 | 2,096 | 6,115 | 0 | 0 | 1.9 MiB | 2.5x |
| | free5GC util v1.3.2 | 1,311 | 1,298 to 1,410 | 3,644 | 8,666 | 19 | 1,248 | 7.1 MiB | 4.5x |
| 128-NEA1 (SNOW 3G), 1,500 octets | oxirush-security | 5,390 | 5,345 to 5,457 | 15,365 | 32,967 | 0 | 0 | 2.5 MiB | |
| | cryptography-rs 0.8.0, Snow3g | 6,605 | 6,552 to 6,826 | 18,922 | 65,347 | 0 | 0 | 2.5 MiB | 1.2x |
| | cryptography-rs 0.8.0, Snow3gCt | 99,892 | 99,112 to 103,296 | 285,560 | 908,615 | 0 | 0 | 2.5 MiB | 19x |
| | Open5GS v2.8.0 | 4,855 | 4,840 to 5,013 | 13,932 | 42,136 | 0 | 0 | 1.9 MiB | 0.90x |
| | free5GC nas v1.2.3 | 1,085,151 | 1,073,897 to 1,122,608 | 3,078,550 | 5,358,262 | 3 | 3,152 | 3.1 MiB | 200x |
| 128-NEA2 (AES-CTR), 1,500 octets | oxirush-security | 659.6 | 652 to 680.1 | 1,900 | 2,437 | 0 | 0 | 2.5 MiB | |
| | aes 0.8.4, ctr 0.9.2 | 635.7 | 625.4 to 670.5 | 1,829 | 2,991 | 0 | 0 | 2.5 MiB | about the same |
| | Open5GS v2.8.0 | 7,207 | 7,180 to 7,433 | 20,620 | 69,722 | 0 | 0 | 1.9 MiB | 11x |
| | free5GC nas v1.2.3 | 1,254 | 1,234 to 1,274 | 3,432 | 6,446 | 4 | 2,576 | 7.1 MiB | 1.9x |
| 128-NEA3 (ZUC), 1,500 octets | oxirush-security | 6,072 | 6,016 to 6,796 | 17,570 | 50,744 | 0 | 0 | 2.5 MiB | |
| | zuc 0.4.1 | 5,654 | 5,532 to 5,702 | 15,968 | 55,064 | 0 | 0 | 2.5 MiB | 0.93x |
| | cryptography-rs 0.8.0, Zuc128 | 5,590 | 5,547 to 5,675 | 16,000 | 59,126 | 0 | 0 | 2.5 MiB | 0.92x |
| | cryptography-rs 0.8.0, Zuc128Ct | 94,937 | 94,706 to 95,591 | 273,402 | 852,167 | 0 | 0 | 2.5 MiB | 16x |
| | Open5GS v2.8.0 | 13,477 | 13,442 to 13,650 | 38,680 | 126,029 | 1 | 1,596 | 1.9 MiB | 2.2x |
| | free5GC nas v1.2.3 | 21,753 | 21,699 to 22,183 | 61,409 | 203,253 | 2 | 3,072 | 7.1 MiB | 3.6x |
| 128-NIA1 (SNOW 3G), 1,500 octets | oxirush-security | 876.2 | 868.6 to 895.6 | 2,508 | 4,950 | 0 | 0 | 2.5 MiB | |
| | Open5GS v2.8.0 | 1,032,588 | 1,027,753 to 1,037,478 | 2,963,547 | 5,514,519 | 0 | 0 | 1.9 MiB | 1,200x |
| | free5GC nas v1.2.3 | 937,362 | 935,783 to 1,096,312 | 2,676,038 | 4,688,215 | 3 | 108 | 2.7 MiB | 1,100x |
| 128-NIA2 (AES-CMAC), 1,500 octets | oxirush-security | 2,618 | 2,613 to 2,652 | 7,502 | 2,706 | 0 | 0 | 2.5 MiB | |
| | aes 0.8.4, cmac 0.7.2 | 2,544 | 2,532 to 2,573 | 7,268 | 2,634 | 0 | 0 | 2.5 MiB | 0.97x |
| | Open5GS v2.8.0 | 6,716 | 6,688 to 6,760 | 19,271 | 60,224 | 0 | 0 | 1.9 MiB | 2.6x |
| | free5GC nas v1.2.3 | 4,280 | 4,255 to 4,447 | 11,998 | 21,032 | 8 | 2,240 | 7.1 MiB | 1.6x |
| 128-NIA3 (ZUC), 1,500 octets | oxirush-security | 6,470 | 6,440 to 6,579 | 18,467 | 55,212 | 0 | 0 | 2.5 MiB | |
| | zuc 0.4.1 | 10,861 | 10,673 to 11,269 | 31,132 | 114,561 | 0 | 0 | 2.5 MiB | 1.7x |
| | Open5GS v2.8.0 | 61,797 | 60,919 to 69,105 | 177,022 | 443,082 | 1 | 1,604 | 1.9 MiB | 9.6x |
| | free5GC nas v1.2.3 | 59,181 | 58,995 to 60,591 | 167,991 | 602,373 | 2 | 1,540 | 6.9 MiB | 9.2x |

`benches/compare/compare.sh 3` runs every row on core 3, ten rounds
(`ROUNDS` sets them). It fetches each implementation at the version that
it pins, and builds Open5GS's libraries of NAS security; perf may need
`PERF="sudo -n perf"`.
