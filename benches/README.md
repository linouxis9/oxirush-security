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
