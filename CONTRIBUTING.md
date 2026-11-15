# Contributing to oxirush-security

## Tests

```sh
cargo test --all-features
python3 -I tests/five_g_aka_chain.py
python3 -I tests/interworking_keys.py
```

The two Python programs derive the 5G AKA chain and the keys of a change
between 5GS and EPS a second time, with the HMAC-SHA-256 of Python's
standard library, and compare them with the crate's.

The repository has three more programs, which the published crate does not
have:

| Directory | What it checks |
|-----------|----------------|
| [`differential/`](differential/README.md) | MILENAGE against the `milenage` crate, Open5GS and free5GC on a million random subscribers |
| [`leftovers/`](leftovers/README.md) | That no key, round key or keystream is left on the stack or in the registers after each operation |
| [`emulated-aarch64/`](emulated-aarch64/README.md) | The AArch64 vector code against the scalar code, on an emulated processor |

`examples/` has five programs, such as
`cargo run --example suci_conceal --features suci`.

## Fuzzing

```sh
cargo +nightly fuzz run algorithms -- -max_total_time=60
```

`fuzz/` has six [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets.
CI runs each for a minute at a push, an hour each weekday, and four hours on
Saturday.

## Benchmarks

[`benches/README.md`](benches/README.md) has the figures and the commands.

## Pull requests

A pull request comes with a test for what it changes. Sign off your commits
(`git commit -s`): by contributing you agree to the [Developer Certificate
of Origin](https://developercertificate.org/). [SECURITY.md](SECURITY.md)
says how to report a vulnerability.
