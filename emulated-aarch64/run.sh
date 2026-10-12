#!/usr/bin/env bash
# Build the guest program for a bare AArch64 processor, and run it on an
# emulated one: see README.md.
set -eu
cd "$(dirname "$0")"
(cd guest && cargo build --release)
(cd host && cargo run --release -- ../guest/target/aarch64-unknown-none/release/oxirush-security-emulated-guest)
