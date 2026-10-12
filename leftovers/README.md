# What an operation leaves

```bash
cargo run --release
```

```text
operation                                                                    form  depth  cleared  areas
nea_cipher 128-EEA2, 64 octets                                        vector code    576     2048      1   nothing left (12 without the clearing)
CipheringContext::cipher 128-EEA2, 64 octets                          vector code    176     1280      1   nothing left (6 without the clearing)
nia_mac_batch of 128-EIA2, 16 x 61 octets, from contexts              vector code   7912    16384      1   nothing left
nas_5gs::derive_kamf                                                  vector code   1048     4096      1   nothing left (4 without the clearing)
Suci::deconceal, Profile B                                            vector code   4464    12288      1   nothing left (3 without the clearing)
...
1605 leftovers are seen when nothing is cleared after an operation
```

The program calls each public operation of oxirush-security that computes
with a key, on x86-64 Linux, and reads what the operation left: the stack
below its caller, painted with a pattern before the call, and the registers
that a function need not give back (RAX, RCX, RDX, RSI, RDI, R8 to R11, YMM0
to YMM15), stored as the operation returns. The keys live on the heap of the
program, which passes references: a copy that the scan finds was made by the
crate, or by a crate that it uses.

Each operation runs in the three forms of the code (the vector instructions
of the processor, those of 128 bits alone, none), twice in each form.

Without the clearing that follows its work (`hooks::unwiped`):

- the scan looks for the key, what is expanded from it (AES round keys, CMAC
  subkeys, the stages of a generator), the keystream, and the blocks and
  hashes of HMAC. The number in brackets is how many of them it found: it
  would see them if the clearing left them;
- `depth` is how many octets of stack the work wrote below where the
  clearing starts.

As a program has it, the run fails when:

- one of those values is on the stack or in a register;
- an area that the crate cleared is not zero. There are `areas` of them, the
  deepest of `cleared` octets;
- a vector register is not zero;
- the work went deeper than `cleared` less a margin, a quarter of `depth`
  and 128 octets at least.

## The depths

The crate clears a fixed number of octets of stack after each kind of work.
The deepest work of each kind, in octets:

| Work | Cleared | Deepest on x86-64 | Deepest on emulated AArch64 |
|------|--------:|------------------:|----------------------------:|
| AES on its instructions, one message with a keyed context | 1280 | 848 | 688 |
| AES on its instructions, from a key | 2048 | 992 | 1088 |
| One message of SNOW 3G or ZUC, AES without its instructions, a new context or generator | 4096 | 2496 | 1928 |
| The messages of a batch one after the other, without the vector code | 6144 | 2992 | 1760 |
| A derivation | 4096 | 1576 | 1336 |
| Words of a generator, a comparison | 1536 | 736 | 400 |
| SUCI | 12288 | 5577 | not in the program |
| Several messages side by side | 16384 | 7952 | 8304 |

On x86-64 the figure is the deepest of eleven builds of the 521 cases: the
release profile, AES and SHA-256 without their instructions
(`--cfg aes_backend="soft" --cfg sha2_backend="soft"`), link-time
optimization with one codegen unit, and `opt-level = "s"`, each with
Rust 1.98.1 and with Rust 1.88, then one codegen unit, `opt-level = 2` and
`-C target-cpu=native` with Rust 1.98.1. On AArch64 it is that of the 22
operations of [`emulated-aarch64/`](../emulated-aarch64), built at
`opt-level = 2` for a processor with NEON and AES.

A build with debug assertions clears 49152 octets after any work. With the
crate and the crates that it uses at `opt-level = 0` under an optimized
scan, the deepest work was 22056 octets and the scan found nothing. The
disassembly of that build shows what it cannot see: a value that an
operation returns in a register goes through the frame of its function,
where the 32 bits of a word of `Snow3G::next_word` or `Zuc::next_word` stay.

## What the scan does not show

- Another target. Nothing is measured outside x86-64 and the emulated
  AArch64 processor.
- Another compiler or other settings. How deep a function goes is the
  compiler's choice: the figures above are what the margins rest on.
- A value in a form that the scan does not look for, in a general
  register. The stack and the vector registers are checked whatever they
  hold.
- The copies of the program. A key or a context that the program moves
  leaves its octets where it was, and `new`, `from_slice` and `clone` copy
  octets as any copy does.

The program reads memory below its stack pointer and stores registers from
assembly. It is a test tool: it is not published, and nothing of the crate
depends on it. CI runs it in six builds.
