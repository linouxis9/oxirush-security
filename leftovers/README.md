# What an operation leaves

```sh
cargo run --release
```

```text
processor: AMD Ryzen 7 5700G with Radeon Graphics, with AES, VAES, AVX2, SHA, without AVX-512F
the aes crate runs on the AES instructions, a block after the other
oxirush-security runs: Vector256 (vector and AES instructions of 128 bits, eight generators side by side in a batch on AVX2)
operation                                                                    form  depth  cleared  areas
nea_cipher 128-EEA2, 64 octets                                        vector code    576     2304      1   nothing left (12 without the clearing)
CipheringContext::cipher 128-EEA2, 64 octets                          vector code    176     1792      1   nothing left (6 without the clearing)
nia_mac_batch of 128-EIA2, 16 x 61 octets, from contexts              vector code   7944    18432      1   nothing left
nas_5gs::derive_kamf                                                  vector code   1048     4096      1   nothing left (4 without the clearing)
Suci::deconceal, Profile B                                            vector code   4224    12288      1   nothing left (2 without the clearing)
...
1703 leftovers are seen when nothing is cleared after an operation
the deepest work for each number of octets that is cleared:
    1536    216  14 %   Zuc::next_word, scalar code
    1792    368  20 %   CipheringContext::cipher 128-EEA2, 1500 octets, vector code
    2304    800  34 %   nea_cipher_batch of 128-EEA2, 16 x 1500 octets, from keys, vector code
    4096   1240  30 %   nas_5gs::compute_res_star, vector code
    8192   2344  28 %   IntegrityContext::new 128-EIA2, scalar code
   12288   4224  34 %   Suci::deconceal, Profile B, vector code
   18432   7944  43 %   nia_mac_batch of 128-EIA2, 16 x 61 octets, from contexts, vector code
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
- what the operation returns in a register, a keystream word of
  `next_word` for instance, is on the stack, where the crate is optimized:
  an unoptimized build keeps such a value in the frames that it goes
  through, which the documentation of the crate says;
- an area that the crate cleared is not zero. There are `areas` of them, the
  deepest of `cleared` octets;
- a vector register is not zero;
- the work used more than three quarters of `cleared`.

## The depths

The crate clears a fixed number of octets of stack after each kind of work:
at least twice what the deepest work of the kind used wherever it was run.

| Work | Cleared | Deepest on x86-64 | Deepest on emulated AArch64 |
|------|--------:|------------------:|----------------------------:|
| AES on its instructions, one message with a keyed context | 1792 | 848 | 688 |
| AES on its instructions, from a key, and MILENAGE on them | 2304 | 992 | 1088 |
| One message of SNOW 3G or ZUC, a new generator | 4096 | 1872 | 1928 |
| A derivation | 4096 | 1572 | 1336 |
| What goes through the `aes` crate: AES without its instructions, a new keyed context, the messages of a batch one after the other, MILENAGE without the AES instructions | 8192 on x86, 6144 elsewhere | 2992, and 3968 by the frames of the code for AVX-512F | 1760 |
| Words of a generator, a comparison | 1536 | 736 | 400 |
| SUCI | 12288 | 5337 | not in the program |
| Several messages side by side, the MILENAGE of several subscribers side by side | 18432 | 8000 | 8304 |

On x86-64 the figure is the deepest of the 521 cases in eighteen builds on
an AMD Ryzen 7 5700G: the release profile, AES and SHA-256 without their
instructions (`--cfg aes_backend="soft" --cfg sha2_backend="soft"`),
link-time optimization with one codegen unit, `opt-level = "s"`, one
codegen unit, `opt-level = 2` and `-C target-cpu=native`, each with
Rust 1.99 and with Rust 1.98, and the first four with Rust 1.88, and of
the 78 cases of MILENAGE in the six builds of CI on the same processor,
where they go 952, 2424 and 5968 octets deep at most in the rows of AES,
of the `aes` crate and of the work side by side. On AArch64 it is that of
the 26 operations of [`emulated-aarch64/`](../emulated-aarch64), built at
`opt-level = 2` for a processor with NEON and AES.

The scan fails at three quarters of what is cleared, and not at its end.
What is cleared is twice the deepest work that was seen: a processor, a
compiler or a version of a crate that goes up to half as deep again
passes, and one that goes deeper fails while a quarter is not yet used, so
that the figure is raised before an operation leaves anything. The last
lines of a run give the deepest work for each figure.

A build with debug assertions clears 49152 octets after any work. With the
crate and the crates that it uses at `opt-level = 0` under an optimized
scan, the deepest work was 22056 octets and the scan found nothing. The
disassembly of that build shows what it cannot see: a value that an
operation returns in a register goes through the frame of its function,
where the 32 bits of a word of `Snow3G::next_word` or `Zuc::next_word` stay.

## The processor

The first lines of a run say which processor it measured, because code
that asks the processor what it has goes more or less deep by the answer.

| What asks | Its codes | Run here |
|-----------|-----------|----------|
| The crate | The vector code of 256 bits, that of 128 bits, none | The three forms of each case |
| `sha2` | With the SHA instructions, without | The release build, and the build with `sha2_backend="soft"` |
| `aes` | Without the AES instructions, with them, and from its version 0.9.3 with AVX-512F and VAES | The build with `aes_backend="soft"` and the release build; the last one on the runners of CI that have such a processor |

The crate calls the `aes` crate where its own vector code does not run: on
a processor without the AES instructions, in a 32-bit program, and in the
form without vector code of this scan, where `aes` finds the AES
instructions of the processor by itself.

Its counter mode gave `aes` eight counter blocks at a time. From its
version 0.9.3, `aes` has code for 64 blocks side by side on a processor
with AVX-512F and VAES, whose frame is for 64 blocks whatever the number
that it is given: 1904 octets and 1120 more in a release build with
Rust 1.99, where its code on the AES instructions has 408. It writes ZMM16
and ZMM17 as well, which the crate does not clear. 128-EEA2 without the
vector code went 2296 octets deep here and 3832 to 3848 on a runner of
GitHub, of the 4096 that were cleared then: the scan of CI failed there,
with nothing left.

The counter mode now runs inside the code that `aes` has chosen, and asks
it for what does not follow the processor. Its code without instructions
is given the 2 or 4 blocks that it works on at once. A code on the AES
instructions encrypts eight counter blocks one after the other, which the
compiler and the processor overlap. The code of `aes` for 30 and for 64
blocks is no longer in the binary. In the same build the frame of the
counter mode is 448 octets on the AES instructions and 512 for AVX-512F,
and the same work goes 2168 octets deep here.

The frame for AVX-512F is not the same in every build: `aes` copies its
round keys for 512-bit registers before it calls the counter mode, and the
compiler removes that copy in some builds and keeps it in others. In the
twelve binaries of Rust 1.99 and 1.98 that were read, the frames for
AVX-512F are 64 to 2136 octets, where those on the AES instructions are 64
to 448. Added to what was measured here, that is 3968 octets at most on
such a processor: 8192 are cleared on x86, and 6144 on another target,
where `aes` has no such code. In one of the twelve, link-time optimization
with Rust 1.99, the compiler put the counter mode in ZMM16 and ZMM17.

## What the scan does not show

- Another target. Nothing is measured outside x86-64 and the emulated
  AArch64 processor.
- Another compiler or other settings. How deep a function goes is the
  compiler's choice: the figures above are measures, and nothing bounds
  what another compiler does.
- A processor that no run was on. The counter mode has a variant for a
  processor with AVX-512F and VAES, which runs on the runners of CI that
  have one, and not here.
- ZMM16 to ZMM31, the upper halves of ZMM0 to ZMM15 and the mask
  registers, which the scan does not read. The crate clears ZMM0 to ZMM15
  whole, and its own code writes no other. The form without the vector
  code is another matter on a processor with AVX-512F, where the compiler
  may put the counter mode in ZMM16 and above, as it did in one build. A
  64-bit program does not run that form there: such a processor has the
  instructions of the vector code. A 32-bit program has no ZMM16.
- A value in a form that the scan does not look for, in a general
  register. The stack and the vector registers are checked whatever they
  hold.
- The copies of the program. A key or a context that the program moves
  leaves its octets where it was, and `new`, `from_slice` and `clone` copy
  octets as any copy does.

The program reads memory below its stack pointer and stores registers from
assembly. It is a test tool: it is not published, and nothing of the crate
depends on it. CI runs it in six builds, at each change and each week.
