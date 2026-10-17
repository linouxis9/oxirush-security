/*
   OxiRush
   Copyright 2025-2026 Valentin D'Emmanuele

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

//! The security functions of 5GS and EPS: MILENAGE, key derivation, NAS
//! integrity and ciphering, and SUCI concealment, per 3GPP TS 35.206,
//! TS 33.102, TS 33.501 and TS 33.401.
//!
//! ```rust
//! use oxirush_security::nas_5gs::{
//!     KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
//! };
//! use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};
//!
//! // KAMF, the key of the AMF
//! let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
//! let k_amf = KAmf::from_slice(&hex::decode(k_amf).unwrap()).unwrap();
//!
//! // The NAS keys of the algorithms that the AMF selected
//! let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
//! let k_nas_enc = derive_knas_enc(&k_amf, nea2);
//! let k_nas_int = derive_knas_int(&k_amf, nia2);
//! println!("KNASenc {}", hex::encode(k_nas_enc.as_octets()));
//! println!("KNASint {}", hex::encode(k_nas_int.as_octets()));
//!
//! // An uplink REGISTRATION COMPLETE on 3GPP access with NAS COUNT 0: cipher
//! // it, then compute the MAC over the sequence number and the ciphertext
//! let (count, access, uplink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Uplink);
//! let mut message = [0x7e, 0x00, 0x43];
//! nas_cipher(&k_nas_enc, count, access, uplink, &mut message, nea2);
//! let protected = [&[count.sequence_number()][..], &message].concat();
//! let mac = nas_mac(&k_nas_int, count, access, uplink, &protected, nia2);
//! println!("ciphered {}, MAC {mac:08x}", hex::encode(message));
//! ```
//!
//! ```text
//! KNASenc f47ae570afde775373d1b313d2176f54
//! KNASint 28ddb5356880149b9fee22f2367522a4
//! ciphered b57dd5, MAC 83e4d009
//! ```
//!
//! A key has a type of its own, which is wiped when it is dropped: KNASenc
//! does not compile where KNASint is expected. The crate stores no key and
//! keeps no NAS COUNT: the caller passes both for each message, and
//! [`NasCount`] gives the next one and the one of a received message. A
//! receiver computes the MAC first, then deciphers with the same call
//! (TS 24.501 §4.4.3). No function panics on its arguments.
//!
//! The [README](https://github.com/linouxis9/oxirush-security#readme) has
//! an example for each task: a 5G AKA run from MILENAGE to KAMF, a
//! re-synchronisation, the keys of a handover, NAS protection in EPS, SUCI
//! concealment, the algorithms on the 3GPP test sets.
//!
//! # Where things are
//!
//! | Where | Contents |
//! |-------|----------|
//! | The crate root | What 5GS and EPS share: the algorithms, their inputs, the keyed contexts, the batches, CK, IK, RAND and AUTN, the PLMN and TBCD |
//! | [`nas_5gs`] | TS 33.501: the keys and their derivations, NAS integrity and ciphering, the SUPI, the SUCI and the 5G-GUTI |
//! | [`nas_eps`] | TS 33.401: the keys and their derivations, NAS integrity and ciphering, the short MAC of a SERVICE REQUEST, HASHMME |
//! | [`milenage`] | TS 35.206 and TS 33.102: MILENAGE, its keys and values, the authentication vector of a home network, the check of AUTN in a USIM and the AUTS of a re-synchronisation, for one subscriber or for many |
//! | [`kdf`] | The KDF of TS 33.220, for a derivation that the crate does not have |
//!
//! An item has one path. The two systems have keys and functions of the
//! same name, [`nas_5gs::KNasInt`] and [`nas_eps::KNasInt`],
//! [`nas_5gs::derive_knas_int`] and [`nas_eps::derive_knas_int`]: the
//! module says which one a program means, and the type of the key that a
//! function takes refuses the other.
//!
//! # What it implements
//!
//! The last column names the kind of reference value that the tests have,
//! which [the section on tests](#what-the-tests-compare-with) explains.
//!
//! | What | Functions | Specification | Reference values |
//! |------|-----------|---------------|------------------|
//! | NAS ciphering | `nas_cipher` of each system | NEA0 and EEA0, 128-NEA1 and 128-EEA1 (SNOW 3G), 128-NEA2 and 128-EEA2 (AES-CTR), 128-NEA3 and 128-EEA3 (ZUC): TS 33.401 Annex B.1 | 3GPP |
//! | NAS integrity | `nas_mac` of each system | 128-NIA1 and 128-EIA1 (SNOW 3G), 128-NIA2 and 128-EIA2 (AES-CMAC), 128-NIA3 and 128-EIA3 (ZUC): TS 33.401 Annex B.2 | 3GPP |
//! | The algorithms themselves | [`nea_cipher`], [`nia_mac`] and their `*_bits` forms, with any COUNT, BEARER and length in bits | The same | 3GPP |
//! | A key kept between messages | [`CipheringContext`], [`IntegrityContext`] | The same | 3GPP |
//! | Several messages at once | [`nea_cipher_batch`], [`nia_mac_batch`] on a [`CipherJob`] or a [`MacJob`] for each message | The same | 3GPP |
//! | Keystream generators | [`Snow3G`], [`Zuc`] | TS 35.216, TS 35.222 | 3GPP |
//! | MILENAGE | `milenage::Milenage`: f1, f1\*, f2 to f5, f5\*; `milenage::Opc::from_op` | TS 35.206 §4.1 | 3GPP, other implementations |
//! | Authentication | `authentication_vector`, `check_autn`, `auts`, `verify_auts` of `milenage::Milenage`, and their batches | TS 33.102 §6.3.2, §6.3.3 and §6.3.5 | other implementations |
//! | 5G AKA | `derive_kausf`, `compute_res_star`, `compute_xres_star`, `compute_hres_star`, `compute_hxres_star`, `derive_kseaf`, `derive_kamf`, `derive_knas_enc`, `derive_knas_int`, `derive_kgnb`, `derive_nh` | TS 33.501 Annex A.2 and A.4 to A.10 | other implementations |
//! | Other 5GS derivations | KAMF', KN3IWF, KNG-RAN\*, KSN, the RRC and UP keys, the SoR and UPU MACs, the TNAP usage keys, KIAB | TS 33.501 Annex A | calculated |
//! | EPS derivations | KASME, KNASint and KNASenc, KeNB, NH, KeNB\*, the AS keys, the NAS token, the CK'/IK' mapping, SRVCC, S-KeNB, S-KgNB, LWIP-PSK, S-KWT, K_n | TS 33.401 Annex A | calculated |
//! | HASHMME | `nas_eps::compute_hash_mme` | TS 33.401 Annex I.2 | other implementations |
//! | 5GS/EPS key mapping | Idle mobility and connected handover in both directions, and KASME_SRVCC | TS 33.501 Annexes A.14, A.15 and A.21 | calculated |
//! | Other NAS MACs | `nas_5gs::nas_container_mac`; `nas_eps::re_establishment_nas_mac`; `nas_eps::service_request_short_mac` | TS 33.501 §6.9.2.3.3; TS 33.401 §7.4.4; TS 24.301 §9.9.3.28 | calculated |
//! | SUPI and SUCI | `nas_5gs::Supi`; `nas_5gs::Suci` with the null scheme, Profile A (X25519) and Profile B (secp256r1), for an IMSI and for a NAI, on the SUPI and the two forms of a SUCI of oxirush-utils | TS 33.501 Annex C, TS 23.003 §2.2A, §2.2B and §28.7.3 | 3GPP |
//! | 5G-GUTI, 5G-S-TMSI | `nas_5gs::Guti`, `nas_5gs::STmsi`: the values of oxirush-utils | TS 24.501 §9.11.3.4 | calculated |
//! | PLMN and TBCD | [`Plmn`], `tbcd::encode`, `tbcd::decode`: those of oxirush-utils | TS 24.008 §10.5.1.3, TS 29.002 | calculated |
//! | Algorithm selection | [`select_integrity_algo`], [`select_ciphering_algo`] and their `*_with_preference` forms | TS 33.401 §7.2.4.3.1, TS 33.501 §6.7.1 | calculated |
//!
//! The default order of the selection is NIA2, NIA1, NIA3, never NIA0, and
//! NEA2, NEA1, NEA3, NEA0.
//!
//! The functions of whole octets cannot fail. The `*_bits` forms take a
//! length in bits: they keep the unused low bits of the last octet when
//! they cipher and ignore them for a MAC.
//!
//! Concealment draws a fresh ephemeral key, so two SUCIs of one SUPI
//! differ. Profile B always compresses the point (TS 33.501 Annex C.3.4),
//! and de-concealment refuses an uncompressed ephemeral point, as
//! TS 33.514 §4.2.1.3 requires.
//!
//! # Inputs and errors
//!
//! A value that a specification bounds has a type that holds only the
//! values in range. A number from a peer or from a configuration enters
//! through `TryFrom`, `new` or `from_nas_octets`, which return a
//! [`SecurityError`] or, for an identity, an error of [`identity`], and the
//! functions that take these types have nothing left to refuse.
//!
//! | Input | Type or check |
//! |-------|---------------|
//! | Key, RES\*, XRES\*, XRES | A type for each, such as [`nas_5gs::KAmf`], [`Ck`] or [`milenage::K`]: `new` takes the octets, `from_slice` a slice, `as_octets` gives them back. Wiped on drop, not `Copy`, and never printed: `{:?}` shows the name alone |
//! | RAND, AUTN | [`Rand`] and [`Autn`], built and viewed as a key is. They travel in clear: `{:?}` prints their octets, as it prints an identity whole |
//! | SQN, AMF, MAC-A, MAC-S, RES, AUTS | The public values of [`milenage`], built, viewed and printed as RAND is. [`milenage::Sqn`] takes a number with `try_from`, which refuses one above 2^48 - 1 |
//! | The MAC of an AUTN or an AUTS | `Err(MacFailure)` when it is not the one that K gives |
//! | Algorithm | [`IntegrityAlgorithm`] and [`CipheringAlgorithm`], under both names (`NIA2` and `EIA2`). `try_from(u8)` refuses 4 and above |
//! | NAS COUNT | [`NasCount`], 24 bits. `next` and `estimate` refuse to wrap around |
//! | COUNT of the KgNB and KeNB derivations | A `NasCount`, or [`AccessKeyCount::Handover`] for the 2^32 - 1 of a handover |
//! | NAS connection of 5GS | [`nas_5gs::NasConnection`]: `ThreeGpp` (identifier 1) or `Non3Gpp` (2) |
//! | DIRECTION | [`Direction`]: `Uplink` or `Downlink` |
//! | COUNT and BEARER of the algorithms themselves | Any `u32`, and [`Bearer`], 5 bits |
//! | Length in bits | `Err(BitLengthExceedsData)` when the buffer is shorter |
//! | PCI, ARFCN, AMF Set ID, AMF Pointer, cell identity | `Err(OutOfRange)` above the largest value |
//! | PLMN, TBCD string, 5G-GUTI, 5G-S-TMSI | [`Plmn`], `nas_5gs::Guti`, `nas_5gs::STmsi`: an error of [`identity`] that names the member at fault and says why, which is `Err(Identity)` in a function of this crate |
//! | SUPI | `nas_5gs::Supi`: an IMSI or a NAI, from its identity or from the text of a service based interface |
//! | SUCI from a peer | `nas_5gs::Suci`: a `nas_5gs::SuciError` that says what could not be read, or which step of the de-concealment failed |
//! | KDF parameter of variable length | `Err(InputTooLong)` above 65535 octets |
//!
//! # Key material and timing
//!
//! ## What an operation leaves
//!
//! An operation that computes with a key clears what it used when it
//! returns: an algorithm, a keyed context, a batch, a generator, a
//! derivation, a comparison, a SUCI, MILENAGE.
//!
//! | What | How |
//! |------|-----|
//! | The values that the code names | Keys, round keys, CMAC subkeys, generator states, keystream, and the blocks and hashes of HMAC are wiped where they are, with `zeroize`. The SHA-256 of `sha2` and the AES of `aes` are built with their `zeroize` features: the crate does not compile without them. |
//! | The stack | The work runs in a frame of its own. When it has returned, the stack below is set to zero over a fixed number of octets, which the table of the stack gives. |
//! | The registers | The registers that a function need not give back as it found them are set to zero. |
//!
//! | Target | Registers that are cleared | Checked by |
//! |--------|----------------------------|------------|
//! | x86-64 | RAX, RCX, RDX, RSI, RDI, R8 to R11, and the vector registers 0 to 15, whole | `leftovers/` in the repository, for every operation in each form of the code, in eighteen optimized builds with Rust 1.88, 1.98 and 1.99 here, and in those of CI on its runners |
//! | AArch64 | X0 to X17, and V0 to V31 | `emulated-aarch64/`, for 26 operations on an emulated processor |
//! | Another target | None. The stack is cleared by a function whose frame is where the work was | Nothing |
//!
//! Both programs run an operation, then look for its key, its round keys,
//! its subkeys, the stages of its generator, its keystream and its HMAC
//! values on the stack and in the registers. They also see that what was
//! cleared is zero, that the vector registers are zero, and that the work
//! used three quarters of what is cleared at most. CI runs both, at each
//! change and each week.
//!
//! | Work | Stack cleared after it, in octets |
//! |------|-----------------------------------|
//! | AES on its instructions, one message with a keyed context | 1792 |
//! | AES on its instructions, from a key; MILENAGE on them | 2304 |
//! | One message of SNOW 3G or ZUC, a derivation, a new generator | 4096 |
//! | What goes through the `aes` crate: AES without its instructions, a new keyed context, the messages of a batch one after the other, MILENAGE without the AES instructions | 8192 on x86 and x86-64, 6144 elsewhere |
//! | Words of a generator, a comparison | 1536 |
//! | SUCI | 12288 |
//! | Several messages side by side, the MILENAGE of several subscribers side by side | 18432 |
//! | Any, in a build with debug assertions | 49152 |
//!
//! An operation needs that much stack. Each figure is at least twice what
//! the deepest work of its kind used wherever it was run, and the scan
//! fails above three quarters. `leftovers/README.md` has the figures, and
//! says what of them depends on the processor.
//!
//! What stays:
//!
//! - What an operation returns, which is the program's. A key and a
//!   context are wiped when they are dropped.
//! - The copies of the program. A key or a context that is moved leaves
//!   its octets where it was: Rust does not wipe what a value moves from.
//!   `new`, `from_slice` and `clone` copy octets as any copy does. Make a
//!   key where it stays, and pass references.
//! - An unoptimized build without debug assertions, whose code goes
//!   deeper than what is cleared. In any unoptimized build, a value that
//!   an operation returns in a register goes through the frame of its
//!   function: a keystream word of `next_word` stays there.
//! - ZMM16 to ZMM31 and the mask registers, in a build that enables
//!   AVX-512 for every processor.
//! - What the system copies of the memory of a process: swap, a core dump.
//! - Work that goes deeper than what is cleared after it. The figures are
//!   measured, not proven: a processor, a compiler or a later version of
//!   `aes`, `sha2`, `x25519-dalek` or `p256` may go deeper than what was
//!   seen.
//!
//! On an AMD Ryzen 7 5700G the clearing adds about 16 ns to a message of
//! AES with a keyed context, 18 ns to one from a key, 30 ns to a message
//! of SNOW 3G or ZUC or to a derivation, and 75 to 140 ns to each
//! algorithm of a batch that runs side by side. For 64 octets that is 7 to
//! 12 % of SNOW 3G and of ZUC, and it more than doubles 128-EEA2 with a
//! keyed context, from 13 ns to 29. A batch pays once for all its
//! messages: sixteen of 128-EEA2 with their contexts take 276 ns in one
//! call, and 478 one by one. `benches/README.md` in the repository has the
//! figures.
//!
//! A program that cannot afford it is built with
//! `RUSTFLAGS="--cfg oxirush_security_unwiped"`. The named values are
//! still wiped; the stack and the registers are left as the work left
//! them. It is a `--cfg` of the build and not a feature, so that no
//! dependency of a program can turn the clearing off for it.
//!
//! ## Timing
//!
//! SNOW 3G, ZUC, AES, 128-EIA1, 128-EIA3, AES-CMAC and MILENAGE neither
//! index memory nor branch on a secret value, in any of their forms, for
//! one message or for several. [`implementation`] says which form runs: the
//! vector code on an x86-64 processor with SSSE3, SSE4.1, AES-NI and
//! PCLMULQDQ or an AArch64 one with AES, and the scalar code elsewhere.
//!
//! | Code | How |
//! |------|-----|
//! | SNOW 3G and ZUC on vector instructions | An S-box is read with shuffle instructions, whose index is an operand and not an address. S1 of SNOW 3G and the S-box inside S1 of ZUC are the AES instruction. |
//! | The two MACs of SNOW 3G and ZUC | Their products are the carry-less multiplication instruction. |
//! | AES | The key expansion and the rounds are the AES instruction. Without it, AES is the bitsliced code of the `aes` crate. |
//! | Several messages | What a generator or a chain does at a step depends on the lengths of the messages: the time of a message depends on no octet or key of another. |
//! | SNOW 3G and ZUC in scalar code | The S-box SQ is read whole and narrowed down through masks. S0 of ZUC is three four-bit S-boxes, each a word that is shifted. MULα, DIVα and the products of the MACs are carry-less products, made with shifts and multiplications. |
//! | MILENAGE | AES with K, and sums and rotations of OPc and TEMP by amounts that the constants of the framework give. A MAC-A or a MAC-S is compared through `subtle`. |
//! | A comparison | [`constant_time_eq`] goes through `subtle`: its time depends on the lengths, and not on where the values differ. |
//!
//! What was checked, and what was not:
//!
//! - The disassembly of the release build for x86-64 with Rust 1.98.1 was
//!   read: SNOW 3G and ZUC in each form, AES on its instructions, the six
//!   algorithms and the two functions of several messages. Their
//!   conditional jumps test a length, a loop counter, a place in a buffer,
//!   a feature of the processor, whether a generator has started or which
//!   message it works for. None tests a secret. Those of MILENAGE, alone
//!   and in a batch, test the form of the code, the number of jobs,
//!   whether a job has its result, and the outcome of the comparison of a
//!   MAC, which the caller is told.
//! - That reading found one: the compiler had turned the masked selection
//!   of SQ in the scalar code into jumps on bits of the state. A mask that
//!   a secret bit gives now goes through `core::hint::black_box`.
//! - The scalar code shifts by a secret amount and multiplies secret
//!   words. Both take a time that does not depend on their operands on the
//!   x86-64 and AArch64 processors of today, and may not on a small
//!   processor whose multiplier stops early.
//! - No timing was measured, and no other target or compiler was read.
//!   The AArch64 form is the code of the x86-64 one on other instructions.
//!   It runs on an emulated AArch64 processor, where it gives what its
//!   scalar code and the x86-64 code give, and CI runs the tests on an
//!   AArch64 machine.
//!
//! The `unsafe` code of the crate is in one private module, `common::simd`,
//! and of two kinds. The first is the calls of the code that is compiled
//! for the vector instructions, once the processor is seen to have them:
//! that code takes and returns values, never a pointer. The second is the
//! instructions that set to zero the registers and the stack below the
//! stack pointer after a piece of work.
//!
//! # What the tests compare with
//!
//! The unit tests and `tests/spec_vectors.rs` rest on four kinds of
//! reference values, which do not carry the same weight.
//!
//! | Kind | What is tested against it |
//! |------|---------------------------|
//! | **3GPP** test data | 128-EEA1/2/3 and 128-EIA1/2/3 on the TS 33.401 Annex C, TS 35.217, TS 35.218 and TS 35.223 sets, including non-byte-aligned EEA1, EEA2, EEA3, EIA1, EIA2 and EIA3 inputs; the SNOW 3G and ZUC keystreams; SUCI on every TS 33.501 Annex C.4 data set; MILENAGE on the six sets of TS 35.207 with their intermediate values and on the twenty of TS 35.208, of which set 2 repeats set 1, and its AES on the twenty Rijndael sets of TS 35.208 and the round keys of TS 35.207. |
//! | **RFC and FIPS** test data | HMAC-SHA-256, which is this crate's over the SHA-256 of `sha2`, on test cases 1, 2, 3, 6 and 7 of RFC 4231; SHA-256 on the examples of FIPS 180-4; the subkeys of AES-CMAC on the example of RFC 4493; the key expansion and the cipher of AES on its instructions on the examples of FIPS 197. |
//! | Values of **other implementations** | The 5G AKA chain from the TS 35.208 test set 1 MILENAGE outputs through KAUSF, XRES\*, HXRES\*, KSEAF, KAMF, the NAS keys, KgNB and NH, which `tests/five_g_aka_chain.py` derives with the HMAC-SHA-256 of Python's standard library over the inputs that TS 33.501 Annex A lays out; HASHMME on ATTACH REQUESTs and the values a network returned for them; OPc, the authentication vector, the check of its AUTN, the AUTS and its reading, RES\* and the refusal of an AUTN or an AUTS with a bit changed, against the `milenage` crate 0.1.6, Open5GS 2.8.0 and free5GC (its util 1.3.2) on a million random subscribers, with `differential/` in the repository. |
//! | Values **calculated** in the tests | The other 5GS KDFs, the EPS and interworking KDFs, and the NAS container, short and re-establishment MACs are compared with HMAC-SHA-256 or the MAC over the parameter layout as the test writes it. The identity encodings and the algorithm selection are compared with what the test writes too. MILENAGE with the constants of an operator, which no test data has, is compared with the framework of TS 35.206 §4.1 written bit by bit over the AES of the `aes` crate. These tests keep a layout from changing unnoticed; they are not independent vectors. |
//!
//! The two forms of SNOW 3G and ZUC, on vector instructions and in scalar
//! code, are compared with each other: the keystream words of 400 keys and
//! IVs, taken in pieces of every length, and the six algorithms on messages
//! of every length up to 300 octets, in whole octets and at a length in
//! bits. AES on its instructions is compared with the `aes` crate in the
//! same way, and 128-EIA2 with AES-CMAC as RFC 4493 writes it, at every
//! length in bits up to 70 octets. The 3GPP test data goes through the form
//! that the processor of the test has. CI runs the tests on x86-64, on
//! AArch64, and on 32-bit x86, which has the scalar code alone.
//!
//! [`nea_cipher_batch`] and [`nia_mac_batch`] are compared with the
//! functions of one message on batches of 0 to 40 messages of mixed
//! algorithms and lengths, in whole octets and in bits, with eight
//! generators side by side, with four and in scalar code. The 3GPP test
//! sets of the three ciphering algorithms, of 128-EIA1 and of 128-EIA3, and
//! set 7 of 128-EIA2, also go through them in one batch. The batches of
//! MILENAGE are compared with the functions of one subscriber on 0 to 40
//! subscribers, with the constants of TS 35.206 and with others, and AUTNs
//! that are accepted and refused; every test of MILENAGE runs on the AES
//! instructions and on the `aes` crate.
//!
//! CI also fuzzes what takes octets from a peer, with the four
//! `cargo fuzz` targets under `fuzz/`, for a minute each at a push and for
//! half an hour each week: a SUCI, a scheme output and a NAI
//! are read without a panic, what is concealed is deconcealed, an identity
//! or a digit string that decodes encodes back to its octets, and every
//! algorithm takes any message at any length in bits and gives the same on
//! vector instructions and in scalar code, alone and in a batch.
//!
//! `tests/readme.rs` runs each Rust block of the README and of this page
//! and compares what it prints with the text under it.
//!
//! # Limits
//!
//! | Subject | Limit |
//! |---------|-------|
//! | Audit | The crate has not had a security audit. Its timing has been read in the source and in one compiled build, not measured. |
//! | State | It stores no keys, and it keeps neither the NAS COUNT, nor replay state, nor a SQN: those belong to the caller. |
//! | AKA | It has MILENAGE and not TUAK (TS 35.231). Whether a SQN is fresh and whether an AMF has the separation bit are the caller's to decide. |
//! | NAS messages | It protects octets. It does not encode a NAS message or its security header. |
//! | Re-establishment MAC | The 28-bit reading of the target Cell-ID is this crate's: no test data or other implementation exists to check it against. |
//!
//! # Terms
//!
//! | Term | Meaning |
//! |------|---------|
//! | UE, AMF, MME | The device (User Equipment), and the function of the core network that it talks NAS to: the AMF in 5GS, the MME in EPS |
//! | gNB, eNB | The base station of 5GS and of EPS |
//! | AKA | Authentication and Key Agreement. It gives the ciphering key CK, the integrity key IK, the response RES, and the sequence number SQN hidden under the anonymity key AK |
//! | MILENAGE | The example algorithm set of 3GPP for the functions of AKA, f1 to f5\*: AES with the key K of the subscriber, around OPc, which an operator derives from its OP |
//! | AUTN, AUTS | The authentication token that a network sends with RAND: SQN ⊕ AK, the AMF and MAC-A; and what a USIM answers when the SQN is out of range: SQNMS ⊕ AK\* and MAC-S |
//! | KAUSF, KSEAF, KAMF | The keys of the 5GS hierarchy, each derived from the one before: of the AUSF in the home network, of the SEAF in the serving network, of the AMF |
//! | KNASenc, KNASint | The keys that cipher and authenticate NAS messages, derived from KAMF in 5GS and from KASME in EPS |
//! | KASME | The key of EPS that CK and IK give, at the place of KAMF |
//! | KgNB, KeNB, NH | The key of a base station, and the Next Hop key that replaces it at a handover |
//! | ABBA | Anti-Bidding down Between Architectures: a parameter of the KAMF derivation, `0x0000` so far |
//! | KDF | Key derivation function: HMAC-SHA-256 over a string S that TS 33.220 lays out |
//! | NAS COUNT | The 24-bit counter of the NAS messages of one direction, which the algorithms take |
//! | MAC | Message authentication code: the 32 bits that protect the integrity of a message |
//! | NEA, NIA; EEA, EIA | The ciphering and integrity algorithms, as 5GS and as EPS name them. They are the same four of each |
//! | SUPI, SUCI | The Subscription Permanent Identifier, an IMSI or a NAI, and its concealed form, the Subscription Concealed Identifier that a UE sends |
//! | IMSI, MSIN | The International Mobile Subscriber Identity, and its last part, the subscriber number that a SUCI conceals |
//! | NAI | Network Access Identifier, `username@realm` (RFC 7542) |
//! | GCI, GLI | The Global Cable Identifier and the Global Line Identifier, two identities of wireline access that are written as NAIs |
//! | PLMN, MCC, MNC | A Public Land Mobile Network, which its Mobile Country Code and its Mobile Network Code identify |
//! | 5G-GUTI, 5G-S-TMSI | The temporary identity that an AMF gives a UE, and its short form |
//! | TBCD | Telephony Binary Coded Decimal: two digits to an octet, the first in the low half |
//!
//! # Features
//!
//! `std`, `suci` and `nai` are on by default.
//!
//! | Feature | Adds | Needs |
//! |---------|------|-------|
//! | none | The algorithms, the keyed contexts and the batches, MILENAGE, the keys and every derivation, NAS integrity and ciphering, the selection of the algorithms, the types of the inputs, the SUPI, the 5G-GUTI and the PLMN | `core` alone: no allocator. 15 crates in its tree, oxirush-utils one of them, and no procedural macro |
//! | `alloc` | What returns a `Vec` or a `String`: `kdf::build_s`, `tbcd::encode`, `tbcd::decode`, `Supi::into_owned` | An allocator |
//! | `std` | On an AArch64 system other than Linux, Android and Apple's: the choice of the code on the vector and AES instructions when the program runs. Nothing else | The standard library. It brings `alloc` |
//! | `suci` | `nas_5gs::Suci`: the SUCI of an IMSI in a mobile identity, concealed and de-concealed with the null scheme, Profile A (X25519) and Profile B (secp256r1) | `alloc`, which it brings, and a source of random numbers that `getrandom` has for the target: concealment draws a key. 42 crates |
//! | `nai` | The SUCI in the NAI format, and the SUCI of a SUPI that is a NAI: a network specific identifier, a GCI or a GLI | `suci`, which it brings, with the Unicode normalization and the IDNA of oxirush-utils. 70 crates |
//!
//! Without `std` the crate is `no_std`. The key derivations give the
//! hasher their parameters part after part: the string S of TS 33.220 is
//! not built, and nothing is allocated.
//!
//! The processor is asked what it has when the program first runs an
//! algorithm, with or without `std`: by CPUID on x86-64, and through the
//! auxiliary vector of Linux and Android on AArch64, while Apple's AArch64
//! processors all have the instructions. On a target without an operating
//! system nothing can be asked: the code on the vector and AES instructions
//! runs when the build enables them for every processor of the target, with
//! `-C target-feature=+ssse3,+sse4.1,+aes,+pclmulqdq` or `+neon,+aes`, or
//! with a `-C target-cpu` that has them, and the scalar code otherwise.
//! With `+avx2` as well, a batch has eight generators side by side.
//! [`implementation`] says which code runs, and the values are the same.
//!
//! On a target without an operating system, `getrandom` has no source of
//! random numbers of its own: the program that uses `suci` gives it one, as
//! the documentation of `getrandom` says for its custom backend.
//!
//! # Specifications
//!
//! | Specification | For |
//! |---------------|-----|
//! | TS 33.501 | 5G security architecture: key derivation, algorithm IDs, SUCI |
//! | TS 33.401 | EPS security architecture: key derivation, NAS COUNT, EIA/EEA |
//! | TS 33.102 | 3G security: authentication vectors, AUTN, AUTS, re-synchronisation |
//! | TS 35.205, 35.206, 35.207, 35.208 | MILENAGE: general, algorithm, implementers' test data, conformance test data |
//! | TS 35.215, 35.216, 35.217, 35.218 | SNOW 3G modes, core, and test data |
//! | TS 35.221, 35.222, 35.223 | ZUC modes, core, and test data |

// The tests use the standard library, whatever the features of the build.
#![cfg_attr(not(test), no_std)]
// `unsafe` is allowed in one module, `common::simd`, which says why
#![deny(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

#[cfg(feature = "alloc")]
extern crate alloc;
#[cfg(all(feature = "std", not(test)))]
extern crate std;

mod common;
pub mod milenage;
pub mod nas_5gs;
pub mod nas_eps;

// The examples of the README are compiled and run with the doctests. They
// use every feature.
#[cfg(all(doctest, feature = "nai"))]
#[doc = include_str!("../README.md")]
struct Readme;

/// The key derivation function of TS 33.220 Annex B.2, of which every
/// derivation of [`nas_5gs`] and of [`nas_eps`] is a use: for a
/// derivation that the crate does not have.
pub mod kdf {
    #[cfg(feature = "alloc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
    pub use crate::common::kdf::build_s;
    pub use crate::common::kdf::{extract_128, kdf};
    /// The wrapper of the keys that this module returns, which wipes
    /// them when they are dropped: `Zeroizing` of the `zeroize` crate.
    pub use zeroize::Zeroizing;
}

// The crate root has what 5GS and EPS share, and nothing that one of them
// has under the same name with another meaning: the keys of a hierarchy
// and their derivations are in the module of their system.
pub use common::algo::{
    select_ciphering_algo, select_ciphering_algo_with_preference, select_integrity_algo,
    select_integrity_algo_with_preference,
};
pub use common::batch::{CipherJob, MacJob, nea_cipher_batch, nia_mac_batch};
pub use common::code::{Code, Implementation, implementation};
pub use common::context::{CipheringContext, IntegrityContext};
pub use common::ct::constant_time_eq;
pub use common::error::SecurityError;
pub use common::input::{
    AccessKeyCount, Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount,
};
pub use common::keys::{Autn, CipheringKey, Ck, Ik, IntegrityKey, Rand};
pub use common::nea::{nea_cipher, nea_cipher_bits};
pub use common::nia::{nia_mac, nia_mac_bits};
pub use common::snow3g::Snow3G;
pub use common::zuc::Zuc;
/// The identities of 3GPP networks as values: those of oxirush-utils,
/// whose errors [`SecurityError::Identity`] holds.
pub use oxirush_utils::identity;
/// The PLMN identity: an MCC and an MNC (TS 23.003 §2.2), with its octets
/// in a NAS message (`to_nas_octets`, TS 24.008 §10.5.1.3).
pub use oxirush_utils::identity::Plmn;
/// TBCD strings (TS 29.002): `tbcd::encode` and `tbcd::decode`.
#[cfg(feature = "alloc")]
#[cfg_attr(docsrs, doc(cfg(feature = "alloc")))]
pub use oxirush_utils::identity::tbcd;

/// What the crate's fuzz targets, its emulated AArch64 program and its scan
/// of leftovers drive beside the public functions. A build with
/// `--cfg oxirush_security_hooks` has this module, and no other build.
#[cfg(oxirush_security_hooks)]
#[doc(hidden)]
pub mod hooks {
    /// Run `work` without the clearing of the registers and of the stack
    /// that follows each public operation, to see what the operation
    /// leaves and how deep it goes. The setting is the program's, not a
    /// thread's.
    #[cfg(not(oxirush_security_unwiped))]
    pub fn unwiped<R>(work: impl FnOnce() -> R) -> R {
        crate::common::wipe::hooks::unwiped(work)
    }

    /// How many areas of stack were cleared after pieces of work since the
    /// last call, and the address and the octets of the first eight. Under
    /// [`unwiped`], on x86-64 and on AArch64, they are the areas that would
    /// have been cleared.
    #[cfg(not(oxirush_security_unwiped))]
    pub fn cleared() -> (usize, [(usize, usize); 8]) {
        crate::common::wipe::hooks::cleared()
    }

    /// Run `work` without the vector instructions of the processor, on the
    /// scalar code that every target has. The setting is the program's, not
    /// a thread's.
    pub fn scalar<R>(work: impl FnOnce() -> R) -> R {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        return crate::common::simd::scalar(work);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        work()
    }

    /// Run `work` without the vector instructions of 256 bits, as on a
    /// processor that has those of 128 bits alone.
    pub fn narrow<R>(work: impl FnOnce() -> R) -> R {
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        return crate::common::simd::narrow(work);
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        work()
    }
}
