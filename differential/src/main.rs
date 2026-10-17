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

//! MILENAGE of oxirush-security beside three other implementations, on
//! random subscribers: the `milenage` crate 0.1.6, Open5GS (C) and
//! free5GC (Go).
//!
//! ```text
//! usage: oxirush-security-differential [CASES] [--seed SEED] [--without open5gs|free5gc]
//! ```
//!
//! Each case draws K, OP, RAND, SQN, AMF and SQNMS. The crate computes OPc,
//! an authentication vector, the check of its AUTN by a USIM, an AUTS for
//! SQNMS and its reading by the home network, RES\* of 5GS, and the
//! refusal of the AUTN and of the AUTS with one bit changed. Each other
//! implementation computes what it has of these with its own functions,
//! and every value must be the same:
//!
//! | Implementation | Its functions |
//! |----------------|---------------|
//! | `milenage` 0.1.6 | `Milenage::new_with_op`, `f1`, `f1star`, `f2345`, `f5star`, `compute_res_star` |
//! | Open5GS | `milenage_opc`, `milenage_generate`, `milenage_check`, `milenage_f1`, `milenage_f2345`, `milenage_auts` of `lib/crypt/milenage.c`, built from the tree that `OPEN5GS` names when this program is built |
//! | free5GC | `GenerateOPc`, `GenerateAKAParameters`, `GenerateKeysWithAUTN`, `GenerateAUTS`, `ValidateAUTS` of `github.com/free5gc/util/milenage`, in the program of `free5gc/`, which `FREE5GC` names when this one runs |
//!
//! The run fails when a value differs, and when Open5GS or free5GC is
//! missing, unless `--without` names it. A case that differs is printed by
//! its number and the seed, which draw it again: no key is printed.

use oxirush_security::milenage::{Amf, Auts, K, Milenage, Op, Opc, Sqn};
use oxirush_security::{Autn, Rand};
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, ExitCode, Stdio};

/// Numbers that look random, the same for a seed.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn octets<const N: usize>(&mut self) -> [u8; N] {
        core::array::from_fn(|_| self.next() as u8)
    }
}

/// The inputs of a case.
struct Case {
    k: [u8; 16],
    op: [u8; 16],
    rand: [u8; 16],
    sqn: [u8; 6],
    amf: [u8; 2],
    sqn_ms: [u8; 6],
    /// The bit of the AUTN, and of the AUTS, that is changed.
    bit: usize,
}

/// What an implementation gives for a case, as octets: each value has a
/// name, and an implementation gives those that it has.
type Outputs = Vec<(&'static str, Vec<u8>)>;

const SN_NAME: &[u8] = b"5G:mnc093.mcc208.3gppnetwork.org";

/// The values of this crate.
fn oxirush(case: &Case) -> Outputs {
    let k = K::new(&case.k);
    let opc = Opc::from_op(&k, &Op::new(&case.op));
    let subscriber = Milenage::new(&k, &opc);
    let (rand, sqn, amf) = (
        Rand::new(&case.rand),
        Sqn::new(&case.sqn),
        Amf::new(&case.amf),
    );
    let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
    let response = subscriber
        .check_autn(&rand, vector.autn())
        .expect("the AUTN of the vector");
    let auts = subscriber.auts(&rand, &Sqn::new(&case.sqn_ms));
    let sqn_ms = subscriber
        .verify_auts(&rand, &auts)
        .expect("the AUTS of the USIM");

    let mut autn = *vector.autn().as_octets();
    autn[case.bit % 128 / 8] ^= 0x80 >> (case.bit % 8);
    let autn_refused = subscriber.check_autn(&rand, &Autn::new(&autn)).is_err();
    let mut changed = *auts.as_octets();
    changed[case.bit % 112 / 8] ^= 0x80 >> (case.bit % 8);
    let auts_refused = subscriber.verify_auts(&rand, &Auts::new(&changed)).is_err();
    let res_star = response.res_star(SN_NAME).expect("a serving network name");

    vec![
        ("OPc", opc.as_octets().to_vec()),
        ("AUTN", vector.autn().as_octets().to_vec()),
        ("XRES", vector.xres().as_octets().to_vec()),
        ("CK", vector.ck().as_octets().to_vec()),
        ("IK", vector.ik().as_octets().to_vec()),
        ("AK", subscriber.f5(&rand).as_octets().to_vec()),
        ("SQN of the USIM", response.sqn().as_octets().to_vec()),
        ("RES of the USIM", response.res().as_octets().to_vec()),
        ("CK of the USIM", response.ck().as_octets().to_vec()),
        ("IK of the USIM", response.ik().as_octets().to_vec()),
        ("AUTS", auts.as_octets().to_vec()),
        ("SQNMS of the AUTS", sqn_ms.as_octets().to_vec()),
        (
            "AUTN with a bit changed refused",
            vec![u8::from(autn_refused)],
        ),
        (
            "AUTS with a bit changed refused",
            vec![u8::from(auts_refused)],
        ),
        ("RES*", res_star.as_octets().to_vec()),
    ]
}

/// The values of the `milenage` crate 0.1.6, the AUTN and the AUTS made of
/// its functions as its users make them.
fn milenage_0_1_6(case: &Case) -> Outputs {
    let mut subscriber = milenage::Milenage::new_with_op(case.k, case.op);
    let opc = subscriber.opc;
    let mac_a = subscriber.f1(&case.rand, &case.sqn, &case.amf);
    let (res, ck, ik, ak) = subscriber.f2345(&case.rand);
    let mut autn = [0u8; 16];
    for (at, octet) in autn[..6].iter_mut().enumerate() {
        *octet = case.sqn[at] ^ ak[at];
    }
    autn[6..8].copy_from_slice(&case.amf);
    autn[8..].copy_from_slice(&mac_a);
    let ak_star = subscriber.f5star(&case.rand);
    let mac_s = subscriber.f1star(&case.rand, &case.sqn_ms, &[0, 0]);
    let mut auts = [0u8; 14];
    for (at, octet) in auts[..6].iter_mut().enumerate() {
        *octet = case.sqn_ms[at] ^ ak_star[at];
    }
    auts[6..].copy_from_slice(&mac_s);
    let res_star = subscriber
        .compute_res_star("208", "93", &case.rand, &res)
        .expect("a PLMN");
    vec![
        ("OPc", opc.to_vec()),
        ("AUTN", autn.to_vec()),
        ("XRES", res.to_vec()),
        ("CK", ck.to_vec()),
        ("IK", ik.to_vec()),
        ("AK", ak.to_vec()),
        ("AUTS", auts.to_vec()),
        ("RES*", res_star.to_vec()),
    ]
}

/// Open5GS, built from its source tree with this program.
#[cfg(open5gs)]
mod open5gs {
    use super::{Case, Outputs};
    use std::os::raw::c_int;

    unsafe extern "C" {
        fn milenage_opc(k: *const u8, op: *const u8, opc: *mut u8);
        fn milenage_generate(
            opc: *const u8,
            amf: *const u8,
            k: *const u8,
            sqn: *const u8,
            rand: *const u8,
            autn: *mut u8,
            ik: *mut u8,
            ck: *mut u8,
            ak: *mut u8,
            res: *mut u8,
            res_len: *mut usize,
        );
        fn milenage_check(
            opc: *const u8,
            k: *const u8,
            sqn: *const u8,
            rand: *const u8,
            autn: *const u8,
            ik: *mut u8,
            ck: *mut u8,
            res: *mut u8,
            res_len: *mut usize,
            auts: *mut u8,
        ) -> c_int;
        fn milenage_f1(
            opc: *const u8,
            k: *const u8,
            rand: *const u8,
            sqn: *const u8,
            amf: *const u8,
            mac_a: *mut u8,
            mac_s: *mut u8,
        ) -> c_int;
        fn milenage_f2345(
            opc: *const u8,
            k: *const u8,
            rand: *const u8,
            res: *mut u8,
            ck: *mut u8,
            ik: *mut u8,
            ak: *mut u8,
            akstar: *mut u8,
        ) -> c_int;
        fn milenage_auts(
            opc: *const u8,
            k: *const u8,
            rand: *const u8,
            auts: *const u8,
            sqn: *mut u8,
        ) -> c_int;
    }

    /// The values of Open5GS. Its check of an AUTN takes the SQNMS of the
    /// USIM and refuses a SQN that is not above it: it is given zeros.
    pub fn values(case: &Case) -> Outputs {
        let (mut opc, mut autn, mut ik, mut ck, mut ak, mut res) = (
            [0u8; 16], [0u8; 16], [0u8; 16], [0u8; 16], [0u8; 6], [0u8; 8],
        );
        let (mut ue_ik, mut ue_ck, mut ue_res, mut ue_auts) =
            ([0u8; 16], [0u8; 16], [0u8; 8], [0u8; 14]);
        let (mut mac_s, mut ak_star, mut sqn_ms, mut ignored) =
            ([0u8; 8], [0u8; 6], [0u8; 6], [0u8; 6]);
        let (mut res_len, mut ue_res_len) = (8usize, 8usize);
        let none = std::ptr::null_mut();
        let zeros = [0u8; 6];
        let check = |autn: &[u8; 16],
                     ik: &mut [u8; 16],
                     ck: &mut [u8; 16],
                     res: &mut [u8; 8],
                     res_len: &mut usize,
                     auts: &mut [u8; 14],
                     opc: &[u8; 16]| {
            // SAFETY: each pointer is that of an array of the length that
            // `milenage_check` reads or writes there (lib/crypt/milenage.c).
            unsafe {
                milenage_check(
                    opc.as_ptr(),
                    case.k.as_ptr(),
                    zeros.as_ptr(),
                    case.rand.as_ptr(),
                    autn.as_ptr(),
                    ik.as_mut_ptr(),
                    ck.as_mut_ptr(),
                    res.as_mut_ptr(),
                    res_len,
                    auts.as_mut_ptr(),
                )
            }
        };
        // SAFETY: each pointer is that of an array of the length that the
        // function reads or writes there (lib/crypt/milenage.c), or null
        // where the function takes null for an output it is not asked for.
        unsafe {
            milenage_opc(case.k.as_ptr(), case.op.as_ptr(), opc.as_mut_ptr());
            milenage_generate(
                opc.as_ptr(),
                case.amf.as_ptr(),
                case.k.as_ptr(),
                case.sqn.as_ptr(),
                case.rand.as_ptr(),
                autn.as_mut_ptr(),
                ik.as_mut_ptr(),
                ck.as_mut_ptr(),
                ak.as_mut_ptr(),
                res.as_mut_ptr(),
                &mut res_len,
            );
            // AUTS = SQNMS ⊕ AK*, then MAC-S with an AMF of zeros
            milenage_f2345(
                opc.as_ptr(),
                case.k.as_ptr(),
                case.rand.as_ptr(),
                none,
                none,
                none,
                none,
                ak_star.as_mut_ptr(),
            );
            milenage_f1(
                opc.as_ptr(),
                case.k.as_ptr(),
                case.rand.as_ptr(),
                case.sqn_ms.as_ptr(),
                zeros[..2].as_ptr(),
                none,
                mac_s.as_mut_ptr(),
            );
        }
        let mut auts = [0u8; 14];
        for (at, octet) in auts[..6].iter_mut().enumerate() {
            *octet = case.sqn_ms[at] ^ ak_star[at];
        }
        auts[6..].copy_from_slice(&mac_s);
        let mut changed_auts = auts;
        changed_auts[case.bit % 112 / 8] ^= 0x80 >> (case.bit % 8);
        let mut changed_autn = autn;
        changed_autn[case.bit % 128 / 8] ^= 0x80 >> (case.bit % 8);

        let (mut other_ik, mut other_ck, mut other_res, mut other_auts) =
            ([0u8; 16], [0u8; 16], [0u8; 8], [0u8; 14]);
        let mut other_len = 8usize;
        let checked = check(
            &autn,
            &mut ue_ik,
            &mut ue_ck,
            &mut ue_res,
            &mut ue_res_len,
            &mut ue_auts,
            &opc,
        );
        let refused_autn = check(
            &changed_autn,
            &mut other_ik,
            &mut other_ck,
            &mut other_res,
            &mut other_len,
            &mut other_auts,
            &opc,
        ) != 0;
        // SAFETY: as above, for `milenage_auts`.
        let (read, refused_auts) = unsafe {
            (
                milenage_auts(
                    opc.as_ptr(),
                    case.k.as_ptr(),
                    case.rand.as_ptr(),
                    auts.as_ptr(),
                    sqn_ms.as_mut_ptr(),
                ),
                milenage_auts(
                    opc.as_ptr(),
                    case.k.as_ptr(),
                    case.rand.as_ptr(),
                    changed_auts.as_ptr(),
                    ignored.as_mut_ptr(),
                ) != 0,
            )
        };
        let mut outputs = vec![
            ("OPc", opc.to_vec()),
            ("AUTN", autn.to_vec()),
            ("XRES", res[..res_len].to_vec()),
            ("CK", ck.to_vec()),
            ("IK", ik.to_vec()),
            ("AK", ak.to_vec()),
            ("AUTS", auts.to_vec()),
            (
                "AUTN with a bit changed refused",
                vec![u8::from(refused_autn)],
            ),
            (
                "AUTS with a bit changed refused",
                vec![u8::from(refused_auts)],
            ),
        ];
        match checked {
            0 => outputs.extend([
                ("RES of the USIM", ue_res[..ue_res_len].to_vec()),
                ("CK of the USIM", ue_ck.to_vec()),
                ("IK of the USIM", ue_ik.to_vec()),
            ]),
            _ => outputs.push(("the AUTN of the vector accepted", vec![0])),
        }
        match read {
            0 => outputs.push(("SQNMS of the AUTS", sqn_ms.to_vec())),
            _ => outputs.push(("the AUTS accepted", vec![0])),
        }
        outputs
    }
}

/// The program of free5GC, which takes the inputs of a case on a line and
/// gives its values on a line (`free5gc/main.go`).
struct Free5gc {
    child: std::process::Child,
    output: BufReader<std::process::ChildStdout>,
}

impl Free5gc {
    fn start(program: &std::ffi::OsStr) -> std::io::Result<Self> {
        let mut child = Command::new(program)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?;
        let output = BufReader::new(child.stdout.take().expect("its standard output"));
        Ok(Self { child, output })
    }

    fn values(&mut self, case: &Case) -> Outputs {
        let h = |octets: &[u8]| hex::encode(octets);
        let input = self.child.stdin.as_mut().expect("its standard input");
        let fields = [
            h(&case.k),
            h(&case.op),
            h(&case.rand),
            h(&case.sqn),
            h(&case.amf),
            h(&case.sqn_ms),
            case.bit.to_string(),
        ];
        writeln!(input, "{}", fields.join(" ")).expect("free5GC takes a line");
        let mut line = String::new();
        self.output
            .read_line(&mut line)
            .expect("free5GC gives a line");
        let fields: Vec<&str> = line.split_whitespace().collect();
        let names = [
            "OPc",
            "AUTN",
            "XRES",
            "CK",
            "IK",
            "SQN of the USIM",
            "AK",
            "CK of the USIM",
            "IK of the USIM",
            "RES of the USIM",
            "AUTS",
            "SQNMS of the AUTS",
        ];
        if fields.len() != names.len() + 2 {
            return vec![("a line of values from free5GC", line.into_bytes())];
        }
        let mut outputs: Outputs = names
            .iter()
            .zip(&fields)
            .map(|(name, value)| (*name, hex::decode(value).unwrap_or_default()))
            .collect();
        for (name, value) in [
            "AUTN with a bit changed refused",
            "AUTS with a bit changed refused",
        ]
        .into_iter()
        .zip(&fields[names.len()..])
        {
            outputs.push((name, vec![u8::from(*value == "true")]));
        }
        outputs
    }
}

/// The names of the values of `theirs` that are not those of `ours`.
fn differences(ours: &Outputs, theirs: &Outputs) -> Vec<&'static str> {
    theirs
        .iter()
        .filter(|(name, value)| {
            ours.iter()
                .find(|(our_name, _)| our_name == name)
                .is_none_or(|(_, our_value)| our_value != value)
        })
        .map(|(name, _)| *name)
        .collect()
}

fn main() -> ExitCode {
    let mut arguments = std::env::args().skip(1);
    let (mut cases, mut seed, mut without) = (100_000u64, 0x9e37_79b9_7f4a_7c15u64, Vec::new());
    while let Some(argument) = arguments.next() {
        match argument.as_str() {
            "--seed" => {
                seed = arguments
                    .next()
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(seed)
            }
            "--without" => without.extend(arguments.next()),
            number => match number.parse() {
                Ok(number) => cases = number,
                Err(_) => {
                    eprintln!(
                        "usage: oxirush-security-differential [CASES] [--seed SEED] [--without open5gs|free5gc]"
                    );
                    return ExitCode::FAILURE;
                }
            },
        }
    }
    let wanted = |name: &str| !without.iter().any(|without| without == name);

    let mut failed = false;
    #[cfg(not(open5gs))]
    if wanted("open5gs") {
        eprintln!(
            "FAILED: no Open5GS: build with OPEN5GS naming its source tree, or --without open5gs"
        );
        failed = true;
    }
    let mut free5gc = match std::env::var_os("FREE5GC") {
        Some(program) if wanted("free5gc") => match Free5gc::start(&program) {
            Ok(free5gc) => Some(free5gc),
            Err(error) => {
                eprintln!("FAILED: free5GC: {error}");
                failed = true;
                None
            }
        },
        _ if wanted("free5gc") => {
            eprintln!(
                "FAILED: no free5GC: FREE5GC names the program of free5gc/, or --without free5gc"
            );
            failed = true;
            None
        }
        _ => None,
    };
    if failed {
        return ExitCode::FAILURE;
    }

    let mut implementations: Vec<(&str, u64, u64)> = vec![("milenage 0.1.6", 0, 0)];
    #[cfg(open5gs)]
    if wanted("open5gs") {
        implementations.push(("Open5GS", 0, 0));
    }
    if free5gc.is_some() {
        implementations.push(("free5GC", 0, 0));
    }

    let mut random = Random(seed);
    for number in 0..cases {
        let case = Case {
            k: random.octets(),
            op: random.octets(),
            rand: random.octets(),
            sqn: random.octets(),
            amf: random.octets(),
            sqn_ms: random.octets(),
            bit: (random.next() % 128) as usize,
        };
        let ours = oxirush(&case);
        for (name, compared, different) in &mut implementations {
            let theirs = match *name {
                "milenage 0.1.6" => milenage_0_1_6(&case),
                #[cfg(open5gs)]
                "Open5GS" => open5gs::values(&case),
                _ => free5gc
                    .as_mut()
                    .map(|free5gc| free5gc.values(&case))
                    .unwrap_or_default(),
            };
            let differ = differences(&ours, &theirs);
            *compared += theirs.len() as u64;
            if !differ.is_empty() {
                *different += 1;
                if *different <= 5 {
                    println!(
                        "case {number} of seed {seed}: {name} differs in {}",
                        differ.join(", ")
                    );
                }
            }
        }
    }

    println!("{cases} random subscribers of seed {seed}:");
    for (name, compared, different) in &implementations {
        println!("  {name}: {compared} values compared, {different} cases differ");
        failed |= *different > 0;
    }
    if failed {
        println!("FAILED");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}
