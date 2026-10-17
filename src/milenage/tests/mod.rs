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

//! MILENAGE on every test set of TS 35.207 and TS 35.208, with their
//! intermediate values, and the authentication of TS 33.102 on it.
//!
//! Each test runs in both forms of the code: AES on the instructions of
//! the processor, and the `aes` crate, as a processor without them has it.

mod sets;

use super::kernel::{Temp, in1, with_kernel};
use super::*;
use crate::common::error::SecurityError;
use crate::common::keys::Autn;
use sets::{RIJNDAEL, ROUND_KEYS, TS_35_207_F1, TS_35_207_F2_TO_F5, TS_35_208};

fn octets<const N: usize>(hexadecimal: &str) -> [u8; N] {
    hex::decode(hexadecimal)
        .expect("hexadecimal digits")
        .try_into()
        .expect("the length of the value")
}

fn number(hexadecimal: &str) -> u128 {
    u128::from_be_bytes(octets(hexadecimal))
}

/// `test` in each form of the code: on the AES instructions where this
/// processor has them, and with the `aes` crate.
fn in_both_forms(test: impl Fn(&str)) {
    test("the code of this processor");
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    crate::common::simd::scalar(|| test("the aes crate"));
}

/// Numbers that look random, the same at every run.
fn random(seed: u64) -> impl FnMut() -> u64 {
    let mut state = seed;
    move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    }
}

fn random_octets<const N: usize>(next: &mut impl FnMut() -> u64) -> [u8; N] {
    core::array::from_fn(|_| next() as u8)
}

#[test]
fn every_set_of_ts_35_208() {
    // Set 2 is set 1 again, as the document has it
    assert_eq!(TS_35_208[1], TS_35_208[0]);
    in_both_forms(|form| {
        for (set, values) in (1..).zip(TS_35_208) {
            let [
                k,
                rand,
                sqn,
                amf,
                op,
                opc,
                f1,
                f1_star,
                f2,
                f5,
                f3,
                f4,
                f5_star,
            ] = values;
            let k = K::new(&octets(k));
            let computed = Opc::from_op(&k, &Op::new(&octets(op)));
            assert_eq!(computed, octets(opc), "OPc, set {set}, {form}");

            let subscriber = Milenage::new(&k, &computed);
            let (rand, sqn, amf) = (
                Rand::new(&octets(rand)),
                Sqn::new(&octets(sqn)),
                Amf::new(&octets(amf)),
            );
            let name = |function| format!("{function}, set {set}, {form}");
            assert_eq!(
                subscriber.f1(&rand, &sqn, &amf),
                octets(f1),
                "{}",
                name("f1")
            );
            let mac_s = subscriber.f1_star(&rand, &sqn, &amf);
            assert_eq!(mac_s, octets(f1_star), "{}", name("f1*"));
            assert_eq!(subscriber.f2(&rand), octets(f2), "{}", name("f2"));
            assert_eq!(subscriber.f3(&rand), octets(f3), "{}", name("f3"));
            assert_eq!(subscriber.f4(&rand), octets(f4), "{}", name("f4"));
            assert_eq!(subscriber.f5(&rand), octets(f5), "{}", name("f5"));
            assert_eq!(
                subscriber.f5_star(&rand),
                octets(f5_star),
                "{}",
                name("f5*")
            );

            let (res, ck, ik, ak) = subscriber.f2345(&rand);
            assert_eq!(
                (res, ck, ik, ak),
                (
                    Res::new(&octets(f2)),
                    Ck::new(&octets(f3)),
                    Ik::new(&octets(f4)),
                    Ak::new(&octets(f5)),
                ),
                "{}",
                name("f2345")
            );
        }
    });
}

/// The intermediate values of TS 35.207 §4 for f1 and f1\*: IN1, OPc,
/// TEMP, rot(IN1 ⊕ OPc, r1), and the input and the output of the second
/// encryption.
#[test]
fn the_intermediate_values_of_f1_in_ts_35_207() {
    in_both_forms(|form| {
        for (set, values) in (1..).zip(TS_35_207_F1) {
            let [
                k,
                rand,
                sqn,
                amf,
                op,
                in_1,
                opc,
                temp,
                rotated,
                input,
                output,
                f1,
                f1_star,
            ] = values;
            let k = K::new(&octets(k));
            let computed = Opc::from_op(&k, &Op::new(&octets(op)));
            assert_eq!(computed, octets(opc), "OPc, set {set}, {form}");
            let (sqn, amf) = (octets(sqn), octets(amf));
            assert_eq!(in1(&sqn, &amf), number(in_1), "IN1, set {set}");

            let constants = Constants::default();
            with_kernel(k.as_octets(), |kernel| {
                let opc = computed.as_octets();
                let of_rand = Temp::new(kernel, &constants, opc, &octets(rand));
                assert_eq!(of_rand.temp(), number(temp), "TEMP, set {set}, {form}");
                let opc = u128::from_be_bytes(*opc);
                assert_eq!(
                    (number(in_1) ^ opc).rotate_left(64),
                    number(rotated),
                    "rot(IN1 ⊕ OPc, r1), set {set}"
                );
                let second = of_rand.input_1(&sqn, &amf);
                assert_eq!(second, number(input), "input of OUT1, set {set}, {form}");
                let out1 = of_rand.outputs([second])[0];
                assert_eq!(out1 ^ opc, number(output), "E of OUT1, set {set}, {form}");
            });
            let (subscriber, rand) = (Milenage::new(&k, &computed), Rand::new(&octets(rand)));
            let (sqn, amf) = (Sqn::new(&sqn), Amf::new(&amf));
            assert_eq!(
                subscriber.f1(&rand, &sqn, &amf),
                octets(f1),
                "f1, set {set}"
            );
            let mac_s = subscriber.f1_star(&rand, &sqn, &amf);
            assert_eq!(mac_s, octets(f1_star), "f1*, set {set}");
        }
    });
}

/// The intermediate values of TS 35.207 §5 and §6 for f2 to f5\*: OPc,
/// TEMP ⊕ OPc, and the input and the output of each second encryption.
#[test]
fn the_intermediate_values_of_f2_to_f5_in_ts_35_207() {
    in_both_forms(|form| {
        for (set, values) in (1..).zip(TS_35_207_F2_TO_F5) {
            let [k, rand, op, opc, temp_opc] = [0, 1, 2, 3, 4].map(|at| values[at]);
            let inputs: [&str; 4] = [5, 6, 7, 8].map(|at| values[at]);
            let outputs: [&str; 4] = [9, 10, 11, 12].map(|at| values[at]);
            let [f2, f5, f3, f4, f5_star] = [13, 14, 15, 16, 17].map(|at| values[at]);

            let k = K::new(&octets(k));
            let computed = Opc::from_op(&k, &Op::new(&octets(op)));
            assert_eq!(computed, octets(opc), "OPc, set {set}, {form}");
            let constants = Constants::default();
            with_kernel(k.as_octets(), |kernel| {
                let of_rand = Temp::new(kernel, &constants, computed.as_octets(), &octets(rand));
                let opc = number(opc);
                assert_eq!(
                    of_rand.temp() ^ opc,
                    number(temp_opc),
                    "TEMP ⊕ OPc, set {set}"
                );
                // f2 and f5, f3, f4, f5*: OUT2, OUT3, OUT4 and OUT5
                for ((i, input), output) in (2..).zip(inputs).zip(outputs) {
                    let second = of_rand.input(i);
                    assert_eq!(second, number(input), "input of OUT{i}, set {set}, {form}");
                    let out = of_rand.outputs([second])[0];
                    assert_eq!(out ^ opc, number(output), "E of OUT{i}, set {set}, {form}");
                }
            });

            let (subscriber, rand) = (Milenage::new(&k, &computed), Rand::new(&octets(rand)));
            assert_eq!(subscriber.f2(&rand), octets(f2), "f2, set {set}");
            assert_eq!(subscriber.f5(&rand), octets(f5), "f5, set {set}");
            assert_eq!(subscriber.f3(&rand), octets(f3), "f3, set {set}");
            assert_eq!(subscriber.f4(&rand), octets(f4), "f4, set {set}");
            assert_eq!(subscriber.f5_star(&rand), octets(f5_star), "f5*, set {set}");
        }
    });
}

/// The kernel of MILENAGE on the Rijndael sets of TS 35.208 §3.3, and the
/// round keys of those of TS 35.207 §3 on the AES instructions.
#[test]
fn the_kernel_is_the_rijndael_of_ts_35_207_and_ts_35_208() {
    in_both_forms(|form| {
        for (set, [plaintext, ciphertext, key]) in (1..).zip(RIJNDAEL) {
            with_kernel(&octets(key), |kernel| {
                let mut block = [number(plaintext)];
                kernel.encrypt(&mut block);
                assert_eq!(block[0], number(ciphertext), "Rijndael set {set}, {form}");
            });
        }
        for (set, values) in (1..).zip(ROUND_KEYS) {
            with_kernel(&octets(values[0]), |kernel| {
                let mut block = [number(values[1])];
                kernel.encrypt(&mut block);
                assert_eq!(block[0], number(values[13]), "TS 35.207 set {set}, {form}");
                #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
                if let super::kernel::Kernel::Instructions(_, schedule) = kernel {
                    for (round, expected) in values[2..13].iter().enumerate() {
                        let round_key = schedule[round].to_le_bytes();
                        assert_eq!(hex::encode(round_key), *expected, "round key {round}");
                    }
                }
            });
        }
    });
}

/// A subscriber, a RAND, a SQN and an AMF drawn from `next`.
fn drawn(next: &mut impl FnMut() -> u64) -> (Milenage, Rand, Sqn, Amf) {
    let (k, opc) = (K::new(&random_octets(next)), Opc::new(&random_octets(next)));
    (
        Milenage::new(&k, &opc),
        Rand::new(&random_octets(next)),
        Sqn::new(&random_octets(next)),
        Amf::new(&random_octets(next)),
    )
}

#[test]
fn a_vector_is_made_of_the_functions_and_its_autn_is_accepted() {
    in_both_forms(|form| {
        let mut next = random(0x9e37_79b9_7f4a_7c15);
        for _ in 0..200 {
            let (subscriber, rand, sqn, amf) = drawn(&mut next);
            let vector = subscriber.authentication_vector(&rand, &sqn, &amf);
            let (res, ck, ik, ak) = subscriber.f2345(&rand);
            let mac_a = subscriber.f1(&rand, &sqn, &amf);
            let mut autn = [0u8; 16];
            for ((octet, sqn), ak) in autn.iter_mut().zip(sqn.as_octets()).zip(ak.as_octets()) {
                *octet = sqn ^ ak;
            }
            autn[6..8].copy_from_slice(amf.as_octets());
            autn[8..].copy_from_slice(mac_a.as_octets());
            assert_eq!(vector.autn(), &Autn::new(&autn), "{form}");
            assert_eq!(vector.rand(), &rand);
            assert!(vector.xres().accepts(&res));
            assert_eq!((vector.ck(), vector.ik()), (&ck, &ik));

            let response = subscriber
                .check_autn(&rand, vector.autn())
                .expect("accepted");
            assert_eq!((response.sqn(), response.amf()), (&sqn, &amf), "{form}");
            assert_eq!(
                (response.res(), response.ck(), response.ik()),
                (&res, &ck, &ik)
            );
        }
    });
}

#[test]
fn an_autn_with_one_bit_changed_is_refused() {
    in_both_forms(|form| {
        let mut next = random(0xd1b5_4a32_d192_ed03);
        for _ in 0..8 {
            let (subscriber, rand, sqn, amf) = drawn(&mut next);
            let autn = *subscriber
                .authentication_vector(&rand, &sqn, &amf)
                .autn()
                .as_octets();
            for bit in 0..128 {
                let mut changed = autn;
                changed[bit / 8] ^= 0x80 >> (bit % 8);
                assert_eq!(
                    subscriber
                        .check_autn(&rand, &Autn::new(&changed))
                        .map(|_| ()),
                    Err(SecurityError::MacFailure),
                    "bit {bit}, {form}"
                );
            }
            // Nor is it the AUTN of another RAND, or of another subscriber
            let mut other = *rand.as_octets();
            other[15] ^= 1;
            let refused = subscriber.check_autn(&Rand::new(&other), &Autn::new(&autn));
            assert_eq!(refused.map(|_| ()), Err(SecurityError::MacFailure));
            let (stranger, ..) = drawn(&mut next);
            let refused = stranger.check_autn(&rand, &Autn::new(&autn));
            assert_eq!(refused.map(|_| ()), Err(SecurityError::MacFailure));
        }
    });
}

#[test]
fn an_auts_gives_its_sqn_ms_back_and_one_bit_changed_is_refused() {
    in_both_forms(|form| {
        let mut next = random(0x2545_f491_4f6c_dd1d);
        for round in 0..200 {
            let (subscriber, rand, sqn_ms, _) = drawn(&mut next);
            let auts = subscriber.auts(&rand, &sqn_ms);
            // SQNMS ⊕ AK*, then MAC-S with an AMF of zeros
            let ak_star = subscriber.f5_star(&rand);
            let mac_s = subscriber.f1_star(&rand, &sqn_ms, &Amf::new(&[0, 0]));
            let concealed: [u8; 6] =
                core::array::from_fn(|at| sqn_ms.as_octets()[at] ^ ak_star.as_octets()[at]);
            assert_eq!(&auts.as_octets()[..6], &concealed, "{form}");
            assert_eq!(&auts.as_octets()[6..], mac_s.as_octets(), "{form}");
            assert_eq!(
                subscriber.verify_auts(&rand, &auts),
                Ok(sqn_ms.clone()),
                "{form}"
            );

            if round < 8 {
                for bit in 0..112 {
                    let mut changed = *auts.as_octets();
                    changed[bit / 8] ^= 0x80 >> (bit % 8);
                    assert_eq!(
                        subscriber.verify_auts(&rand, &Auts::new(&changed)),
                        Err(SecurityError::MacFailure),
                        "bit {bit}, {form}"
                    );
                }
                // The AUTS of a RAND is not that of another one
                let mut other = *rand.as_octets();
                other[0] ^= 0x80;
                let refused = subscriber.verify_auts(&Rand::new(&other), &auts);
                assert_eq!(refused, Err(SecurityError::MacFailure));
            }
        }
    });
}

/// RES\* and XRES\* of test set 1 of TS 35.208, whose RES, CK and IK the
/// 5G AKA chain of the crate takes (`tests/five_g_aka_chain.py`).
#[test]
fn res_star_and_xres_star_are_those_of_the_kdf() {
    let [k, rand, sqn, amf, _, opc, ..] = TS_35_208[0];
    let subscriber = Milenage::new(&K::new(&octets(k)), &Opc::new(&octets(opc)));
    let rand = Rand::new(&octets(rand));
    let vector =
        subscriber.authentication_vector(&rand, &Sqn::new(&octets(sqn)), &Amf::new(&octets(amf)));
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let xres_star = vector.xres_star(sn_name).unwrap();
    assert_eq!(
        hex::encode(xres_star.as_octets()),
        "5cc9527f4d21c43bee83a15443acf1c4"
    );
    let response = subscriber.check_autn(&rand, vector.autn()).unwrap();
    assert!(xres_star.accepts(&response.res_star(sn_name).unwrap()));
    let other = response
        .res_star(b"5G:mnc001.mcc001.3gppnetwork.org")
        .unwrap();
    assert!(!xres_star.accepts(&other));
}

/// The framework of TS 35.206 §4.1 as it is written: bit strings, a
/// rotation of a string towards its first bit, and E of the `aes` crate.
/// For constants that an operator chose, which no test data has.
fn written_out(
    k: &[u8; 16],
    opc: &[u8; 16],
    rand: &[u8; 16],
    in1: &[u8; 16],
    c: &[[u8; 16]; 5],
    r: &[u8; 5],
) -> [[u8; 16]; 5] {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let e = |x: [u8; 16]| {
        let mut block = x;
        aes::Aes128Enc::new(k.into()).encrypt_block((&mut block).into());
        block
    };
    let xor = |a: [u8; 16], b: [u8; 16]| -> [u8; 16] { core::array::from_fn(|at| a[at] ^ b[at]) };
    let bit = |x: &[u8; 16], at: usize| (x[at / 8] >> (7 - at % 8)) & 1;
    // y = x[r] || x[r+1] || ... || x[127] || x[0] || ... || x[r-1]
    let rot = |x: [u8; 16], r: u8| -> [u8; 16] {
        let mut y = [0u8; 16];
        for at in 0..128 {
            y[at / 8] |= bit(&x, (at + usize::from(r)) % 128) << (7 - at % 8);
        }
        y
    };
    let temp = e(xor(*rand, *opc));
    let mut out = [[0u8; 16]; 5];
    out[0] = xor(e(xor(xor(temp, rot(xor(*in1, *opc), r[0])), c[0])), *opc);
    for i in 1..5 {
        out[i] = xor(e(xor(rot(xor(temp, *opc), r[i]), c[i])), *opc);
    }
    out
}

#[test]
fn constants_of_an_operator_are_taken_as_the_framework_writes_them() {
    // Those of TS 35.206 §4.1, and their checks
    let mut c = [[0u8; 16]; 5];
    for (constant, last) in c.iter_mut().zip([0, 1, 2, 4, 8]) {
        constant[15] = last;
    }
    assert_eq!(
        Constants::new(c, [64, 0, 32, 64, 96]),
        Ok(Constants::default())
    );
    assert_eq!(
        Constants::new(c, [64, 0, 32, 128, 96]),
        Err(SecurityError::OutOfRange {
            field: "r",
            maximum: 127,
            got: 128
        })
    );
    let (mut same, mut rotations) = (c, [64, 0, 32, 64, 96]);
    same[3] = same[1];
    rotations[3] = rotations[1];
    assert!(matches!(
        Constants::new(same, rotations),
        Err(SecurityError::InvalidParameter(_))
    ));
    // A pair that differs by its constant alone, or its rotation alone, is
    // another pair
    assert!(Constants::new(same, [64, 0, 32, 8, 96]).is_ok());

    in_both_forms(|form| {
        let mut next = random(0x510e_527f_ade6_82d1);
        for round in 0..300 {
            let (k, opc, rand): ([u8; 16], [u8; 16], [u8; 16]) = (
                random_octets(&mut next),
                random_octets(&mut next),
                random_octets(&mut next),
            );
            let (sqn, amf): ([u8; 6], [u8; 2]) =
                (random_octets(&mut next), random_octets(&mut next));
            // The constants of the specification first, then rotations by
            // any number of bits
            let (c, r) = match round {
                0 => (c, [64, 0, 32, 64, 96]),
                _ => (
                    core::array::from_fn(|_| random_octets(&mut next)),
                    core::array::from_fn(|_| (next() % 128) as u8),
                ),
            };
            let Ok(constants) = Constants::new(c, r) else {
                continue;
            };
            let subscriber = Milenage::with_constants(&K::new(&k), &Opc::new(&opc), constants);
            assert_eq!(subscriber.constants(), constants);
            let out = written_out(&k, &opc, &rand, &in1(&sqn, &amf).to_be_bytes(), &c, &r);
            let (rand, sqn, amf) = (Rand::new(&rand), Sqn::new(&sqn), Amf::new(&amf));
            let first = |at: usize, n: usize| out[at][..n].to_vec();
            let last = |at: usize, n: usize| out[at][16 - n..].to_vec();
            let name = format!("round {round}, {form}");
            assert_eq!(
                subscriber.f1(&rand, &sqn, &amf).as_octets().to_vec(),
                first(0, 8),
                "{name}"
            );
            let mac_s = subscriber.f1_star(&rand, &sqn, &amf);
            assert_eq!(mac_s.as_octets().to_vec(), last(0, 8), "{name}");
            assert_eq!(
                subscriber.f2(&rand).as_octets().to_vec(),
                last(1, 8),
                "{name}"
            );
            assert_eq!(
                subscriber.f5(&rand).as_octets().to_vec(),
                first(1, 6),
                "{name}"
            );
            assert_eq!(subscriber.f3(&rand), out[2], "{name}");
            assert_eq!(subscriber.f4(&rand), out[3], "{name}");
            assert_eq!(
                subscriber.f5_star(&rand).as_octets().to_vec(),
                first(4, 6),
                "{name}"
            );
        }
    });
}

#[test]
fn nothing_of_a_key_is_printed() {
    let subscriber = Milenage::new(&K::new(&[0x5a; 16]), &Opc::new(&[0x5a; 16]));
    let printed = format!("{subscriber:?}");
    assert_eq!(
        printed,
        "Milenage { constants: Constants(r [64, 0, 32, 64, 96], c \
         00000000000000000000000000000000 00000000000000000000000000000001 \
         00000000000000000000000000000002 00000000000000000000000000000004 \
         00000000000000000000000000000008), .. }"
    );
    let rand = Rand::new(&[0x11; 16]);
    let vector = subscriber.authentication_vector(&rand, &Sqn::new(&[0; 6]), &Amf::new(&[0x80, 0]));
    let printed = format!("{vector:?}");
    assert!(
        printed.starts_with("AuthenticationVector { rand: Rand(1111"),
        "{printed}"
    );
    assert!(printed.contains("xres: Xres(..), ck: Ck(..), ik: Ik(..), autn: Autn("));
    let response = subscriber.check_autn(&rand, vector.autn()).unwrap();
    let printed = format!("{response:?}");
    assert!(printed.contains("sqn: Sqn(000000000000), amf: Amf(8000), res: Res("));
    assert!(printed.ends_with("ck: Ck(..), ik: Ik(..) }"), "{printed}");
}

/// A batch gives each job what the function of one subscriber gives it,
/// for 0 to 40 jobs: subscribers with the constants of the specification
/// and with others, AUTNs that are accepted and AUTNs that are not.
#[test]
fn a_batch_gives_each_job_what_one_call_gives_it() {
    in_both_forms(|form| {
        let mut next = random(0x6a09_e667_f3bc_c908);
        for jobs in 0..=40 {
            let drawn: Vec<(Milenage, Rand, Sqn, Amf)> = (0..jobs)
                .map(|at| {
                    let (subscriber, rand, sqn, amf) = drawn(&mut next);
                    let constants = match at % 3 {
                        2 => Constants::new(
                            core::array::from_fn(|_| random_octets(&mut next)),
                            core::array::from_fn(|_| (next() % 128) as u8),
                        )
                        .unwrap_or_default(),
                        _ => Constants::default(),
                    };
                    let subscriber =
                        Milenage::with_constants(&subscriber.k, &subscriber.opc, constants);
                    (subscriber, rand, sqn, amf)
                })
                .collect();

            let mut vectors: Vec<VectorJob<'_>> = drawn
                .iter()
                .map(|(subscriber, rand, sqn, amf)| VectorJob::new(subscriber, rand, sqn, amf))
                .collect();
            assert!(vectors.iter().all(|job| job.vector().is_none()));
            authentication_vector_batch(&mut vectors);
            let autns: Vec<Autn> = vectors
                .iter()
                .zip(&drawn)
                .map(|(job, (subscriber, rand, sqn, amf))| {
                    let vector = job.vector().expect("a vector");
                    let alone = subscriber.authentication_vector(rand, sqn, amf);
                    assert_eq!(vector.autn(), alone.autn(), "{jobs} jobs, {form}");
                    assert_eq!(vector.rand(), alone.rand());
                    assert_eq!(vector.xres(), alone.xres());
                    assert_eq!((vector.ck(), vector.ik()), (alone.ck(), alone.ik()));
                    // Every other AUTN with its MAC-A changed
                    let mut autn = *vector.autn().as_octets();
                    autn[15] ^= u8::from(rand.as_octets()[0] % 2 == 0);
                    Autn::new(&autn)
                })
                .collect();

            let mut checks: Vec<AutnJob<'_>> = drawn
                .iter()
                .zip(&autns)
                .map(|((subscriber, rand, ..), autn)| AutnJob::new(subscriber, rand, autn))
                .collect();
            check_autn_batch(&mut checks);
            for ((job, (subscriber, rand, ..)), autn) in checks.iter().zip(&drawn).zip(&autns) {
                let alone = subscriber.check_autn(rand, autn);
                match (job.response().expect("a response"), alone) {
                    (Ok(response), Ok(alone)) => {
                        assert_eq!((response.sqn(), response.amf()), (alone.sqn(), alone.amf()));
                        assert_eq!(response.res(), alone.res(), "{jobs} jobs, {form}");
                        assert_eq!((response.ck(), response.ik()), (alone.ck(), alone.ik()));
                    }
                    (Err(error), Err(alone)) => assert_eq!(error, alone),
                    (response, alone) => panic!("{response:?} and {alone:?}, {form}"),
                }
            }
        }
    });
}
