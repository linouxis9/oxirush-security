//! The two ends of MILENAGE authentication, the home network and the USIM, on any
//! subscriber, any RAND, any SQN and any AMF (TS 33.102 §6.3, TS 35.206): the vector of
//! the home network is accepted by the USIM with the same K, which reads its SQN and AMF
//! back and gives the RES, CK and IK of the vector; f2 to f5 one at a time give what
//! f2345 gives; an AUTN with any one bit changed is refused for its MAC; the AUTS of any
//! SQNMS gives SQNMS back to the home network, and one with a bit changed is refused;
//! RES* is XRES* for any serving network name. A batch of vectors, and of checks, gives
//! for each job what the call of one gives, on the vector instructions and on the scalar
//! code.
//!
//! The comparison with the scalar code goes through the crate's hooks:
//! `RUSTFLAGS="--cfg oxirush_security_hooks" cargo fuzz run milenage`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::batch::{self, AutnJob, VectorJob};
use oxirush_security::hooks::scalar;
use oxirush_security::milenage::{Amf, Auts, K, Milenage, Op, Opc, Sqn};
use oxirush_security::{Autn, Rand, SecurityError};

/// A subscriber, a challenge and what is done with it, from 65 octets, and the serving
/// network name after them.
struct Case<'a> {
    k: [u8; 16],
    op: [u8; 16],
    /// Whether OP gives OPc, or is OPc
    from_op: bool,
    rand: [u8; 16],
    sqn: u64,
    sqn_ms: u64,
    amf: [u8; 2],
    /// The bit of the AUTN, and of the AUTS, that is changed
    bit: u8,
    /// How many subscribers the batches have, the first one this one
    jobs: u8,
    sn_name: &'a [u8],
}

fn case(bytes: &[u8]) -> Option<Case<'_>> {
    let (head, sn_name) = bytes.split_at_checked(65)?;
    let array = |at: usize| -> [u8; 16] { head[at..at + 16].try_into().unwrap() };
    let number = |at: usize| {
        u64::from_be_bytes([
            0,
            0,
            head[at],
            head[at + 1],
            head[at + 2],
            head[at + 3],
            head[at + 4],
            head[at + 5],
        ])
    };
    Some(Case {
        k: array(0),
        op: array(16),
        rand: array(32),
        sqn: number(48),
        sqn_ms: number(54),
        amf: [head[60], head[61]],
        from_op: head[62] & 1 == 1,
        bit: head[63],
        jobs: head[64] % 17,
        sn_name,
    })
}

/// The subscriber of K and OP, or of K and OPc.
fn subscriber(k: &[u8; 16], op: &[u8; 16], from_op: bool) -> Milenage {
    let k = K::new(k);
    let opc = match from_op {
        true => Opc::from_op(&k, &Op::new(op)),
        false => Opc::new(op),
    };
    Milenage::new(&k, &opc)
}

fn one(case: &Case<'_>) {
    let usim = subscriber(&case.k, &case.op, case.from_op);
    let rand = Rand::new(&case.rand);
    let sqn = Sqn::try_from(case.sqn).expect("48 bits are a SQN");
    let amf = Amf::new(&case.amf);

    // The vector, as f1 to f5 give it
    let vector = usim.authentication_vector(&rand, &sqn, &amf);
    let (res, ck, ik, ak) = usim.f2345(&rand);
    assert_eq!(res.as_octets(), usim.f2(&rand).as_octets());
    assert_eq!(ck.as_octets(), usim.f3(&rand).as_octets());
    assert_eq!(ik.as_octets(), usim.f4(&rand).as_octets());
    assert_eq!(ak.as_octets(), usim.f5(&rand).as_octets());
    assert_eq!(vector.xres().as_octets(), res.as_octets());
    assert_eq!(
        (vector.ck().as_octets(), vector.ik().as_octets()),
        (ck.as_octets(), ik.as_octets())
    );
    let autn = vector.autn().as_octets();
    let concealed: Vec<u8> = sqn
        .as_octets()
        .iter()
        .zip(ak.as_octets())
        .map(|(s, a)| s ^ a)
        .collect();
    assert_eq!(autn[..6], concealed[..], "SQN ⊕ AK");
    assert_eq!(autn[6..8], case.amf, "AMF");
    assert_eq!(
        autn[8..],
        usim.f1(&rand, &sqn, &amf).as_octets()[..],
        "MAC-A"
    );

    // The USIM takes it, and reads SQN and AMF back
    let response = usim
        .check_autn(&rand, vector.autn())
        .expect("the USIM takes the vector of its home network");
    assert_eq!(response.sqn().get(), case.sqn);
    assert_eq!(response.amf().as_octets(), &case.amf);
    assert!(vector.xres().accepts(response.res()));
    assert_eq!(
        (response.ck().as_octets(), response.ik().as_octets()),
        (ck.as_octets(), ik.as_octets())
    );
    match (
        vector.xres_star(case.sn_name),
        response.res_star(case.sn_name),
    ) {
        (Ok(xres_star), Ok(res_star)) => assert!(xres_star.accepts(&res_star), "RES* is XRES*"),
        (Err(_), Err(_)) => {}
        (xres_star, res_star) => panic!(
            "XRES* {:?} and RES* {:?} of one name",
            xres_star.is_ok(),
            res_star.is_ok()
        ),
    }

    // An AUTN with one bit changed is refused for its MAC
    let mut changed = *autn;
    changed[usize::from(case.bit / 8 % 16)] ^= 1 << (case.bit % 8);
    assert!(
        matches!(
            usim.check_autn(&rand, &Autn::new(&changed)),
            Err(SecurityError::MacFailure)
        ),
        "an AUTN with a bit changed is taken"
    );

    // The AUTS of SQNMS gives it back, and not with a bit changed
    let sqn_ms = Sqn::try_from(case.sqn_ms).expect("48 bits are a SQN");
    let auts = usim.auts(&rand, &sqn_ms);
    assert_eq!(
        usim.verify_auts(&rand, &auts).map(|sqn| sqn.get()),
        Ok(case.sqn_ms)
    );
    let mut changed = *auts.as_octets();
    changed[usize::from(case.bit / 8 % 14)] ^= 1 << (case.bit % 8);
    assert!(
        matches!(
            usim.verify_auts(&rand, &Auts::new(&changed)),
            Err(SecurityError::MacFailure)
        ),
        "an AUTS with a bit changed is taken"
    );
}

/// A batch of `case.jobs` subscribers, each K the case's with its first octet changed:
/// each job has what the call of one gives, and each check of a changed AUTN fails.
fn batches(case: &Case<'_>) {
    let subscribers: Vec<Milenage> = (0..case.jobs)
        .map(|n| {
            let mut k = case.k;
            k[0] ^= n;
            subscriber(&k, &case.op, case.from_op)
        })
        .collect();
    let rand = Rand::new(&case.rand);
    let sqn = Sqn::try_from(case.sqn).expect("48 bits are a SQN");
    let amf = Amf::new(&case.amf);
    let mut jobs: Vec<VectorJob<'_>> = subscribers
        .iter()
        .map(|subscriber| VectorJob::new(subscriber, &rand, &sqn, &amf))
        .collect();
    batch::authentication_vectors(&mut jobs);
    let autns: Vec<Autn> = jobs
        .iter()
        .zip(&subscribers)
        .enumerate()
        .map(|(n, (job, subscriber))| {
            let vector = job.vector().expect("a vector of each job");
            let alone = subscriber.authentication_vector(&rand, &sqn, &amf);
            assert_eq!(
                vector.autn().as_octets(),
                alone.autn().as_octets(),
                "the AUTN of job {n}"
            );
            assert_eq!(
                vector.xres().as_octets(),
                alone.xres().as_octets(),
                "the XRES of job {n}"
            );
            assert_eq!(
                (vector.ck().as_octets(), vector.ik().as_octets()),
                (alone.ck().as_octets(), alone.ik().as_octets()),
                "CK and IK of job {n}"
            );
            // Every other AUTN has a bit changed
            let mut autn = *vector.autn().as_octets();
            if n % 2 == 1 {
                autn[usize::from(case.bit / 8 % 16)] ^= 1 << (case.bit % 8);
            }
            Autn::new(&autn)
        })
        .collect();
    let mut checks: Vec<AutnJob<'_>> = subscribers
        .iter()
        .zip(&autns)
        .map(|(subscriber, autn)| AutnJob::new(subscriber, &rand, autn))
        .collect();
    batch::check_autn(&mut checks);
    for (n, ((check, subscriber), autn)) in checks.iter().zip(&subscribers).zip(&autns).enumerate()
    {
        let alone = subscriber.check_autn(&rand, autn);
        match (check.response().expect("a response of each job"), alone) {
            (Ok(batched), Ok(alone)) => {
                assert_eq!(batched.sqn().get(), alone.sqn().get(), "the SQN of job {n}");
                assert_eq!(
                    batched.res().as_octets(),
                    alone.res().as_octets(),
                    "the RES of job {n}"
                );
                assert_eq!(
                    (batched.ck().as_octets(), batched.ik().as_octets()),
                    (alone.ck().as_octets(), alone.ik().as_octets()),
                    "CK and IK of job {n}"
                );
            }
            (Err(batched), Err(alone)) => assert_eq!(batched, alone, "the error of job {n}"),
            (batched, alone) => panic!(
                "job {n}: the batch gives {:?}, the call of one {:?}",
                batched.is_ok(),
                alone.is_ok()
            ),
        }
        assert_eq!(
            n % 2 == 1,
            check.response().is_some_and(|response| response.is_err()),
            "job {n}"
        );
    }
}

fuzz_target!(|bytes: &[u8]| {
    let Some(case) = case(bytes) else { return };
    one(&case);
    batches(&case);
    // On the scalar code, without the vector instructions
    scalar(|| {
        one(&case);
        batches(&case);
    });
});
