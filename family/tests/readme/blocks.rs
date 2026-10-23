// The blocks of the README that use other crates of the family, each as a
// function. `tests/readme.rs` writes this file and says how: do not edit it.
#![allow(unused)]

use std::cell::RefCell;

thread_local!(static PRINTED: RefCell<String> = const { RefCell::new(String::new()) });

// What a block prints is kept, to be compared with what the README shows.
macro_rules! println {
    () => {
        PRINTED.with(|printed| printed.borrow_mut().push('\n'))
    };
    // The line is made first, where the block is: its arguments may have a
    // `?` or an `await`.
    ($($argument:tt)*) => {{
        let line = format!($($argument)*);
        PRINTED.with(|printed| {
            let mut printed = printed.borrow_mut();
            printed.push_str(&line);
            printed.push('\n');
        })
    }};
}

/// What `block` prints.
pub fn printed(block: fn()) -> String {
    PRINTED.with(|printed| printed.borrow_mut().clear());
    block();
    PRINTED.with(|printed| printed.take())
}

pub const BLOCKS: &[fn()] = &[
    block_1,
];

/// The block 1 of the README that uses other crates.
fn block_1() {
    use oxirush_nas::nas_5gs::{self, GmmCause, Nas5gsMessage, NasFGmmCause, NasFGmmStatus};
    use oxirush_security::nas_5gs::{
        KAmf, NasConnection, derive_knas_enc, derive_knas_int, nas_cipher, nas_mac,
    };
    use oxirush_security::{CipheringAlgorithm, Direction, IntegrityAlgorithm, NasCount};

    fn main() -> Result<(), Box<dyn std::error::Error>> {
        let k_amf = "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4";
        let k_amf = KAmf::from_slice(&hex::decode(k_amf)?)?;
        let (nea2, nia2) = (CipheringAlgorithm::NEA2, IntegrityAlgorithm::NIA2);
        let (k_nas_enc, k_nas_int) = (derive_knas_enc(&k_amf, nea2), derive_knas_int(&k_amf, nia2));

        // A 5GMM STATUS with cause #22, which oxirush-nas encodes
        let cause = NasFGmmCause::from_cause(GmmCause::Congestion);
        let status = Nas5gsMessage::new_5gmm(NasFGmmStatus::new(cause));
        let mut message = status.encode()?;

        // The AMF ciphers it, computes the MAC over the sequence number and the
        // ciphertext, and puts the security header before them: header type 2
        let (count, access, downlink) = (NasCount::ZERO, NasConnection::ThreeGpp, Direction::Downlink);
        nas_cipher(&k_nas_enc, count, access, downlink, &mut message, nea2);
        let protected = [&[count.sequence_number()][..], &message].concat();
        let mac = nas_mac(&k_nas_int, count, access, downlink, &protected, nia2);
        let octets = [&[0x7e, 0x02][..], &mac.to_be_bytes(), &protected].concat();
        println!("{}", hex::encode(&octets));

        // The UE: oxirush-nas reads the security header, and its security
        // context checks the MAC and deciphers with the same functions
        println!("{}", Nas5gsMessage::decode(&octets)?);
        let (nia, nea) = (nas_5gs::IntegrityAlgorithm::NIA2, nas_5gs::CipheringAlgorithm::NEA2);
        let mut ue = nas_5gs::NasSecurityContext::from_fresh_kamf(&k_amf, nia, nea)?;
        println!("{}", ue.unprotect(&octets, nas_5gs::Direction::Downlink)?.message);
        Ok(())
    }
    main().unwrap();
}
