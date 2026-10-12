//! The algorithms take any message and any length in bits without a panic:
//! ciphering twice gives the data back, the bits after the length are left
//! alone or ignored, and a length that the buffer does not hold is an error.
//! On a processor with the vector instructions, they give what the scalar
//! code gives, in a batch each message has what it has alone, and a keyed
//! context gives what the function with the key gives.
//!
//! The comparison turns the vector paths off through the crate's hooks:
//! `RUSTFLAGS="--cfg oxirush_security_hooks" cargo fuzz run algorithms`.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::hooks::{narrow, scalar};
use oxirush_security::nas_5gs::{KNasEnc, KNasInt};
use oxirush_security::{
    Bearer, CipherJob, CipheringAlgorithm, CipheringContext, Direction, IntegrityAlgorithm,
    IntegrityContext, MacJob, nea_cipher, nea_cipher_batch, nea_cipher_bits, nia_mac,
    nia_mac_batch, nia_mac_bits,
};

fuzz_target!(|bytes: &[u8]| {
    // The inputs come from the first octets: a key, a COUNT, a BEARER, a
    // DIRECTION, an algorithm and a length in bits; the rest is the message
    let Some((head, message)) = bytes.split_at_checked(24) else {
        return;
    };
    let octets: [u8; 16] = head[..16].try_into().expect("16 octets");
    let (key, enc) = (KNasInt::new(&octets), KNasEnc::new(&octets));
    let count = u32::from_be_bytes(head[16..20].try_into().expect("4 octets"));
    let bearer = Bearer::new(head[20] & 0x1f).expect("five bits");
    let direction = Direction::try_from(head[21] & 1).expect("one bit");
    let integrity = IntegrityAlgorithm::try_from(head[22] & 3).expect("0 to 3");
    let ciphering = CipheringAlgorithm::try_from(head[22] & 3).expect("0 to 3");
    let available = message.len() as u64 * 8;
    let bits = u64::from(u16::from_be_bytes([head[22] >> 2, head[23]])) % (available + 9);

    // Whole octets, on the vector instructions of the processor and
    // without them
    let mac = nia_mac(&key, count, bearer, direction, message, integrity);
    let scalar_mac = scalar(|| nia_mac(&key, count, bearer, direction, message, integrity));
    assert_eq!(mac, scalar_mac);
    let mut data = message.to_vec();
    nea_cipher(&enc, count, bearer, direction, &mut data, ciphering);
    let mut scalar_data = message.to_vec();
    scalar(|| nea_cipher(&enc, count, bearer, direction, &mut scalar_data, ciphering));
    assert_eq!(data, scalar_data);

    // A keyed context, made on the vector instructions and without them
    let contexts = || {
        (
            IntegrityContext::new(&key, integrity),
            CipheringContext::new(&enc, ciphering),
        )
    };
    for (integrity_context, ciphering_context) in [contexts(), scalar(contexts)] {
        assert_eq!(
            integrity_context.mac(count, bearer, direction, message),
            mac
        );
        let mut context_data = message.to_vec();
        ciphering_context.cipher(count, bearer, direction, &mut context_data);
        assert_eq!(context_data, data);
    }
    nea_cipher(&enc, count, bearer, direction, &mut data, ciphering);
    assert_eq!(data, message);

    // The message next to others, of other keys, lengths and algorithms, or
    // all of one algorithm: each has what the functions of one message give
    // it, with eight generators side by side, with four and in scalar code
    let others = 1 + usize::from(head[23] % 12);
    let algorithm_of = |index: usize| match head[21] & 2 {
        0 => (head[index % 16] ^ head[22]) & 3,
        _ => head[22] & 3,
    };
    let integrity_of = |index| IntegrityAlgorithm::try_from(algorithm_of(index)).expect("0 to 3");
    let ciphering_of = |index| CipheringAlgorithm::try_from(algorithm_of(index)).expect("0 to 3");
    let key_of = |index: usize| std::array::from_fn(|octet| octets[octet] ^ index as u8);
    let keys: Vec<KNasInt> = (0..others)
        .map(|index| KNasInt::new(&key_of(index)))
        .collect();
    let encs: Vec<KNasEnc> = (0..others)
        .map(|index| KNasEnc::new(&key_of(index)))
        .collect();
    // Every other message of a batch comes from a keyed context
    let integrity_contexts: Vec<IntegrityContext> = (0..others)
        .map(|index| IntegrityContext::new(&keys[index], integrity_of(index)))
        .collect();
    let ciphering_contexts: Vec<CipheringContext> = (0..others)
        .map(|index| CipheringContext::new(&encs[index], ciphering_of(index)))
        .collect();
    let messages: Vec<&[u8]> = (0..others)
        .map(|index| {
            let length = (usize::from(head[index % 24]) * (index + 1)) % (message.len() + 1);
            &message[..length]
        })
        .collect();
    let expected: Vec<(Vec<u8>, u32)> = (0..others)
        .map(|index| {
            let (integrity, ciphering) = (integrity_of(index), ciphering_of(index));
            let mac = nia_mac(
                &keys[index],
                count,
                bearer,
                direction,
                messages[index],
                integrity,
            );
            let mut data = messages[index].to_vec();
            nea_cipher(&encs[index], count, bearer, direction, &mut data, ciphering);
            (data, mac)
        })
        .collect();
    let in_a_batch = || {
        let mut macs: Vec<MacJob<'_>> = (0..others)
            .map(|index| match index % 2 {
                0 => {
                    let (key, integrity) = (&keys[index], integrity_of(index));
                    MacJob::new(key, count, bearer, direction, messages[index], integrity)
                }
                _ => integrity_contexts[index].job(count, bearer, direction, messages[index]),
            })
            .collect();
        nia_mac_batch(&mut macs);
        let mut data: Vec<Vec<u8>> = messages.iter().map(|message| message.to_vec()).collect();
        let mut jobs: Vec<CipherJob<'_>> = data
            .iter_mut()
            .enumerate()
            .map(|(index, data)| match index % 2 {
                0 => {
                    let (key, ciphering) = (&encs[index], ciphering_of(index));
                    CipherJob::new(key, count, bearer, direction, data, ciphering)
                }
                _ => ciphering_contexts[index].job(count, bearer, direction, data),
            })
            .collect();
        nea_cipher_batch(&mut jobs);
        drop(jobs);
        let macs = macs
            .iter()
            .map(|job| job.mac().expect("the batch computed it"));
        data.into_iter().zip(macs).collect::<Vec<_>>()
    };
    assert_eq!(in_a_batch(), expected);
    assert_eq!(narrow(in_a_batch), expected);
    assert_eq!(scalar(in_a_batch), expected);

    // A length in bits
    let mac_bits = nia_mac_bits(&key, count, bearer, direction, message, bits, integrity);
    let ciphered = nea_cipher_bits(&enc, count, bearer, direction, &mut data, bits, ciphering);
    if bits > available {
        assert!(mac_bits.is_err() && ciphered.is_err());
        assert_eq!(data, message);
        return;
    }
    let mac_bits = mac_bits.expect("the length is within the message");
    ciphered.expect("the length is within the data");
    let (integrity_context, ciphering_context) = contexts();
    assert_eq!(
        integrity_context.mac_bits(count, bearer, direction, message, bits),
        Ok(mac_bits)
    );
    let mut context_data = message.to_vec();
    ciphering_context
        .cipher_bits(count, bearer, direction, &mut context_data, bits)
        .expect("the length is within the data");
    assert_eq!(context_data, data);
    scalar(|| {
        assert_eq!(
            nia_mac_bits(&key, count, bearer, direction, message, bits, integrity),
            Ok(mac_bits)
        );
        let mut scalar_data = message.to_vec();
        nea_cipher_bits(
            &enc,
            count,
            bearer,
            direction,
            &mut scalar_data,
            bits,
            ciphering,
        )
        .expect("the length is within the data");
        assert_eq!(scalar_data, data);
    });
    if bits == available {
        assert_eq!(mac_bits, mac);
    }

    // The bits after the length are as they were, and the octets too
    let octets = bits.div_ceil(8) as usize;
    assert_eq!(data[octets..], message[octets..]);
    if bits % 8 != 0 {
        let unused = 0xffu8 >> (bits % 8);
        assert_eq!(data[octets - 1] & unused, message[octets - 1] & unused);
    }
    nea_cipher_bits(&enc, count, bearer, direction, &mut data, bits, ciphering)
        .expect("the length is within the data");
    assert_eq!(data, message);

    // They do not change the MAC either
    let mut changed = message.to_vec();
    for octet in &mut changed[octets..] {
        *octet ^= 0xff;
    }
    if bits % 8 != 0 {
        changed[octets - 1] ^= 0xffu8 >> (bits % 8);
    }
    assert_eq!(
        nia_mac_bits(&key, count, bearer, direction, &changed, bits, integrity),
        Ok(mac_bits)
    );
});
