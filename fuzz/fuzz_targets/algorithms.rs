//! The algorithms take any message and any length in bits without a panic:
//! ciphering twice gives the data back, the bits after the length are left
//! alone or ignored, and a length that the buffer does not hold is an error.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::{
    Bearer, CipheringAlgorithm, Direction, IntegrityAlgorithm, nea_cipher, nea_cipher_bits,
    nia_mac, nia_mac_bits,
};

fuzz_target!(|bytes: &[u8]| {
    // The inputs come from the first octets: a key, a COUNT, a BEARER, a
    // DIRECTION, an algorithm and a length in bits; the rest is the message
    let Some((head, message)) = bytes.split_at_checked(24) else {
        return;
    };
    let key: [u8; 16] = head[..16].try_into().expect("16 octets");
    let count = u32::from_be_bytes(head[16..20].try_into().expect("4 octets"));
    let bearer = Bearer::new(head[20] & 0x1f).expect("five bits");
    let direction = Direction::try_from(head[21] & 1).expect("one bit");
    let integrity = IntegrityAlgorithm::try_from(head[22] & 3).expect("0 to 3");
    let ciphering = CipheringAlgorithm::try_from(head[22] & 3).expect("0 to 3");
    let available = message.len() as u64 * 8;
    let bits = u64::from(u16::from_be_bytes([head[22] >> 2, head[23]])) % (available + 9);

    // Whole octets
    let mac = nia_mac(&key, count, bearer, direction, message, integrity);
    let mut data = message.to_vec();
    nea_cipher(&key, count, bearer, direction, &mut data, ciphering);
    nea_cipher(&key, count, bearer, direction, &mut data, ciphering);
    assert_eq!(data, message);

    // A length in bits
    let mac_bits = nia_mac_bits(&key, count, bearer, direction, message, bits, integrity);
    let ciphered = nea_cipher_bits(&key, count, bearer, direction, &mut data, bits, ciphering);
    if bits > available {
        assert!(mac_bits.is_err() && ciphered.is_err());
        assert_eq!(data, message);
        return;
    }
    let mac_bits = mac_bits.expect("the length is within the message");
    ciphered.expect("the length is within the data");
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
    nea_cipher_bits(&key, count, bearer, direction, &mut data, bits, ciphering)
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
