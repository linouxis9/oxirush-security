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

//! The two ECIES profiles of TS 33.501 Annex C.3.4, and the keys of the
//! home network.

use super::{ProtectionScheme, SuciError};
use aes::Aes128Enc;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use alloc::vec::Vec;
use core::fmt;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Octets of the encryption key, of the initial counter block and of the
/// MAC key, which both profiles have alike (Annex C.3.4.1 and C.3.4.2).
const ENC_KEY_LEN: usize = 16;
const ICB_LEN: usize = 16;
const MAC_KEY_LEN: usize = 32;
/// Octets of the MAC tag.
pub(super) const MAC_LEN: usize = 8;
/// Octets of the ephemeral public key of Profile A.
pub(super) const PROFILE_A_PUBLIC_KEY_LEN: usize = 32;
/// Octets of the ephemeral public key of Profile B, which is compressed.
pub(super) const PROFILE_B_PUBLIC_KEY_LEN: usize = 33;

/// A private key of the home network, with which a SIDF de-conceals the
/// SUCIs of one profile.
///
/// The key is wiped when it is dropped, and `{:?}` prints its profile
/// alone.
pub struct HomeNetworkPrivateKey(Private);

enum Private {
    A(x25519_dalek::StaticSecret),
    B(p256::SecretKey),
}

impl HomeNetworkPrivateKey {
    /// A key of Profile A: the 32 octets of an X25519 private key
    /// (RFC 7748 §5).
    pub fn profile_a(octets: &[u8; 32]) -> Self {
        Self(Private::A(x25519_dalek::StaticSecret::from(*octets)))
    }

    /// A key of Profile B: the 32 octets of a private key of secp256r1,
    /// the high one first.
    ///
    /// Zero, and a number that is not below the order of the curve, are
    /// [`SuciError::InvalidKey`].
    pub fn profile_b(octets: &[u8; 32]) -> Result<Self, SuciError> {
        match p256::SecretKey::from_bytes(octets.into()) {
            Ok(key) => Ok(Self(Private::B(key))),
            Err(_) => Err(SuciError::InvalidKey),
        }
    }

    /// The profile of the key: [`ProtectionScheme::ProfileA`] or
    /// [`ProtectionScheme::ProfileB`].
    pub fn scheme(&self) -> ProtectionScheme {
        match self.0 {
            Private::A(_) => ProtectionScheme::ProfileA,
            Private::B(_) => ProtectionScheme::ProfileB,
        }
    }

    /// The public key that goes with it, which the home network gives its
    /// subscribers.
    pub fn public_key(&self) -> HomeNetworkPublicKey {
        HomeNetworkPublicKey(match &self.0 {
            Private::A(key) => Public::A(x25519_dalek::PublicKey::from(key).to_bytes()),
            Private::B(key) => Public::B(key.public_key()),
        })
    }
}

/// The profile, and nothing of the key.
impl fmt::Debug for HomeNetworkPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HomeNetworkPrivateKey({:?}, ..)", self.scheme())
    }
}

/// A public key of the home network, with which a UE conceals its SUPI.
#[derive(Clone, PartialEq, Eq)]
pub struct HomeNetworkPublicKey(Public);

#[derive(Clone, PartialEq, Eq)]
enum Public {
    A([u8; 32]),
    B(p256::PublicKey),
}

impl HomeNetworkPublicKey {
    /// A key of Profile A: the 32 octets of an X25519 public key
    /// (RFC 7748 §5).
    pub fn profile_a(octets: &[u8; 32]) -> Self {
        Self(Public::A(*octets))
    }

    /// A key of Profile B: a point of secp256r1 in its compressed form of
    /// 33 octets or its uncompressed form of 65 (SEC 1 §2.3.3).
    ///
    /// Another encoding, and octets that are not a point of the curve, are
    /// [`SuciError::InvalidKey`].
    pub fn profile_b(sec1: &[u8]) -> Result<Self, SuciError> {
        // SEC 1 has other encodings, which p256 would decode: the x-only
        // one of tag 0x05 among them
        let known = matches!(
            (sec1.first(), sec1.len()),
            (Some(0x02 | 0x03), 33) | (Some(0x04), 65)
        );
        match p256::PublicKey::from_sec1_bytes(sec1) {
            Ok(key) if known => Ok(Self(Public::B(key))),
            _ => Err(SuciError::InvalidKey),
        }
    }

    /// The profile of the key: [`ProtectionScheme::ProfileA`] or
    /// [`ProtectionScheme::ProfileB`].
    pub fn scheme(&self) -> ProtectionScheme {
        match self.0 {
            Public::A(_) => ProtectionScheme::ProfileA,
            Public::B(_) => ProtectionScheme::ProfileB,
        }
    }

    /// Its octets: the 32 of an X25519 key, or the 33 of the compressed
    /// form of a point of secp256r1.
    pub fn to_octets(&self) -> Vec<u8> {
        use p256::elliptic_curve::sec1::ToSec1Point;
        match &self.0 {
            Public::A(key) => key.to_vec(),
            Public::B(key) => key.to_sec1_point(true).as_bytes().to_vec(),
        }
    }
}

impl fmt::Debug for HomeNetworkPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "HomeNetworkPublicKey({:?}, ", self.scheme())?;
        for octet in self.to_octets() {
            write!(f, "{octet:02x}")?;
        }
        f.write_str(")")
    }
}

/// The keying data K of a shared secret: the encryption key, the ICB and
/// the MAC key (Annex C.3.2), by the ANSI-X9.63-KDF with SHA-256 over the
/// secret, a 32-bit counter from 1 and SharedInfo1, the ephemeral public
/// key. It is wiped on drop, like the hash states.
struct KeyingData(Zeroizing<[u8; 64]>);

impl KeyingData {
    fn new(shared_secret: &[u8], ephemeral_public_key: &[u8]) -> Self {
        use crate::common::sha256::sha256;
        const { assert!(ENC_KEY_LEN + ICB_LEN + MAC_KEY_LEN == 64) };
        let mut data = Zeroizing::new([0u8; 64]);
        let (halves, _) = data.as_chunks_mut::<32>();
        for (counter, half) in (1u32..).zip(halves) {
            let digest = sha256(&[shared_secret, &counter.to_be_bytes(), ephemeral_public_key]);
            half.copy_from_slice(digest.as_ref());
        }
        Self(data)
    }

    fn encryption_key(&self) -> &[u8; ENC_KEY_LEN] {
        self.0.first_chunk().expect("K has 64 octets")
    }

    fn icb(&self) -> &[u8; ICB_LEN] {
        self.0[ENC_KEY_LEN..]
            .first_chunk()
            .expect("K has 64 octets")
    }

    fn mac_key(&self) -> &[u8; MAC_KEY_LEN] {
        self.0.last_chunk().expect("K has 64 octets")
    }

    /// The MAC tag of a ciphertext: the first eight octets of its
    /// HMAC-SHA-256 (Annex C.3.4.0).
    fn mac_tag(&self, ciphertext: &[u8]) -> [u8; MAC_LEN] {
        let mac = Zeroizing::new(crate::common::sha256::hmac_sha256(
            self.mac_key(),
            ciphertext,
        ));
        *mac.first_chunk().expect("SHA-256 gives 32 octets")
    }

    /// Encrypt or decrypt, which is one operation.
    fn cipher(&self, data: &[u8]) -> Vec<u8> {
        aes128_ctr(self.encryption_key(), self.icb(), data)
    }
}

/// AES-128-CTR encryption with the ICB as the first counter block. The
/// next ones follow by the standard incrementing function of NIST
/// SP 800-38A Appendix B.1 with m = 32 (TS 33.501 Annex C.3.4.0): the last
/// four octets count modulo 2^32, and the twelve before them stay. The
/// keystream and counter blocks are wiped.
fn aes128_ctr(key: &[u8; 16], icb: &[u8; 16], data: &[u8]) -> Vec<u8> {
    let aes = Aes128Enc::new(key.into());
    let mut out = Vec::with_capacity(data.len());
    let mut counter = Zeroizing::new(*icb);
    for chunk in data.chunks(16) {
        let mut block = aes::Block::from(*counter);
        aes.encrypt_block(&mut block);
        for (d, k) in chunk.iter().zip(block.iter()) {
            out.push(d ^ k);
        }
        block.as_mut_slice().zeroize();
        let (_, low) = counter.split_at_mut(12);
        let next = u32::from_be_bytes([low[0], low[1], low[2], low[3]]).wrapping_add(1);
        low.copy_from_slice(&next.to_be_bytes());
    }
    out
}

/// The scheme output of a plaintext: the ephemeral public key, the
/// ciphertext and the MAC tag (Annex C.3.2).
fn scheme_output(keys: &KeyingData, ephemeral_public_key: &[u8], plaintext: &[u8]) -> Vec<u8> {
    let ciphertext = keys.cipher(plaintext);
    let mac = keys.mac_tag(&ciphertext);
    let mut output = Vec::with_capacity(ephemeral_public_key.len() + ciphertext.len() + MAC_LEN);
    output.extend_from_slice(ephemeral_public_key);
    output.extend_from_slice(&ciphertext);
    output.extend_from_slice(&mac);
    output
}

/// Conceal a plaintext, which is not empty, for the home network: the
/// scheme output of the profile of `key`, with a fresh ephemeral key.
pub(super) fn conceal(key: &HomeNetworkPublicKey, plaintext: &[u8]) -> Result<Vec<u8>, SuciError> {
    match &key.0 {
        Public::A(home) => {
            use x25519_dalek::{PublicKey, StaticSecret};
            // The secret of this one concealment. It is drawn here, and
            // not by `EphemeralSecret::random`, so that a failure of the
            // system's random number generator is an error and not a panic
            let mut seed = Zeroizing::new([0u8; 32]);
            getrandom::fill(seed.as_mut()).map_err(|_| SuciError::RandomSource)?;
            let secret = StaticSecret::from(*seed);
            let ephemeral = PublicKey::from(&secret);
            let shared = secret.diffie_hellman(&PublicKey::from(*home));
            // A point of small order gives the same secret to everyone
            if !shared.was_contributory() {
                return Err(SuciError::InvalidKey);
            }
            let keys = KeyingData::new(shared.as_bytes(), ephemeral.as_bytes());
            Ok(scheme_output(&keys, ephemeral.as_bytes(), plaintext))
        }
        Public::B(home) => {
            use p256::ecdh::EphemeralSecret;
            use p256::elliptic_curve::Generate;
            use p256::elliptic_curve::sec1::ToSec1Point;
            let secret = EphemeralSecret::try_generate().map_err(|_| SuciError::RandomSource)?;
            // Profile B compresses the point, which is also SharedInfo1
            let ephemeral = secret.public_key().to_sec1_point(true);
            let shared = secret.diffie_hellman(home);
            let keys = KeyingData::new(shared.raw_secret_bytes().as_slice(), ephemeral.as_bytes());
            Ok(scheme_output(&keys, ephemeral.as_bytes(), plaintext))
        }
    }
}

/// De-conceal the scheme output of the profile of `key`: the plaintext,
/// once the MAC tag is verified (Annex C.3.3).
///
/// The steps are in this order, and each failure is of one of them: the
/// length ([`SuciError::Truncated`]), the ephemeral public key
/// ([`SuciError::MalformedPoint`]), then the MAC tag
/// ([`SuciError::MacMismatch`]), which is compared in a time that does not
/// depend on where it differs. Nothing is decrypted before the tag is
/// right.
pub(super) fn deconceal(
    key: &HomeNetworkPrivateKey,
    scheme_output: &[u8],
) -> Result<Zeroizing<Vec<u8>>, SuciError> {
    let public_key_len = match key.0 {
        Private::A(_) => PROFILE_A_PUBLIC_KEY_LEN,
        Private::B(_) => PROFILE_B_PUBLIC_KEY_LEN,
    };
    // An ephemeral public key, at least one octet of ciphertext and a tag
    if scheme_output.len() < public_key_len + 1 + MAC_LEN {
        return Err(SuciError::Truncated);
    }
    let (ephemeral, rest) = scheme_output.split_at(public_key_len);
    let (ciphertext, mac) = rest.split_at(rest.len() - MAC_LEN);

    let keys = match &key.0 {
        Private::A(home) => {
            let point: [u8; 32] = ephemeral.try_into().expect("32 octets were split off");
            let shared = home.diffie_hellman(&x25519_dalek::PublicKey::from(point));
            // A point of small order gives a secret that the sender did
            // not need the home network's public key for
            if !shared.was_contributory() {
                return Err(SuciError::MalformedPoint);
            }
            KeyingData::new(shared.as_bytes(), ephemeral)
        }
        Private::B(home) => {
            // Profile B always compresses the point (Annex C.3.4.2); an
            // uncompressed one is refused (TS 33.514 §4.2.1.3)
            if !matches!(ephemeral[0], 0x02 | 0x03) {
                return Err(SuciError::MalformedPoint);
            }
            let point = p256::PublicKey::from_sec1_bytes(ephemeral)
                .map_err(|_| SuciError::MalformedPoint)?;
            let shared = p256::elliptic_curve::ecdh::diffie_hellman(
                home.to_nonzero_scalar(),
                point.as_affine(),
            );
            KeyingData::new(shared.raw_secret_bytes().as_slice(), ephemeral)
        }
    };
    if mac.ct_eq(&keys.mac_tag(ciphertext)).unwrap_u8() != 1 {
        return Err(SuciError::MacMismatch);
    }
    Ok(Zeroizing::new(keys.cipher(ciphertext)))
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// The keying data and the scheme output of a shared secret, an
    /// ephemeral public key and a plaintext, as the UE computes them: for
    /// the intermediate values of Annex C.4.
    pub(in crate::nas_5gs::suci) struct Steps {
        pub encryption_key: [u8; 16],
        pub icb: [u8; 16],
        pub mac_key: [u8; 32],
        pub ciphertext: Vec<u8>,
        pub mac_tag: [u8; 8],
    }

    pub(in crate::nas_5gs::suci) fn steps(
        shared_secret: &[u8],
        ephemeral_public_key: &[u8],
        plaintext: &[u8],
    ) -> Steps {
        let keys = KeyingData::new(shared_secret, ephemeral_public_key);
        let ciphertext = keys.cipher(plaintext);
        Steps {
            encryption_key: *keys.encryption_key(),
            icb: *keys.icb(),
            mac_key: *keys.mac_key(),
            mac_tag: keys.mac_tag(&ciphertext),
            ciphertext,
        }
    }

    /// TS 33.501 Annex C.3.4.0: the counter blocks follow from the ICB by
    /// "the standard incrementing function in section B.1 of NIST Special
    /// Publication 800-38A with m = 32 bits". The low 32 bits count modulo
    /// 2^32, and the 96 bits before them stay as the ICB has them.
    ///
    /// The ciphertext is that of OpenSSL's AES-128 in ECB mode over the
    /// counter blocks written out by hand: the ICB, then the ICB with
    /// 00000000 and with 00000001 in its last four octets.
    #[test]
    fn the_counter_of_aes_ctr_wraps_within_its_low_32_bits() {
        let key = [0x2b; 16];
        let mut icb = [0x11; 16];
        icb[12..].copy_from_slice(&[0xff; 4]);
        let ciphertext = aes128_ctr(&key, &icb, b"verylongusername1@and-then-some-more");
        assert_eq!(
            hex::encode(ciphertext),
            "25c21910b8e66ee4adf491532c01539af6187cb86ab3bb84ee8371ef6a7e8a0fe33ec06c"
        );

        // No carry leaves the low 32 bits, whatever is before them
        let block = |counter: [u8; 16]| {
            let mut block = aes::Block::from(counter);
            Aes128Enc::new(&key.into()).encrypt_block(&mut block);
            block
        };
        let keystream = aes128_ctr(&key, &[0xff; 16], &[0u8; 32]);
        let mut second = [0xff; 16];
        second[12..].copy_from_slice(&[0; 4]);
        assert_eq!(keystream[..16], block([0xff; 16])[..]);
        assert_eq!(keystream[16..], block(second)[..]);
    }

    #[test]
    fn a_private_key_shows_its_profile_alone() {
        let a = HomeNetworkPrivateKey::profile_a(&[0x42; 32]);
        assert_eq!(format!("{a:?}"), "HomeNetworkPrivateKey(ProfileA, ..)");
        assert_eq!(a.scheme(), ProtectionScheme::ProfileA);
        assert_eq!(a.public_key().scheme(), ProtectionScheme::ProfileA);
        let b = HomeNetworkPrivateKey::profile_b(&[0x42; 32]).unwrap();
        assert_eq!(format!("{b:?}"), "HomeNetworkPrivateKey(ProfileB, ..)");
        assert_eq!(b.public_key().to_octets().len(), 33);
        // Zero and the order of the curve are no private keys
        assert_eq!(
            HomeNetworkPrivateKey::profile_b(&[0; 32]).unwrap_err(),
            SuciError::InvalidKey
        );
        assert_eq!(
            HomeNetworkPrivateKey::profile_b(&[0xff; 32]).unwrap_err(),
            SuciError::InvalidKey
        );
    }

    #[test]
    fn a_profile_b_public_key_is_compressed_or_uncompressed() {
        use p256::elliptic_curve::sec1::ToSec1Point;
        let key = HomeNetworkPrivateKey::profile_b(&[0x42; 32])
            .unwrap()
            .public_key();
        let compressed = key.to_octets();
        assert_eq!(
            HomeNetworkPublicKey::profile_b(&compressed),
            Ok(key.clone())
        );
        let Public::B(point) = &key.0 else {
            panic!("a key of Profile B");
        };
        let uncompressed = point.to_sec1_point(false);
        assert_eq!(
            HomeNetworkPublicKey::profile_b(uncompressed.as_bytes()),
            Ok(key)
        );
        // x and y alone, an X25519 key, an x that no point of the curve
        // has, and nothing
        let mut no_point = [0x01; 33];
        no_point[0] = 0x02;
        for other in [
            &uncompressed.as_bytes()[1..],
            &[0x42; 32][..],
            &no_point[..],
            &[][..],
        ] {
            assert_eq!(
                HomeNetworkPublicKey::profile_b(other),
                Err(SuciError::InvalidKey),
                "{other:02x?}"
            );
        }
    }
}
