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

//! The integrity algorithms of 5GS and EPS (TS 33.501 Annex D.3,
//! TS 33.401 Annex B.2).
//!
//! - NIA0, EIA0: null integrity.
//! - 128-NIA1, 128-EIA1: SNOW 3G (TS 33.401 Annex B.2.2, TS 35.215 and TS 35.216).
//! - 128-NIA2, 128-EIA2: AES-CMAC (TS 33.401 Annex B.2.3).
//! - 128-NIA3, 128-EIA3: ZUC (TS 33.401 Annex B.2.4, TS 35.221 and TS 35.222).
//!
//! These functions take what the algorithms take: any 32-bit COUNT and a
//! five-bit [`Bearer`]. A program calls them through an
//! [`IntegrityContext`](crate::IntegrityContext), or for a NAS message
//! through [`nas_5gs::nas_mac`](crate::nas_5gs::nas_mac) and
//! [`nas_eps::nas_mac`](crate::nas_eps::nas_mac), which take a NAS COUNT.
use crate::common::aes128::{Aes128, RoundKeys};
use crate::common::ct::{clmul64, clmul128, mask64};
use crate::common::error::SecurityError;
use crate::common::input::{Bearer, Direction, octets_of};
use crate::common::keys::IntegrityKey;
use crate::common::nea::ctr_prefix;
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use crate::common::simd::{AesSchedule, Instructions};
use crate::common::snow3g::Snow3G;
use crate::common::wipe;
use crate::common::zuc::Zuc;
use oxirush_utils::identity::Algorithm;
use zeroize::{Zeroize, Zeroizing};

/// Compute the 32-bit MAC of a message of whole octets with `algorithm`.
///
/// The null algorithm gives zero.
pub fn nia_mac(
    key: &impl IntegrityKey,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: &[u8],
    algorithm: Algorithm,
) -> u32 {
    let (key, message) = (key.key_octets(), BitString::whole(message));
    mac_message(key, count, bearer, direction, message, algorithm)
}

/// Compute the MAC that [`nia_mac`] computes over the first `bit_length`
/// bits of `message`. The unused low-order bits of the last octet are
/// ignored.
///
/// A `bit_length` above the length of `message` in bits is
/// [`SecurityError::BitLengthExceedsData`], with the null algorithm too.
pub fn nia_mac_bits(
    key: &impl IntegrityKey,
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: &[u8],
    bit_length: u64,
    algorithm: Algorithm,
) -> Result<u32, SecurityError> {
    let (key, bits) = (key.key_octets(), BitString::new(message, bit_length)?);
    Ok(mac_message(key, count, bearer, direction, bits, algorithm))
}

/// The MAC of the first bits of one message, which are known to be there,
/// and what the work left cleared: each algorithm in a frame of its own,
/// as deep as it goes and no deeper.
pub(crate) fn mac_message(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'_>,
    algorithm: Algorithm,
) -> u32 {
    match algorithm {
        Algorithm::Null => 0,
        Algorithm::Snow3g => wipe::message(|| eia1(key, count, bearer, direction, message)),
        Algorithm::Aes => {
            let blocks = CmacBlocks::new(count, bearer, direction, message);
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            if let Some(instructions) = Instructions::detect() {
                return wipe::aes(|| cmac_lanes(instructions, [key], &[blocks])[0]);
            }
            wipe::portable(|| eia2_portable(key, &blocks))
        }
        Algorithm::Zuc => wipe::message(|| eia3(key, count, bearer, direction, message)),
    }
}

/// The MAC of the first bits of a message, for a caller that clears after
/// its own work.
#[cfg(feature = "batch")]
pub(crate) fn mac_of_bits(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'_>,
    algorithm: Algorithm,
) -> u32 {
    match algorithm {
        Algorithm::Null => 0,
        Algorithm::Snow3g => eia1(key, count, bearer, direction, message),
        Algorithm::Aes => eia2(key, count, bearer, direction, message),
        Algorithm::Zuc => eia3(key, count, bearer, direction, message),
    }
}

/// The first bits of a message: the octets that hold them, and how many
/// bits of the last octet belong to them.
#[derive(Clone, Copy)]
pub(crate) struct BitString<'a> {
    /// The octets that hold the bits; the last may be partial.
    pub(crate) octets: &'a [u8],
    /// Bits of the last octet that are part of the string: 1 to 8, or 8
    /// for an empty string.
    last_bits: u32,
}

impl<'a> BitString<'a> {
    pub(crate) fn new(message: &'a [u8], bit_length: u64) -> Result<Self, SecurityError> {
        let octets = octets_of(bit_length, message.len())?;
        Ok(Self {
            octets: &message[..octets],
            last_bits: match (bit_length % 8) as u32 {
                0 => 8,
                bits => bits,
            },
        })
    }

    pub(crate) fn whole(message: &'a [u8]) -> Self {
        Self {
            octets: message,
            last_bits: 8,
        }
    }

    /// The length in bits modulo 2^64, which is what the algorithms that
    /// take a LENGTH input read of it.
    pub(crate) fn bit_length(&self) -> u64 {
        (self.octets.len() as u64)
            .wrapping_mul(8)
            .wrapping_sub(u64::from(8 - self.last_bits))
    }

    /// The mask of the bits of the last octet that are part of the string.
    pub(crate) fn last_mask(&self) -> u8 {
        0xff << (8 - self.last_bits)
    }
}

// ── NIA1: 128-EIA1 (SNOW 3G MAC) ──────────────────────────────────────────────

/// The MAC of 128-NIA1 / 128-EIA1 (TS 33.401 Annex B.2.2, TS 35.215 §4,
/// TS 35.216).
///
/// The inputs map to UIA2 (UEA2/UIA2 specification §4.4):
/// ```text
/// - FRESH = BEARER << 27
/// - IV[0] = FRESH ^ (DIRECTION << 15)
/// - IV[1] = COUNT ^ (DIRECTION << 31)
/// - IV[2] = FRESH
/// - IV[3] = COUNT
/// ```
fn eia1(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'_>,
) -> u32 {
    eia1_evaluate(&eia1_words(key, count, bearer, direction), message)
}

/// The keystream words that 128-EIA1 takes.
pub(crate) const EIA1_WORDS: usize = 5;

/// The key words and the IV of SNOW 3G for 128-EIA1.
pub(crate) fn eia1_key_and_iv(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
) -> (Zeroizing<[u32; 4]>, [u32; 4]) {
    let fresh = u32::from(bearer.get()) << 27;
    let dir32 = u32::from(u8::from(direction));

    // The key words are loaded last word first (UIA2 §4.4).
    let (words, _) = key.as_chunks::<4>();
    let k = Zeroizing::new([
        u32::from_be_bytes(words[3]),
        u32::from_be_bytes(words[2]),
        u32::from_be_bytes(words[1]),
        u32::from_be_bytes(words[0]),
    ]);
    let iv = [fresh ^ (dir32 << 15), count ^ (dir32 << 31), fresh, count];
    (k, iv)
}

/// The five keystream words of 128-EIA1: z[0..1] = P, z[2..3] = Q and
/// z[4] = the final mask.
fn eia1_words(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
) -> Zeroizing<[u32; EIA1_WORDS]> {
    let (k, iv) = eia1_key_and_iv(key, count, bearer, direction);
    let mut snow = Snow3G::start(*k, iv);
    let mut z = Zeroizing::new([0u32; EIA1_WORDS]);
    snow.words(z.as_mut());
    z
}

/// The MAC of 128-EIA1 from its five keystream words: the evaluation of
/// the message as a polynomial at P, the length times Q, and the mask
/// (UIA2 §4.4).
pub(crate) fn eia1_evaluate(z: &[u32; EIA1_WORDS], message: BitString<'_>) -> u32 {
    let p = ((z[0] as u64) << 32) | (z[1] as u64);
    let q = ((z[2] as u64) << 32) | (z[3] as u64);

    // The message in 64-bit blocks, the last one padded with zero bits.
    // The last octet of the message may have bits that are not of it.
    let mut eval = match message.octets.split_last() {
        Some((last, whole)) => {
            let (blocks, rest) = whole.as_chunks::<8>();
            let mut block = [0u8; 8];
            block[..rest.len()].copy_from_slice(rest);
            block[rest.len()] = last & message.last_mask();
            eia1_blocks(p, blocks, Some(u64::from_be_bytes(block)))
        }
        None => 0,
    };

    // The block of the length, multiplied by Q
    eval ^= message.bit_length();
    eval = mul64(eval, q);
    // MAC-I = upper 32 bits XOR z[4]
    ((eval >> 32) as u32) ^ z[4]
}

/// The evaluation at P of the blocks of a message, the last of which is
/// `last`, times P: the evaluation takes a block and is multiplied by P.
fn eia1_blocks(p: u64, blocks: &[[u8; 8]], last: Option<u64>) -> u64 {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return instructions.eia1_blocks(p, blocks, last);
    }
    let blocks = blocks.iter().map(|block| u64::from_be_bytes(*block));
    blocks
        .chain(last)
        .fold(0, |evaluation, block| mul64(evaluation ^ block, p))
}

fn mul64(a: u64, b: u64) -> u64 {
    let (low, high) = clmul128(a, b);
    reduce64(low, high)
}

/// A carry-less product of 128 bits modulo x^64 + x^4 + x^3 + x + 1.
#[inline]
pub(crate) fn reduce64(low: u64, high: u64) -> u64 {
    let overflow = (high >> 63) ^ (high >> 61) ^ (high >> 60);
    let fold = |word: u64| word ^ (word << 1) ^ (word << 3) ^ (word << 4);
    low ^ fold(high) ^ fold(overflow)
}

// ── NIA2: 128-EIA2 (AES-CMAC) ─────────────────────────────────────────────────

/// Doubling in GF(2^128) for the CMAC subkeys (RFC 4493 §2.3), with no
/// branch on the secret top bit.
fn cmac_double(value: u128) -> u128 {
    let carry = mask64((value >> 127) as u64);
    (value << 1) ^ u128::from(0x87 & carry)
}

/// The MAC of 128-NIA2 / 128-EIA2 (TS 33.401 Annex B.2.3): the first four
/// octets of the AES-CMAC of
///
/// ```text
/// M = COUNT[31:0] || BEARER[4:0] || DIRECTION[0] || 0*26 || message
/// ```
///
/// The last octet of a message that does not end with one is left
/// aligned, and its unused low-order bits are ignored, as in TS 33.401
/// Annex C.2.
#[cfg(feature = "batch")]
fn eia2(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'_>,
) -> u32 {
    let blocks = CmacBlocks::new(count, bearer, direction, message);
    // The key expansion, the subkeys and the chain in one piece of code,
    // without a keyed state between them, which a message alone does not
    // need
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return cmac_lanes(instructions, [key], &[blocks])[0];
    }
    eia2_portable(key, &blocks)
}

/// AES-CMAC of a message, from its blocks, with the `aes` crate: the
/// first four octets.
fn eia2_portable(key: &[u8; 16], blocks: &CmacBlocks<'_>) -> u32 {
    let cipher = Aes128::new(key);
    let (k1, k2) = subkeys(cipher.encrypt(0));
    let last = Zeroizing::new(blocks.last_with(k1, k2));
    cbc_mac(&cipher, blocks, *last)
}

/// The subkeys K1 and K2 of AES-CMAC with a key, which do not change
/// from a message to the next (RFC 4493 §2.3): each a number whose first
/// octet is the low one. `round_keys` are those of the key.
pub(crate) fn cmac_subkeys(key: &[u8; 16], round_keys: RoundKeys<'_>) -> [u128; 2] {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some((instructions, schedule)) = round_keys.schedule() {
        let mut l = Zeroizing::new([0u128]);
        instructions.aes_encrypt([schedule], &mut l);
        let (k1, k2) = subkeys(l[0]);
        return [k1, k2];
    }
    let _ = round_keys;
    let (k1, k2) = subkeys(Aes128::new(key).encrypt(0));
    [k1, k2]
}

/// AES-CMAC of a message, from its blocks, with a key, its round keys and
/// its subkeys: the first four octets. For a caller that clears after its
/// own work.
#[cfg(feature = "batch")]
pub(crate) fn cmac(
    key: &[u8; 16],
    round_keys: RoundKeys<'_>,
    subkeys: &[u128; 2],
    blocks: &CmacBlocks<'_>,
) -> u32 {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some((instructions, schedule)) = round_keys.schedule() {
        return cmac_instructions(instructions, schedule, subkeys, blocks);
    }
    let _ = round_keys;
    cmac_portable(key, subkeys, blocks)
}

/// AES-CMAC of one message as [`cmac`] computes it, and what the work
/// left cleared.
pub(crate) fn cmac_message(
    key: &[u8; 16],
    round_keys: RoundKeys<'_>,
    subkeys: &[u128; 2],
    blocks: &CmacBlocks<'_>,
) -> u32 {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some((instructions, schedule)) = round_keys.schedule() {
        return wipe::aes_keyed(|| cmac_instructions(instructions, schedule, subkeys, blocks));
    }
    let _ = round_keys;
    wipe::portable(|| cmac_portable(key, subkeys, blocks))
}

/// The chain of AES-CMAC on the AES instructions, with the round keys.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn cmac_instructions(
    instructions: Instructions,
    schedule: &AesSchedule,
    subkeys: &[u128; 2],
    blocks: &CmacBlocks<'_>,
) -> u32 {
    let last = Zeroizing::new(blocks.last_with(subkeys[0], subkeys[1]));
    let (first, body) = ([blocks.first], [blocks.body]);
    let mac = Zeroizing::new(instructions.aes_cbc_mac([schedule], first, body, &[*last]));
    (mac[0] as u32).swap_bytes()
}

/// The chain of AES-CMAC with the `aes` crate, which expands the key.
fn cmac_portable(key: &[u8; 16], subkeys: &[u128; 2], blocks: &CmacBlocks<'_>) -> u32 {
    let last = Zeroizing::new(blocks.last_with(subkeys[0], subkeys[1]));
    cbc_mac(&Aes128::new(key), blocks, *last)
}

/// The MAC of the CBC-MAC chain of a message with the `aes` crate, one
/// block after the other. `last` is the last block with its subkey.
fn cbc_mac(cipher: &Aes128, blocks: &CmacBlocks<'_>, last: u128) -> u32 {
    // `state = AES(state XOR block)`, for each block, in one array that is
    // wiped once: to wipe a copy of the state at each block cost a quarter
    // of the time of a long message
    let mut state = Zeroizing::new([0u8; 16]);
    if let Some(first) = blocks.first {
        *state = first.to_le_bytes();
        cipher.encrypt_in_place(&mut state);
    }
    for block in blocks.body {
        for (octet, of_block) in state.iter_mut().zip(block) {
            *octet ^= of_block;
        }
        cipher.encrypt_in_place(&mut state);
    }
    *state = (u128::from_le_bytes(*state) ^ last).to_le_bytes();
    cipher.encrypt_in_place(&mut state);
    // The first four octets, the first one high
    u32::from_be_bytes([state[0], state[1], state[2], state[3]])
}

/// The subkeys K1 and K2 from `l`, the encryption of a block of zeros
/// (RFC 4493 §2.3): L, as the number whose first octet is the high one,
/// doubled once and twice. Each is given as the number whose first octet
/// is the low one.
fn subkeys(l: u128) -> (u128, u128) {
    let k1 = cmac_double(l.swap_bytes());
    (k1.swap_bytes(), cmac_double(k1).swap_bytes())
}

/// The blocks of AES-CMAC of one message of 128-EIA2, which no key has
/// touched yet. The first octet of a block that is a number is the low
/// octet of the number.
pub(crate) struct CmacBlocks<'a> {
    /// The block that begins with COUNT, BEARER and DIRECTION and takes
    /// the first eight octets of the message, when it is not the last.
    first: Option<u128>,
    /// The whole blocks after it and before the last.
    body: &'a [[u8; 16]],
    /// The last block, of 1 to 16 octets, with its padding.
    last: u128,
    /// Whether the last block is complete, and takes the subkey K1. One
    /// that is padded takes K2 (RFC 4493 §2.4).
    complete: bool,
}

impl<'a> CmacBlocks<'a> {
    pub(crate) fn new(
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: BitString<'a>,
    ) -> Self {
        // A block as a number has its first octet as the low one. The
        // first block begins with COUNT || BEARER || DIRECTION || 0^26, and
        // takes the first eight octets of the message.
        let prefix = u128::from(u64::from_le_bytes(ctr_prefix(count, bearer, direction)));
        let octets = message.octets;
        let (first, body, mut last, filled);
        match octets.split_first_chunk::<8>() {
            // Every block but the last goes through the CBC-MAC as it is:
            // the last one, of 1 to 16 octets, is kept for the subkey
            Some((head, rest)) if !rest.is_empty() => {
                first = Some(prefix | (u128::from(u64::from_le_bytes(*head)) << 64));
                filled = (rest.len() - 1) % 16 + 1;
                let (whole, end) = rest.split_at(rest.len() - filled);
                body = whole.as_chunks::<16>().0;
                last = match octets.last_chunk::<16>() {
                    // The last sixteen octets of the message end with
                    // those of the block
                    Some(sixteen) => u128::from_le_bytes(*sixteen) >> (8 * (16 - filled)),
                    None => number_of(end),
                };
            }
            // The message is in the block of the prefix
            _ => {
                (first, body) = (None, &[][..]);
                last = prefix | (number_of(octets) << 64);
                filled = 8 + octets.len();
            }
        }

        // The last block: as it is when it is complete, otherwise with a
        // one bit and zero bits after the message
        let partial_octet = !octets.is_empty() && message.last_bits != 8;
        let complete = !partial_octet && filled == 16;
        if partial_octet {
            let last_octet = 8 * (filled - 1);
            last &= !(u128::from(!message.last_mask()) << last_octet);
            last |= u128::from(0x80u8 >> message.last_bits) << last_octet;
        } else if filled < 16 {
            last |= 0x80 << (8 * filled);
        }
        Self {
            first,
            body,
            last,
            complete,
        }
    }

    /// The last block with its subkey: K1 when it is complete, and K2
    /// when it is padded (RFC 4493 §2.4).
    fn last_with(&self, k1: u128, k2: u128) -> u128 {
        self.last ^ if self.complete { k1 } else { k2 }
    }
}

/// At most fifteen octets as a number, the first octet as the low one.
fn number_of(octets: &[u8]) -> u128 {
    let octets = octets.iter().rev();
    octets.fold(0, |number, octet| (number << 8) | u128::from(*octet))
}

/// AES-CMAC of several messages, each with its key, on the AES
/// instructions: the key expansions run side by side, and so do the chains
/// of the CBC-MACs, a block of each message at a time.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
pub(crate) fn cmac_lanes<const N: usize>(
    instructions: Instructions,
    keys: [&[u8; 16]; N],
    blocks: &[CmacBlocks<'_>; N],
) -> [u32; N] {
    let schedules = instructions.aes_schedules(keys);
    let schedules = schedules.each_ref();

    // The subkeys, from the encryption of a block of zeros
    let mut last = Zeroizing::new([0u128; N]);
    instructions.aes_encrypt(schedules, &mut last);
    for (last, blocks) in last.iter_mut().zip(blocks) {
        let (k1, k2) = subkeys(*last);
        *last = blocks.last_with(k1, k2);
    }
    cbc_mac_lanes(instructions, schedules, blocks, &last)
}

/// The key of a message of a batch: its octets, or AES-CMAC with its key
/// from a context that has it.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[derive(Clone, Copy)]
#[cfg(feature = "batch")]
pub(crate) enum CmacKey<'a> {
    Octets(&'a [u8; 16]),
    /// The round keys and the subkeys K1 and K2.
    Keyed(&'a AesSchedule, &'a [u128; 2]),
}

/// AES-CMAC of several messages as [`cmac_lanes`] computes it, of which
/// some have a keyed context: their round keys and their subkeys come
/// from there, and those of the others are computed side by side.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
#[cfg(feature = "batch")]
pub(crate) fn cmac_lanes_keyed<const N: usize>(
    instructions: Instructions,
    keys: [CmacKey<'_>; N],
    blocks: &[CmacBlocks<'_>; N],
) -> [u32; N] {
    const NO_KEY: [u8; 16] = [0; 16];
    let octets = keys.map(|key| match key {
        CmacKey::Octets(octets) => octets,
        CmacKey::Keyed(..) => &NO_KEY,
    });
    let mut expanded = Zeroizing::new([[0u128; 11]; N]);
    let mut last = Zeroizing::new([0u128; N]);
    if keys.iter().any(|key| matches!(key, CmacKey::Octets(_))) {
        expanded = instructions.aes_schedules(octets);
        instructions.aes_encrypt(expanded.each_ref(), &mut last);
    }
    let mut schedules = expanded.each_ref();
    for (((schedule, last), key), blocks) in schedules
        .iter_mut()
        .zip(last.iter_mut())
        .zip(keys)
        .zip(blocks)
    {
        let (k1, k2) = match key {
            CmacKey::Octets(_) => subkeys(*last),
            CmacKey::Keyed(round_keys, subkeys) => {
                *schedule = round_keys;
                (subkeys[0], subkeys[1])
            }
        };
        *last = blocks.last_with(k1, k2);
    }
    cbc_mac_lanes(instructions, schedules, blocks, &last)
}

/// The MACs of the CBC-MAC chains of several messages, whose last blocks
/// have their subkeys.
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
fn cbc_mac_lanes<const N: usize>(
    instructions: Instructions,
    schedules: [&AesSchedule; N],
    blocks: &[CmacBlocks<'_>; N],
    last: &[u128; N],
) -> [u32; N] {
    let first = blocks.each_ref().map(|blocks| blocks.first);
    let body = blocks.each_ref().map(|blocks| blocks.body);
    let macs = Zeroizing::new(instructions.aes_cbc_mac(schedules, first, body, last));
    // The first four octets, the high one first
    macs.map(|mac| (mac as u32).swap_bytes())
}

// ── NIA3: 128-EIA3 (ZUC MAC) ──────────────────────────────────────────────────

/// The MAC of 128-NIA3 / 128-EIA3 (TS 33.401 Annex B.2.4, TS 35.221 §4).
///
/// IV construction (EEA3/EIA3 specification §4.3):
/// ```text
///   Bytes [0..3]:  COUNT (big-endian)
///   Byte  [4]:     BEARER << 3
///   Bytes [5..7]:  0x000000
///   Byte  [8]:     COUNT_byte0 XOR (DIRECTION << 7)
///   Bytes [9..13]: COUNT_byte1..BEARER_byte (iv[1..5])
///   Byte  [14]:    iv[6] XOR (DIRECTION << 7)  = DIRECTION << 7 (since iv[6]=0)
///   Byte  [15]:    0x00
/// ```
fn eia3(
    key: &[u8; 16],
    count: u32,
    bearer: Bearer,
    direction: Direction,
    message: BitString<'_>,
) -> u32 {
    let iv = eia3_iv(count, bearer, direction);
    let mut zuc = Zuc::start(key, &iv);
    let mut mac = Eia3::new(message);
    let mut keystream = Zeroizing::new([0u32; KEYSTREAM_WORDS]);
    let mut left = mac.words();
    while left > 0 {
        let words = &mut keystream[..left.min(KEYSTREAM_WORDS)];
        zuc.words(words);
        mac.take(words);
        left -= words.len();
    }
    mac.mac()
}

/// The number of keystream words that 128-EIA3 takes from its generator at
/// a time.
const KEYSTREAM_WORDS: usize = 32;

/// The IV of ZUC for 128-EIA3.
pub(crate) fn eia3_iv(count: u32, bearer: Bearer, direction: Direction) -> [u8; 16] {
    let direction = u8::from(direction);
    let mut iv = [0u8; 16];
    iv[0..4].copy_from_slice(&count.to_be_bytes());
    iv[4] = bearer.get() << 3;
    // The upper half repeats the lower one, with the direction bit in two
    // places
    iv.copy_within(0..8, 8);
    iv[8] ^= direction << 7;
    iv[14] ^= direction << 7;
    iv
}

/// 128-EIA3 of a message, which is given the keystream of its generator
/// in the order of the words (EIA3 §4.4).
///
/// The keystream is z[0], z[1], ... in 32-bit words, and the MAC takes of
/// it the word that starts at the position of each one bit of the message.
/// The window holds the two words around the position, so the word at any
/// of 32 positions is 32 of its bits.
///
/// The words for the set bits of 32 bits of the message add up to one
/// carry-less product: bit i of the message, counted from the first, takes
/// the window shifted left by i, and the word is in its high half. With the
/// 32 bits reversed, bit i is the coefficient of x^i.
pub(crate) struct Eia3<'a> {
    message: BitString<'a>,
    /// The 32-bit groups of the message, the last of which may be short.
    groups: usize,
    /// The two keystream words that came last.
    window: u64,
    tag: u32,
    /// How many keystream words came.
    taken: usize,
}

impl<'a> Eia3<'a> {
    pub(crate) fn new(message: BitString<'a>) -> Self {
        Self {
            message,
            groups: message.octets.len().div_ceil(4),
            window: 0,
            tag: 0,
            taken: 0,
        }
    }

    /// How many keystream words the MAC takes: L = ceil(LENGTH / 32) + 2.
    pub(crate) fn words(&self) -> usize {
        self.groups + 2
    }

    /// The next keystream words, z[0] first.
    pub(crate) fn take(&mut self, mut words: &[u32]) {
        // The last octet of the message may have bits that are not of it:
        // the groups before the one it is in are whole. Group g is taken
        // when z[g + 1] comes.
        let whole = self.groups.saturating_sub(1);
        while let Some((first, rest)) = words.split_first() {
            if (1..=whole).contains(&self.taken) {
                let group = self.taken - 1;
                let count = words.len().min(whole - group);
                let octets = &self.message.octets[4 * group..4 * (group + count)];
                let (groups, _) = octets.as_chunks();
                (self.tag, self.window) = eia3_groups(self.tag, self.window, groups, words);
                self.taken += count;
                words = &words[count..];
            } else {
                self.word(*first);
                words = rest;
            }
        }
    }

    /// The first keystream word, or one of those from the last group of
    /// the message on.
    fn word(&mut self, word: u32) {
        let index = self.taken;
        self.taken += 1;
        self.window = (self.window << 32) | u64::from(word);

        // The window holds z[index - 1] and z[index]: the words for the
        // set bits of the group that starts at z[index - 1]
        if let Some(group) = index.checked_sub(1).filter(|group| *group < self.groups) {
            let octets = &self.message.octets[4 * group..];
            let mut bits = [0u8; 4];
            let length = octets.len().min(4);
            bits[..length].copy_from_slice(&octets[..length]);
            if group + 1 == self.groups {
                bits[length - 1] &= self.message.last_mask();
            }
            let bits = u64::from(u32::from_be_bytes(bits).reverse_bits());
            self.tag ^= (clmul64(bits, self.window) >> 32) as u32;
        }
        // The word at the position LENGTH, which starts in z[groups] when
        // the last group is whole and in the word before it otherwise
        if index == self.groups {
            let end = (self.message.bit_length() % 32) as u32;
            self.tag ^= match end {
                0 => word,
                end => ((self.window << end) >> 32) as u32,
            };
        }
        // The last word, z[L - 1]
        if index == self.groups + 1 {
            self.tag ^= word;
        }
    }

    /// The MAC, once every word came.
    pub(crate) fn mac(&self) -> u32 {
        debug_assert_eq!(self.taken, self.words());
        self.tag
    }
}

impl Drop for Eia3<'_> {
    fn drop(&mut self) {
        self.window.zeroize();
        self.tag.zeroize();
    }
}

/// 128-EIA3 over whole groups of 32 bits of a message: for each, the next
/// keystream word comes into the window, and the group takes its words.
/// The tag and the window after them.
fn eia3_groups(mut tag: u32, mut window: u64, groups: &[[u8; 4]], words: &[u32]) -> (u32, u64) {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    if let Some(instructions) = Instructions::detect() {
        return instructions.eia3_groups(tag, window, groups, words);
    }
    for (group, word) in groups.iter().zip(words) {
        window = (window << 32) | u64::from(*word);
        let bits = u64::from(u32::from_be_bytes(*group).reverse_bits());
        tag ^= (clmul64(bits, window) >> 32) as u32;
    }
    (tag, window)
}

#[cfg(test)]
impl Eia3<'_> {
    /// Whether the tag and the window are zero: for the tests of `simd`,
    /// which drop the state in place.
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    pub(crate) fn is_wiped(&self) -> bool {
        (self.tag, self.window) == (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nia1_mac(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
    ) -> u32 {
        nia_mac(key, count, bearer, direction, message, Algorithm::Snow3g)
    }

    fn nia1_mac_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
        bit_length: u64,
    ) -> Result<u32, SecurityError> {
        let algorithm = Algorithm::Snow3g;
        nia_mac_bits(
            key, count, bearer, direction, message, bit_length, algorithm,
        )
    }

    fn nia2_mac(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
    ) -> u32 {
        nia_mac(key, count, bearer, direction, message, Algorithm::Aes)
    }

    fn nia2_mac_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
        bit_length: u64,
    ) -> Result<u32, SecurityError> {
        let algorithm = Algorithm::Aes;
        nia_mac_bits(
            key, count, bearer, direction, message, bit_length, algorithm,
        )
    }

    fn nia3_mac(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
    ) -> u32 {
        nia_mac(key, count, bearer, direction, message, Algorithm::Zuc)
    }

    fn nia3_mac_bits(
        key: &[u8; 16],
        count: u32,
        bearer: Bearer,
        direction: Direction,
        message: &[u8],
        bit_length: u64,
    ) -> Result<u32, SecurityError> {
        let algorithm = Algorithm::Zuc;
        nia_mac_bits(
            key, count, bearer, direction, message, bit_length, algorithm,
        )
    }

    fn bearer(value: u8) -> Bearer {
        Bearer::new(value).unwrap()
    }

    fn direction(bit: u8) -> Direction {
        Direction::try_from(bit).unwrap()
    }

    /// The subkeys of RFC 4493 §4, "Subkey Generation": K1 and K2 from
    /// AES-128(key, 0), where neither doubling has a carry, and the two
    /// doublings that have one.
    #[test]
    fn cmac_double_gives_the_subkeys_of_rfc_4493() {
        let l = 0x7df7_6b0c_1ab8_99b3_3e42_f047_b91b_546f;
        let k1 = cmac_double(l);
        assert_eq!(k1, 0xfbee_d618_3571_3366_7c85_e08f_7236_a8de);
        assert_eq!(cmac_double(k1), 0xf7dd_ac30_6ae2_66cc_f90b_c11e_e46d_513b);

        assert_eq!(cmac_double(1 << 127), 0x87);
        assert_eq!(cmac_double(u128::MAX), u128::MAX ^ 0x86);
    }

    /// AES-CMAC as RFC 4493 §2.4 says it, on a string of bits, with the
    /// `aes` crate: the string in blocks, the last one complete and with
    /// K1, or padded with a one bit and zero bits and with K2.
    fn cmac_of_rfc_4493(key: &[u8; 16], octets: &[u8], bits: usize) -> [u8; 16] {
        use aes::cipher::{BlockCipherEncrypt, KeyInit};
        let cipher = aes::Aes128Enc::new(key.into());
        let mut l = [0u8; 16];
        cipher.encrypt_block((&mut l).into());
        let k1 = cmac_double(u128::from_be_bytes(l));
        let k2 = cmac_double(k1);

        let mut string = octets[..bits.div_ceil(8)].to_vec();
        let complete = bits > 0 && bits.is_multiple_of(128);
        if !complete {
            match bits % 8 {
                0 => string.push(0x80),
                used => {
                    let last = string.last_mut().unwrap();
                    *last = (*last & (0xff << (8 - used))) | (0x80 >> used);
                }
            }
            string.resize(string.len().next_multiple_of(16), 0);
        }
        let subkey = if complete { k1 } else { k2 };
        let (blocks, _) = string.as_chunks_mut::<16>();
        let last = blocks.last_mut().unwrap();
        *last = (u128::from_be_bytes(*last) ^ subkey).to_be_bytes();

        let mut state = [0u8; 16];
        for block in blocks {
            state = (u128::from_ne_bytes(state) ^ u128::from_ne_bytes(*block)).to_ne_bytes();
            cipher.encrypt_block((&mut state).into());
        }
        state
    }

    /// 128-EIA2 is AES-CMAC of COUNT, BEARER, DIRECTION, 26 zero bits and
    /// the message (TS 33.401 Annex B.2.3), at every length in bits up to
    /// a few blocks, on the AES instructions and without them.
    #[test]
    fn eia2_is_the_cmac_of_the_prefix_and_the_message() {
        let mut state = 0x6a09_e667_f3bc_c908u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for bits in 0..=8 * 70u64 {
            let key: [u8; 16] = core::array::from_fn(|_| next() as u8);
            let (count, bearer, direction) = (next() as u32, (next() % 32) as u8, next() & 1);
            let message: Vec<u8> = (0..bits.div_ceil(8) + 2).map(|_| next() as u8).collect();

            let mut string = count.to_be_bytes().to_vec();
            string.extend([(bearer << 3) | ((direction as u8) << 2), 0, 0, 0]);
            string.extend(&message);
            let expected = cmac_of_rfc_4493(&key, &string, 64 + bits as usize);
            let expected = u32::from_be_bytes([expected[0], expected[1], expected[2], expected[3]]);

            let mac = || {
                let (bearer, direction) = (self::bearer(bearer), self::direction(direction as u8));
                nia2_mac_bits(&key, count, bearer, direction, &message, bits).unwrap()
            };
            assert_eq!(mac(), expected, "{bits} bits");
            #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
            assert_eq!(
                crate::common::simd::scalar(mac),
                expected,
                "{bits} bits, scalar"
            );
        }
    }

    // ── NIA1 test vectors from free5gc (3GPP TS 35.215/35.216) ────────────────

    // ── NIA2 test vectors ────────────────────────────────────────────────────

    // TS 33.401 Annex C.2.1 (test set 1): the 58-bit message exercises the
    // bit-oriented CMAC padding that the octet-only NAS path does not need.
    #[test]
    fn nia2_3gpp_non_byte_aligned_vector() {
        let key: [u8; 16] = hex::decode("2bd6459f82c5b300952c49104881ff48")
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode("3332346263393840").unwrap();
        assert_eq!(
            nia2_mac_bits(&key, 0x38a6_f056, bearer(0x18), direction(0), &message, 58),
            Ok(0x118c_6eb8)
        );
    }

    #[test]
    fn nia2_remaining_non_byte_aligned_annex_c2_vectors() {
        // TS 33.401 Annex C.2 sets 3, 4, and 6. Each vector is also
        // recomputed after changing only unused low-order padding bits.
        for (key, count, bearer_value, direction_bit, message, bits, expected, unused_mask) in [
            (
                "7e5e94431e11d73828d739cc6ced4573",
                0x36af_6144,
                0x18,
                1,
                "b3d3c9170a4e1632f60f861013d22d84b726b6a278d802d1eeaf1321ba5929dc",
                254,
                0x1f60_b01d,
                0x03,
            ),
            (
                "d3419be821087acd02123a9248033359",
                0xc759_0ea9,
                0x17,
                0,
                concat!(
                    "bbb057038809496bcff86d6fbc8ce5b135a06b166054f2d565be8ace75dc851e",
                    "0bcdd8f07141c495872fb5d8c0c66a8b6da556663e4e461205d84580bee5bc7e"
                ),
                511,
                0x6846_a2f0,
                0x01,
            ),
            (
                "6832a65cff4473621ebdd4ba26a921fe",
                0x36af_6144,
                0x18,
                0,
                concat!(
                    "d3c53839626820717765667620323837636240981ba6824c1bfb1ab485472029",
                    "b71d808ce33e2cc3c0b5fc1f3de8a6dc"
                ),
                383,
                0xf066_8c1e,
                0x01,
            ),
        ] {
            let key: [u8; 16] = hex::decode(key).unwrap().try_into().unwrap();
            let mut message = hex::decode(message).unwrap();
            let (bearer, direction) = (bearer(bearer_value), direction(direction_bit));
            assert_eq!(
                nia2_mac_bits(&key, count, bearer, direction, &message, bits),
                Ok(expected)
            );
            *message.last_mut().unwrap() ^= unused_mask;
            assert_eq!(
                nia2_mac_bits(&key, count, bearer, direction, &message, bits),
                Ok(expected)
            );
        }
    }

    // TS 33.401 Annex C.2.5; the message is byte-aligned.
    #[test]
    fn nia2_3gpp_byte_aligned_vector() {
        let key: [u8; 16] = hex::decode("83fd23a244a74cf358da3019f1722635")
            .unwrap()
            .try_into()
            .unwrap();
        let message = hex::decode(concat!(
            "35c68716633c66fb750c266865d53c11ea05b1e9fa49c8398d48e1efa5909d39",
            "47902837f5ae96d5a05bc8d61ca8dbef1b13a4b4abfe4fb1006045b674bb5472",
            "9304c382be53a5af05556176f6eaa2ef1d05e4b083181ee674cda5a485f74d7a"
        ))
        .unwrap();
        assert_eq!(message.len(), 96);
        assert_eq!(
            nia2_mac(&key, 0x36af_6144, bearer(0x0f), direction(1), &message),
            0xe657_e182
        );
    }

    /// The product in GF(2^64) is that of the shift-and-add multiplication,
    /// one bit of `b` at a time.
    #[test]
    fn mul64_is_the_product_modulo_the_polynomial_of_uia2() {
        fn reference(mut a: u64, mut b: u64) -> u64 {
            let mut result = 0;
            for _ in 0..64 {
                if b & 1 == 1 {
                    result ^= a;
                }
                b >>= 1;
                let carry = a >> 63;
                a <<= 1;
                if carry == 1 {
                    a ^= 0x1b; // x^4 + x^3 + x + 1
                }
            }
            result
        }
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let edges = [0, 1, 2, 0x1b, 1 << 63, u64::MAX, u64::MAX - 1];
        for a in edges {
            for b in edges {
                assert_eq!(mul64(a, b), reference(a, b), "{a:#x} {b:#x}");
            }
        }
        for _ in 0..20_000 {
            let (a, b) = (next(), next());
            assert_eq!(mul64(a, b), reference(a, b), "{a:#x} {b:#x}");
        }
    }

    // ── NIA0 null integrity ───────────────────────────────────────────────────

    #[test]
    fn test_nia0_null() {
        let key = [0u8; 16];
        assert_eq!(
            nia_mac(
                &key,
                0,
                Bearer::ZERO,
                Direction::Uplink,
                &[0x7E, 0x00, 0x41],
                Algorithm::Null
            ),
            0
        );
    }

    // ── nia_mac dispatch ──────────────────────────────────────────────────────

    #[test]
    fn nia_mac_is_each_algorithm_on_whole_octets() {
        crate::bounded(|| {
            let key = [0x47u8; 16];
            let msg = &[0xABu8; 11];
            let bits = (msg.len() * 8) as u64;
            let (count, bearer, direction) = (0x12345678, bearer(3), Direction::Downlink);
            let mac = |algorithm| nia_mac(&key, count, bearer, direction, msg, algorithm);

            let nia1 = nia1_mac(&key, count, bearer, direction, msg);
            assert_eq!(mac(Algorithm::Snow3g), nia1);
            assert_eq!(
                nia1_mac_bits(&key, count, bearer, direction, msg, bits),
                Ok(nia1)
            );
            let nia2 = nia2_mac(&key, count, bearer, direction, msg);
            assert_eq!(mac(Algorithm::Aes), nia2);
            assert_eq!(
                nia2_mac_bits(&key, count, bearer, direction, msg, bits),
                Ok(nia2)
            );
            let nia3 = nia3_mac(&key, count, bearer, direction, msg);
            assert_eq!(mac(Algorithm::Zuc), nia3);
            assert_eq!(
                nia3_mac_bits(&key, count, bearer, direction, msg, bits),
                Ok(nia3)
            );
            assert!(nia1 != nia2 && nia2 != nia3 && nia1 != nia3);
        });
    }

    /// The bits after `bit_length` in the last octet are not part of the
    /// message (TS 33.401 Annex C.2 gives lengths that are not multiples
    /// of 8), with every algorithm and at every length of a short message.
    #[test]
    fn unused_bits_of_the_last_octet_are_ignored() {
        crate::bounded(|| {
            let key: [u8; 16] = hex::decode("2bd6459f82c5b300952c49104881ff48")
                .unwrap()
                .try_into()
                .unwrap();
            let message: Vec<u8> = (0..40u8)
                .map(|octet| octet.wrapping_mul(37) ^ 0x5a)
                .collect();
            for algorithm in [Algorithm::Snow3g, Algorithm::Aes, Algorithm::Zuc] {
                let mac = |message: &[u8], bits| {
                    nia_mac_bits(
                        &key,
                        0x38a6f056,
                        bearer(0x1f),
                        Direction::Uplink,
                        message,
                        bits,
                        algorithm,
                    )
                    .unwrap()
                };
                for bits in 1..=(message.len() as u64 * 8) {
                    let octets = bits.div_ceil(8) as usize;
                    let unused = (octets as u64 * 8 - bits) as u32;
                    // The octets after the last one, and the bits after the last
                    // one, change nothing
                    let mut changed = message.clone();
                    changed[octets - 1] ^= ((1u16 << unused) - 1) as u8;
                    for octet in &mut changed[octets..] {
                        *octet ^= 0xff;
                    }
                    assert_eq!(mac(&message, bits), mac(&changed, bits), "{bits}");
                    // The last bit of the message does
                    changed[octets - 1] ^= 1 << unused;
                    assert_ne!(mac(&message, bits), mac(&changed, bits), "{bits}");
                }
            }
        });
    }

    #[test]
    fn a_bit_length_longer_than_the_message_is_an_error() {
        crate::bounded(|| {
            let key = [0x5a; 16];
            let message = [0xa5, 0x58];
            let refused = Err(SecurityError::BitLengthExceedsData {
                bits: 17,
                octets: 2,
            });
            let (bearer, direction) = (Bearer::MAX, Direction::Downlink);
            for algorithm in [
                Algorithm::Null,
                Algorithm::Snow3g,
                Algorithm::Aes,
                Algorithm::Zuc,
            ] {
                assert_eq!(
                    nia_mac_bits(&key, 7, bearer, direction, &message, 17, algorithm),
                    refused
                );
                assert!(nia_mac_bits(&key, 7, bearer, direction, &message, 16, algorithm).is_ok());
                assert!(nia_mac_bits(&key, 7, bearer, direction, &[], 0, algorithm).is_ok());
            }
            assert_eq!(
                nia1_mac_bits(&key, 7, bearer, direction, &message, 17),
                refused
            );
            assert_eq!(
                nia2_mac_bits(&key, 7, bearer, direction, &message, 17),
                refused
            );
            assert_eq!(
                nia3_mac_bits(&key, 7, bearer, direction, &message, 17),
                refused
            );
            assert!(nia1_mac_bits(&key, 7, bearer, direction, &message, u64::MAX).is_err());
        });
    }
}
