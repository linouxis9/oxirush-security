/// 3GPP TS 33.220 Annex B.2 KDF and 5G key derivation per TS 33.501
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Generic KDF: HMAC-SHA-256(key, S)
pub fn kdf(key: &[u8], s: &[u8]) -> [u8; 32] {
    let mut mac =
        HmacSha256::new_from_slice(key).expect("HMAC-SHA-256 accepts any key size per RFC 2104");
    mac.update(s);
    mac.finalize().into_bytes().into()
}

/// Build the S parameter: FC || (P_i || L_i)*
pub fn build_s(fc: u8, params: &[&[u8]]) -> Vec<u8> {
    let mut s = vec![fc];
    for p in params {
        s.extend_from_slice(p);
        assert!(p.len() <= 0xFFFF, "KDF parameter exceeds 65535 bytes");
        let len = p.len() as u16;
        s.extend_from_slice(&len.to_be_bytes());
    }
    s
}

/// Derive KAUSF from CK || IK (TS 33.501 Annex A.2)
///
/// `fc`: 0x6A (Free5GC / UE-side) or 0x6B (standard spec / network-side)
pub fn derive_kausf(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    sqn_xor_ak: &[u8; 6],
    fc: u8,
) -> [u8; 32] {
    let ck_ik: Vec<u8> = ck.iter().chain(ik.iter()).copied().collect();
    let s = build_s(fc, &[sn_name, sqn_xor_ak]);
    kdf(&ck_ik, &s)
}

/// Derive KSEAF from KAUSF (TS 33.501 Annex A.6, FC=0x6C)
pub fn derive_kseaf(kausf: &[u8; 32], sn_name: &[u8]) -> [u8; 32] {
    let s = build_s(0x6C, &[sn_name]);
    kdf(kausf, &s)
}

/// Derive KAMF from KSEAF (TS 33.501 Annex A.7, FC=0x6D)
///
/// `supi_digits`: IMSI digits only (no "imsi-" prefix).
/// The caller must strip any prefix before calling.
pub fn derive_kamf(kseaf: &[u8; 32], supi_digits: &str, abba: &[u8]) -> [u8; 32] {
    let s = build_s(0x6D, &[supi_digits.as_bytes(), abba]);
    kdf(kseaf, &s)
}

/// Derive NAS keys from KAMF (TS 33.501 Annex A.8, FC=0x69)
///
/// algo_type: 0x01 = NAS-enc-alg, 0x02 = NAS-int-prot-alg
/// algo_id:   0x00 = NEA0/NIA0, 0x01 = NEA1/NIA1, 0x02 = NEA2/NIA2, 0x03 = NEA3/NIA3
///
/// Returns the full 32-byte output; take the last 16 bytes as the 128-bit key.
pub fn derive_nas_key(kamf: &[u8; 32], algo_type: u8, algo_id: u8) -> [u8; 32] {
    let s = build_s(0x69, &[&[algo_type], &[algo_id]]);
    kdf(kamf, &s)
}

/// Extract the usable 128-bit key from a 256-bit KDF output (last 16 bytes per spec)
pub fn extract_128(full: &[u8; 32]) -> [u8; 16] {
    full[16..]
        .try_into()
        .expect("32-byte array yields 16-byte tail")
}

/// Compute HRES* = SHA-256(RAND || RES*)[16:32] for local verification of the UE's RES*.
pub fn compute_hres_star(rand: &[u8; 16], res_star: &[u8]) -> [u8; 16] {
    debug_assert!(res_star.len() == 16, "RES* must be 16 bytes");
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(rand.as_ref());
    h.update(res_star);
    h.finalize()[16..]
        .try_into()
        .expect("SHA-256 output yields 16-byte tail")
}

/// Derive K_gNB from K_AMF and UL NAS COUNT (TS 33.501 Annex A.9, FC=0x6E)
///
/// `ul_nas_count`: the UL NAS COUNT value used in the trigger message
/// (SecurityModeComplete for initial registration, ServiceRequest for reconnection).
///
/// Access type distinguisher P1 = 0x01 (3GPP access).
pub fn derive_kgnb(kamf: &[u8; 32], ul_nas_count: u32) -> [u8; 32] {
    let count_bytes = ul_nas_count.to_be_bytes();
    let access_type: &[u8] = &[0x01]; // 3GPP access
    let s = build_s(0x6E, &[&count_bytes, access_type]);
    kdf(kamf, &s)
}

/// Derive Next Hop (NH) key for handover key refresh (TS 33.501 Annex A.10, FC=0x6F)
///
/// `sync_input`: K_gNB (first NH) or previous NH (subsequent NHs).
pub fn derive_nh(kamf: &[u8; 32], sync_input: &[u8; 32]) -> [u8; 32] {
    let s = build_s(0x6F, &[sync_input.as_ref()]);
    kdf(kamf, &s)
}

/// Compute XRES* for 5G-AKA (TS 33.501 Annex A.4, FC=0x6B)
pub fn compute_xres_star(
    ck: &[u8; 16],
    ik: &[u8; 16],
    sn_name: &[u8],
    rand: &[u8; 16],
    xres: &[u8],
) -> Vec<u8> {
    debug_assert!(!xres.is_empty(), "XRES must not be empty");
    let ck_ik: Vec<u8> = ck.iter().chain(ik.iter()).copied().collect();
    let s = build_s(0x6B, &[sn_name, rand.as_ref(), xres]);
    let full = kdf(&ck_ik, &s);
    full[16..].to_vec()
}
