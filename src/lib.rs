pub mod algo;
/// oxirush-security: 5G NAS security algorithms
///
/// Implements 3GPP TS 33.501 security primitives:
/// - Key derivation (KAUSF, KSEAF, KAMF, KNASint, KNASenc)
/// - Integrity: NIA1 (SNOW 3G), NIA2 (AES-CMAC), NIA3 (ZUC)
/// - Ciphering: NEA0 (null), NEA1 (SNOW 3G), NEA2 (AES-CTR), NEA3 (ZUC)
/// - 5G-GUTI construction/parsing
pub mod error;
pub mod guti;
pub mod kdf;
pub mod nea;
pub mod nia;
pub mod plmn;
pub mod snow3g;
pub mod suci;
pub mod zuc;

// Re-export commonly used items
pub use algo::{select_ciphering_algo, select_integrity_algo};
pub use error::SecurityError;
pub use guti::{build_guti_bytes, mobile_identity_type, parse_guti_tmsi, parse_s_tmsi};
pub use kdf::{
    compute_hres_star, compute_xres_star, derive_kamf, derive_kausf, derive_kgnb, derive_kseaf,
    derive_nas_key, derive_nh, extract_128,
};
pub use nea::{nas_cipher, nea1_cipher, nea2_cipher, nea3_cipher};
pub use nia::{nas_mac, nia1_mac, nia2_mac, nia3_mac};
pub use plmn::{plmn_from_bytes, plmn_to_bytes, tbcd_decode, tbcd_encode};
pub use suci::{
    msin_to_bcd, suci_conceal, suci_decrypt_a, suci_decrypt_b, suci_scheme_output_a,
    suci_scheme_output_b, suci_to_string, suci_to_supi,
};
