//! Demonstrate the 5G key derivation chain per TS 33.501 Annex A:
//! KAUSF -> KSEAF -> KAMF -> KNASint / KNASenc -> K_gNB

use oxirush_security::*;

fn main() {
    // Example key material (from test vectors)
    let k_ausf = [0xAA; 32]; // In practice, derived from AUSF via 5G-AKA
    let sn_name = b"5G:mnc093.mcc208.3gppnetwork.org";
    let abba = [0x00, 0x00]; // 5G standalone

    // KAUSF -> KSEAF
    let k_seaf = derive_kseaf(&k_ausf, sn_name);
    println!("KSEAF: {}", hex::encode(k_seaf));

    // KSEAF -> KAMF
    let supi = "208930000000001";
    let k_amf = derive_kamf(&k_seaf, supi, &abba);
    println!("KAMF:  {}", hex::encode(k_amf));

    // KAMF -> KNASint (NIA2 = algorithm ID 2, distinguisher 0x02)
    let k_nas_int = derive_nas_key(&k_amf, 0x02, 2); // integrity, NIA2
    println!("KNASint (NIA2): {}", hex::encode(k_nas_int));

    // KAMF -> KNASenc (NEA2 = algorithm ID 2, distinguisher 0x01)
    let k_nas_enc = derive_nas_key(&k_amf, 0x01, 2); // ciphering, NEA2
    println!("KNASenc (NEA2): {}", hex::encode(k_nas_enc));

    // KAMF -> K_gNB (for initial context setup)
    let k_gnb = derive_kgnb(&k_amf, 0); // uplink NAS COUNT = 0
    println!("K_gNB: {}", hex::encode(k_gnb));

    // K_gNB -> NH (for handover, NCC=1)
    let nh = derive_nh(&k_amf, &k_gnb);
    println!("NH (NCC=1): {}", hex::encode(nh));
}
