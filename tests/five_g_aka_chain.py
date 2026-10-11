#!/usr/bin/env python3
"""The values of the 5G AKA key chain test, from another implementation.

TS 33.501 has no test data for its key derivation functions. This script
derives the chain that `five_g_aka_key_chain` of `src/nas_5gs/kdf.rs` and
the README check, with the HMAC-SHA-256 of Python's standard library over
the S strings of TS 33.220 Annex B.2 and TS 33.501 Annex A.2 to A.10. It
shares no code with the crate.

    python3 tests/five_g_aka_chain.py

It prints each value and exits with an error if one differs from what the
crate's test expects.
"""

import hashlib
import hmac
import sys


def kdf(key: bytes, fc: int, *parameters: bytes) -> bytes:
    """HMAC-SHA-256(key, FC || P0 || L0 || P1 || L1 ...), TS 33.220 Annex B.2."""
    s = bytes([fc])
    for parameter in parameters:
        s += parameter + len(parameter).to_bytes(2, "big")
    return hmac.new(key, s, hashlib.sha256).digest()


# CK, IK, RAND, RES and SQN xor AK: the MILENAGE outputs of TS 35.208 test set 1
ck = bytes.fromhex("b40ba9a3c58b2a05bbf0d987b21bf8cb")
ik = bytes.fromhex("f769bcd751044604127672711c6d3441")
rand = bytes.fromhex("23553cbe9637a89d218ae64dae47bf35")
res = bytes.fromhex("a54211d5e3ba50bf")
sqn_xor_ak = bytes.fromhex("55f328b43577")
sn_name = b"5G:mnc093.mcc208.3gppnetwork.org"
supi = b"208930000000001"
abba = bytes.fromhex("0000")

# Annex A.2, A.4 and A.5: KAUSF, XRES* and HXRES*
k_ausf = kdf(ck + ik, 0x6A, sn_name, sqn_xor_ak)
xres_star = kdf(ck + ik, 0x6B, sn_name, rand, res)[16:]
hxres_star = hashlib.sha256(rand + xres_star).digest()[16:]

# Annex A.6 and A.7: KSEAF and KAMF
k_seaf = kdf(k_ausf, 0x6C, sn_name)
k_amf = kdf(k_seaf, 0x6D, supi, abba)

# Annex A.8: KNASenc of 128-NEA2 and KNASint of 128-NIA2, the 128 least
# significant bits
k_nas_enc = kdf(k_amf, 0x69, b"\x01", b"\x02")[16:]
k_nas_int = kdf(k_amf, 0x69, b"\x02", b"\x02")[16:]

# Annex A.9 and A.10: KgNB from uplink NAS COUNT 0 on 3GPP access, then NH
k_gnb = kdf(k_amf, 0x6E, (0).to_bytes(4, "big"), b"\x01")
nh = kdf(k_amf, 0x6F, k_gnb)

EXPECTED = {
    "KAUSF": (k_ausf, "f2e35260f85194d4f891504d02111e56689ac23dd393bee3abbcc5bfbc013ef9"),
    "XRES*": (xres_star, "5cc9527f4d21c43bee83a15443acf1c4"),
    "HXRES*": (hxres_star, "6970075e3c8245fdc2073003cf166279"),
    "KSEAF": (k_seaf, "cfddde483bd1318a412e98870f556410905be4fb7500abed93ee16af71bbb3fa"),
    "KAMF": (k_amf, "9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4"),
    "KNASenc": (k_nas_enc, "f47ae570afde775373d1b313d2176f54"),
    "KNASint": (k_nas_int, "28ddb5356880149b9fee22f2367522a4"),
    "KgNB": (k_gnb, "c18166e13cfde1dea842c708f6e0b3372b6896664df4e865c0c78bd270852005"),
    "NH": (nh, "383c6b76bf2a99aa2ca4c5136d4122a2b942301f0b9e07439786939cd30c4a4b"),
}

failed = False
for name, (value, expected) in EXPECTED.items():
    same = value.hex() == expected
    failed |= not same
    print(f"{name:8} {value.hex()} {'' if same else '!= ' + expected}")
sys.exit(1 if failed else 0)
