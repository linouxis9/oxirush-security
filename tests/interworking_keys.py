#!/usr/bin/env python3
"""The values of the interworking keys test, from another implementation.

TS 33.501 has no test data for the keys that map a security context of 5GS
to one of EPS and back (Annex A.14 and A.15), nor for the access stratum
keys of a handover between the two systems. This script derives the keys
that `interworking_keys_match_another_implementation` of
`src/nas_5gs/kdf.rs` checks, with the HMAC-SHA-256 of Python's standard
library, over strings S written here octet by octet from the clauses: FC,
then each parameter and its length in two octets (TS 33.220 Annex B.2). It
shares no code with the crate.

    python3 -I tests/interworking_keys.py

It prints each value and exits with an error if one is not the value that
the crate's test expects, which it reads in the source of the test.
"""

import hashlib
import hmac
import pathlib
import re
import sys


def kdf(key: bytes, s: str) -> bytes:
    """HMAC-SHA-256(key, S), S given in hexadecimal with spaces between its fields."""
    return hmac.new(key, bytes.fromhex(s.replace(" ", "")), hashlib.sha256).digest()


# KAMF of the 5G AKA chain of `tests/five_g_aka_chain.py`: TS 35.208 test set
# 1, serving network 208-93, SUPI 208930000000001, ABBA 0000
k_amf = bytes.fromhex("9d63b519775a92ca861ca6a50d848fa8ebf160ea7b73735a85b33737e73c55b4")

# Idle mobility from 5GS to EPS (TS 33.501 clauses 8.5.2 and 8.6.1): the TAU
# REQUEST is protected with the uplink 5G NAS COUNT 00 a1 b2 c3, from which
# KASME' is derived. Annex A.14.1: FC 0x73, P0 the uplink NAS COUNT, L0 00 04
k_asme_idle = kdf(k_amf, "73 00a1b2c3 0004")

# Handover from 5GS to EPS (clause 8.3.2): KASME' of the downlink 5G NAS COUNT
# 00 03 02 01. Annex A.14.2: FC 0x74, P0 the downlink NAS COUNT, L0 00 04
k_asme_ho = kdf(k_amf, "74 00030201 0004")
# KeNB of KASME' at the uplink NAS COUNT 2^32 - 1. TS 33.401 Annex A.3:
# FC 0x11, P0 the uplink NAS COUNT, L0 00 04
k_enb = kdf(k_asme_ho, "11 ffffffff 0004")
# NH twice, for {NH, NCC=2}. TS 33.401 Annex A.4: FC 0x12, P0 KeNB for the
# first NH and the NH before it for the next, L0 00 20
nh_1 = kdf(k_asme_ho, "12 " + k_enb.hex() + " 0020")
nh_2 = kdf(k_asme_ho, "12 " + nh_1.hex() + " 0020")

# Idle mobility from EPS to 5GS (clauses 8.2 and 8.6.2), with the KASME'
# above: KAMF' of the uplink EPS NAS COUNT 00 00 01 02 of the TAU REQUEST
# that the REGISTRATION REQUEST has. Annex A.15.1: FC 0x75, P0 that COUNT,
# L0 00 04
k_amf_idle = kdf(k_asme_idle, "75 00000102 0004")

# Handover from EPS to 5GS (clause 8.4.2), with the KASME' of the handover
# above: the source MME gives its next NH, for NCC 3, from which KAMF' is
# derived. Annex A.15.2: FC 0x76, P0 the NH, L0 00 20
nh_3 = kdf(k_asme_ho, "12 " + nh_2.hex() + " 0020")
k_amf_ho = kdf(k_asme_ho, "76 " + nh_3.hex() + " 0020")
# The temporary KgNB of KAMF' at the uplink NAS COUNT 2^32 - 1, sent with
# NCC 0. Annex A.9: FC 0x6E, P0 the uplink NAS COUNT, L0 00 04, P1 the
# access type distinguisher of 3GPP access 01, L1 00 01
k_gnb = kdf(k_amf_ho, "6e ffffffff 0004 01 0001")
# The NH that the AMF keeps for NCC 1. Annex A.10: FC 0x6F, P0 KgNB, L0 00 20
nh_5g = kdf(k_amf_ho, "6f " + k_gnb.hex() + " 0020")

DERIVED = {
    "KASME' (idle)": k_asme_idle,
    "KASME' (HO)": k_asme_ho,
    "KeNB": k_enb,
    "NH 1": nh_1,
    "NH 2": nh_2,
    "KAMF' (idle)": k_amf_idle,
    "NH 3": nh_3,
    "KAMF' (HO)": k_amf_ho,
    "KgNB": k_gnb,
    "NH (5G)": nh_5g,
}

# What the crate's test expects: the hexadecimal strings that its source
# compares the keys with
test = (pathlib.Path(__file__).parent.parent / "src" / "nas_5gs" / "kdf.rs").read_text()
start = test.index("fn interworking_keys_match_another_implementation")
expected = set(re.findall(r'"([0-9a-f]{64})"', test[start : test.index("#[test]", start)]))

failed = False
for name, value in DERIVED.items():
    same = value.hex() in expected
    failed |= not same
    print(f"{name:13} {value.hex()} {'' if same else 'is not in the test of the crate'}")
sys.exit(1 if failed else 0)
