//! The identities and the digit strings of a peer never panic the functions
//! that read them, what decodes encodes back to the octets it came from,
//! and a NAS COUNT is estimated within its range.
#![no_main]

use libfuzzer_sys::fuzz_target;
use oxirush_security::nas_5gs::{Guti, MobileIdentityType, STmsi, Supi};
use oxirush_security::{NasCount, Plmn, tbcd_decode, tbcd_encode};

fuzz_target!(|bytes: &[u8]| {
    // A 5G-GUTI or a 5G-S-TMSI mobile identity: what is read is written
    // back to the same octets, but for the spare bit of the first
    let kind = MobileIdentityType::of(bytes);
    assert_eq!(kind.is_none(), bytes.is_empty());
    if let Ok(guti) = Guti::from_octets(bytes) {
        assert_eq!(kind, Some(MobileIdentityType::Guti));
        let octets = guti.to_octets();
        assert_eq!((octets[0], &octets[1..]), (0xf2, &bytes[1..]));
        let (plmn, region) = (guti.plmn(), guti.amf_region_id());
        let (set, pointer, tmsi) = (guti.amf_set_id(), guti.amf_pointer(), guti.tmsi());
        assert_eq!(Guti::new(plmn, region, set, pointer, tmsi), Ok(guti));
        assert_eq!(STmsi::new(set, pointer, tmsi), Ok(guti.s_tmsi()));
    }
    if let Ok(s_tmsi) = STmsi::from_octets(bytes) {
        assert_eq!(kind, Some(MobileIdentityType::STmsi));
        let octets = s_tmsi.to_octets();
        assert_eq!((octets[0], &octets[1..]), (0xf4, &bytes[1..]));
    }

    // A PLMN identity: what decodes encodes to the same three octets
    if let Some(octets) = bytes.first_chunk::<3>()
        && let Ok(plmn) = Plmn::from_octets(octets)
    {
        assert_eq!(&plmn.to_octets(), octets);
        assert_eq!(Plmn::new(plmn.mcc(), plmn.mnc()), Ok(plmn));
    }

    // A TBCD string: what decodes encodes to the same octets
    if let Ok(text) = tbcd_decode(bytes) {
        assert_eq!(tbcd_encode(&text).as_deref(), Ok(bytes));
    }

    // A NAS COUNT and a sequence number: the estimate is the first COUNT
    // from the lowest one on that ends with the sequence number
    if let Some(&[high, middle, low, sequence_number, bits]) = bytes.first_chunk() {
        let lowest = u32::from_be_bytes([0, high, middle, low]);
        let lowest = NasCount::new(lowest).expect("24 bits");
        if let Ok(count) = lowest.estimate(sequence_number) {
            assert_eq!(count.sequence_number(), sequence_number);
            assert!(count >= lowest && count.get() - lowest.get() < 256);
        }
        // Where the COUNT wraps around, the estimate is the same modulo 2^24
        let wrapped = lowest.wrapping_estimate(sequence_number);
        assert_eq!(wrapped.sequence_number(), sequence_number);
        if let Ok(count) = lowest.estimate(sequence_number) {
            assert_eq!(wrapped, count);
        } else {
            assert!(wrapped < lowest);
        }
        let _ = lowest.estimate_from_low_bits(sequence_number, bits.into());
        let _ = lowest.wrapping_estimate_from_low_bits(sequence_number, bits.into());
        match lowest.next() {
            Ok(next) => assert_eq!(next, lowest.wrapping_next()),
            Err(_) => assert_eq!(lowest.wrapping_next(), NasCount::ZERO),
        }
    }

    // Text from a configuration is refused or encoded, never a panic
    if let Ok(text) = std::str::from_utf8(bytes) {
        let _ = tbcd_encode(text);
        if let Ok(supi) = Supi::parse(text) {
            assert_eq!(supi.to_string(), text);
        }
        let _ = Supi::imsi(text);
        let _ = Supi::network_specific(text);
        if let Some((mcc, mnc)) = text.split_at_checked(3) {
            let _ = Plmn::new(mcc, mnc);
        }
    }
});
