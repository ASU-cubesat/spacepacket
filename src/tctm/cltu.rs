//! Generate Communications Link Transmission Unit (CLTU) packets
//! as defined in CCSDS 231.0-B-4

use crate::tctm::randomizer::{apply_randomization, Randomization};

mod bch;

#[derive(Debug, Clone, Copy)]
/// Possible  CCSDS 231.0-B-4  CLTU encoding types
pub enum EncodingScheme {
    /// A modified (63, 56) Bose-Chaudhuri-Hocquenghem code.
    /// Generates 7 parity bits for every 56 data bits
    BCH,
    /// The same as the [Self::BCH] but with CCSDS 231.0-B-4
    /// randomized applied to the TC frame before BCH encoding.
    BCHRandomized,
}

/// Generates a Communications Link Transmission Unit (CLTU) from an input
/// byte stream using the chosen encoding scheme.
pub fn generate_ctlu<P: AsRef<[u8]>>(bytes: P, encoding: EncodingScheme) -> Vec<u8> {
    let bytes = bytes.as_ref();
    match encoding {
        EncodingScheme::BCH => bch::encode_bch_ctlu(bytes),
        EncodingScheme::BCHRandomized => {
            bch::encode_bch_ctlu(apply_randomization(bytes, Randomization::TC).as_slice())
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    // test values derived from https://github.com/yamcs/yamcs/blob/78b9553caf3c9f7ef7a6e6897d236a69aeed8190/yamcs-core/src/test/java/org/yamcs/tctm/ccsds/error/BchCltuGeneratorTest.java
    // and by extension from SpacePyLibrary
    // https://github.com/Stefan-Korner/SpacePyLibrary/blob/master/UnitTest/testData.py
    const TC_FRAME_01: &[u8] = &[
        0x22, 0xF6, 0x00, 0xFF, 0x00, 0x42, 0x1A, 0x8C, 0xC0, 0x0E, 0x01, 0x0D, 0x19, 0x06, 0x02,
        0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0x00, 0x01, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x02, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x0F, 0x00, 0x03, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x04, 0xFF, 0x00,
        0x00, 0x00, 0x00, 0x0F, 0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x06, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x07, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x08,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x09, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00,
        0x0A, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x0B, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F,
        0x00, 0x0C, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x0D, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x0E, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x0F, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0x00, 0x10, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x11, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x0F, 0x00, 0x12, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x13, 0xFF, 0x00,
        0x00, 0x00, 0x00, 0x0F, 0x00, 0x14, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x15, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x16, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x17,
        0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x18, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00,
        0x19, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x1A, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F,
        0x00, 0x1B, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x1C, 0xFF, 0x00, 0x00, 0x00, 0xAD,
        0x1A,
    ];

    const CLTU_01: &[u8] = &[
        0xEB, 0x90, 0x22, 0xF6, 0x00, 0xFF, 0x00, 0x42, 0x1A, 0x12, 0x8C, 0xC0, 0x0E, 0x01, 0x0D,
        0x19, 0x06, 0x5A, 0x02, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8A, 0x00, 0x01, 0x00, 0x00,
        0x00, 0xFF, 0x00, 0xCC, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x01, 0xFF, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0x00, 0x02, 0x5A, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x92, 0x03, 0xFF,
        0x00, 0x00, 0x00, 0x00, 0x0F, 0xD6, 0x00, 0x04, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xD4, 0x0F,
        0x00, 0x05, 0xFF, 0x00, 0x00, 0x00, 0xA8, 0x00, 0x0F, 0x00, 0x06, 0xFF, 0x00, 0x00, 0xC8,
        0x00, 0x00, 0x0F, 0x00, 0x07, 0xFF, 0x00, 0xCA, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x08, 0xFF,
        0x66, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x09, 0xA8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F,
        0x00, 0x92, 0x0A, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0xF4, 0x00, 0x0B, 0xFF, 0x00, 0x00,
        0x00, 0x00, 0x5A, 0x0F, 0x00, 0x0C, 0xFF, 0x00, 0x00, 0x00, 0xB0, 0x00, 0x0F, 0x00, 0x0D,
        0xFF, 0x00, 0x00, 0xD8, 0x00, 0x00, 0x0F, 0x00, 0x0E, 0xFF, 0x00, 0x96, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x0F, 0xFF, 0xDA, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x10, 0x82, 0xFF, 0x00,
        0x00, 0x00, 0x00, 0x0F, 0x00, 0x92, 0x11, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x92, 0x00,
        0x12, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x2A, 0x0F, 0x00, 0x13, 0xFF, 0x00, 0x00, 0x00, 0x24,
        0x00, 0x0F, 0x00, 0x14, 0xFF, 0x00, 0x00, 0x4A, 0x00, 0x00, 0x0F, 0x00, 0x15, 0xFF, 0x00,
        0x72, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x16, 0xFF, 0x2E, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00,
        0x17, 0x20, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x92, 0x18, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0xB0, 0x00, 0x19, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x90, 0x0F, 0x00, 0x1A, 0xFF,
        0x00, 0x00, 0x00, 0x3C, 0x00, 0x0F, 0x00, 0x1B, 0xFF, 0x00, 0x00, 0xF8, 0x00, 0x00, 0x0F,
        0x00, 0x1C, 0xFF, 0x00, 0x2E, 0x00, 0x00, 0xAD, 0x1A, 0x55, 0x55, 0x55, 0xEC, 0xC5, 0xC5,
        0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79,
    ];

    const TC_FRAME_02: &[u8] = &[
        0x22, 0xF6, 0x00, 0x23, 0x00, 0x82, 0x00, 0x0F, 0x00, 0x1D, 0xFF, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x00, 0x1E, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x1F, 0xFF, 0x00, 0x00, 0x00,
        0x00, 0x0F, 0xAC, 0x8F, 0x00, 0x68,
    ];

    const CLTU_02: &[u8] = &[
        0xEB, 0x90, 0x22, 0xF6, 0x00, 0x23, 0x00, 0x82, 0x00, 0x24, 0x0F, 0x00, 0x1D, 0xFF, 0x00,
        0x00, 0x00, 0x34, 0x00, 0x0F, 0x00, 0x1E, 0xFF, 0x00, 0x00, 0x10, 0x00, 0x00, 0x0F, 0x00,
        0x1F, 0xFF, 0x00, 0xD8, 0x00, 0x00, 0x00, 0x0F, 0xAC, 0x8F, 0x00, 0x90, 0x68, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x06, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79,
    ];

    #[rstest]
    #[case(TC_FRAME_01, CLTU_01)]
    #[case(TC_FRAME_02, CLTU_02)]
    fn cltu_gen(#[case] tc_frame: &[u8], #[case] cltu: &[u8]) {
        assert_eq!(cltu, generate_ctlu(tc_frame, EncodingScheme::BCH))
    }
}
