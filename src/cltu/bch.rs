use lazy_static::lazy_static;
/// CCSDS BCH polynomial x^7 + x^6 + x^2 + 1
/// is then left shifted 1 bit
const CCSDS_POLYNOMIAL: u8 = 0x8A_u8;
const START_SEQUNCE: &[u8] = &[0xEB, 0x90];
const TAIL_SEQUENCE: &[u8] = &[0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0xC5, 0x79];

lazy_static! {
    static ref LOOKUP_TALBE: [u8; 256] = (0_u8..=255)
        .map(|val| {
            (0..8_u8).fold(val, |val, _| {
                if val & 0x80 == 0 {
                    val << 1
                } else {
                    (val << 1) ^ CCSDS_POLYNOMIAL
                }
            })
        })
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
}

/// Compute BCH codeword as defined in CCSDS 232.0-B-4 with polynomial
/// polynomial x^7 + x^6 + x^2 + 1
pub fn compute_bch_parity(bytes: &[u8; 7]) -> u8 {
    // bch encoding takes 7 byte chunks of data then computes 1 parity byte

    let mut remainder = bytes
        .iter()
        .fold(0, |acc, val| LOOKUP_TALBE[(val ^ acc) as usize]);
    // logical complement of the remainder
    remainder ^= 0xFF;
    // force the 0th byte to be 0 since there are only 7 parity bits.
    remainder &= 0xFE;
    remainder
}

pub(crate) fn encode_bch_ctlu(bytes: &[u8]) -> Vec<u8> {
    let mut output = START_SEQUNCE.to_vec();

    let mut iter = bytes.chunks_exact(7);

    (&mut iter).for_each(|chunk| {
        output.extend_from_slice(chunk);
        // unwraping is safe here because we have forced chunks of length 7
        output.push(compute_bch_parity(chunk.try_into().unwrap()));
    });

    // handle any remainder by resizing to 7-bytes chunk
    if !iter.remainder().is_empty() {
        let mut remainder = iter.remainder().to_vec();
        // padd with bits of alternating 0 and 1s starting with 0
        remainder.resize(7, 0x55_u8);
        output.extend_from_slice(&remainder);
        // unwraping is safe here because we have forced a  length of 7
        output.push(compute_bch_parity(remainder.as_slice().try_into().unwrap()));
    }
    output.extend_from_slice(TAIL_SEQUENCE);

    output
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    // test values derived from https://github.com/yamcs/yamcs/blob/78b9553caf3c9f7ef7a6e6897d236a69aeed8190/yamcs-core/src/test/java/org/yamcs/tctm/ccsds/error/BchCltuGeneratorTest.java
    // and by extension from SpacePyLibrary
    // https://github.com/Stefan-Korner/SpacePyLibrary/blob/master/UnitTest/testData.py

    #[rstest]
    #[case([0x22, 0xF6, 0x00, 0xFF, 0x00, 0x42, 0x1A], 0x12)]
    #[case([0x8C, 0xC0, 0x0E, 0x01, 0x0D, 0x19, 0x06], 0x5A)]
    #[case([0x30, 0x1B, 0x00, 0x09, 0x00, 0x82, 0x00], 0x54)]
    #[case([0x10, 0xE4, 0xC1, 0x55, 0x55, 0x55, 0x55], 0x3E)]
    fn bch_encoding(#[case] input: [u8; 7], #[case] parity: u8) {
        assert_eq!(parity, compute_bch_parity(&input))
    }
}
