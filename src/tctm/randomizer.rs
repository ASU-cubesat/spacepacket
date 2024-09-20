use lazy_static::lazy_static;
lazy_static! {
    // CCSDS 131.0-B-5 TC randomizer with generator polynomial
    // h(x) = x^8 + x^6 + x^4 + x^3 + x^2 + x + 1
    pub(crate) static ref TC_RANDOMIZER: Box<[u8]> = {
        let mut lfsr = 0xFF_u8;
        let mut extra_bit = 0_u8;

        [0_u8; 255]
            .into_iter()
            .map(|mut val| {
                (0..8).for_each(|_| {
                    val = (val << 1) | (lfsr & 1);
                    extra_bit = (lfsr
                        ^ (lfsr >> 1)
                        ^ (lfsr >> 2)
                        ^ (lfsr >> 3)
                        ^ (lfsr >> 4)
                        ^ (lfsr >> 6))
                        & 1;
                    lfsr = (lfsr >> 1) | (extra_bit << 7);
                });
                val
            })
            .collect::<Vec<_>>()
            .into_boxed_slice()
    };


    // legacy 255 byte TM randomizer with generator polynomial
    // h(x) = x^8 + x^7 + x^5 + x^3 + 1
    pub(crate) static ref TM_RANDOMIZER_255: Box<[u8]> ={
        let mut lfsr = 0xFF_u8;
        let mut extra_bit = 0_u8;

        [0_u8; 255].into_iter().map(|mut val| {
            (0..8).for_each(|_|{
                val = (val <<1) | (lfsr & 1);
                extra_bit = (
                    lfsr
                    ^ (lfsr >> 3)
                    ^ (lfsr >> 5)
                    ^ (lfsr >> 7)
                ) & 1;

                lfsr = (lfsr >> 1) | (extra_bit << 7);
                });
                val
        }).collect::<Vec<_>>()
        .into_boxed_slice()

    };

    // Recommended 131071 length repeater with generator polynomial
    // h(x) = x^17 + x^14 + 1
    pub(crate) static ref TM_RANDOMIZER_131071: Box<[u8]> ={
        let mut lfsr = 0x18E38_u32;
        let mut extra_bit = 0x0_u32;

        [0_u8; 131071].into_iter().map(|mut val|{
            (0..8).for_each(|_| {
                // accumulate the output bits into the output
                // register
                val = (val << 1) | ((lfsr  & 1) as u8);

                // perform xor output on the taps
                extra_bit = (lfsr ^ (lfsr >> 14)) & 1;

                // polynomial depth is 17 bits, so shift by depth - 1
                lfsr = (lfsr >> 1) | (extra_bit << 16);
            });
            val
        }).collect::<Vec<_>>().into_boxed_slice()
    };
}

pub(crate) enum Randomization {
    TC,
    Tm255,
    Tm131071,
}

pub(crate) fn apply_randomization<P: AsRef<[u8]>>(bytes: P, randomizer: Randomization) -> Vec<u8> {
    let randomization_generator = match randomizer {
        Randomization::TC => &(*TC_RANDOMIZER),
        Randomization::Tm255 => &(*TM_RANDOMIZER_255),
        Randomization::Tm131071 => &(*TM_RANDOMIZER_131071),
    };
    bytes
        .as_ref()
        .iter()
        .zip(randomization_generator.iter().cycle())
        .map(|(val, rand)| val ^ rand)
        .collect()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn tc_randomizer() {
        let expected_seq = [
            0b1111_1111_u8,
            0b0011_1001,
            0b1001_1110,
            0b0101_1010,
            0b0110_1000,
        ];

        let seq: [u8; 5] = TC_RANDOMIZER[..5].try_into().unwrap();

        assert_eq!(expected_seq, seq)
    }

    #[test]
    fn tm_randomizer_255() {
        let expected_seq = [
            0b1111_1111_u8,
            0b0100_1000,
            0b0000_1110,
            0b1100_0000,
            0b1001_1010,
        ];

        let seq: [u8; 5] = TM_RANDOMIZER_255[..5].try_into().unwrap();

        assert_eq!(expected_seq, seq)
    }

    #[test]
    fn tm_randomizer_131071() {
        let expected_eq = [
            0b0001_1100_u8,
            0b0111_0001,
            0b1011_1001,
            0b0001_1011,
            0b1010_1001,
        ];

        let seq: [u8; 5] = TM_RANDOMIZER_131071[..5].try_into().unwrap();

        assert_eq!(expected_eq, seq)
    }
}
