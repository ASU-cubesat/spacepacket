//! Implementation of the TC Space Data Link Protocool
//! as defined in CCSDS 232.0-B-4
//!

use std::io::{Error, ErrorKind, Read};

use byteorder::{BigEndian, ReadBytesExt};

/// The Bypass Flag is used to control the types of
/// Frame Acceptanc Check performed by the receiving entity.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BypassFlag {
    /// This type of frame indicates the normal acceptance
    /// checks shall be performed
    TypeA = 0,
    /// Under Type-B acceptance chcecks are bypassed
    TypeB = 1,
}
impl BypassFlag {
    pub fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(Self::TypeA),
            1 => Ok(Self::TypeB),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid BypassFlag value {val:}. Can only be 1 bit."),
            )),
        }
    }
}

/// Control Command Flag indicates if the packet contains
/// data (Type-D) or control information to set up the
/// Frame Acceptance and Reporting Mechanism (FARM)
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlFlag {
    /// This type of frame contains Data
    TypeD = 0,
    /// A control frame with parameters
    /// to configure FARM to accept data.
    TypeC = 1,
}
impl ControlFlag {
    pub fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(Self::TypeD),
            1 => Ok(Self::TypeC),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid ControlFlag value {val:}. Can only be 1 bit."),
            )),
        }
    }
}

/// Primary Header for a TC Transfer Frame
/// This Header is only meant to be used with a [TCTransferFrame]
/// as the length of the payload is calculated at encoding time.
// When calclulating Length of this header, only 10 bits are allowed.
// Additionally it is considered length -1 consistent with SpacePackets
// this leaves a maximum size of 1024 bytes per packet
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TCPrimaryHeader {
    /// Transfer Frame Version number.
    /// Currently fixed to '00'
    /// Encoded in 2 bits
    pub tfvn: u8,

    /// Bypass Flag determines the type of Frame Acceptance Checks
    /// applied by receiving entity
    pub bypass_flag: BypassFlag,

    /// Control Command Flag indicates if the packet contains
    /// data (Type-D) or control information to set up the
    /// Frame Acceptance and Reporting Mechanism (FARM)
    pub control_flag: ControlFlag,

    /// 10-bit unique identifier for the spacecraft
    pub scid: u16,

    /// The identifier of the virtual channel to which this
    /// packet belongs. 6-bits maximum.
    pub vcid: u8,

    /// Sequence number of this frame, used by Type-A
    /// FARMs to check frames are received sequentially
    pub sequence_number: u8,
}
impl TCPrimaryHeader {
    /// Validate header values which require bit masks will fit in the
    /// desginate bit-depth
    ///
    /// # Errors
    ///
    /// This function errors under the following circumstances
    ///  - [Self::tfvn] > 3
    ///  - [Self::scid] > 1023
    ///  - [Self::vcid] > 63
    pub fn validate(&self) -> Result<(), Error> {
        if self.tfvn > 3 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Transfer frame version number must be <=3 but found {}",
                    self.tfvn
                ),
            ));
        }

        if self.scid > 1023 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Spacecraft ID must be <=1023 but found {}", self.scid),
            ));
        }

        if self.vcid > 63 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Virtual Channel ID must be <=63 but found {}", self.vcid),
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// A TeleCommand (TC) Transfer Frame per CCSDS 232.0-B-4
pub struct TCTransferFrame {
    /// Primary Header information with exception of the payload
    /// length.
    header: TCPrimaryHeader,

    /// Packet payload has a maximum length of 1019 bytes
    payload: Vec<u8>,
}
impl TCTransferFrame {
    /// Initialize a new TC Transfer Frame.
    ///
    /// # Errors
    ///
    /// This function errors under the following circumstances
    ///  - payload length is > 1019 bytes
    ///  - [TCPrimaryHeader::tfvn] > 3
    ///  - [TCPrimaryHeader::scid] > 1023
    ///  - [TCPrimaryHeader::vcid] > 63
    pub fn new(header: TCPrimaryHeader, payload: Vec<u8>) -> Result<Self, Error> {
        header.validate()?;

        if payload.len() > 1019 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Payload length must be <=1019 bytes but supplied payload has length {}",
                    payload.len()
                ),
            ));
        }

        Ok(Self { header, payload })
    }

    /// Retrieve the meta-data header information for this packet.
    /// Header information does not include length of the payload.
    pub fn header(&self) -> TCPrimaryHeader {
        self.header
    }

    /// Borrow the payload of this packet. The payload has a maximum possible length of 1019 bytes
    pub fn payload(&self) -> &[u8] {
        self.payload.as_slice()
    }

    /// Encode the Transfer frame into a byte stream.
    /// Assumes Big Endian byte order
    pub fn encode(mut self) -> Vec<u8> {
        let TCPrimaryHeader {
            tfvn,
            bypass_flag,
            control_flag,
            scid,
            vcid,
            sequence_number,
        } = self.header;

        let first_word = {
            (tfvn as u16 & 0x3_u16) << 14
            | (bypass_flag as u16 & 0x1_u16) << 13
            | (control_flag as u16 & 0x1_u16) << 12
            // two spare bits here reserved
            | (scid & 0x3ff_u16)
        };

        let encoded_len = (self.payload.len() - 1) as u16;
        let second_word = { ((vcid as u16 & 0x3f_u16) << 10) | (encoded_len & 0x3ff_u16) };

        let mut message = first_word.to_be_bytes().to_vec();

        message.extend_from_slice(&second_word.to_be_bytes());
        message.push(sequence_number);

        message.append(&mut self.payload);

        message
    }

    /// Decode a transfer frame from a byte stream.
    /// Assumes Big Endian byte order
    pub fn decode<R: Read>(buffer: &mut R) -> Result<Self, Error> {
        let first_word = buffer.read_u16::<BigEndian>()?;
        let second_word = buffer.read_u16::<BigEndian>()?;

        let payload_len = (second_word & 0x3ff_u16) + 1;

        let header = TCPrimaryHeader {
            tfvn: ((first_word >> 14) & 0x3_u16) as u8,
            bypass_flag: BypassFlag::from_u8(((first_word >> 13) & 0x1_u16) as u8)?,
            control_flag: ControlFlag::from_u8(((first_word >> 12) & 0x1_u16) as u8)?,
            scid: first_word & 0x3ff_u16,
            vcid: ((second_word >> 10) & 0x3f_u16) as u8,
            sequence_number: buffer.read_u8()?,
        };

        let mut payload = vec![0_u8; payload_len as usize];

        buffer.read_exact(&mut payload)?;

        Self::new(header, payload)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(0, 5, 2)]
    #[should_panic]
    // tfvn out of bounds
    #[case(4, 5, 33)]
    #[should_panic]
    // scid out of bounds
    #[case(0, 1024, 62)]
    #[should_panic]
    // vcid out of bounds
    #[case(0, 7, 65)]
    fn header_validation(#[case] tfvn: u8, #[case] scid: u16, #[case] vcid: u8) {
        let header = TCPrimaryHeader {
            tfvn,
            bypass_flag: BypassFlag::TypeA,
            control_flag: ControlFlag::TypeC,
            scid,
            vcid,
            sequence_number: 23,
        };

        assert!(header.validate().is_ok())
    }

    #[rstest]
    #[case(b"some bytes foo bar baz".to_vec())]
    #[should_panic]
    #[case(vec![0_u8; 2048])]
    fn frame_roundtrip(
        #[values(BypassFlag::TypeA, BypassFlag::TypeB)] bypass_flag: BypassFlag,
        #[values(ControlFlag::TypeD, ControlFlag::TypeD)] control_flag: ControlFlag,
        #[case] payload: Vec<u8>,
        #[values(0, 33, 1023)] scid: u16,
        #[values(0, 3, 7)] vcid: u8,
    ) {
        let expected = TCTransferFrame::new(
            TCPrimaryHeader {
                tfvn: 0,
                bypass_flag,
                control_flag,
                scid,
                vcid,
                sequence_number: 23,
            },
            payload,
        )
        .unwrap();

        let buffer = expected.clone().encode();

        let recovered = TCTransferFrame::decode(&mut buffer.as_slice())
            .expect("Should be able to roundtrip TCTransferFrame");

        assert_eq!(expected, recovered)
    }
}
