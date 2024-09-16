//! Implementation of the Telemetry Frame (TM) as defined in CCSDS 132.0-B-3

use std::io::{Error, ErrorKind, Read};

use byteorder::{BigEndian, ReadBytesExt};

use crate::GroupingFlag;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Flag to indicate if the associated field is present in a TM Tranfser Frame.
pub enum BooleanFieldFlag {
    NotPresent = 0,
    Present = 1,
}
impl BooleanFieldFlag {
    pub fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(Self::NotPresent),
            1 => Ok(Self::Present),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid BooleanFieldFlag value {val:}. Can only be 1 bit."),
            )),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Flag to identify type type of data in the TM Transfer Frame Data Field.
pub enum SynchronizationFlag {
    /// Indicates the presence of octet-synchronized and forward-ordered
    /// Packets or Idle Data
    Nominal = 0,
    /// Indicates the presence of Virtual Channel Access Service Data Unit (VCA_SDU)
    /// in the data field
    VcaSdu = 1,
}
impl SynchronizationFlag {
    pub fn from_u8(val: u8) -> Result<Self, Error> {
        match val {
            0 => Ok(Self::Nominal),
            1 => Ok(Self::VcaSdu),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!("Invalid SynchronizationFlag value {val:}. Can only be 1 bit."),
            )),
        }
    }
}

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// When the [TMDataFieldStatus::synchronization_flag] is set to [SynchronizationFlag::VcaSdu]
/// this field is undefined.
pub enum SegmentLength {
    /// This flag has no meaning when synchronization is set to [SynchronizationFlag::VcaSdu]
    Undefined(u8),
    /// Value is fixed to `0b11` to align with non-use of Source Packet Segments in previous standards.
    /// when synchronization is set to [SynchronizationFlag::Nominal]
    Unsegmented = 0b11,
}
impl SegmentLength {
    pub fn from_u8(value: u8) -> Result<Self, Error> {
        match value {
            val if val < 0b11 => Ok(Self::Undefined(val)),
            0b11 => Ok(Self::Unsegmented),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!("SegmentLength can must be less than 4, found {val}"),
            )),
        }
    }

    pub fn into_u8(self) -> u8 {
        match self {
            SegmentLength::Undefined(val) => val & 0x3,
            SegmentLength::Unsegmented => 0b11,
        }
    }
}

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirstHeaderPointer {
    /// Index of  the first header must be less than 2046
    ByteIndex(u16),
    OnlyIdleData = 0b111_1111_1110,
    NoPacket = 0b111_1111_1111,
}
impl FirstHeaderPointer {
    pub fn into_u16(self) -> u16 {
        match self {
            FirstHeaderPointer::ByteIndex(value) => value & 0x7ff,
            FirstHeaderPointer::OnlyIdleData => 0b111_1111_1110,
            FirstHeaderPointer::NoPacket => 0b111_1111_1111,
        }
    }

    pub fn from_u16(value: u16) -> Result<Self, Error> {
        match value {
            val if val < 2046 => Ok(Self::ByteIndex(val)),
            0b111_1111_1110 => Ok(Self::OnlyIdleData),
            0b111_1111_1111 => Ok(Self::NoPacket),
            val => Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Invalid FristHeaderPointer value. \
                    Value must be less than 2048 but received {val}."
                ),
            )),
        }
    }

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::ByteIndex(index) => {
                if index < &2046_u16 {
                    Ok(())
                } else {
                    Err(Error::new(
                        ErrorKind::InvalidData,
                        format!("First Header byte index must be less than 2046 found {index}"),
                    ))
                }
            }
            Self::OnlyIdleData => Ok(()),
            Self::NoPacket => Ok(()),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Data Field status is a 16-bit value of meta-data flags
/// used to identify how to decode the Data Field
pub struct TMDataFieldStatus {
    /// Indicated if a seconday header is attached to this TM Transfer Field
    pub secondary_header_flag: BooleanFieldFlag,

    /// Flag state is used to discern the type of data in the TM Data Field.
    pub synchronization_flag: SynchronizationFlag,

    /// as Defined in  CCSDS 132.0-B-3: If the Synchronization Flag is set to ‘0’,
    /// the Packet Order Flag is reserved for future use by the CCSDS and is set to ‘0’.
    /// If the Synchronization Flag is set to [SynchronizationFlag::VcaSdu], the
    /// use of the Packet Order Flag is undefined.
    pub packet_order: bool,

    /// When [Self::synchronization_flag] is [SynchronizationFlag::Nominal]
    /// this flag is set to a fixed value [GroupingFlag::Unsegm] to align with a previous standard version
    /// which allowed for segemneted Packets.
    ///
    /// When [Self::synchronization_flag] is [SynchronizationFlag::VcaSdu]
    /// this flag is undefined.
    pub segment_length: GroupingFlag,

    /// Identifies the byte offset of the start of the next packet inside
    /// the data field
    pub first_header_pointer: FirstHeaderPointer,
}
impl TMDataFieldStatus {
    /// Validate Data Field status values
    ///
    /// # Errors
    ///
    /// This function errors under the following circumstances
    ///  - [Self::first_header_pointer] is of type [FirstHeaderPointer::ByteIndex]  with index > 2046
    pub fn validate(&self) -> Result<(), Error> {
        self.first_header_pointer.validate()
    }

    /// Encode into a byte stream
    pub fn encode(self) -> Vec<u8> {
        let Self {
            secondary_header_flag,
            synchronization_flag,
            packet_order,
            segment_length,
            first_header_pointer,
        } = self;

        let word = (secondary_header_flag as u16) << 15
            | (synchronization_flag as u16) << 14
            | (packet_order as u16) << 13
            | (segment_length as u16) << 11
            | first_header_pointer.into_u16();

        word.to_be_bytes().to_vec()
    }

    /// Decode the Status field from a byte stream
    pub fn decode<R: Read>(buffer: &mut R) -> Result<Self, Error> {
        let first_word = buffer.read_u16::<BigEndian>()?;

        Ok(Self {
            secondary_header_flag: BooleanFieldFlag::from_u8((first_word >> 15) as u8 & 0x1_u8)?,
            synchronization_flag: SynchronizationFlag::from_u8((first_word >> 14) as u8 & 0x1_u8)?,
            packet_order: (first_word >> 13) & 0x1 == 1,
            segment_length: GroupingFlag::from_2bits((first_word >> 11) as u8 & 0x3),
            first_header_pointer: FirstHeaderPointer::from_u16(first_word & 0x7FF_u16)?,
        })
    }
}

/// Primary Header for a TM transfer Frame.
/// This header is meant to be with a [TMTransferFrame]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TMPrimaryHeader {
    /// Transfer Frame Version number.
    /// Currently fixed to '00'
    /// Encoded in 2 bits
    pub tfvn: u8,

    /// 10-bit unique identifier for the spacecraft
    pub scid: u16,

    /// The identifier of the virtual channel to which this
    /// packet belongs. 6-bits maximum.
    pub vcid: u8,

    /// Flag to identify whether the Operational Control Field
    /// is present or not in the TM Transfer Frame.
    pub ocf_flag: BooleanFieldFlag,

    /// Sequence count (modulo 256) of frames in the master channel.
    pub mc_frame_count: u8,

    /// Sequence coutn (modulo 256) of frames in the virtual channel.
    pub vc_frame_count: u8,

    /// Metadata about the Transfer Frame Data Field used to decode underlying packets.
    pub data_field_status: TMDataFieldStatus,
}
impl TMPrimaryHeader {
    /// Validate header values which require bit masks will fit in the
    /// desginate bit-depth
    ///
    /// # Errors
    ///
    /// This function errors under the following circumstances
    ///  - [Self::tfvn] > 3
    ///  - [Self::scid] > 1023
    ///  - [Self::vcid] > 7
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

        if self.vcid > 7 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!("Virtual Channel ID must be <=7 but found {}", self.vcid),
            ));
        }

        self.data_field_status.validate()?;

        Ok(())
    }

    /// Encode self into a byte steam
    pub fn encode(self) -> Vec<u8> {
        let Self {
            tfvn,
            scid,
            vcid,
            ocf_flag,
            mc_frame_count,
            vc_frame_count,
            data_field_status,
        } = self;

        let first_word = {
            (tfvn as u16 & 0x3_u16) << 14
                | (scid & 0x3ff_u16) << 4
                | (vcid as u16 & 0x7_u16) << 1
                | ocf_flag as u16
        };

        let mut message = first_word.to_be_bytes().to_vec();

        message.push(mc_frame_count);
        message.push(vc_frame_count);
        message.extend_from_slice(&data_field_status.encode());

        message
    }

    /// Decode from a byte steam
    pub fn decode<R: Read>(buffer: &mut R) -> Result<Self, Error> {
        let first_word = buffer.read_u16::<BigEndian>()?;

        Ok(Self {
            tfvn: (first_word >> 14) as u8 & 0x3_u8,
            scid: (first_word >> 4) & 0x3ff_u16,
            vcid: (first_word >> 1) as u8 & 0x7_u8,
            ocf_flag: BooleanFieldFlag::from_u8((first_word & 0x1_u16) as u8)?,
            mc_frame_count: buffer.read_u8()?,
            vc_frame_count: buffer.read_u8()?,
            data_field_status: TMDataFieldStatus::decode(buffer)?,
        })
    }
}

/// A flexible Platform for the Secondary Header in a TM Transfer Frame.
/// This secondary header computes the length of the Secondary Header Payload
/// at en/de-coding time, as such it should only be used along with a [TMTransferFrame]
/// to ensure correctness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TMSecondaryHeader {
    /// The version number of the secondary header
    /// CCSDS 132.0-B-3 recognizes only one version, which is
    /// Version 1, the binary encoded Version Number of which is ‘00’.
    pub tfvn: u8,

    /// The data Field of the secondary header contains mission specific
    /// information. Maximum length is 63 bytes.
    pub data_field: Vec<u8>,
}
impl TMSecondaryHeader {
    /// Validate header values which require bit masks will fit in the
    /// desginate bit-depth.
    ///
    /// Errors:
    ///  - if [Self::tfvn] > 3
    ///  - if [Self::data_field] has length > 63
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

        if self.data_field.len() > 63 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                format!(
                    "Secondary Header data field must have length <=63. Found {}",
                    self.data_field.len()
                ),
            ));
        }

        Ok(())
    }

    /// Encode to a byte steam
    pub fn encode(self) -> Vec<u8> {
        let Self {
            tfvn,
            mut data_field,
        } = self;

        // the secondary header is 1 byte
        // and the encoded length is total length -1
        // so we need to take len() +1 -1 or just len
        let packet_len = (data_field.len()) as u8;
        let mut message = vec![{ (tfvn & 0x3_u8) << 6 | packet_len }];
        message.append(&mut data_field);
        message
    }

    /// Decode from a byte steam
    pub fn decode<R: Read>(buffer: &mut R) -> Result<Self, Error> {
        let first_byte = buffer.read_u8()?;

        // the length field is total length -1, add 1 to get the length of the header too
        // then subtract again to get length of the data array
        let data_len = (first_byte & 0x3f) as usize;
        Ok(Self {
            tfvn: (first_byte >> 6) & 0x3,
            data_field: {
                let mut tmp = vec![0; data_len];
                buffer.read_exact(&mut tmp)?;
                tmp
            },
        })
    }
}

/// A Telemetry (TM) Transfer Frame used in telemetry downlink defined in  CCSDS 132.0-B-3
/// Operational Control Field and Frame Error Control Field are not automatically
/// decoded and are left in the data_field of this structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TMTransferFrame {
    /// TM primary header meta-data
    pub primary_header: TMPrimaryHeader,

    /// The Data Field of telemetry values. May have a [TMSecondaryHeader]
    /// at the beginning. This is indicated by the presence of [TMDataFieldStatus::secondary_header_flag]
    ///
    /// The length of this field is fixed on a per physical channel basis.
    /// As such it is impossible to decode one without apriori knowledge of the
    /// length.
    pub data_field: Vec<u8>,
}
impl TMTransferFrame {
    /// Encode this packet into a byte stream
    pub fn encode(self) -> Vec<u8> {
        let Self {
            primary_header,
            mut data_field,
        } = self;
        let mut message = primary_header.encode();
        message.append(&mut data_field);
        message
    }

    /// Decode a Transfer Frame from a byte stream.
    /// Frame lengths are fixed on per-mission physical channel basis.
    /// As such it is impossible to decode one without apriori knowledge of the
    /// length.
    ///
    /// The length parameter to this function is the length of the entire Frame:
    ///  - Primary Header [6-bytes]
    ///  - Secondary Header (<= 64 bytes, if present)
    ///  - Trailer (2, 4, or 6 bytes, if present)
    pub fn decode<R: Read>(buffer: &mut R, length: usize) -> Result<Self, Error> {
        Ok(Self {
            primary_header: TMPrimaryHeader::decode(buffer)?,
            data_field: {
                let mut tmp = vec![0_u8; length - 6];
                buffer.read_exact(&mut tmp)?;
                tmp
            },
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use rstest::rstest;

    #[rstest]
    #[case(0, 5, 2, 12)]
    #[case(0, 1023, 7, 2045)]
    #[should_panic]
    // tfvn out of bounds
    #[case(4, 5, 2, 2045)]
    #[should_panic]
    // scid out of bounds
    #[case(0, 1024, 5, 1023)]
    #[should_panic]
    // vcid out of bounds
    #[case(0, 7, 8, 1023)]
    #[should_panic]
    // first header index out of bounds
    #[case(0, 100, 3, 2049)]
    fn tm_header_validation(
        #[case] tfvn: u8,
        #[case] scid: u16,
        #[case] vcid: u8,
        #[case] index: u16,
    ) {
        let header = TMPrimaryHeader {
            tfvn,
            scid,
            vcid,
            ocf_flag: BooleanFieldFlag::Present,
            mc_frame_count: 7,
            vc_frame_count: 244,
            data_field_status: TMDataFieldStatus {
                secondary_header_flag: BooleanFieldFlag::NotPresent,
                synchronization_flag: SynchronizationFlag::Nominal,
                packet_order: false,
                segment_length: GroupingFlag::Unsegm,
                first_header_pointer: FirstHeaderPointer::ByteIndex(index),
            },
        };

        assert!(header.validate().is_ok())
    }

    #[rstest]
    fn tm_primary_header(
        #[values(0, 5, 1023)] scid: u16,
        #[values(0, 3, 7)] vcid: u8,
        #[values(BooleanFieldFlag::NotPresent, BooleanFieldFlag::Present)]
        ocf_flag: BooleanFieldFlag,
        #[values(BooleanFieldFlag::NotPresent, BooleanFieldFlag::Present)]
        secondary_header_flag: BooleanFieldFlag,
        #[values(SynchronizationFlag::Nominal, SynchronizationFlag::VcaSdu)]
        synchronization_flag: SynchronizationFlag,
        #[values(GroupingFlag::First, GroupingFlag::Unsegm)] segment_length: GroupingFlag,
        #[values(0, 2045, 2046, 2047)] index: u16,
    ) {
        let expected = TMPrimaryHeader {
            tfvn: 0b11,
            scid,
            vcid,
            ocf_flag,
            mc_frame_count: 77,
            vc_frame_count: 128,
            data_field_status: TMDataFieldStatus {
                secondary_header_flag,
                synchronization_flag,
                packet_order: false,
                segment_length,
                first_header_pointer: FirstHeaderPointer::from_u16(index)
                    .expect("Bad index number"),
            },
        };

        let bytes = expected.encode();

        let recovered = TMPrimaryHeader::decode(&mut bytes.as_slice())
            .expect("Unable to decode TMPrimaryHeader");

        assert_eq!(expected, recovered)
    }
}
