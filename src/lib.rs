#![cfg_attr(docsrs, feature(doc_cfg))]
#![doc = include_str!("../README.md")]
/// CCSDS compliant packet definition and implementations
use byteorder::{BigEndian, ReadBytesExt};
#[cfg(feature = "crc")]
#[cfg_attr(docsrs, doc(cfg(feature = "crc")))]
use crc::Crc;

#[cfg(feature = "crc")]
use std::fmt::Display;

use std::io::Read;

#[cfg(any(feature = "async-codec", feature = "tokio-codec"))]
#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "async-codec", feature = "tokio-codec")))
)]
/// This module provides implementations
/// to provide Sink/Stream support for parsing [SpacePacket]s from
/// network data with a synchronization marker.
///
/// It provides implementations of both the asynchronous-codec and the tokio-util::codec
/// traits for compatibility.
pub mod codec;

#[cfg(feature = "crc")]
#[cfg_attr(docsrs, doc(cfg(feature = "crc")))]
#[doc(inline)]
/// A re-export of the [crc] crate.
pub use crc;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// CCSDS grouping flag to determine packet location in a stream.
pub enum GroupingFlag {
    /// Intermediate stream packet
    Interm = 0b00,
    /// First stream packet
    First = 0b01,
    /// Last stream packet
    Last = 0b10,
    /// Packet contains unsegmented data
    Unsegm = 0b11,
}

impl GroupingFlag {
    pub fn from_2bits(input: u8) -> Self {
        match input & 0b11 {
            0b00 => Self::Interm,
            0b01 => Self::First,
            0b10 => Self::Last,
            0b11 => Self::Unsegm,
            _ => unreachable!(),
        }
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// Possible CCSDS packet types.
/// Used to differentiate between command and telemetry packets.
pub enum PacketType {
    /// A Telemetry Packet.
    Telemetry = 0,
    /// A Command Packet.
    Command = 1,
}
impl PacketType {
    pub fn from_1bit(bit: u8) -> Self {
        match bit & 0x1 {
            0 => Self::Telemetry,
            1 => Self::Command,
            _ => unreachable!(),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
/// CCSCS Primary header defined in 133.0-B-2 June 2020
/// This struct is only mean to be used within a [SpacePacket]
/// to contain all information on the packet. The packet length
/// is omitted because it is calculated at encoding time.
pub struct PrimaryHeader {
    /// CCSDS version. Currently fixed to 0 but available in case standards change.
    pub version: u8,
    /// Whether the packet is a telemetry or command packet.
    pub packet_type: PacketType,
    /// The Aplication ID of the receiving entity.
    pub apid: u16,
    /// A flag indicating the presence of a secondary header.
    pub secondary_header: bool,
    /// The grouping status of this packet.
    pub grouping: GroupingFlag,
    /// The sequence count of this packet. In practice this is restricted to a <= 16384_u16.
    pub sequence_count: u16,
}

impl PrimaryHeader {
    /// Encode to a byte stream for network communication.
    /// This encoding assumed BigEndian-ness
    pub fn encode(&self) -> Vec<u8> {
        let mut message = vec![];
        let header_0 = u16::from(self.version & 0x7) << 13
                    | u16::from(self.packet_type as u8 & 0x1) << 12
                    // Flag for secondary header
                    | (self.secondary_header as u16) << 11
                    | (self.apid & 0x7FF);
        let header_1 = (self.grouping as u16) << 14 | (self.sequence_count & 0x3FFF);

        message.extend_from_slice(&header_0.to_be_bytes());
        message.extend_from_slice(&header_1.to_be_bytes());

        message
    }
    /// Decode from a byte stream for network communication.
    /// This decoding assumes BigEndian-ness
    pub fn decode<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let header0 = buffer.read_u16::<BigEndian>()?;

        let (version, packet_type, secondary_header, apid) = (
            ((header0 & 0xe000) >> 13) as u8,
            PacketType::from_1bit(((header0 & 0x1000) >> 12) as u8),
            ((header0 & 0x800) >> 11) != 0,
            (header0 & 0x7ff),
        );
        let header1 = buffer.read_u16::<BigEndian>()?;

        let (grouping, sequence_count) = (
            GroupingFlag::from_2bits(((header1 & 0xc000) >> 14) as u8),
            header1 & 0x3fff,
        );

        Ok(Self {
            version,
            packet_type,
            apid,
            secondary_header,
            grouping,
            sequence_count,
        })
    }
}

/// A thin wrapper for CRC enable SpacePackets
/// This is used to distinguish between a packet with an invalid CRC but valid form
/// And and unrecoverable decoding error.
#[cfg(feature = "crc")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletePacket {
    /// The CRC validated packet
    Valid(SpacePacket),
    /// The expected and computed CRC values associated with this packet.
    /// The packet was deemed invalid and discarded but is a recoverable error.
    InvalidCRC(u16, u16),
}
#[cfg(feature = "crc")]
impl Display for CompletePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self{
            CompletePacket::Valid(packet) => write!(f, "{:?}", packet),
            CompletePacket::InvalidCRC(expected, computed) => write!(f, "Invalid CRC encountered in packet decoding. Expected {expected:>#06X} Received {computed:>#06X}"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
/// CCSCS Space Packet defined in 133.0-B-2 June 2020
/// Primary header generated automatically when initializing this structue.
pub struct SpacePacket {
    /// Primary header information.
    pub primary_header: PrimaryHeader,
    /// Flexible payload to be decoded by the end user.
    pub payload: Vec<u8>,
}
impl SpacePacket {
    pub fn new(
        version: u8,
        packet_type: PacketType,
        apid: u16,
        grouping: GroupingFlag,
        sequence_count: u16,
        secondary_header: bool,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            primary_header: PrimaryHeader {
                version,
                packet_type,
                apid,
                grouping,
                sequence_count,
                secondary_header,
            },
            payload,
        }
    }
}
impl SpacePacket {
    /// Encodes the packet and header to a bytes array.
    /// This encoding assumed BigEndian-ness
    /// Adds the payload len -1 to the appropriate location in the encoded header
    pub fn encode(&self) -> Vec<u8> {
        let mut message = self.primary_header.encode();
        // lists the length of the payload minus one as per CCSDS specs
        let header_2 = (self.payload.len() - 1) as u16;

        message.extend(header_2.to_be_bytes());
        message.extend(self.payload.clone());

        message
    }
    /// Decode the header and retrieve the payload
    /// This decoding assumed BigEndian-ness
    pub fn decode<R: Read>(buffer: &mut R) -> std::io::Result<Self> {
        let primary_header = PrimaryHeader::decode(buffer)?;
        // add one to acount for CCSDS standard subtracting 1
        let message_len = buffer.read_u16::<BigEndian>()? + 1;

        let payload = {
            let mut temp = vec![0_u8; message_len as usize];
            buffer.read_exact(&mut temp)?;
            temp
        };

        Ok(Self {
            primary_header,
            payload,
        })
    }

    #[cfg(feature = "crc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crc")))]
    /// Encode the CCSDS packet and append a CRC-16 value using the provied [Crc].
    /// This method assumes the length of the CRC should be **included** in the payload length of the CCSDS Packet.
    pub fn encode_crc(&self, crc: &Crc<u16>) -> Vec<u8> {
        let mut message = self.primary_header.encode();
        // lists the length of the payload minus one as per CCSDS specs
        // add two to account for crc appended to the end
        let header_2 = (self.payload.len() - 1 + 2) as u16;

        message.extend(header_2.to_be_bytes());
        message.extend(self.payload.clone());
        message.extend(crc.checksum(message.as_slice()).to_be_bytes());

        message
    }

    #[cfg(feature = "crc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crc")))]
    /// Decode a CCSDS packet with an appended a CRC-16 value using the provied [Crc].
    /// This method assumes the length of the CRC should be **included** in the payload length of the CCSDS Packet.
    /// The crc is stripped from the byte stream and not included in the returned packet.
    /// Error if the packet's CRC is not valid.
    pub fn decode_crc<R: Read>(buffer: &mut R, crc: &Crc<u16>) -> std::io::Result<CompletePacket> {
        let full_message = {
            // read the ccsds header
            let header_buffer = {
                let mut tmp = [0_u8; 6];
                buffer.read_exact(&mut tmp)?;
                tmp
            };
            // get the total length of the packet
            // add one to acount for CCSDS standard subtracting 1
            let message_len = (&header_buffer.as_slice()[4..6]).read_u16::<BigEndian>()? + 1;

            let mut temp = vec![0_u8; message_len as usize];
            buffer.read_exact(&mut temp)?;
            [header_buffer.to_vec(), temp].concat()
        };
        let crc_sent = (&full_message[full_message.len() - 2..]).read_u16::<BigEndian>()?;
        let computed_crc = crc.checksum(&full_message[0..full_message.len() - 2]);
        match crc_sent == computed_crc {
            true => {}
            false => return Ok(CompletePacket::InvalidCRC(crc_sent, computed_crc)),
        };

        let primary_header = PrimaryHeader::decode(&mut full_message.as_slice())?;

        Ok(CompletePacket::Valid(Self {
            primary_header,
            payload: full_message[6..full_message.len() - 2].to_vec(),
        }))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "crc")]
    use crc::CRC_16_IBM_3740;
    use rstest::rstest;

    #[rstest]
    fn header_roundtrip(
        #[values(
            GroupingFlag::Interm,
            GroupingFlag::First,
            GroupingFlag::Last,
            GroupingFlag::Unsegm
        )]
        grouping: GroupingFlag,
        #[values(true, false)] secondary_header: bool,
        #[values(PacketType::Command, PacketType::Telemetry)] packet_type: PacketType,
    ) {
        let expected = PrimaryHeader {
            version: 0_u8,
            packet_type,
            apid: 2042_u16,
            secondary_header,
            grouping,
            sequence_count: 16355_u16,
        };

        let buffer = expected.encode();

        let recovered = PrimaryHeader::decode(&mut buffer.as_slice())
            .expect("Unable to decode Primary Header.");

        assert_eq!(expected, recovered)
    }

    #[rstest]
    fn spacepacket_roundtrip(
        #[values(
            GroupingFlag::Interm,
            GroupingFlag::First,
            GroupingFlag::Last,
            GroupingFlag::Unsegm
        )]
        grouping: GroupingFlag,
        #[values(true, false)] secondary_header: bool,
        #[values(PacketType::Command, PacketType::Telemetry)] packet_type: PacketType,
    ) {
        let expected = SpacePacket::new(
            0,
            packet_type,
            1555_u16,
            grouping,
            1423_u16,
            secondary_header,
            "a test input".as_bytes().to_vec(),
        );

        let buffer = expected.encode();

        let recovered =
            SpacePacket::decode(&mut buffer.as_slice()).expect("Unable to parse SpacePacket.");

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(feature = "crc")]
    fn spacepacket_roundtrip_crc(
        #[values(
            GroupingFlag::Interm,
            GroupingFlag::First,
            GroupingFlag::Last,
            GroupingFlag::Unsegm
        )]
        grouping: GroupingFlag,
        #[values(true, false)] secondary_header: bool,
        #[values(PacketType::Command, PacketType::Telemetry)] packet_type: PacketType,
    ) {
        let crc = Crc::<u16>::new(&CRC_16_IBM_3740);
        let expected = SpacePacket::new(
            0,
            packet_type,
            1555_u16,
            grouping,
            1423_u16,
            secondary_header,
            "a test input".as_bytes().to_vec(),
        );

        let buffer = expected.encode_crc(&crc);

        let recovered = SpacePacket::decode_crc(&mut buffer.as_slice(), &crc)
            .expect("Unable to parse SpacePacket.");

        assert_eq!(CompletePacket::Valid(expected), recovered)
    }

    #[rstest]
    #[cfg(feature = "crc")]
    fn spacepacket_roundtrip_invalid_crc(
        #[values(
            GroupingFlag::Interm,
            GroupingFlag::First,
            GroupingFlag::Last,
            GroupingFlag::Unsegm
        )]
        grouping: GroupingFlag,
        #[values(true, false)] secondary_header: bool,
        #[values(PacketType::Command, PacketType::Telemetry)] packet_type: PacketType,
    ) {
        let crc = Crc::<u16>::new(&CRC_16_IBM_3740);
        let expected = SpacePacket::new(
            0,
            packet_type,
            1555_u16,
            grouping,
            1423_u16,
            secondary_header,
            "a test input".as_bytes().to_vec(),
        );

        let (buffer, expected_crc) = {
            let mut tmp = expected.encode_crc(&crc);
            let n_bytes = tmp.len();
            let crc = u16::from_be_bytes([tmp[n_bytes - 2], tmp[n_bytes - 1]]);
            tmp[n_bytes - 2..].copy_from_slice(&(crc + 1).to_be_bytes());
            (tmp, crc)
        };

        let recovered = SpacePacket::decode_crc(&mut buffer.as_slice(), &crc)
            .expect("Unable to parse SpacePacket.");

        // expected and recovered actually switch here because we alter the CRC on the original message
        assert_eq!(
            CompletePacket::InvalidCRC(expected_crc + 1, expected_crc),
            recovered
        )
    }
}
