use crate::{Result as CCSDSResult, SpacePacket, SpacePacketError};
use bytes::{Buf, BytesMut};

#[cfg(feature = "crc")]
use crc::Crc;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CodecState {
    Sync,
    Data,
}

#[cfg_attr(
    docsrs,
    doc(cfg(any(feature = "async-codec", feature = "tokio-codec")))
)]
/// A Codec used to Encode/Decode [SpacePacket]s from Streams and Sinks.
/// This Codec can be useful when designing programs that must listen for
/// a packet on an I/O device.
pub struct SpacePacketCodec {
    sync_marker: Box<[u8]>,
    state: CodecState,
    #[cfg(feature = "crc")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crc")))]
    crc: Option<Crc<u16>>,
}
impl SpacePacketCodec {
    /// Create a new SpacePacketCodec with the input synchronization
    /// marker. This codec with sweep through the input byte stream
    /// until the synchronization marker is found, then parse a [SpacePacket].
    ///
    /// crc agrument only valid on feature `crcs`
    pub fn new<T: AsRef<[u8]>>(
        sync_marker: T,
        #[cfg(feature = "crc")] crc: Option<Crc<u16>>,
    ) -> Self {
        Self {
            sync_marker: sync_marker.as_ref().to_owned().into_boxed_slice(),
            state: CodecState::Sync,
            #[cfg(feature = "crc")]
            crc,
        }
    }

    fn find_sync<B: AsRef<[u8]>>(&mut self, source: &B) -> Option<usize> {
        if self.sync_marker.is_empty() {
            return Some(0);
        }
        source
            .as_ref()
            .windows(self.sync_marker.len())
            .position(|window| window == &*self.sync_marker)
    }

    fn decode_helper(&mut self, buffer: &mut BytesMut) -> CCSDSResult<Option<SpacePacket>> {
        if self.state == CodecState::Sync {
            if let Some(index) = self.find_sync(buffer) {
                buffer.advance(index + self.sync_marker.len());
                self.state = CodecState::Data;
            } else {
                // There is no sync marker in the current buffer
                // but keep SYNC_MARKERS.len() - 1 bytes
                // in case syncs cross buffer boundaries
                let len = buffer.remaining();
                if len > self.sync_marker.len() - 1 {
                    buffer.advance(len - (self.sync_marker.len() - 1));
                }
                // Return None to indiciate more data is needed
                return Ok(None);
            }
        }

        // 7 is the minimum length of a ccsds packet
        // header: 6 bytes
        // payload:  1 byte
        if buffer.remaining() < 7 {
            // Not enough bytes for a packet
            return Ok(None);
        }

        // check the length marker
        // bytes 4 and 5 (0 index) are CCSDS length - 1
        // add 6 for the header
        let packet_length =
            u16::from_be_bytes(buffer.as_ref()[4..6].try_into().unwrap()) as usize + 1 + 6;

        if buffer.remaining() < packet_length {
            // full packet has not yet arrived
            // reserve enough bytes so we can fit it in the buffer
            buffer.reserve(packet_length - buffer.remaining());

            // Tell the frame we need more bytes
            return Ok(None);
        }

        let data = buffer.as_ref()[..packet_length].to_vec();
        buffer.advance(packet_length);
        // We know there is a packet's length of data whether or not it is valid
        // Rever to check for sync
        self.state = CodecState::Sync;

        #[cfg(feature = "crc")]
        match &self.crc {
            Some(crc) => SpacePacket::decode_crc(&mut data.as_slice(), crc).map(Some),
            None => SpacePacket::decode(&mut data.as_slice()).map(Some),
        }

        #[cfg(not(feature = "crc"))]
        SpacePacket::decode(&mut data.as_slice()).map(Some)
    }
}

#[cfg(feature = "async-codec")]
mod non_tokio {
    use super::*;

    use asynchronous_codec::{Decoder, Encoder};

    impl Decoder for SpacePacketCodec {
        type Item = SpacePacket;

        type Error = SpacePacketError;

        fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            self.decode_helper(src)
        }
    }

    impl Encoder for SpacePacketCodec {
        type Item = SpacePacket;

        type Error = SpacePacketError;

        fn encode(
            &mut self,
            item: Self::Item,
            dst: &mut asynchronous_codec::BytesMut,
        ) -> Result<(), Self::Error> {
            let bytes = {
                #[cfg(feature = "crc")]
                match &self.crc {
                    Some(crc) => item.encode_crc(crc),
                    None => item.encode(),
                }
                #[cfg(not(feature = "crc"))]
                item.encode()
            };

            dst.reserve(bytes.len() + self.sync_marker.len());
            dst.extend(&*self.sync_marker);
            dst.extend(bytes);
            Ok(())
        }
    }
}

#[cfg(feature = "tokio-codec")]
mod tokio_codec {
    use tokio_util::codec::{Decoder, Encoder};

    use super::*;

    impl Decoder for SpacePacketCodec {
        type Item = SpacePacket;

        type Error = SpacePacketError;

        fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
            self.decode_helper(src)
        }
    }

    impl Encoder<SpacePacket> for SpacePacketCodec {
        type Error = SpacePacketError;

        fn encode(
            &mut self,
            item: SpacePacket,
            dst: &mut bytes::BytesMut,
        ) -> Result<(), Self::Error> {
            let bytes = {
                #[cfg(feature = "crc")]
                match &self.crc {
                    Some(crc) => item.encode_crc(crc),
                    None => item.encode(),
                }
                #[cfg(not(feature = "crc"))]
                item.encode()
            };

            dst.reserve(bytes.len() + self.sync_marker.len());
            dst.extend(&*self.sync_marker);
            dst.extend(bytes);
            Ok(())
        }
    }
}

#[cfg(all(test, feature = "async-codec"))]
mod test {
    use super::*;

    use asynchronous_codec::Framed;
    use rstest::rstest;

    use futures::{executor, io::Cursor, SinkExt, TryStreamExt};

    #[cfg(feature = "crc")]
    use crc::CRC_16_IBM_3740;
    #[cfg(feature = "crc")]
    const CRC_CCITT_FALSE: Crc<u16> = Crc::<u16>::new(&CRC_16_IBM_3740);

    #[rstest]
    #[cfg(not(feature = "crc"))]
    fn codec_no_sync() {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);

        let mut framed = Framed::new(buffer, SpacePacketCodec::new([]));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([]));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(not(feature = "crc"))]
    fn codec_sync() {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);

        let mut framed = Framed::new(buffer, SpacePacketCodec::new([0xAA, 0xBB]));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([0xAA, 0xBB]));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(not(feature = "crc"))]
    fn codec_sync_noise() {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let mut buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        buffer.set_position(20);

        let mut framed = Framed::new(buffer, SpacePacketCodec::new([0xAA, 0xBB]));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);
        // fill the first 20 bytes with junk
        cursor.get_mut()[..20].copy_from_slice((0_u8..20).collect::<Vec<u8>>().as_slice());
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([0xAA, 0xBB]));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(feature = "crc")]
    fn codec_no_sync_crc(
        #[values((None, None),( Some(CRC_CCITT_FALSE),  Some(CRC_CCITT_FALSE)))] crc: (
            Option<Crc<u16>>,
            Option<Crc<u16>>,
        ),
    ) {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);

        let (crc, crc2) = crc;
        let mut framed = Framed::new(buffer, SpacePacketCodec::new([], crc));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([], crc2));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(feature = "crc")]
    fn codec_sync_crc(
        #[values((None, None),( Some(CRC_CCITT_FALSE),  Some(CRC_CCITT_FALSE)))] crc: (
            Option<Crc<u16>>,
            Option<Crc<u16>>,
        ),
    ) {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);

        let (crc, crc2) = crc;
        let mut framed = Framed::new(buffer, SpacePacketCodec::new([0xAA, 0xBB], crc));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([0xAA, 0xBB], crc2));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }

    #[rstest]
    #[cfg(feature = "crc")]
    fn codec_sync_noise_crc(
        #[values((None, None),( Some(CRC_CCITT_FALSE),  Some(CRC_CCITT_FALSE)))] crc: (
            Option<Crc<u16>>,
            Option<Crc<u16>>,
        ),
    ) {
        let expected = SpacePacket::new(
            0,
            crate::PacketType::Command,
            17,
            crate::GroupingFlag::Unsegm,
            50_00,
            false,
            (0..77_u8).collect::<Vec<u8>>(),
        );

        let mut buf = vec![0_u8; 10];
        let mut buffer: Cursor<&mut Vec<u8>> = Cursor::new(&mut buf);
        buffer.set_position(20);

        let (crc, crc2) = crc;
        let mut framed = Framed::new(buffer, SpacePacketCodec::new([0xAA, 0xBB], crc));

        executor::block_on(framed.send(expected.clone())).unwrap();

        // reset the buffer position
        let mut cursor = framed.into_inner();
        cursor.set_position(0);
        // fill the first 20 bytes with junk
        cursor.get_mut()[..20].copy_from_slice((0_u8..20).collect::<Vec<u8>>().as_slice());
        cursor.set_position(0);

        let mut framed = Framed::new(cursor, SpacePacketCodec::new([0xAA, 0xBB], crc2));

        let recovered = executor::block_on(framed.try_next()).unwrap().unwrap();

        assert_eq!(expected, recovered)
    }
}
