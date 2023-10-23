use std::io::Error as IoError;
use thiserror::Error;

/// A SpacePacket Result, conveniently wrapping the [SpacePacketError]
pub type Result<T> = std::result::Result<T, SpacePacketError>;

#[derive(Error, Debug)]
/// Error types which can occur while parsing bytes.
pub enum SpacePacketError {
    #[error("I/O error during packet decoding")]
    IO(#[from] IoError),
    #[cfg(feature = "crcs")]
    #[cfg_attr(docsrs, doc(cfg(feature = "crcs")))]
    #[error("Packet CRCs do not match. Expected {0:#X} != Computed {1:#X}.")]
    InvalidCRC(u16, u16),
}
