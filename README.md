![ci](https://github.com/ASU-Cubesat/spacepacket/actions/workflows/build_and_test.yaml/badge.svg)

Yet another CCSDS space packet protocol implementation with built in encoding and decoding.

### Why another packet crate?
This crate's interface provides a wrapper for a CCSDS packet payload (including secondary headers), opposed to just parsing header bytes.
The full packet is parsed into a SpacePacket struct, all overhead for the payload encoding length (including with CRC validation) is handled for the end user.

This crate was created after viewing other rust-based CCSDS crates and wanting a more friendly user interface for packet interaction.

Currently this crate assumes Big Endian for all byte streams. Though this may change to be generic over endian in the future.


## Optional Features
#### CRC Support
This crate provides data validation via CRC-16 calculation through the [crc crate](https://github.com/mrhooray/crc-rs).
#### Sink/Stream Support
Another optional feature this crate provides is support for for sapcepacket I/O via sinks and stream through the async-codec and tokio-codec features.
This allows users to easily create asynchronous listeners for spacepackets with optional sync markers and CRC support.


# Examples
```rust
use spacepacket::{GroupingFlag, PacketType, SpacePacket};

let payload = b"secret payload".to_vec();
let packet = SpacePacket::new(
    0,
    PacketType::Command,
    0x012,
    GroupingFlag::Unsegm,
    3,
    true,
    payload,
);
```
