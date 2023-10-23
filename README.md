# spacepacket

![ci](https://github.com/ASU-Cubesat/spacepacket/actions/workflows/build_and_test.yaml/badge.svg)

Yet another CCSDS space packet protocol implementation with bild in encoding and decoding.
This crate also includes CRC functionality with 16-bit CRCs via the [crc crate](https://github.com/mrhooray/crc-rs).

### Why another packet crate?
This crate's interface provides a wrapper for a CCSDS packet payload (including secondary headers), opposed to just parsing header bytes.
The full packet is parsed into a SpacePacket struct, all overhead for the payload encoding length (including with CRC validation) is handled for the end user.

This crate was created after viewing other rust-based CCSDS crates and wanting a more friendly user interface for packet interaction.

#### Sink/Stream Support
Another optional feature this crate provides is support for for sapcepacket I/O via sinks and stream through the async-codec and tokio-codec features.
This allows users to easily create asynchronous listeners for spacepackets with optional sync markers and CRC support.