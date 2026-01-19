![ci](https://github.com/ASU-Cubesat/spacepacket/actions/workflows/build_and_test.yaml/badge.svg)

Yet another CCSDS space packet protocol implementation with built in encoding and decoding.

### Why another packet crate?
This crate's interface provides a wrapper for a CCSDS packet payload (including secondary headers), opposed to just parsing header bytes.
The full packet is parsed into a SpacePacket struct, all overhead for the payload encoding length (including with CRC validation) is handled for the end user.

This crate was created after viewing other rust-based CCSDS crates and wanting a more friendly user interface for packet interaction.

Currently this crate assumes Big Endian for all byte streams. Though this may change to be generic over endianness in the future.


## Optional Features
#### CRC Support
This crate provides data validation via CRC-16 calculation through the [crc crate](https://github.com/mrhooray/crc-rs).
#### Sink/Stream Support
Another optional feature this crate provides is support for for sapcepacket I/O via sinks and stream through the async-codec and tokio-codec features.
This allows users to easily create asynchronous listeners for spacepackets with optional sync markers and CRC support.
#### TC/TM Support and CLTU Generation
TeleCommand (TC) and Telemetry (TM) Frames are supported when the `tctm` feature is enabled.

Communications Link Transmission Unit (CLTU) packets can also be constructed
when this feature is enabled. Currently only BCH and Randomized BCH
encoding is supported however LDPC encoding is planned as a future enhancement.

| Feature | Description | Default |
|---------|-------------|---------|
| `crc` | Enables CRC-16 support for Space Packets | No |
| `async-codec` | Implements `asynchronous-codec` traits | No |
| `tokio-codec` | Implements `tokio-util::codec` traits | No |
| `tctm` | Enables TC/TM frame and CLTU support | No |


## Examples

### Basic TC Space Packet

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

let bytestream = packet.encode();
let recovered_packet = SpacePacket::decode(&mut bytestream.as_slice()).unwrap();
assert_eq!(packet, recovered_packet)
```

### Basic TM Space Packet

```rust
use spacepacket::{GroupingFlag, PacketType, SpacePacket};

let payload = b"Hello, Space!".to_vec();
let packet = SpacePacket::new(
    0,                        // version
    PacketType::Telemetry,    // packet type
    0x042,                    // APID
    GroupingFlag::Unsegm,     // grouping
    123,                      // sequence count
    false,                    // no secondary header
    payload,
);

let encoded = packet.encode();
let recovered = SpacePacket::decode(&mut encoded.as_slice()).unwrap();
assert_eq!(packet, recovered);
```

### Space Packet with CRC

```rust
use spacepacket::{GroupingFlag, PacketType, SpacePacket, CompletePacket};
use crc::{Crc, CRC_16_IBM_3740};

let crc = Crc::<u16>::new(&CRC_16_IBM_3740);
let packet = SpacePacket::new(
    0,
    PacketType::Command,
    0x123,
    GroupingFlag::Unsegm,
    42,
    true,
    b"Command payload".to_vec(),
);

let encoded = packet.encode_crc(&crc);
let recovered = SpacePacket::decode_crc(&mut encoded.as_slice(), &crc).unwrap();

if let CompletePacket::Valid(pkt) = recovered {
    println!("CRC validated successfully!");
}
```

### TC Transfer Frame

```rust
use spacepacket::tctm::tc::{TCPrimaryHeader, TCTransferFrame, BypassFlag, ControlFlag};

let header = TCPrimaryHeader {
    tfvn: 0,
    bypass_flag: BypassFlag::TypeA,
    control_flag: ControlFlag::TypeD,
    scid: 758,
    vcid: 0,
    sequence_number: 5,
};

let frame = TCTransferFrame::new(header, b"TC payload".to_vec()).unwrap();
let encoded = frame.encode();
let recovered = TCTransferFrame::decode(&mut encoded.as_slice()).unwrap();
```

### CLTU Generation

```rust
use spacepacket::tctm::cltu::{generate_cltu, EncodingScheme};

let tc_frame_bytes = /* ... TC frame ... */;
let cltu = generate_cltu(&tc_frame_bytes, EncodingScheme::BCH);
// CLTU is ready for transmission
```

---
## Implementation status

  Fully Implemented:
  - ✅ Space Packet Protocol (CCSDS 133.0-B-2) core functionality
  - ✅ TC Transfer Frames (CCSDS 232.0-B-4)
  - ✅ TM Transfer Frames (CCSDS 132.0-B-3) with randomization
  - ✅ CLTU generation with BCH encoding
  - ✅ CRC-16 support (optional feature)
  - ✅ Async codec support for streaming

  Not Implemented:
  - ❌ Octet String Service (Section 3.4)
  - ❌ Service Primitives (abstract interfaces replaced by direct methods)
  - ❌ Managed Parameters
  - ❌ FARM (Frame Acceptance and Reporting Mechanism)
  - ❌ LDPC encoding (planned future enhancement)


### Space Packet Protocol

| Feature/Function | Section | Status |
|------------------|---------|--------|
| Packet Primary Header | 4.1.2 | ✅ Fully Implemented |
| Packet Type Field | 4.1.2.3.2 | ✅ Fully Implemented |
| APID Field | 4.1.2.4 | ✅ Fully Implemented |
| Sequence Flags (Grouping) | 4.1.2.5 | ✅ Fully Implemented |
| Sequence Count | 4.1.2.6 | ✅ Fully Implemented |
| Packet Data Length | 4.1.2.7 | ✅ Fully Implemented (auto-calculated) |
| Packet Secondary Header | 4.1.3 | ⚠️ Structure supported, content is user-defined |
| Packet Data Field | 4.1.4 | ✅ Fully Implemented |
| Packet Service | 3.2 | ✅ Encode/decode methods provided |
| Octet String Service | 3.4 | ❌ Not Implemented |
| Protocol Procedures (Sending) | 4.2 | ✅ Implemented via encode methods |
| Protocol Procedures (Receiving) | 4.3 | ✅ Implemented via decode methods |
| Managed Parameters | 5 | ❌ Not Implemented |
| CRC Support | Extension | ✅ Optional feature |

### TC Transfer Frames

| Feature/Function | Status |
|------------------|--------|
| TC Primary Header | ✅ Fully Implemented |
| Bypass Flag | ✅ Fully Implemented |
| Control Command Flag | ✅ Fully Implemented |
| TC Frame Encode/Decode | ✅ Fully Implemented |
| Frame Acceptance Checks | ❌ Not Implemented (receiver responsibility) |

### TM Transfer Frames

| Feature/Function | Status |
|------------------|--------|
| TM Primary Header | ✅ Fully Implemented |
| TM Secondary Header | ✅ Structure implemented |
| Data Field Status | ✅ Fully Implemented |
| Synchronization Flag | ✅ Fully Implemented |
| First Header Pointer | ✅ Fully Implemented |
| TM Frame Encode/Decode | ✅ Fully Implemented |
| Randomization (255, 131071) | ✅ Fully Implemented |
| CRC Support | ✅ Optional feature |
| OCF (Operational Control Field) | ⚠️ Included in data_field, not parsed |
| FECF (Frame Error Control Field) | ⚠️ Handled via CRC methods |

### CLTU

| Feature/Function | Status |
|------------------|--------|
| BCH (63, 56) Encoding | ✅ Fully Implemented |
| BCH with Randomization | ✅ Fully Implemented |
| LDPC Encoding | ❌ Not Implemented (planned) |
| Start/Tail Sequences | ✅ Implemented |

---

## References

1. **CCSDS 133.0-B-2** - Space Packet Protocol, Recommended Standard, Issue 2 (June 2020)
2. **CCSDS 232.0-B-4** - TC Space Data Link Protocol, Recommended Standard
3. **CCSDS 132.0-B-3** - TM Space Data Link Protocol, Recommended Standard
4. **CCSDS 231.0-B-4** - TC Synchronization and Channel Coding, Recommended Standard
5. **CCSDS 131.0-B-5** - TM Synchronization and Channel Coding, Recommended Standard

----
# API Documentation

  1. CCSDS 133.0-B-2 Space Packet Protocol - Core packet structures, primary headers, grouping flags, and packet services
  2. Codec Support - Async/Stream processing for real-time packet handling
  3. TeleCommand (TC) Transfer Frames - CCSDS 232.0-B-4 implementation
  4. Telemetry (TM) Transfer Frames - CCSDS 132.0-B-3 implementation with randomization
  5. CLTU Generation - CCSDS 231.0-B-4 BCH encoding support
  6. Feature Flags - Optional cargo features (crc, async-codec, tokio-codec, tctm)
  7. Implementation Status Summary - Complete mapping with ✅/⚠️/❌ indicators
  8. Usage Examples - Practical code examples
  9. References - CCSDS standard citations

## Section 1: CCSDS 133.0-B-2 Space Packet Protocol

### 1.1 Primary Header Structure

**CCSDS Standard Reference:** Section 4.1.2 - Packet Primary Header

#### Rust Types

**`PrimaryHeader` struct** (`src/lib.rs:88-101`)

Represents the CCSDS Primary Header as defined in CCSDS 133.0-B-2.

**Public Fields:**
- `version: u8` - CCSDS version number (3 bits, currently fixed to 0)
- `packet_type: PacketType` - Packet type indicator (1 bit)
- `apid: u16` - Application Process Identifier (11 bits)
- `secondary_header: bool` - Secondary header flag (1 bit)
- `grouping: GroupingFlag` - Sequence flags (2 bits)
- `sequence_count: u16` - Packet sequence count (14 bits)

**Methods:**
- `encode(&self) -> Vec<u8>` (`src/lib.rs:106-119`) - Encodes the primary header to big-endian byte stream
- `decode<R: Read>(buffer: &mut R) -> std::io::Result<Self>` (`src/lib.rs:122-146`) - Decodes from big-endian byte stream

**Status:** ✅ Fully Implemented

---

### 1.2 Packet Type

**CCSDS Standard Reference:** Section 4.1.2.3.2 - Packet Type Field

#### Rust Types

**`PacketType` enum** (`src/lib.rs:67-81`)

Differentiates between telemetry and command packets.

**Variants:**
- `Telemetry = 0` - Telemetry packet (downlink)
- `Command = 1` - Command packet (uplink)

**Methods:**
- `from_1bit(bit: u8) -> Self` - Constructs from a single bit value

**Status:** ✅ Fully Implemented

---

### 1.3 Grouping Flags

**CCSDS Standard Reference:** Section 4.1.2.5 - Sequence Flags

#### Rust Types

**`GroupingFlag` enum** (`src/lib.rs:40-61`)

Indicates packet position in a segmented stream.

**Variants:**
- `Interm = 0b00` - Intermediate segment
- `First = 0b01` - First segment
- `Last = 0b10` - Last segment
- `Unsegm = 0b11` - Unsegmented data (standalone packet)

**Methods:**
- `from_2bits(input: u8) -> Self` - Constructs from 2-bit field

**Status:** ✅ Fully Implemented

---

### 1.4 Space Packet Structure

**CCSDS Standard Reference:** Section 4.1 - Protocol Data Unit

#### Rust Types

**`SpacePacket` struct** (`src/lib.rs:174-234`)

Complete CCSDS Space Packet with primary header and payload.

**Public Fields:**
- `primary_header: PrimaryHeader` - Primary header metadata
- `payload: Vec<u8>` - Flexible user-defined payload (including optional secondary header)

**Constructor:**
- `new(version: u8, packet_type: PacketType, apid: u16, grouping: GroupingFlag, sequence_count: u16, secondary_header: bool, payload: Vec<u8>) -> Self` (`src/lib.rs:181-201`)

**Methods:**
- `encode(&self) -> Vec<u8>` (`src/lib.rs:207-215`) - Encodes to byte stream with automatic length calculation
- `decode<R: Read>(buffer: &mut R) -> std::io::Result<Self>` (`src/lib.rs:219-234`) - Decodes from byte stream

**Status:** ✅ Fully Implemented

---

### 1.5 CRC Support (Optional Feature)

**CCSDS Standard Reference:** Not explicitly defined in 133.0-B-2, but common in space applications

#### Rust Types

**`CompletePacket` enum** (`src/lib.rs:154-169`)

Wrapper for CRC-validated Space Packets (enabled with `crc` feature).

**Variants:**
- `Valid(SpacePacket)` - Packet with valid CRC
- `InvalidCRC(u16, u16)` - Expected and computed CRC values (recoverable error)

**SpacePacket CRC Methods:**
- `encode_crc(&self, crc: &Crc<u16>) -> Vec<u8>` (`src/lib.rs:240-251`) - Encodes with CRC-16 appended
- `decode_crc<R: Read>(buffer: &mut R, crc: &Crc<u16>) -> std::io::Result<CompletePacket>` (`src/lib.rs:259-288`) - Decodes and validates CRC-16

**Status:** ✅ Implemented as optional feature (`crc`)

---

### 1.6 Packet Service

**CCSDS Standard Reference:** Section 3.2 - Packet Service

The library implements the **Packet Service** as defined in CCSDS 133.0-B-2 Section 3.2.

**Service Characteristics Implemented:**
- ✅ Variable-length packet transfer
- ✅ APID-based identification
- ✅ Sequence count for ordering
- ✅ Grouping flags for segmentation
- ✅ Optional secondary header support
- ✅ Big-endian encoding

**Not Implemented:**
- ❌ Service primitives (P-DATA.request, P-DATA.indication) - These are abstract interfaces; the library provides direct encode/decode methods instead
- ❌ Quality of Service guarantees - Delegated to lower layers
- ❌ Flow control - Delegated to application layer

---

### 1.7 Octet String Service

**CCSDS Standard Reference:** Section 3.4 - Octet String Service

**Status:** ❌ Not Implemented

The Octet String Service is not provided by this library. Applications requiring transparent octet stream transfer must implement this separately or use the payload field directly.

---

### 1.8 Secondary Header

**CCSDS Standard Reference:** Section 4.1.3 - Packet Secondary Header

**Status:** ⚠️ Partially Implemented

The library supports the presence of a secondary header via the `secondary_header` flag in `PrimaryHeader`, but does not provide structured types for secondary headers. Secondary headers are mission-specific and included in the `payload` field of `SpacePacket`. Users must implement their own secondary header structures.

**Rationale:** CCSDS 133.0-B-2 Section 4.1.3.1 states that secondary header structure is "project-defined" and registered with SANA.

---

### 1.9 Managed Parameters

**CCSDS Standard Reference:** Section 5 - Managed Parameters

**Status:** ❌ Not Implemented

Protocol configuration parameters (e.g., maximum packet length) are not explicitly managed by the library. These are left to the application implementation.

---

## Section 2: Codec Support (Async/Stream Processing)

### 2.1 SpacePacketCodec (Optional Feature)

**CCSDS Standard Reference:** Not part of CCSDS standard (implementation enhancement)

#### Rust Types

**`SpacePacketCodec` struct** (`src/codec.rs:25-116`)

Provides asynchronous encoding/decoding of Space Packets from byte streams with synchronization marker support.

**Available with features:**
- `async-codec` - Implements `asynchronous_codec::Encoder` and `asynchronous_codec::Decoder`
- `tokio-codec` - Implements `tokio_util::codec::Encoder` and `tokio_util::codec::Decoder`

**Constructor:**
- `new<T: AsRef<[u8]>>(sync_marker: T, crc: Option<Crc<u16>>) -> Self` (`src/codec.rs:38-48`)

**Features:**
- Synchronization marker detection
- Automatic packet boundary detection
- Optional CRC validation
- Stream/Sink trait implementations for async I/O

**Status:** ✅ Implemented as optional features

---

## Section 3: TeleCommand (TC) Transfer Frames

### 3.1 TC Transfer Frame Structure

**CCSDS Standard Reference:** CCSDS 232.0-B-4 - TC Space Data Link Protocol

#### Rust Types

**`TCPrimaryHeader` struct** (`src/tctm/tc.rs:65-127`)

Represents the TC Transfer Frame Primary Header.

**Public Fields:**
- `tfvn: u8` - Transfer Frame Version Number (2 bits, fixed to 0)
- `bypass_flag: BypassFlag` - Frame acceptance check type (1 bit)
- `control_flag: ControlFlag` - Data or control frame indicator (1 bit)
- `scid: u16` - Spacecraft ID (10 bits, max 1023)
- `vcid: u8` - Virtual Channel ID (6 bits, max 63)
- `sequence_number: u8` - Frame sequence number (8 bits)

**Methods:**
- `validate(&self) -> Result<(), Error>` (`src/tctm/tc.rs:101-126`) - Validates field constraints

**Status:** ✅ Fully Implemented

---

**`TCTransferFrame` struct** (`src/tctm/tc.rs:130-234`)

Complete TC Transfer Frame with header and payload.

**Constructor:**
- `new(header: TCPrimaryHeader, payload: Vec<u8>) -> Result<Self, Error>` (`src/tctm/tc.rs:149-163`)

**Methods:**
- `header(&self) -> TCPrimaryHeader` (`src/tctm/tc.rs:167-169`) - Retrieve header metadata
- `payload(&self) -> &[u8]` (`src/tctm/tc.rs:172-174`) - Borrow payload (max 1019 bytes)
- `encode(self) -> Vec<u8>` (`src/tctm/tc.rs:178-208`) - Encode to byte stream
- `decode<R: Read>(buffer: &mut R) -> Result<Self, Error>` (`src/tctm/tc.rs:212-234`) - Decode from byte stream

**Constraints:**
- Maximum payload length: 1019 bytes

**Status:** ✅ Fully Implemented

---

### 3.2 TC Frame Flags

#### Rust Types

**`BypassFlag` enum** (`src/tctm/tc.rs:13-31`)

Controls frame acceptance checks at receiver.

**Variants:**
- `TypeA = 0` - Normal acceptance checks performed
- `TypeB = 1` - Acceptance checks bypassed

**Methods:**
- `from_u8(val: u8) -> Result<Self, Error>`

**Status:** ✅ Fully Implemented

---

**`ControlFlag` enum** (`src/tctm/tc.rs:38-56`)

Indicates data or control frame type.

**Variants:**
- `TypeD = 0` - Data frame
- `TypeC = 1` - Control frame (FARM configuration)

**Methods:**
- `from_u8(val: u8) -> Result<Self, Error>`

**Status:** ✅ Fully Implemented

---

## Section 4: Telemetry (TM) Transfer Frames

### 4.1 TM Transfer Frame Structure

**CCSDS Standard Reference:** CCSDS 132.0-B-3 - TM Space Data Link Protocol

#### Rust Types

**`TMPrimaryHeader` struct** (`src/tctm/tm.rs:226-335`)

Represents the TM Transfer Frame Primary Header.

**Public Fields:**
- `tfvn: u8` - Transfer Frame Version Number (2 bits)
- `scid: u16` - Spacecraft ID (10 bits, max 1023)
- `vcid: u8` - Virtual Channel ID (3 bits, max 7)
- `ocf_flag: BooleanFieldFlag` - Operational Control Field presence flag
- `mc_frame_count: u8` - Master Channel frame count (modulo 256)
- `vc_frame_count: u8` - Virtual Channel frame count (modulo 256)
- `data_field_status: TMDataFieldStatus` - Data field metadata

**Methods:**
- `validate(&self) -> Result<(), Error>` (`src/tctm/tm.rs:263-291`) - Validates field constraints
- `encode(self) -> Vec<u8>` (`src/tctm/tm.rs:294-319`) - Encode to byte stream
- `decode<R: Read>(buffer: &mut R) -> Result<Self, Error>` (`src/tctm/tm.rs:322-335`) - Decode from byte stream

**Status:** ✅ Fully Implemented

---

**`TMDataFieldStatus` struct** (`src/tctm/tm.rs:153-222`)

Metadata about the TM Transfer Frame Data Field.

**Public Fields:**
- `secondary_header_flag: BooleanFieldFlag` - Secondary header presence
- `synchronization_flag: SynchronizationFlag` - Data field type indicator
- `packet_order: bool` - Packet order flag (reserved when synchronization is nominal)
- `segment_length: GroupingFlag` - Segment length indicator
- `first_header_pointer: FirstHeaderPointer` - Byte offset to next packet header

**Methods:**
- `validate(&self) -> Result<(), Error>` (`src/tctm/tm.rs:187-189`)
- `encode(self) -> Vec<u8>` (`src/tctm/tm.rs:192-208`)
- `decode<R: Read>(buffer: &mut R) -> Result<Self, Error>` (`src/tctm/tm.rs:211-221`)

**Status:** ✅ Fully Implemented

---

**`TMTransferFrame` struct** (`src/tctm/tm.rs:421-560`)

Complete TM Transfer Frame with header and data field.

**Public Fields:**
- `primary_header: TMPrimaryHeader` - Primary header metadata
- `data_field: Vec<u8>` - Data field with fixed length (mission-specific)

**Methods:**
- `encode(self, randomization: TMRandomization) -> Vec<u8>` (`src/tctm/tm.rs:444-454`) - Encode with optional randomization
- `decode<R: Read>(buffer: R, length: usize, randomization: TMRandomization) -> Result<Self, Error>` (`src/tctm/tm.rs:488-504`) - Decode with fixed frame length
- `encode_crc(self, crc: &Crc<u16>, randomization: TMRandomization) -> Vec<u8>` (`src/tctm/tm.rs:509-519`) - Encode with CRC-16
- `decode_crc<R: Read>(buffer: &mut R, length: usize, randomization: TMRandomization, crc: &Crc<u16>) -> Result<Self, Error>` (`src/tctm/tm.rs:527-559`) - Decode with CRC validation

**Note:** Frame length must be known a priori (mission-specific, fixed per physical channel).

**Status:** ✅ Fully Implemented

---

### 4.2 TM Frame Flags and Types

#### Rust Types

**`BooleanFieldFlag` enum** (`src/tctm/tm.rs:28-43`)

Indicates presence/absence of fields.

**Variants:**
- `NotPresent = 0`
- `Present = 1`

**Status:** ✅ Fully Implemented

---

**`SynchronizationFlag` enum** (`src/tctm/tm.rs:46-66`)

Indicates data field content type.

**Variants:**
- `Nominal = 0` - Octet-synchronized packets or idle data
- `VcaSdu = 1` - VCA_SDU in data field

**Status:** ✅ Fully Implemented

---

**`FirstHeaderPointer` enum** (`src/tctm/tm.rs:100-150`)

Identifies byte offset of first packet header in data field.

**Variants:**
- `ByteIndex(u16)` - Index value (0-2045)
- `OnlyIdleData = 0b11111111110` - Frame contains only idle data
- `NoPacketStart = 0b11111111111` - Continuation of previous packet

**Methods:**
- `into_u16(self) -> u16`
- `from_u16(value: u16) -> Result<Self, Error>`
- `validate(&self) -> Result<(), Error>`

**Status:** ✅ Fully Implemented

---

### 4.3 TM Secondary Header (Optional)

**`TMSecondaryHeader` struct** (`src/tctm/tm.rs:341-415`)

Mission-specific secondary header for TM frames.

**Public Fields:**
- `tfvn: u8` - Transfer Frame Version Number (2 bits, fixed to 0 per CCSDS 132.0-B-3)
- `data_field: Vec<u8>` - Mission-specific data (max 63 bytes)

**Methods:**
- `validate(&self) -> Result<(), Error>` (`src/tctm/tm.rs:359-381`)
- `encode(self) -> Vec<u8>` (`src/tctm/tm.rs:384-396`)
- `decode<R: Read>(buffer: &mut R) -> Result<Self, Error>` (`src/tctm/tm.rs:399-414`)

**Status:** ✅ Implemented (structure provided, content is mission-specific)

---

### 4.4 TM Randomization Support

**CCSDS Standard Reference:** CCSDS 131.0-B-5 - TM Synchronization and Channel Coding

#### Rust Types

**`TMRandomization` enum** (`src/tctm/tm.rs:14-22`)

Randomization schemes for TM frames.

**Variants:**
- `None` - No randomization
- `Tm255` - 255-bit pseudo-random sequence (polynomial h(x) = x^8 + x^7 + x^5 + x^3 + 1)
- `Tm131071` - 131071-bit pseudo-random sequence (polynomial h(x) = x^17 + x^14 + 1)

**Status:** ✅ Fully Implemented

---

## Section 5: Communications Link Transmission Unit (CLTU)

### 5.1 CLTU Generation

**CCSDS Standard Reference:** CCSDS 231.0-B-4 - TC Synchronization and Channel Coding

#### Rust Types

**`EncodingScheme` enum** (`src/tctm/cltu.rs:10-17`)

CLTU encoding schemes.

**Variants:**
- `BCH` - BCH (63, 56) code with 7 parity bits per 56 data bits
- `BCHRandomized` - BCH encoding with CCSDS randomization applied first

**Status:** ✅ Implemented

---

**`generate_cltu<P: AsRef<[u8]>>(bytes: P, encoding: EncodingScheme) -> Vec<u8>`** (`src/tctm/cltu.rs:21-29`)

Generates a CLTU from input byte stream.

**Parameters:**
- `bytes` - Input data (typically a TC Transfer Frame)
- `encoding` - Encoding scheme to apply

**Returns:** CLTU with start sequence, BCH-encoded codeblocks, and tail sequence

**Status:** ✅ Implemented

**Note:** LDPC encoding is not currently implemented (planned future enhancement per README).

---

## Appendix A: Not Implemented Features

The following CCSDS features are **not implemented** in this library:

1. **Service Primitives (P-DATA.request, P-DATA.indication)** - The library provides direct encode/decode methods rather than formal service primitive interfaces.

2. **Octet String Service (CCSDS 133.0-B-2 Section 3.4)** - Not provided. Use raw byte handling if needed.

3. **Quality of Service (QoS) Management** - Delegated to underlying transport layers.

4. **Flow Control** - Must be implemented at application layer.

5. **Managed Parameters (CCSDS 133.0-B-2 Section 5)** - Protocol configuration is not explicitly managed.

6. **Secondary Header Parsing** - Secondary header structure is mission-specific; users must implement their own parsers.

7. **Frame Acceptance and Reporting Mechanism (FARM)** - TC frame acceptance logic is not implemented.

8. **Operational Control Field (OCF) Parsing** - OCF is included in `data_field` but not parsed.

9. **LDPC Encoding for CLTU** - Planned future enhancement.

10. **Virtual Channel Frame Buffering** - Not provided; must be implemented by users.

