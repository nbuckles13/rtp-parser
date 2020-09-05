
// An RTP packet
#[derive(Debug)]
pub struct RtpPacket<'a> {
    // version -- 2 bits
    pub version: u8,

    // padding flag -- 1 bit
    pub padding: u8,

    // extension flag -- 1 bit
    pub extension: u8,

    // csrc count -- 4 bits
    pub csrc_count: u8,

    // marker flag -- 1 bit
    pub marker: u8,

    // payload type -- 7 bits
    pub payload_type: u8,

    // sequence number -- 2 bytes
    pub sequence_number: u16,

    // timestamp -- 4 bytes
    pub timestamp: u32,

    // synchronization source identifier
    pub ssrc: u32,

    // contributing source identifiers (0 to 15)
    pub csrc: Vec<u32>,

    // payload
    pub payload: &'a [u8],
}
