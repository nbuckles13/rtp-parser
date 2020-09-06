/// An RTP packet header extension, https://tools.ietf.org/html/rfc3550#section-5.3.1
#[derive(Debug)]
pub struct RtpPacketHeaderExtension<'a> {
    // profile -- 2 bytes
    pub profile: u16,

    // length (in number of 32 bit words) -- 2 bytes
    pub length: u16,

    // variable length data -- {length*4} bytes
    pub data: &'a [u8],
}
