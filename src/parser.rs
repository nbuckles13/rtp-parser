use crate::rtp::*;

extern crate nom;
use nom::bits::bits;
use nom::bits::complete::take;
use nom::combinator::rest;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom::{sequence::tuple, IResult};

/// Parse an RTP packet
pub fn parse_rtp_packet(input: &[u8]) -> IResult<&[u8], RtpPacket> {
    let (
        input,
        (
            (version, padding, extension, csrc_count),
            (marker, payload_type),
            sequence_number,
            timestamp,
            ssrc,
        ),
    ) = tuple((parse_vpxcc, parse_mpt, be_u16, be_u32, be_u32))(input)?;

    let (input, csrc) = parse_csrc(input, csrc_count as usize)?;
    let (input, payload) = parse_payload(input)?;

    Ok((
        input,
        RtpPacket {
            version,
            padding,
            extension,
            csrc_count,
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrc,
            payload,
        },
    ))
}

fn parse_vpxcc(input: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8)> {
    let (input, (v, p, x, cc)) = bits(tuple((
        take::<_, _, _, (_, _)>(2usize),
        take::<_, _, _, (_, _)>(1usize),
        take::<_, _, _, (_, _)>(1usize),
        take::<_, _, _, (_, _)>(4usize),
    )))(input)?;

    Ok((input, (v, p, x, cc)))
}

fn parse_mpt(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    let (input, (m, pt)) = bits(tuple((
        take::<_, _, _, (_, _)>(1usize),
        take::<_, _, _, (_, _)>(7usize),
    )))(input)?;

    Ok((input, (m, pt)))
}

fn parse_csrc(input: &[u8], csrc_count: usize) -> IResult<&[u8], Vec<u32>> {
    count(be_u32, csrc_count)(input)
}

fn parse_payload(input: &[u8]) -> IResult<&[u8], &[u8]> {
    rest::<_, (_, _)>(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    // helper function to take a byte and feed it into vpxcc parsing
    fn parse_vpxcc_helper(value: u8) -> (u8, u8, u8, u8) {
        let input: [u8; 1] = [value];
        let result = parse_vpxcc(&input);

        // parsing should work
        assert!(result.is_ok());

        // should have consumed all the data
        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);
        return data.1;
    }

    #[test]
    fn parse_vpxcc_all_one() {
        assert_eq!(parse_vpxcc_helper(0xFF), (0x03, 0x01, 0x01, 0x0F));
    }

    #[test]
    fn parse_vpxcc_all_zero() {
        assert_eq!(parse_vpxcc_helper(0x00), (0x00, 0x00, 0x00, 0x00));
    }

    #[test]
    fn parse_vpxcc_mixed() {
        assert_eq!(parse_vpxcc_helper(0xA5), (0x02, 0x01, 0x00, 0x05));
    }

    #[test]
    fn parse_vpxcc_missing_data() {
        let input: [u8; 0] = [];
        let result = parse_vpxcc(&input);

        assert!(result.is_err());
    }

    fn parse_mpt_helper(value: u8) -> (u8, u8) {
        let input: [u8; 1] = [value];
        let result = parse_mpt(&input);

        // parsing should work
        assert!(result.is_ok());

        // should have consumed all the data
        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);
        return data.1;
    }

    #[test]
    fn parse_mpt_all_zero() {
        assert_eq!(parse_mpt_helper(0x00), (0x00, 0x00));
    }

    #[test]
    fn parse_mpt_all_one() {
        assert_eq!(parse_mpt_helper(0xFF), (0x01, 0x7F));
    }

    #[test]
    fn parse_mpt_mixed() {
        assert_eq!(parse_mpt_helper(0xA5), (0x01, 0x25));
    }

    #[test]
    fn parse_mpt_missing_data() {
        let input: [u8; 0] = [];
        let result = parse_mpt(&input);

        assert!(result.is_err());
    }

    #[test]
    fn parse_csrc_empty() {
        let input: [u8; 0] = [];
        let result = parse_csrc(&input, 0);

        assert!(result.is_ok());
        assert_eq!(result.ok().unwrap().1.len(), 0);
    }

    #[test]
    fn parse_csrc_non_empty() {
        let input: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xA5];

        let result = parse_csrc(&input, 2);
        assert!(result.is_ok());

        let data = result.ok().unwrap();

        // should not have consumed all the data
        assert_eq!(data.0.len(), 1);

        // should have two entries
        assert_eq!(data.1, vec!(0x12345678, 0x90ABCDEF));
    }

    #[test]
    fn parse_csrc_not_enough_data() {
        let input: [u8; 0] = [];
        let result = parse_csrc(&input, 2);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rtp_packet_no_csrc() {
        let data = vec!(0x80, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09);
        let result = parse_rtp_packet(&data);

        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let packet = data.1;
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.padding, 0x00);
        assert_eq!(packet.extension, 0x00);
        assert_eq!(packet.csrc_count, 0x00);
        assert_eq!(packet.marker, 0x00);
        assert_eq!(packet.payload_type, 0x11);
        assert_eq!(packet.sequence_number, 0x1234);
        assert_eq!(packet.timestamp, 0x567890AB);
        assert_eq!(packet.ssrc, 0xCDEFFEDC);
        assert_eq!(packet.csrc, vec![]);
        assert_eq!(packet.payload, [0xBA, 0x09]);
    }

    #[test]
    fn parse_rtp_packet_one_csrc() {
        let data = vec!(0x81, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09, 0x87, 0x65, 0x43);
        let result = parse_rtp_packet(&data);

        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let packet = data.1;
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.padding, 0x00);
        assert_eq!(packet.extension, 0x00);
        assert_eq!(packet.csrc_count, 0x01);
        assert_eq!(packet.marker, 0x00);
        assert_eq!(packet.payload_type, 0x11);
        assert_eq!(packet.sequence_number, 0x1234);
        assert_eq!(packet.timestamp, 0x567890AB);
        assert_eq!(packet.ssrc, 0xCDEFFEDC);
        assert_eq!(packet.csrc, vec![0xBA098765]);
        assert_eq!(packet.payload, [0x43]);
    }
}
