use crate::rtp::*;
use crate::rtp_header_extension::*;

extern crate nom;
use nom::bits::bits;
use nom::bits::complete::take as bits_take;
use nom::bytes::complete::take as bytes_take;
use nom::combinator::rest;
use nom::error::make_error;
use nom::error::ErrorKind;
use nom::Err;
use nom::IResult;
use nom::multi::count;
use nom::number::complete::{be_u16, be_u32};
use nom::sequence::tuple;

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
    let (input, header_extension) = parse_header_extension(input, extension)?;
    let (input, (payload, padding_bytes)) = parse_payload(input, padding)?;

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
            header_extension,
            payload,
            padding_bytes,
        },
    ))
}

fn parse_vpxcc(input: &[u8]) -> IResult<&[u8], (u8, u8, u8, u8)> {
    bits(tuple((
        bits_take::<_, _, _, (_, _)>(2usize),
        bits_take::<_, _, _, (_, _)>(1usize),
        bits_take::<_, _, _, (_, _)>(1usize),
        bits_take::<_, _, _, (_, _)>(4usize),
    )))(input)
}

fn parse_mpt(input: &[u8]) -> IResult<&[u8], (u8, u8)> {
    bits(tuple((
        bits_take::<_, _, _, (_, _)>(1usize),
        bits_take::<_, _, _, (_, _)>(7usize),
    )))(input)
}

fn parse_csrc(input: &[u8], csrc_count: usize) -> IResult<&[u8], Vec<u32>> {
    count(be_u32, csrc_count)(input)
}

fn parse_header_extension(
    input: &[u8],
    extension: u8,
) -> IResult<&[u8], Option<RtpPacketHeaderExtension>> {
    if extension == 0 {
        Ok((input, None))
    } else {
        let (input, (profile, length)) = tuple((be_u16, be_u16))(input)?;
        let (input, data) = bytes_take(length * 4)(input)?;

        Ok((
            input,
            Some(RtpPacketHeaderExtension {
                profile,
                length,
                data,
            }),
        ))
    }
}

fn parse_payload_no_padding(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let (input, payload) = rest::<_, (_, _)>(input)?;
    Ok((input, (payload, &[])))
}

fn parse_payload_padding(input: &[u8]) -> IResult<&[u8], (&[u8], &[u8])> {
    let num_padding_bytes = input.last().map(|i| *i as usize).unwrap_or(usize::MAX);

    if num_padding_bytes <= input.len() {
        tuple((
            bytes_take(input.len() - num_padding_bytes),
            bytes_take(num_padding_bytes),
        ))(input)
    } else {
        Err(Err::Error(make_error(input, ErrorKind::Eof)))
    }
}

fn parse_payload(input: &[u8], padding: u8) -> IResult<&[u8], (&[u8], &[u8])> {
    if padding == 0x00 {
        parse_payload_no_padding(input)
    } else {
        parse_payload_padding(input)
    }
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
    fn parse_header_extension_empty_valid() {
        let input: [u8; 0] = [];
        let result = parse_header_extension(&input, 0);
        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert!(data.1.is_none());
    }

    #[test]
    fn parse_header_extension_empty_invalid() {
        let input: [u8; 0] = [];
        let result = parse_header_extension(&input, 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_header_extension_non_empty() {
        let input: [u8; 8] = [0x12, 0x34, 0x00, 0x01, 0x56, 0x78, 0x90, 0xAB];
        let result = parse_header_extension(&input, 1);
        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);
        assert!(data.1.is_some());

        let header_extension = data.1.unwrap();
        assert_eq!(header_extension.profile, 0x1234);
        assert_eq!(header_extension.length, 0x0001);
        assert_eq!(header_extension.data, [0x56, 0x78, 0x90, 0xAB]);
    }

    #[test]
    fn parse_payload_no_padding() {
        let input: [u8; 1] = [0x12];
        let result = parse_payload(&input, 0);
        assert!(result.is_ok());
        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let (payload, padding_bytes) = data.1;
        assert_eq!(payload, [0x12]);
        assert_eq!(padding_bytes, []);
    }

    #[test]
    fn parse_payload_padding_valid() {
        let input: [u8; 4] = [0x12, 0x00, 0x00, 0x03];
        let result = parse_payload(&input, 1);
        assert!(result.is_ok());
        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let (payload, padding_bytes) = data.1;
        assert_eq!(payload, [0x12]);
        assert_eq!(padding_bytes, [0x00, 0x00, 0x03]);
    }

    #[test]
    fn parse_payload_padding_valid_no_payload() {
        let input: [u8; 4] = [0x12, 0x00, 0x00, 0x04];
        let result = parse_payload(&input, 1);
        assert!(result.is_ok());
        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let (payload, padding_bytes) = data.1;
        assert_eq!(payload, []);
        assert_eq!(padding_bytes, [0x12, 0x00, 0x00, 0x04]);
    }

    #[test]
    fn parse_payload_padding_invalid() {
        // number of padding bytes (last value in array) is too large
        let input: [u8; 4] = [0x12, 0x00, 0x00, 0x05];
        let result = parse_payload(&input, 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_payload_padding_empty() {
        let input: [u8; 0] = [];
        let result = parse_payload(&input, 1);
        assert!(result.is_err());
    }

    #[test]
    fn parse_rtp_packet_no_csrc_no_header_extension() {
        let data = vec![
            0x80, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09,
        ];
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
        assert!(packet.header_extension.is_none());
        assert_eq!(packet.payload, [0xBA, 0x09]);
        assert_eq!(packet.padding_bytes, []);
    }

    #[test]
    fn parse_rtp_packet_csrc() {
        let data = vec![
            0x81, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09,
            0x87, 0x65, 0x43,
        ];
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
        assert!(packet.header_extension.is_none());
        assert_eq!(packet.payload, [0x43]);
        assert_eq!(packet.padding_bytes, []);
    }

    #[test]
    fn parse_rtp_packet_header_ext() {
        let data = vec![
            0x90, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09,
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11, 0x43,
        ];
        let result = parse_rtp_packet(&data);

        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let packet = data.1;
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.padding, 0x00);
        assert_eq!(packet.extension, 0x01);
        assert_eq!(packet.csrc_count, 0x00);
        assert_eq!(packet.marker, 0x00);
        assert_eq!(packet.payload_type, 0x11);
        assert_eq!(packet.sequence_number, 0x1234);
        assert_eq!(packet.timestamp, 0x567890AB);
        assert_eq!(packet.ssrc, 0xCDEFFEDC);
        assert_eq!(packet.csrc, vec![]);
        assert!(packet.header_extension.is_some());

        let header_extension = packet.header_extension.unwrap();
        assert_eq!(header_extension.profile, 0xBA09);
        assert_eq!(header_extension.length, 0x0002);
        assert_eq!(
            header_extension.data,
            [0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11]
        );

        assert_eq!(packet.payload, [0x43]);
        assert_eq!(packet.padding_bytes, []);
    }

    #[test]
    fn parse_rtp_packet_csrc_header_ext() {
        let data = vec![
            0x91, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09,
            0x87, 0x65, 0x43, 0x21, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11,
            0x43,
        ];
        let result = parse_rtp_packet(&data);

        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let packet = data.1;
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.padding, 0x00);
        assert_eq!(packet.extension, 0x01);
        assert_eq!(packet.csrc_count, 0x01);
        assert_eq!(packet.marker, 0x00);
        assert_eq!(packet.payload_type, 0x11);
        assert_eq!(packet.sequence_number, 0x1234);
        assert_eq!(packet.timestamp, 0x567890AB);
        assert_eq!(packet.ssrc, 0xCDEFFEDC);
        assert_eq!(packet.csrc, vec![0xBA098765]);
        assert!(packet.header_extension.is_some());

        let header_extension = packet.header_extension.unwrap();
        assert_eq!(header_extension.profile, 0x4321);
        assert_eq!(header_extension.length, 0x0002);
        assert_eq!(
            header_extension.data,
            [0x00, 0x00, 0x00, 0x00, 0x11, 0x11, 0x11, 0x11]
        );

        assert_eq!(packet.payload, [0x43]);
        assert_eq!(packet.padding_bytes, []);
    }

    #[test]
    fn parse_rtp_packet_padding() {
        let data = vec![
            0xA0, 0x11, 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x09, 0x03
        ];
        let result = parse_rtp_packet(&data);

        assert!(result.is_ok());

        let data = result.ok().unwrap();
        assert_eq!(data.0.len(), 0);

        let packet = data.1;
        assert_eq!(packet.version, 0x02);
        assert_eq!(packet.padding, 0x01);
        assert_eq!(packet.extension, 0x00);
        assert_eq!(packet.csrc_count, 0x00);
        assert_eq!(packet.marker, 0x00);
        assert_eq!(packet.payload_type, 0x11);
        assert_eq!(packet.sequence_number, 0x1234);
        assert_eq!(packet.timestamp, 0x567890AB);
        assert_eq!(packet.ssrc, 0xCDEFFEDC);
        assert_eq!(packet.csrc, vec![]);
        assert!(packet.header_extension.is_none());
        assert_eq!(packet.payload, []);
        assert_eq!(packet.padding_bytes, [0xBA, 0x09, 0x03]);
    }
}
