use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;
pub const PROTO_ICMPV6: u8 = 58;

const IPV4_MIN_HEADER: usize = 20;
const IPV6_HEADER: usize = 40;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseError {
    Empty,
    UnsupportedVersion(u8),
    Truncated,
    BadHeaderLength,
    BadTotalLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPacket<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    /// IPv4 : champ protocole. IPv6 : premier next-header, éventuellement un en-tête d'extension.
    pub protocol: u8,
    /// Non nul ou `more_fragments` : ne jamais lire d'en-tête L4 dans ce paquet.
    pub fragment_offset: u16,
    pub more_fragments: bool,
    pub payload: &'a [u8],
}

impl IpPacket<'_> {
    pub fn is_fragment(&self) -> bool {
        self.fragment_offset != 0 || self.more_fragments
    }
}

/// Le TUN livre un paquet IP par lecture ; tout octet au-delà de la longueur annoncée est ignoré.
pub fn parse(buf: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    let first = *buf.first().ok_or(ParseError::Empty)?;
    match first >> 4 {
        4 => parse_v4(buf, first),
        6 => parse_v6(buf),
        other => Err(ParseError::UnsupportedVersion(other)),
    }
}

fn parse_v4(buf: &[u8], first: u8) -> Result<IpPacket<'_>, ParseError> {
    if buf.len() < IPV4_MIN_HEADER {
        return Err(ParseError::Truncated);
    }
    let header_len = usize::from(first & 0x0f) * 4;
    if header_len < IPV4_MIN_HEADER {
        return Err(ParseError::BadHeaderLength);
    }
    let total_len = usize::from(be16(buf, 2)?);
    if total_len < header_len || total_len > buf.len() {
        return Err(ParseError::BadTotalLength);
    }
    let flags_fragment = be16(buf, 6)?;
    Ok(IpPacket {
        src: IpAddr::V4(Ipv4Addr::from(array::<4>(buf, 12)?)),
        dst: IpAddr::V4(Ipv4Addr::from(array::<4>(buf, 16)?)),
        protocol: byte(buf, 9)?,
        fragment_offset: flags_fragment & 0x1fff,
        more_fragments: flags_fragment & 0x2000 != 0,
        payload: buf
            .get(header_len..total_len)
            .ok_or(ParseError::BadTotalLength)?,
    })
}

fn parse_v6(buf: &[u8]) -> Result<IpPacket<'_>, ParseError> {
    if buf.len() < IPV6_HEADER {
        return Err(ParseError::Truncated);
    }
    let end = IPV6_HEADER + usize::from(be16(buf, 4)?);
    Ok(IpPacket {
        src: IpAddr::V6(Ipv6Addr::from(array::<16>(buf, 8)?)),
        dst: IpAddr::V6(Ipv6Addr::from(array::<16>(buf, 24)?)),
        protocol: byte(buf, 6)?,
        fragment_offset: 0,
        more_fragments: false,
        payload: buf
            .get(IPV6_HEADER..end)
            .ok_or(ParseError::BadTotalLength)?,
    })
}

fn byte(buf: &[u8], at: usize) -> Result<u8, ParseError> {
    buf.get(at).copied().ok_or(ParseError::Truncated)
}

fn be16(buf: &[u8], at: usize) -> Result<u16, ParseError> {
    Ok(u16::from_be_bytes(array::<2>(buf, at)?))
}

fn array<const N: usize>(buf: &[u8], at: usize) -> Result<[u8; N], ParseError> {
    buf.get(at..at + N)
        .and_then(|s| s.try_into().ok())
        .ok_or(ParseError::Truncated)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn ipv4(protocol: u8, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut p = vec![
            0x45, 0, 0, 0, 0, 0, 0, 0, 64, protocol, 0, 0, 10, 111, 0, 1, 93, 184, 216, 34,
        ];
        p[2..4].copy_from_slice(&total.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn ipv6(next_header: u8, payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0x60, 0, 0, 0];
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.extend_from_slice(&[next_header, 64]);
        p.extend_from_slice(&"fd00:6d73::1".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(&"2001:db8::53".parse::<Ipv6Addr>().unwrap().octets());
        p.extend_from_slice(payload);
        p
    }

    #[test]
    fn parses_ipv4_udp() {
        let buf = ipv4(PROTO_UDP, &[1, 2, 3, 4]);
        let packet = parse(&buf).unwrap();
        assert_eq!(packet.src, "10.111.0.1".parse::<IpAddr>().unwrap());
        assert_eq!(packet.dst, "93.184.216.34".parse::<IpAddr>().unwrap());
        assert_eq!(packet.protocol, PROTO_UDP);
        assert_eq!(packet.payload, &[1, 2, 3, 4]);
        assert!(!packet.is_fragment());
    }

    #[test]
    fn ignores_trailing_bytes_beyond_total_length() {
        let mut buf = ipv4(PROTO_TCP, &[9; 8]);
        buf.extend_from_slice(&[0xff; 16]);
        assert_eq!(parse(&buf).unwrap().payload, &[9; 8]);
    }

    #[test]
    fn flags_ipv4_fragments() {
        let mut buf = ipv4(PROTO_UDP, &[0; 8]);
        buf[6] = 0x20;
        assert!(parse(&buf).unwrap().is_fragment());
        buf[6] = 0x00;
        buf[7] = 0x01;
        assert!(parse(&buf).unwrap().is_fragment());
    }

    #[test]
    fn rejects_inconsistent_ipv4_lengths() {
        let mut buf = ipv4(PROTO_UDP, &[0; 4]);
        buf[0] = 0x44;
        assert_eq!(parse(&buf), Err(ParseError::BadHeaderLength));

        let mut buf = ipv4(PROTO_UDP, &[0; 4]);
        buf[2..4].copy_from_slice(&200u16.to_be_bytes());
        assert_eq!(parse(&buf), Err(ParseError::BadTotalLength));

        let mut buf = ipv4(PROTO_UDP, &[0; 4]);
        buf[0] = 0x4f;
        assert_eq!(parse(&buf), Err(ParseError::BadTotalLength));
    }

    #[test]
    fn parses_ipv6_tcp() {
        let buf = ipv6(PROTO_TCP, &[7; 20]);
        let packet = parse(&buf).unwrap();
        assert_eq!(packet.src, "fd00:6d73::1".parse::<IpAddr>().unwrap());
        assert_eq!(packet.protocol, PROTO_TCP);
        assert_eq!(packet.payload.len(), 20);
    }

    #[test]
    fn rejects_ipv6_payload_overflow() {
        let mut buf = ipv6(PROTO_UDP, &[0; 8]);
        buf[4..6].copy_from_slice(&9u16.to_be_bytes());
        assert_eq!(parse(&buf), Err(ParseError::BadTotalLength));
    }

    #[test]
    fn rejects_short_and_unknown_inputs() {
        assert_eq!(parse(&[]), Err(ParseError::Empty));
        assert_eq!(parse(&[0x45; 19]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0x60; 39]), Err(ParseError::Truncated));
        assert_eq!(parse(&[0x50; 64]), Err(ParseError::UnsupportedVersion(5)));
    }

    #[test]
    fn never_panics_on_any_prefix() {
        let buf = ipv6(PROTO_UDP, &[0xaa; 32]);
        for len in 0..=buf.len() {
            let _ = parse(&buf[..len]);
        }
        let buf = ipv4(PROTO_TCP, &[0x55; 32]);
        for len in 0..=buf.len() {
            let _ = parse(&buf[..len]);
        }
    }
}
