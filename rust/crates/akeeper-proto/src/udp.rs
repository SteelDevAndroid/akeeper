use std::net::SocketAddr;

use crate::checksum;
use crate::ip::{self, IpPacket, PROTO_UDP};

const HEADER: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpError {
    NotUdp,
    Fragment,
    Truncated,
    BadLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Datagram<'a> {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: &'a [u8],
}

pub fn parse<'a>(packet: &IpPacket<'a>) -> Result<Datagram<'a>, UdpError> {
    if packet.protocol != PROTO_UDP {
        return Err(UdpError::NotUdp);
    }
    if packet.is_fragment() {
        return Err(UdpError::Fragment);
    }
    let seg = packet.payload;
    let header = seg.get(..HEADER).ok_or(UdpError::Truncated)?;
    let field = |at: usize| {
        header
            .get(at..at + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(UdpError::Truncated)
    };
    let len = usize::from(field(4)?);
    let payload = seg.get(HEADER..len).ok_or(UdpError::BadLength)?;
    Ok(Datagram {
        src: SocketAddr::new(packet.src, field(0)?),
        dst: SocketAddr::new(packet.dst, field(2)?),
        payload,
    })
}

pub use crate::ip::BuildError;

/// Écrit un paquet IP + UDP complet (sommes de contrôle comprises) dans `out`, vidé au préalable.
pub fn build(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), BuildError> {
    let udp_len = u16::try_from(HEADER + payload.len()).map_err(|_| BuildError::TooLarge)?;
    let mut segment = Vec::with_capacity(usize::from(udp_len));
    segment.extend_from_slice(&src.port().to_be_bytes());
    segment.extend_from_slice(&dst.port().to_be_bytes());
    segment.extend_from_slice(&udp_len.to_be_bytes());
    segment.extend_from_slice(&[0, 0]);
    segment.extend_from_slice(payload);

    let acc = checksum::pseudo_header(src.ip(), dst.ip(), PROTO_UDP, u32::from(udp_len));
    // 0 signifie « pas de somme » en UDP : la valeur calculée nulle s'écrit 0xffff.
    let sum = match checksum::finish(checksum::add(acc, &segment)) {
        0 => 0xffff,
        s => s,
    };
    if let Some(slot) = segment.get_mut(6..8) {
        slot.copy_from_slice(&sum.to_be_bytes());
    }
    ip::build(src.ip(), dst.ip(), PROTO_UDP, &segment, out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn sa(s: &str) -> SocketAddr {
        s.parse().unwrap()
    }

    #[test]
    fn round_trips_ipv4() {
        let mut out = Vec::new();
        build(
            sa("10.111.0.53:53"),
            sa("10.111.0.1:40000"),
            b"hello",
            &mut out,
        )
        .unwrap();
        let packet = ip::parse(&out).unwrap();
        let datagram = parse(&packet).unwrap();
        assert_eq!(datagram.src, sa("10.111.0.53:53"));
        assert_eq!(datagram.dst, sa("10.111.0.1:40000"));
        assert_eq!(datagram.payload, b"hello");
        assert_eq!(
            checksum::finish(checksum::add(0, &out[..20])),
            0,
            "somme IPv4 invalide"
        );
        let acc = checksum::pseudo_header(packet.src, packet.dst, PROTO_UDP, 13);
        assert_eq!(
            checksum::finish(checksum::add(acc, packet.payload)),
            0,
            "somme UDP invalide"
        );
    }

    #[test]
    fn round_trips_ipv6_with_valid_checksum() {
        let mut out = Vec::new();
        build(
            sa("[fd00:6d73::53]:53"),
            sa("[fd00:6d73::1]:5353"),
            &[1, 2, 3],
            &mut out,
        )
        .unwrap();
        let packet = ip::parse(&out).unwrap();
        let datagram = parse(&packet).unwrap();
        assert_eq!(datagram.payload, &[1, 2, 3]);
        let acc = checksum::pseudo_header(packet.src, packet.dst, PROTO_UDP, 11);
        assert_eq!(checksum::finish(checksum::add(acc, packet.payload)), 0);
    }

    #[test]
    fn rejects_mixed_families_and_bad_lengths() {
        let mut out = Vec::new();
        assert_eq!(
            build(sa("10.0.0.1:1"), sa("[::1]:1"), &[], &mut out),
            Err(BuildError::FamilyMismatch)
        );
        build(sa("10.0.0.1:1"), sa("10.0.0.2:2"), &[0; 4], &mut out).unwrap();
        out[25] = 200;
        let packet = ip::parse(&out).unwrap();
        assert_eq!(parse(&packet), Err(UdpError::BadLength));
    }
}
