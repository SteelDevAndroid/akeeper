use std::net::SocketAddr;

use crate::checksum;
use crate::ip::{self, BuildError, IpPacket, PROTO_TCP};

const MIN_HEADER: usize = 20;

pub const FIN: u8 = 0x01;
pub const SYN: u8 = 0x02;
pub const RST: u8 = 0x04;
pub const ACK: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    NotTcp,
    Fragment,
    Truncated,
    BadHeaderLength,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Segment {
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub seq: u32,
    pub ack: u32,
    pub flags: u8,
    pub payload_len: usize,
}

pub fn parse(packet: &IpPacket<'_>) -> Result<Segment, TcpError> {
    if packet.protocol != PROTO_TCP {
        return Err(TcpError::NotTcp);
    }
    if packet.is_fragment() {
        return Err(TcpError::Fragment);
    }
    let seg = packet.payload;
    let header = seg.get(..MIN_HEADER).ok_or(TcpError::Truncated)?;
    let u16_at = |at: usize| {
        header
            .get(at..at + 2)
            .and_then(|b| b.try_into().ok())
            .map(u16::from_be_bytes)
            .ok_or(TcpError::Truncated)
    };
    let u32_at = |at: usize| {
        header
            .get(at..at + 4)
            .and_then(|b| b.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or(TcpError::Truncated)
    };
    let offset = usize::from(header.get(12).ok_or(TcpError::Truncated)? >> 4) * 4;
    if offset < MIN_HEADER || offset > seg.len() {
        return Err(TcpError::BadHeaderLength);
    }
    Ok(Segment {
        src: SocketAddr::new(packet.src, u16_at(0)?),
        dst: SocketAddr::new(packet.dst, u16_at(2)?),
        seq: u32_at(4)?,
        ack: u32_at(8)?,
        flags: *header.get(13).ok_or(TcpError::Truncated)?,
        payload_len: seg.len() - offset,
    })
}

/// Réponse RST à `incoming` (RFC 9293 §3.10.7.1). `None` si `incoming` est lui-même un RST.
pub fn build_reset(incoming: &Segment, out: &mut Vec<u8>) -> Option<Result<(), BuildError>> {
    if incoming.flags & RST != 0 {
        return None;
    }
    let (seq, ack, flags) = if incoming.flags & ACK != 0 {
        (incoming.ack, 0, RST)
    } else {
        let consumed = u32::from(incoming.flags & SYN != 0) + u32::from(incoming.flags & FIN != 0);
        let ack = incoming
            .seq
            .wrapping_add(incoming.payload_len as u32)
            .wrapping_add(consumed);
        (0, ack, RST | ACK)
    };
    let (src, dst) = (incoming.dst, incoming.src);
    let mut segment = Vec::with_capacity(MIN_HEADER);
    segment.extend_from_slice(&src.port().to_be_bytes());
    segment.extend_from_slice(&dst.port().to_be_bytes());
    segment.extend_from_slice(&seq.to_be_bytes());
    segment.extend_from_slice(&ack.to_be_bytes());
    segment.extend_from_slice(&[(MIN_HEADER as u8 / 4) << 4, flags, 0, 0, 0, 0, 0, 0]);
    let acc = checksum::pseudo_header(src.ip(), dst.ip(), PROTO_TCP, MIN_HEADER as u32);
    let sum = checksum::finish(checksum::add(acc, &segment));
    if let Some(slot) = segment.get_mut(16..18) {
        slot.copy_from_slice(&sum.to_be_bytes());
    }
    Some(ip::build(src.ip(), dst.ip(), PROTO_TCP, &segment, out))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    fn syn_to_853() -> Vec<u8> {
        let mut tcp = vec![0x9c, 0x40, 0x03, 0x55];
        tcp.extend_from_slice(&1000u32.to_be_bytes());
        tcp.extend_from_slice(&0u32.to_be_bytes());
        tcp.extend_from_slice(&[0x50, SYN, 0xff, 0xff, 0, 0, 0, 0]);
        let mut out = Vec::new();
        ip::build(
            "10.111.0.1".parse().unwrap(),
            "10.111.0.53".parse().unwrap(),
            PROTO_TCP,
            &tcp,
            &mut out,
        )
        .unwrap();
        out
    }

    #[test]
    fn parses_syn() {
        let buf = syn_to_853();
        let segment = parse(&ip::parse(&buf).unwrap()).unwrap();
        assert_eq!(segment.dst.port(), 853);
        assert_eq!(segment.seq, 1000);
        assert_eq!(segment.flags, SYN);
        assert_eq!(segment.payload_len, 0);
    }

    #[test]
    fn resets_syn_with_ack_of_seq_plus_one() {
        let buf = syn_to_853();
        let incoming = parse(&ip::parse(&buf).unwrap()).unwrap();
        let mut out = Vec::new();
        build_reset(&incoming, &mut out).unwrap().unwrap();

        let packet = ip::parse(&out).unwrap();
        let reply = parse(&packet).unwrap();
        assert_eq!(reply.src, incoming.dst);
        assert_eq!(reply.dst, incoming.src);
        assert_eq!(reply.flags, RST | ACK);
        assert_eq!(reply.ack, 1001);
        let acc = checksum::pseudo_header(packet.src, packet.dst, PROTO_TCP, 20);
        assert_eq!(checksum::finish(checksum::add(acc, packet.payload)), 0);
    }

    #[test]
    fn never_resets_a_reset() {
        let mut buf = syn_to_853();
        buf[33] = RST;
        let incoming = parse(&ip::parse(&buf).unwrap()).unwrap();
        assert!(build_reset(&incoming, &mut Vec::new()).is_none());
    }

    #[test]
    fn rejects_bad_data_offset() {
        let mut buf = syn_to_853();
        buf[32] = 0x40;
        assert_eq!(
            parse(&ip::parse(&buf).unwrap()),
            Err(TcpError::BadHeaderLength)
        );
        buf[32] = 0xf0;
        assert_eq!(
            parse(&ip::parse(&buf).unwrap()),
            Err(TcpError::BadHeaderLength)
        );
    }
}
