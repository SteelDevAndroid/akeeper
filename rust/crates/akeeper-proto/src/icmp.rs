use std::net::IpAddr;

use crate::checksum;
use crate::ip::{self, BuildError, IpPacket, PROTO_ICMP, PROTO_ICMPV6};

// RFC 8200 §5 : un message ICMPv6 d'erreur ne doit pas dépasser le MTU minimal de 1280 octets.
const IPV6_MIN_MTU: usize = 1280;
const IPV6_HEADER: usize = 40;
const ICMP_HEADER: usize = 8;

/// « Port inaccessible » en réponse à `raw` (paquet complet, déjà parsé en `packet`) :
/// le client abandonne aussitôt, ce qui force par exemple QUIC à se replier sur TCP.
pub fn build_port_unreachable(
    raw: &[u8],
    packet: &IpPacket<'_>,
    out: &mut Vec<u8>,
) -> Result<(), BuildError> {
    let (src, dst) = (packet.dst, packet.src);
    let (protocol, kind, code, quote) = match src {
        // RFC 792 : en-tête IP d'origine + 8 premiers octets de la charge utile.
        IpAddr::V4(_) => {
            let header_len = usize::from(raw.first().map_or(0, |b| b & 0x0f)) * 4;
            (
                PROTO_ICMP,
                3u8,
                3u8,
                raw.get(..raw.len().min(header_len + 8)).unwrap_or_default(),
            )
        }
        IpAddr::V6(_) => {
            let max = IPV6_MIN_MTU - IPV6_HEADER - ICMP_HEADER;
            (
                PROTO_ICMPV6,
                1u8,
                4u8,
                raw.get(..raw.len().min(max)).unwrap_or_default(),
            )
        }
    };
    let mut message = Vec::with_capacity(ICMP_HEADER + quote.len());
    message.extend_from_slice(&[kind, code, 0, 0, 0, 0, 0, 0]);
    message.extend_from_slice(quote);
    // ICMPv4 se somme seul ; ICMPv6 inclut le pseudo-en-tête (RFC 4443 §2.3).
    let acc = match src {
        IpAddr::V4(_) => 0,
        IpAddr::V6(_) => checksum::pseudo_header(src, dst, PROTO_ICMPV6, message.len() as u32),
    };
    let sum = checksum::finish(checksum::add(acc, &message));
    if let Some(slot) = message.get_mut(2..4) {
        slot.copy_from_slice(&sum.to_be_bytes());
    }
    ip::build(src, dst, protocol, &message, out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use crate::udp;
    use std::net::SocketAddr;

    fn quic_initial(src: &str, dst: &str) -> Vec<u8> {
        let mut out = Vec::new();
        udp::build(
            src.parse::<SocketAddr>().unwrap(),
            dst.parse().unwrap(),
            &[0xc3; 1200],
            &mut out,
        )
        .unwrap();
        out
    }

    #[test]
    fn ipv4_quotes_header_and_eight_bytes() {
        let raw = quic_initial("10.111.0.1:50000", "142.250.0.1:443");
        let packet = ip::parse(&raw).unwrap();
        let mut out = Vec::new();
        build_port_unreachable(&raw, &packet, &mut out).unwrap();

        let reply = ip::parse(&out).unwrap();
        assert_eq!(reply.src, packet.dst);
        assert_eq!(reply.dst, packet.src);
        assert_eq!(reply.protocol, PROTO_ICMP);
        assert_eq!(&reply.payload[..2], &[3, 3]);
        assert_eq!(&reply.payload[8..], &raw[..28]);
        assert_eq!(checksum::finish(checksum::add(0, reply.payload)), 0);
    }

    #[test]
    fn ipv6_stays_within_minimum_mtu_with_valid_checksum() {
        let raw = quic_initial("[fd00:6d73::1]:50000", "[2001:db8::443]:443");
        let packet = ip::parse(&raw).unwrap();
        let mut out = Vec::new();
        build_port_unreachable(&raw, &packet, &mut out).unwrap();

        assert!(out.len() <= IPV6_MIN_MTU);
        let reply = ip::parse(&out).unwrap();
        assert_eq!(&reply.payload[..2], &[1, 4]);
        let acc = checksum::pseudo_header(
            reply.src,
            reply.dst,
            PROTO_ICMPV6,
            reply.payload.len() as u32,
        );
        assert_eq!(checksum::finish(checksum::add(acc, reply.payload)), 0);
    }
}
