use std::sync::atomic::{AtomicU64, Ordering};

use akeeper_proto::ip::{self, IpPacket, ParseError};

/// Indices stables : ils sont exposés tels quels à Java via JNI (`NativeEngine.Counter`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Counter {
    Packets = 0,
    Bytes = 1,
    Malformed = 2,
    Tcp = 3,
    Udp = 4,
    Icmp = 5,
    DnsQueries = 6,
    DnsBlocked = 7,
    DnsUpstreamFailures = 8,
    QuicBlocked = 9,
    UdpNatFailures = 10,
    TcpFlows = 11,
    TcpFailures = 12,
    AppBlocked = 13,
    SniBlocked = 14,
    DotBlocked = 15,
    IpBlocked = 16,
}

const COUNTERS: usize = 17;

impl Counter {
    pub fn from_index(index: i32) -> Option<Self> {
        Some(match index {
            0 => Self::Packets,
            1 => Self::Bytes,
            2 => Self::Malformed,
            3 => Self::Tcp,
            4 => Self::Udp,
            5 => Self::Icmp,
            6 => Self::DnsQueries,
            7 => Self::DnsBlocked,
            8 => Self::DnsUpstreamFailures,
            9 => Self::QuicBlocked,
            10 => Self::UdpNatFailures,
            11 => Self::TcpFlows,
            12 => Self::TcpFailures,
            13 => Self::AppBlocked,
            14 => Self::SniBlocked,
            15 => Self::DotBlocked,
            16 => Self::IpBlocked,
            _ => return None,
        })
    }
}

/// Écrit par le seul thread moteur, lu par n'importe quel thread : `Relaxed` suffit, aucun ordre n'est requis entre compteurs.
#[derive(Debug, Default)]
pub struct Stats {
    counters: [AtomicU64; COUNTERS],
}

impl Stats {
    pub fn get(&self, counter: Counter) -> u64 {
        self.counters
            .get(counter as usize)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    pub(crate) fn record(&self, parsed: &Result<IpPacket<'_>, ParseError>, len: usize) {
        self.add(Counter::Packets, 1);
        self.add(Counter::Bytes, len as u64);
        match parsed {
            Ok(packet) => match packet.protocol {
                ip::PROTO_TCP => self.add(Counter::Tcp, 1),
                ip::PROTO_UDP => self.add(Counter::Udp, 1),
                ip::PROTO_ICMP | ip::PROTO_ICMPV6 => self.add(Counter::Icmp, 1),
                _ => {}
            },
            Err(_) => self.add(Counter::Malformed, 1),
        }
    }

    pub(crate) fn add(&self, counter: Counter, value: u64) {
        if let Some(c) = self.counters.get(counter as usize) {
            c.fetch_add(value, Ordering::Relaxed);
        }
    }
}
