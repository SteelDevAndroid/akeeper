#![no_main]

use akeeper_proto::{icmp, ip, tcp, udp};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(packet) = ip::parse(data) else {
        return;
    };
    if let Ok(datagram) = udp::parse(&packet) {
        let mut out = Vec::new();
        if udp::build(datagram.dst, datagram.src, datagram.payload, &mut out).is_ok() {
            let back = ip::parse(&out).expect("paquet UDP construit illisible");
            assert_eq!(udp::parse(&back).expect("UDP construit illisible").payload, datagram.payload);
        }
    }
    let mut icmp_out = Vec::new();
    if icmp::build_port_unreachable(data, &packet, &mut icmp_out).is_ok() {
        assert!(ip::parse(&icmp_out).is_ok(), "ICMP construit illisible");
    }
    if let Ok(segment) = tcp::parse(&packet) {
        let _ = tcp::build_reset(&segment, &mut Vec::new());
    }
});
