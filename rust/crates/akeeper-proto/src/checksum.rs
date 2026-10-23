use std::net::IpAddr;

/// Somme en complément à un (RFC 1071), à replier avec [`finish`].
pub(crate) fn add(mut acc: u32, data: &[u8]) -> u32 {
    for pair in data.chunks(2) {
        let hi = pair.first().copied().unwrap_or(0);
        let lo = pair.get(1).copied().unwrap_or(0);
        acc = acc.wrapping_add(u32::from(u16::from_be_bytes([hi, lo])));
    }
    acc
}

pub(crate) fn finish(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Pseudo-en-tête TCP/UDP. `src` et `dst` sont de la même famille (vérifié par l'appelant).
pub(crate) fn pseudo_header(src: IpAddr, dst: IpAddr, protocol: u8, l4_len: u32) -> u32 {
    let acc = match (src, dst) {
        (IpAddr::V4(s), IpAddr::V4(d)) => add(add(0, &s.octets()), &d.octets()),
        (IpAddr::V6(s), IpAddr::V6(d)) => add(add(0, &s.octets()), &d.octets()),
        _ => 0,
    };
    add(add(acc, &l4_len.to_be_bytes()), &[0, protocol])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_rfc1071_example() {
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(finish(add(0, &data)), !0xddf2);
    }

    #[test]
    fn odd_length_pads_with_zero() {
        assert_eq!(finish(add(0, &[0xab])), finish(add(0, &[0xab, 0x00])));
    }
}
