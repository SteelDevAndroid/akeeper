package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import java.net.InetAddress;

import org.junit.jupiter.api.Test;

class LanRangesTest {

    private static byte[] ip(String literal) throws Exception {
        return InetAddress.getByName(literal).getAddress();
    }

    private static boolean excluded(String literal) throws Exception {
        var address = ip(literal);
        return LanRanges.privateRanges().stream().anyMatch(range -> LanRanges.contains(range, address));
    }

    @Test
    void excludesPrivateNetworksButNeverTheTunnelAddresses() throws Exception {
        assertThat(excluded("192.168.1.20")).isTrue();
        assertThat(excluded("10.0.0.7")).isTrue();
        assertThat(excluded("10.112.0.1")).isTrue();
        assertThat(excluded("172.20.3.4")).isTrue();
        assertThat(excluded("169.254.10.1")).isTrue();
        assertThat(excluded("fd12:3456::1")).isTrue();
        assertThat(excluded("fe80::1")).isTrue();

        // Adresses virtuelles du tunnel : elles doivent rester routées vers le moteur.
        assertThat(excluded("10.111.0.53")).isFalse();
        assertThat(excluded("10.111.255.255")).isFalse();
        assertThat(excluded("fd00:6d73::53")).isFalse();
        // Internet.
        assertThat(excluded("8.8.8.8")).isFalse();
        assertThat(excluded("2606:4700::1111")).isFalse();
    }

    @Test
    void subtractingAHoleLeavesDisjointSiblings() throws Exception {
        var pieces = LanRanges.subtract(new LanRanges.Range(ip("10.0.0.0"), 8), new LanRanges.Range(ip("10.111.0.0"), 16));

        assertThat(pieces).hasSize(8);
        assertThat(LanRanges.subtract(new LanRanges.Range(ip("192.168.0.0"), 16),
                new LanRanges.Range(ip("10.111.0.0"), 16))).hasSize(1);
        assertThat(LanRanges.subtract(new LanRanges.Range(ip("10.111.0.0"), 16),
                new LanRanges.Range(ip("10.0.0.0"), 8))).isEmpty();
    }
}
