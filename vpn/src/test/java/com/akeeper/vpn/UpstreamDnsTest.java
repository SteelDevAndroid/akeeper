package com.akeeper.vpn;

import org.junit.jupiter.api.Test;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class UpstreamDnsTest {

    private static List<InetAddress> addresses(String... literals) {
        return Arrays.stream(literals).map(UpstreamDnsTest::literal).toList();
    }

    private static InetAddress literal(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (UnknownHostException e) {
            throw new IllegalArgumentException(ip, e);
        }
    }

    @Test
    void keepsDistinctRoutableServersInOrderUpToEngineLimit() {
        var selected = UpstreamDns.select(addresses(
                "192.168.1.1", "127.0.0.53", "0.0.0.0", "192.168.1.1", "2001:db8::53", "9.9.9.9", "1.1.1.1", "8.8.8.8"));

        assertThat(selected).containsExactlyElementsOf(addresses("192.168.1.1", "2001:db8::53", "9.9.9.9", "1.1.1.1"));
    }

    @Test
    void emptyWhenNetworkAnnouncesNoUsableServer() {
        assertThat(UpstreamDns.select(addresses("::1", "::"))).isEmpty();
    }
}
