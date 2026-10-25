package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;

class NetworkStateTest {

    @Test
    void lanBypassRequiresValidatedLocalTransport() {
        assertThat(new NetworkState(NetworkState.Transport.WIFI, false, false, true, false).allowsLanBypass()).isTrue();
        assertThat(new NetworkState(NetworkState.Transport.ETHERNET, false, false, true, false).allowsLanBypass()).isTrue();
        assertThat(new NetworkState(NetworkState.Transport.CELLULAR, false, false, true, false).allowsLanBypass()).isFalse();
        assertThat(new NetworkState(NetworkState.Transport.WIFI, false, true, true, false).allowsLanBypass()).isFalse();
        assertThat(new NetworkState(NetworkState.Transport.WIFI, false, false, false, false).allowsLanBypass()).isFalse();
        assertThat(new NetworkState(NetworkState.Transport.WIFI, false, false, true, true).allowsLanBypass()).isFalse();
        assertThat(NetworkState.NONE.allowsLanBypass()).isFalse();
    }
}
