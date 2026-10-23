package com.akeeper.vpn;

import android.net.ConnectivityManager;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetAddress;
import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FlowOwnerResolverTest {

    private static final int TCP = 6;
    private static final byte[] TUN = {10, 111, 0, 1};
    private static final byte[] REMOTE = {93, (byte) 184, (byte) 216, 34};

    @Mock
    private ConnectivityManager connectivityManager;

    private FlowOwnerResolver resolver;

    @BeforeEach
    void setUp() {
        resolver = new FlowOwnerResolver(connectivityManager);
    }

    @Test
    void passesExactEndpointsToTheSystem() throws Exception {
        var local = new InetSocketAddress(InetAddress.getByAddress(TUN), 40000);
        var remote = new InetSocketAddress(InetAddress.getByAddress(REMOTE), 443);
        when(connectivityManager.getConnectionOwnerUid(TCP, local, remote)).thenReturn(10123);

        assertThat(resolver.ownerUid(TCP, TUN, 40000, REMOTE, 443)).isEqualTo(10123);
    }

    @Test
    void securityExceptionWhenNotActiveVpnYieldsInvalidUid() {
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenThrow(new SecurityException());

        assertThat(resolver.ownerUid(TCP, TUN, 40000, REMOTE, 443)).isEqualTo(FlowOwnerResolver.INVALID_UID);
    }

    @Test
    void malformedAddressNeverReachesTheSystem() {
        assertThat(resolver.ownerUid(TCP, new byte[3], 1, REMOTE, 443)).isEqualTo(FlowOwnerResolver.INVALID_UID);
        verifyNoInteractions(connectivityManager);
    }
}
