package com.akeeper.vpn;

import android.net.ConnectivityManager;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.InetSocketAddress;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FlowOwnerResolverTest {

    private static final int TCP = 6;

    @Mock
    private ConnectivityManager connectivityManager;

    private FlowOwnerResolver resolver;

    private final FlowOwnerResolver.FlowKey key = new FlowOwnerResolver.FlowKey(
            TCP,
            InetSocketAddress.createUnresolved("10.111.0.1", 40000),
            InetSocketAddress.createUnresolved("93.184.216.34", 443));

    @BeforeEach
    void setUp() {
        resolver = new FlowOwnerResolver(connectivityManager, 2);
    }

    @Test
    void resolvesOnceThenServesFromCache() {
        when(connectivityManager.getConnectionOwnerUid(TCP, key.local(), key.remote())).thenReturn(10123);

        assertThat(resolver.resolve(key)).hasValue(10123);
        assertThat(resolver.resolve(key)).hasValue(10123);

        verify(connectivityManager, times(1)).getConnectionOwnerUid(anyInt(), any(), any());
    }

    @Test
    void invalidUidIsNotCached() {
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenReturn(FlowOwnerResolver.INVALID_UID);

        assertThat(resolver.resolve(key)).isEmpty();
        assertThat(resolver.resolve(key)).isEmpty();

        verify(connectivityManager, times(2)).getConnectionOwnerUid(anyInt(), any(), any());
    }

    @Test
    void securityExceptionWhenNotActiveVpnYieldsEmpty() {
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenThrow(new SecurityException());

        assertThat(resolver.resolve(key)).isEmpty();
    }

    @Test
    void evictsLeastRecentlyUsedBeyondCapacity() {
        var k2 = new FlowOwnerResolver.FlowKey(TCP, key.local(), InetSocketAddress.createUnresolved("1.1.1.1", 443));
        var k3 = new FlowOwnerResolver.FlowKey(TCP, key.local(), InetSocketAddress.createUnresolved("8.8.8.8", 443));
        when(connectivityManager.getConnectionOwnerUid(anyInt(), any(), any())).thenReturn(10001);

        resolver.resolve(key);
        resolver.resolve(k2);
        resolver.resolve(k3);
        resolver.resolve(key);

        verify(connectivityManager, times(4)).getConnectionOwnerUid(anyInt(), any(), any());
    }
}
