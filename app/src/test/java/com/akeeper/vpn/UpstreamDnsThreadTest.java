package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import android.net.ConnectivityManager;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.Looper;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.annotation.Config;

/** Régression : les rappels réseau ouvrent des sockets, ce que StrictMode interdit sur le thread principal. */
@RunWith(RobolectricTestRunner.class)
@Config(sdk = 36)
public class UpstreamDnsThreadTest {

    @Test
    public void registersItsCallbackOnADedicatedThread() {
        var connectivity = mock(ConnectivityManager.class);
        var upstream = new UpstreamDns(connectivity, null, socket -> true, network -> {
        }, strict -> {
        });

        upstream.start();

        var handler = ArgumentCaptor.forClass(Handler.class);
        verify(connectivity).registerBestMatchingNetworkCallback(any(NetworkRequest.class), any(), handler.capture());
        assertThat(handler.getValue().getLooper()).isNotSameAs(Looper.getMainLooper());
        upstream.close();
    }

    @Test
    public void closesTwiceWithoutFailing() {
        var upstream = new UpstreamDns(mock(ConnectivityManager.class), null, socket -> true, network -> {
        }, strict -> {
        });
        upstream.start();
        upstream.close();
        upstream.close();
    }
}
