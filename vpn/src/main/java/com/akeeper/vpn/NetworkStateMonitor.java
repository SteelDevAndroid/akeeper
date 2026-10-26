package com.akeeper.vpn;

import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.HandlerThread;

import java.util.Objects;
import java.util.function.Consumer;

/** Suit le meilleur réseau physique non-VPN et publie un état compact, dédupliqué. */
final class NetworkStateMonitor extends ConnectivityManager.NetworkCallback implements AutoCloseable {

    private final ConnectivityManager connectivity;
    private final Consumer<NetworkState> listener;
    private HandlerThread thread;
    private boolean closed;
    private Network currentNetwork;
    private NetworkState current = NetworkState.NONE;

    NetworkStateMonitor(ConnectivityManager connectivity, Consumer<NetworkState> listener) {
        this.connectivity = connectivity;
        this.listener = listener;
    }

    synchronized void start() {
        thread = new HandlerThread("akeeper-network-state");
        thread.start();
        var request = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
                .build();
        connectivity.registerBestMatchingNetworkCallback(request, this, new Handler(thread.getLooper()));
    }

    @Override
    public synchronized void onCapabilitiesChanged(Network network, NetworkCapabilities capabilities) {
        if (closed) {
            return;
        }
        currentNetwork = network;
        publish(from(capabilities));
    }

    @Override
    public synchronized void onLost(Network network) {
        if (!closed && Objects.equals(network, currentNetwork)) {
            currentNetwork = null;
            publish(NetworkState.NONE);
        }
    }

    @Override
    public synchronized void close() {
        if (closed) {
            return;
        }
        closed = true;
        connectivity.unregisterNetworkCallback(this);
        thread.quitSafely();
    }

    /**
     * État du réseau par défaut, lu sans attendre le premier rappel : sans lui, le premier tunnel serait établi
     * avec {@link NetworkState#NONE}, puis reconstruit dès ce rappel. Un VPN déjà actif (le nôtre ou un autre) ne
     * renseigne pas sur le réseau physique : {@code NONE}, le choix le plus prudent.
     */
    static NetworkState current(ConnectivityManager connectivity) {
        var capabilities = connectivity.getNetworkCapabilities(connectivity.getActiveNetwork());
        if (capabilities == null || capabilities.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
            return NetworkState.NONE;
        }
        return from(capabilities);
    }

    static NetworkState from(NetworkCapabilities capabilities) {
        NetworkState.Transport transport = capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                ? NetworkState.Transport.WIFI
                : capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET)
                ? NetworkState.Transport.ETHERNET
                : capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)
                ? NetworkState.Transport.CELLULAR : NetworkState.Transport.OTHER;
        return new NetworkState(transport,
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED),
                !capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING),
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL));
    }

    private void publish(NetworkState next) {
        if (!next.equals(current)) {
            current = next;
            listener.accept(next);
        }
    }
}
