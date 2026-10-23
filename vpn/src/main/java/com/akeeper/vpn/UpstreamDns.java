package com.akeeper.vpn;

import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.os.Handler;
import android.os.ParcelFileDescriptor;

import com.akeeper.engine.NativeEngine;

import java.io.IOException;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/**
 * Suit le meilleur réseau non-VPN et confie au moteur un socket UDP protégé par résolveur DNS de ce réseau.
 * Toutes les méthodes s'exécutent sur le {@link Handler} passé à {@link #start}.
 */
final class UpstreamDns extends ConnectivityManager.NetworkCallback implements AutoCloseable {

    interface Protector {
        boolean protect(DatagramSocket socket);
    }

    private static final int DNS_PORT = 53;

    private final ConnectivityManager connectivity;
    private final NativeEngine engine;
    private final Protector protector;
    private final Consumer<Network> onUnderlyingNetwork;

    private Network appliedNetwork;
    private List<InetAddress> appliedServers = List.of();

    UpstreamDns(ConnectivityManager connectivity, NativeEngine engine, Protector protector,
                Consumer<Network> onUnderlyingNetwork) {
        this.connectivity = connectivity;
        this.engine = engine;
        this.protector = protector;
        this.onUnderlyingNetwork = onUnderlyingNetwork;
    }

    void start(Handler handler) {
        // NetworkRequest exclut les VPN par défaut (NOT_VPN) : on suit bien le réseau physique sous-jacent.
        var underlying = new NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();
        connectivity.registerBestMatchingNetworkCallback(underlying, this, handler);
    }

    @Override
    public void onLinkPropertiesChanged(Network network, LinkProperties properties) {
        apply(network, select(properties.getDnsServers()));
    }

    @Override
    public void onLost(Network network) {
        if (network.equals(appliedNetwork)) {
            apply(null, List.of());
        }
    }

    @Override
    public void close() {
        connectivity.unregisterNetworkCallback(this);
        apply(null, List.of());
    }

    /** Résolveurs utilisables : uniques, ni boucle locale ni adresse joker, au plus {@link NativeEngine#MAX_UPSTREAMS}. */
    static List<InetAddress> select(List<InetAddress> servers) {
        return servers.stream()
                .filter(Objects::nonNull)
                .filter(a -> !a.isLoopbackAddress() && !a.isAnyLocalAddress())
                .distinct()
                .limit(NativeEngine.MAX_UPSTREAMS)
                .toList();
    }

    private void apply(Network network, List<InetAddress> servers) {
        // onLinkPropertiesChanged se répète sans changement de DNS : recréer les sockets perdrait les requêtes en vol.
        if (Objects.equals(network, appliedNetwork) && servers.equals(appliedServers)) {
            return;
        }
        appliedNetwork = network;
        appliedServers = servers;
        onUnderlyingNetwork.accept(network);
        for (int slot = 0; slot < NativeEngine.MAX_UPSTREAMS; slot++) {
            int fd = slot < servers.size() ? open(network, servers.get(slot)) : -1;
            engine.setUpstream(slot, fd);
        }
    }

    private int open(Network network, InetAddress server) {
        try (var socket = new DatagramSocket()) {
            network.bindSocket(socket);
            // Sans protect(), la requête amont repartirait dans le tunnel : boucle de routage.
            if (!protector.protect(socket)) {
                return -1;
            }
            socket.connect(new InetSocketAddress(server, DNS_PORT));
            // fromDatagramSocket duplique le fd : la fermeture du socket Java ne touche pas celui cédé au moteur.
            return ParcelFileDescriptor.fromDatagramSocket(socket).detachFd();
        } catch (IOException e) {
            return -1;
        }
    }
}
