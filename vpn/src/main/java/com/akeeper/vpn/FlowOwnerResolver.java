package com.akeeper.vpn;

import android.net.ConnectivityManager;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;

/**
 * Attribution d'une connexion à son app. Sans cache : le moteur n'appelle qu'une fois par nouveau flux
 * et conserve l'UID dans sa table de flux.
 */
public final class FlowOwnerResolver {

    static final int INVALID_UID = -1;

    private final ConnectivityManager connectivityManager;

    public FlowOwnerResolver(ConnectivityManager connectivityManager) {
        this.connectivityManager = connectivityManager;
    }

    /** @return l'UID propriétaire, ou {@link #INVALID_UID} si inconnu ou si l'app n'est plus le VPN actif */
    public int ownerUid(int protocol, byte[] localAddress, int localPort, byte[] remoteAddress, int remotePort) {
        try {
            var local = new InetSocketAddress(InetAddress.getByAddress(localAddress), localPort);
            var remote = new InetSocketAddress(InetAddress.getByAddress(remoteAddress), remotePort);
            return connectivityManager.getConnectionOwnerUid(protocol, local, remote);
        } catch (UnknownHostException malformedAddress) {
            return INVALID_UID;
        } catch (SecurityException notActiveVpn) {
            // Plus le VPN actif (révocation en cours) : flux non attribuable, jamais d'exception vers le moteur.
            return INVALID_UID;
        }
    }
}
