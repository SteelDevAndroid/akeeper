package com.akeeper.engine;

import android.os.ParcelFileDescriptor;

import java.io.IOException;

/**
 * Moteur natif propriétaire du fd TUN : résolveur DNS local filtrant, NAT UDP protégé, neutralisation
 * de l'évasion. Tout paquet sans verdict explicite est abandonné.
 */
public final class NativeEngine implements AutoCloseable {

    static {
        System.loadLibrary("akeeper_ffi");
    }

    /** Nombre maximal de résolveurs amont simultanés ({@code akeeper_engine::MAX_UPSTREAMS}). */
    public static final int MAX_UPSTREAMS = 4;

    /** Indices partagés avec {@code akeeper_engine::Counter} : l'ordre fait partie du contrat JNI. */
    public enum Counter {
        PACKETS, BYTES, MALFORMED, TCP, UDP, ICMP, DNS_QUERIES, DNS_BLOCKED, DNS_UPSTREAM_FAILURES,
        QUIC_BLOCKED, UDP_NAT_FAILURES, TCP_FLOWS, TCP_FAILURES
    }

    /** Rappelé par le thread natif ; doit rester rapide et ne jamais bloquer. */
    @FunctionalInterface
    public interface Host {
        /** {@code VpnService.protect(int)} : exclut ce socket du tunnel. */
        boolean protect(int fd);
    }

    // Garde par le moniteur : un appel natif pendant close() utiliserait la mémoire libérée (use-after-free).
    private long handle;

    private NativeEngine(long handle) {
        this.handle = handle;
    }

    /**
     * Le moteur prend possession des deux fd détachés et les ferme, y compris en cas d'échec.
     *
     * @param blocklistFd liste de domaines, un par ligne ; -1 pour une liste vide
     * @param host        référencé par le moteur jusqu'à {@link #close()}
     */
    public static NativeEngine start(int detachedTunFd, int blocklistFd, Host host) {
        long h = nativeStart(detachedTunFd, blocklistFd, host);
        if (h == 0) {
            throw new IllegalStateException("Démarrage du moteur natif impossible");
        }
        return new NativeEngine(h);
    }

    /**
     * Confie un socket UDP déjà connecté au DNS amont et protégé par {@code VpnService.protect}.
     * Le fd détaché est fermé dans tous les cas ; -1 vide le slot.
     *
     * @return {@code false} si le moteur est arrêté ou refuse le slot
     */
    public synchronized boolean setUpstream(int slot, int detachedSocketFd) {
        if (handle == 0) {
            closeQuietly(detachedSocketFd);
            return false;
        }
        return nativeSetUpstream(handle, slot, detachedSocketFd) == 0;
    }

    /** Renvoie -1 une fois le moteur arrêté. */
    public synchronized long counter(Counter counter) {
        return handle == 0 ? -1 : nativeCounter(handle, counter.ordinal());
    }

    @Override
    public synchronized void close() {
        if (handle != 0) {
            nativeStop(handle);
            handle = 0;
        }
    }

    private static void closeQuietly(int fd) {
        if (fd >= 0) {
            try {
                ParcelFileDescriptor.adoptFd(fd).close();
            } catch (IOException ignored) {
                // Le fd cédé est fermé ou invalide : rien d'autre à libérer.
            }
        }
    }

    private static native long nativeStart(int tunFd, int blocklistFd, Host host);

    private static native int nativeSetUpstream(long handle, int slot, int fd);

    private static native long nativeCounter(long handle, int counter);

    private static native void nativeStop(long handle);
}
