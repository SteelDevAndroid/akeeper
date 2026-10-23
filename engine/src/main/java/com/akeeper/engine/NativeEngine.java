package com.akeeper.engine;

/**
 * Moteur natif propriétaire du fd TUN. Jalon J0 : chaque paquet est compté puis abandonné,
 * rien ne ressort du tunnel tant qu'aucun verdict « autoriser » n'existe.
 */
public final class NativeEngine implements AutoCloseable {

    static {
        System.loadLibrary("akeeper_ffi");
    }

    /** Indices partagés avec {@code akeeper_engine::Counter}. */
    public enum Counter {
        PACKETS, BYTES, MALFORMED, TCP, UDP, ICMP
    }

    // Garde par le moniteur : un compteur lu pendant close() libérerait la mémoire native sous l'appel (use-after-free).
    private long handle;

    private NativeEngine(long handle) {
        this.handle = handle;
    }

    /** Le moteur prend possession de {@code detachedTunFd} et le ferme à l'arrêt, y compris en cas d'échec. */
    public static NativeEngine start(int detachedTunFd) {
        long h = nativeStart(detachedTunFd);
        if (h == 0) {
            throw new IllegalStateException("Démarrage du moteur natif impossible");
        }
        return new NativeEngine(h);
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

    private static native long nativeStart(int tunFd);

    private static native long nativeCounter(long handle, int counter);

    private static native void nativeStop(long handle);
}
