package com.akeeper.vpn;

import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** État de protection publié par {@link ShieldVpnService}, observé par l'UI et la tuile. */
public final class ShieldStatus {

    public record Snapshot(boolean running, LockdownStatus lockdown) {
        public static final Snapshot STOPPED = new Snapshot(false, new LockdownStatus(false, false));
    }

    public interface Subscription extends AutoCloseable {
        @Override
        void close();
    }

    // Écrit par le service, lu depuis n'importe quel thread : aucune section critique, les observateurs ne bloquent pas l'écrivain.
    private static final AtomicReference<Snapshot> CURRENT = new AtomicReference<>(Snapshot.STOPPED);
    private static final Set<Consumer<Snapshot>> LISTENERS = new CopyOnWriteArraySet<>();

    private ShieldStatus() {
    }

    public static Snapshot current() {
        return CURRENT.get();
    }

    /** L'observateur reçoit immédiatement l'état courant, puis chaque changement. */
    public static Subscription observe(Consumer<Snapshot> listener) {
        LISTENERS.add(listener);
        listener.accept(CURRENT.get());
        return () -> LISTENERS.remove(listener);
    }

    static void publish(Snapshot snapshot) {
        CURRENT.set(snapshot);
        LISTENERS.forEach(listener -> listener.accept(snapshot));
    }
}
