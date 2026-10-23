package com.akeeper.vpn;

import com.akeeper.engine.NativeEngine;

import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Consumer;

/** État de protection publié par {@link ShieldVpnService}, observé par l'UI et la tuile. */
public final class ShieldStatus {

    /** {@code privateDnsStrict} : DNS privé en mode strict, le DNS des apps échappe au filtrage. */
    public record Snapshot(boolean running, LockdownStatus lockdown, boolean privateDnsStrict) {
        public static final Snapshot STOPPED = new Snapshot(false, new LockdownStatus(false, false));

        public Snapshot(boolean running, LockdownStatus lockdown) {
            this(running, lockdown, false);
        }

        public Snapshot withPrivateDnsStrict(boolean strict) {
            return new Snapshot(running, lockdown, strict);
        }
    }

    public interface Subscription extends AutoCloseable {
        @Override
        void close();
    }

    // Écrit par le service, lu depuis n'importe quel thread : aucune section critique, les observateurs ne bloquent pas l'écrivain.
    private static final AtomicReference<Snapshot> CURRENT = new AtomicReference<>(Snapshot.STOPPED);
    private static final Set<Consumer<Snapshot>> LISTENERS = new CopyOnWriteArraySet<>();
    private static final AtomicReference<NativeEngine> ENGINE = new AtomicReference<>();

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

    /** Compteur du moteur en cours depuis son démarrage ; vide si la protection est arrêtée. */
    public static OptionalLong counter(NativeEngine.Counter counter) {
        var engine = ENGINE.get();
        long value = engine == null ? -1 : engine.counter(counter);
        return value < 0 ? OptionalLong.empty() : OptionalLong.of(value);
    }

    static void attach(NativeEngine engine) {
        ENGINE.set(engine);
    }

    static void detach() {
        ENGINE.set(null);
    }

    static void publish(Snapshot snapshot) {
        CURRENT.set(snapshot);
        LISTENERS.forEach(listener -> listener.accept(snapshot));
    }
}
