package com.akeeper.vpn;

import android.content.Context;
import android.util.Log;

import com.akeeper.engine.NativeEngine;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Vide le journal du moteur chaque seconde dans la base chiffrée, applique la durée de conservation et suit
 * l'interrupteur de R1. Tout se passe sur un thread dédié : l'ouverture de la base (Keystore, E/S) ne doit pas
 * toucher le thread principal du service.
 */
final class ActivityRecorder implements AutoCloseable {

    private static final String TAG = "ActivityRecorder";
    private static final long DRAIN_SECONDS = 1;
    private static final long PURGE_SECONDS = 10 * 60;

    private final NativeEngine engine;
    private final Context context;
    private final AppPrefs prefs;
    private final ScheduledExecutorService executor = Executors.newSingleThreadScheduledExecutor(r -> {
        var thread = new Thread(r, "akeeper-activity");
        thread.setDaemon(true);
        return thread;
    });
    private final ShieldStatus.Subscription prefsChanges;
    private ActivityLog log;
    private long lastPurge;

    /** {@code prefs} peut être {@code null} (Keystore indisponible) : pas de journal alors, rien n'est stocké en clair. */
    ActivityRecorder(Context context, NativeEngine engine, AppPrefs prefs) {
        this.context = context.getApplicationContext();
        this.engine = engine;
        this.prefs = prefs;
        if (prefs == null) {
            prefsChanges = null;
            return;
        }
        engine.setLogging(prefs.settings().logEnabled());
        prefsChanges = prefs.observe(settings -> engine.setLogging(settings.logEnabled()));
        executor.scheduleWithFixedDelay(this::drain, DRAIN_SECONDS, DRAIN_SECONDS, TimeUnit.SECONDS);
    }

    private void drain() {
        try {
            if (log == null) {
                log = ActivityLog.get(context);
            }
            var events = engine.drainEvents();
            log.insert(events);
            long now = System.currentTimeMillis();
            if (now - lastPurge >= PURGE_SECONDS * 1000) {
                lastPurge = now;
                log.purgeOlderThan(now - TimeUnit.DAYS.toMillis(prefs.settings().retentionDays()));
            }
        } catch (GeneralSecurityException | IOException keystoreUnavailable) {
            // Sans clé, pas de journal : le moteur ne garde rien de plus que son tampon borné.
            engine.setLogging(false);
            Log.w(TAG, "journal indisponible : " + keystoreUnavailable.getClass().getSimpleName());
        } catch (RuntimeException e) {
            // Une erreur de base ne doit jamais arrêter le service ; le prochain cycle réessaie.
            Log.w(TAG, "écriture du journal impossible", e);
        }
    }

    @Override
    public void close() {
        if (prefsChanges != null) {
            prefsChanges.close();
        }
        executor.shutdownNow();
    }
}
