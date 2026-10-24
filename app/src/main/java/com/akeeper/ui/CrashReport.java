package com.akeeper.ui;

import android.app.ActivityManager;
import android.app.ApplicationExitInfo;
import android.content.Context;
import android.util.Log;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;

/**
 * Consigne localement le dernier plantage pour l'afficher au lancement suivant : sans outil de débogage, c'est le seul
 * moyen de connaître la cause. Rien n'est envoyé : l'utilisateur copie le texte s'il le souhaite.
 */
public final class CrashReport {

    private static final String JAVA_CRASH = "last_crash.txt";
    private static final String SEEN = "last_exit_seen";
    // Borne la lecture : une trace démesurée ne doit pas saturer la mémoire ni la boîte de dialogue.
    private static final int MAX_BYTES = 32 * 1024;

    /** Texte à afficher, et horodatage du dernier arrêt système pris en compte (0 si aucun). */
    public record Report(String text, long exitTimestamp) {
    }

    private CrashReport() {
    }

    public static void install(Context context) {
        var dir = context.getApplicationContext().getNoBackupFilesDir();
        var previous = Thread.getDefaultUncaughtExceptionHandler();
        Thread.setDefaultUncaughtExceptionHandler((thread, error) -> {
            write(dir, thread, error);
            if (previous != null) {
                previous.uncaughtException(thread, error);
            }
        });
    }

    /** Dernier plantage non encore acquitté : exception Java, sinon arrêt natif ou blocage relevé par le système. */
    public static Optional<Report> pending(Context context) {
        var dir = context.getNoBackupFilesDir();
        var java = read(new File(dir, JAVA_CRASH));
        if (java.isPresent()) {
            return Optional.of(new Report(java.get(), 0));
        }
        return systemExit(context, readSeen(dir));
    }

    public static void acknowledge(Context context, Report report) {
        var dir = context.getNoBackupFilesDir();
        new File(dir, JAVA_CRASH).delete();
        if (report.exitTimestamp() > 0) {
            try {
                Files.write(new File(dir, SEEN).toPath(), Long.toString(report.exitTimestamp()).getBytes(StandardCharsets.UTF_8));
            } catch (IOException ignored) {
                // Au pire, le même arrêt est signalé une seconde fois.
            }
        }
    }

    private static void write(File dir, Thread thread, Throwable error) {
        try {
            var text = "Thread : " + thread.getName() + "\n" + Log.getStackTraceString(error);
            Files.write(new File(dir, JAVA_CRASH).toPath(), text.getBytes(StandardCharsets.UTF_8));
        } catch (IOException | RuntimeException ignored) {
            // Le gestionnaire ne doit jamais lever : il s'exécute déjà pendant un plantage.
        }
    }

    private static Optional<String> read(File file) {
        try (var in = Files.newInputStream(file.toPath())) {
            return Optional.of(new String(in.readNBytes(MAX_BYTES), StandardCharsets.UTF_8));
        } catch (IOException absent) {
            return Optional.empty();
        }
    }

    private static long readSeen(File dir) {
        try {
            return Long.parseLong(new String(Files.readAllBytes(new File(dir, SEEN).toPath()), StandardCharsets.UTF_8).trim());
        } catch (IOException | NumberFormatException none) {
            return 0;
        }
    }

    private static Optional<Report> systemExit(Context context, long seen) {
        var manager = context.getSystemService(ActivityManager.class);
        if (manager == null) {
            return Optional.empty();
        }
        return manager.getHistoricalProcessExitReasons(context.getPackageName(), 0, 5).stream()
                .filter(info -> info.getTimestamp() > seen && isFailure(info.getReason()))
                .findFirst()
                .map(info -> new Report(describe(info), info.getTimestamp()));
    }

    private static boolean isFailure(int reason) {
        // Les exceptions Java (REASON_CRASH) sont déjà couvertes, avec leur trace, par le fichier du gestionnaire.
        return reason == ApplicationExitInfo.REASON_CRASH_NATIVE || reason == ApplicationExitInfo.REASON_ANR
                || reason == ApplicationExitInfo.REASON_SIGNALED
                || reason == ApplicationExitInfo.REASON_INITIALIZATION_FAILURE;
    }

    private static String describe(ApplicationExitInfo info) {
        return "Arrêt relevé par le système\nraison : " + info.getReason() + "\nstatut : " + info.getStatus()
                + "\nprocessus : " + info.getProcessName() + "\ndescription : " + info.getDescription();
    }
}
