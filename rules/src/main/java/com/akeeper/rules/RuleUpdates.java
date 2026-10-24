package com.akeeper.rules;

import android.content.Context;

import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.ExistingWorkPolicy;
import androidx.work.NetworkType;
import androidx.work.OneTimeWorkRequest;
import androidx.work.PeriodicWorkRequest;
import androidx.work.WorkManager;

import java.time.Duration;

/** Planifie la mise à jour des règles ; sans serveur configuré ({@code akeeper.rulesUrl}), rien n'est planifié. */
public final class RuleUpdates {

    private static final String WORK_NAME = "rule-updates";
    // Les listes d'hameçonnage vivent quelques heures : 12 h est le plus long intervalle utile (listes-de-blocage.md).
    private static final Duration PERIOD = Duration.ofHours(12);

    private RuleUpdates() {
    }

    /** Vrai si un serveur de règles est configuré ({@code akeeper.rulesUrl}) : sinon, ni planification ni mise à jour. */
    public static boolean configured() {
        return !BuildConfig.RULES_URL.isEmpty();
    }

    /** Vérification immédiate demandée par l'utilisateur ; sans effet si une est déjà en cours. */
    public static void updateNow(Context context) {
        if (!configured()) {
            return;
        }
        var request = new OneTimeWorkRequest.Builder(RuleUpdateWorker.class)
                .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .build();
        WorkManager.getInstance(context).enqueueUniqueWork("rule-update-now", ExistingWorkPolicy.KEEP, request);
    }

    public static void schedule(Context context) {
        if (!configured()) {
            return;
        }
        var request = new PeriodicWorkRequest.Builder(RuleUpdateWorker.class, PERIOD)
                .setConstraints(new Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
                .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, Duration.ofMinutes(15))
                .build();
        // KEEP : relancer l'app ne repousse pas la prochaine exécution.
        WorkManager.getInstance(context).enqueueUniquePeriodicWork(WORK_NAME, ExistingPeriodicWorkPolicy.KEEP, request);
    }
}
