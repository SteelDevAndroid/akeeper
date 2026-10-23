package com.akeeper.rules;

import android.content.Context;

import androidx.work.BackoffPolicy;
import androidx.work.Constraints;
import androidx.work.ExistingPeriodicWorkPolicy;
import androidx.work.NetworkType;
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

    public static void schedule(Context context) {
        if (BuildConfig.RULES_URL.isEmpty()) {
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
