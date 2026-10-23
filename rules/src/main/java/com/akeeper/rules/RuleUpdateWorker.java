package com.akeeper.rules;

import android.content.Context;

import androidx.annotation.NonNull;
import androidx.work.Worker;
import androidx.work.WorkerParameters;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

/** Tâche périodique : télécharge et active le bundle publié sur {@code BuildConfig.RULES_URL}. */
public final class RuleUpdateWorker extends Worker {

    public RuleUpdateWorker(@NonNull Context context, @NonNull WorkerParameters params) {
        super(context, params);
    }

    @NonNull
    @Override
    public Result doWork() {
        URL url;
        try {
            url = URI.create(BuildConfig.RULES_URL).toURL();
        } catch (MalformedURLException | IllegalArgumentException unconfigured) {
            return Result.failure();
        }
        var updater = new RuleUpdater(RuleStore.get(getApplicationContext()),
                // HTTPS seul (URL validée par Gradle, cleartext interdit par la config réseau).
                target -> (HttpsURLConnection) target.openConnection());
        return switch (updater.update(url)) {
            case UPDATED, UP_TO_DATE -> Result.success();
            case RETRY -> Result.retry();
            case REJECTED -> Result.failure();
        };
    }
}
