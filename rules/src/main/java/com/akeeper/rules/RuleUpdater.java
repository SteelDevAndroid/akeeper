package com.akeeper.rules;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.GeneralSecurityException;
import java.time.Duration;

/** Télécharge le bundle publié et l'active s'il est authentique et plus récent. Indépendant de WorkManager. */
final class RuleUpdater {

    enum Outcome { UPDATED, UP_TO_DATE, RETRY, REJECTED }

    @FunctionalInterface
    interface Connector {
        HttpURLConnection open(URL url) throws IOException;
    }

    private static final int TIMEOUT_MS = (int) Duration.ofSeconds(30).toMillis();

    private final RuleStore store;
    private final Connector connector;

    RuleUpdater(RuleStore store, Connector connector) {
        this.store = store;
        this.connector = connector;
    }

    Outcome update(URL url) {
        HttpURLConnection connection;
        try {
            connection = connector.open(url);
        } catch (IOException network) {
            return Outcome.RETRY;
        }
        try {
            connection.setConnectTimeout(TIMEOUT_MS);
            connection.setReadTimeout(TIMEOUT_MS);
            // GET conditionnel : sans nouveau bundle, le serveur répond 304 et rien n'est téléchargé.
            store.active().ifPresent(active -> connection.setIfModifiedSince(active.createdAt() * 1000));
            int status = connection.getResponseCode();
            if (status == HttpURLConnection.HTTP_NOT_MODIFIED) {
                return Outcome.UP_TO_DATE;
            }
            if (status != HttpURLConnection.HTTP_OK) {
                return Outcome.RETRY;
            }
            try (var body = connection.getInputStream()) {
                store.install(body);
            }
            return Outcome.UPDATED;
        } catch (RollbackException alreadyCurrent) {
            return Outcome.UP_TO_DATE;
        } catch (GeneralSecurityException forgedOrCorrupted) {
            // Signature invalide : ni activation ni nouvelle tentative rapprochée, la prochaine période réessaiera.
            return Outcome.REJECTED;
        } catch (IOException network) {
            return Outcome.RETRY;
        } finally {
            connection.disconnect();
        }
    }
}
