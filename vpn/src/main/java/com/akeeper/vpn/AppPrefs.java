package com.akeeper.vpn;

import android.content.Context;

import com.google.crypto.tink.Aead;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.EnumSet;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;
import java.util.function.UnaryOperator;

/**
 * Préférences de l'utilisateur, chiffrées au repos comme {@link AppRules} : fichier atomique + Tink AEAD. Les valeurs
 * absentes ou illisibles retombent sur des défauts qui protègent (toutes les catégories actives).
 */
public final class AppPrefs {

    /** Durées de conservation proposées, en jours ; 7 est le maximum (spec §7). */
    public static final int[] RETENTION_CHOICES = {1, 3, 7};

    /**
     * @param disabledCategories catégories de domaines désactivées dans R2
     * @param logEnabled         journal d'activité (R1)
     * @param retentionDays      durée de conservation du journal, l'une de {@link #RETENTION_CHOICES}
     */
    public record Settings(Set<RuleCategory> disabledCategories, boolean logEnabled, int retentionDays) {
        public static final Settings DEFAULT = new Settings(Set.of(), true, 7);

        public Settings {
            disabledCategories = Set.copyOf(disabledCategories);
        }

        public Settings withCategory(RuleCategory category, boolean enabled) {
            var next = EnumSet.noneOf(RuleCategory.class);
            next.addAll(disabledCategories);
            if (enabled) {
                next.remove(category);
            } else {
                next.add(category);
            }
            return new Settings(next, logEnabled, retentionDays);
        }

        public Settings withLogEnabled(boolean enabled) {
            return new Settings(disabledCategories, enabled, retentionDays);
        }

        public Settings withRetentionDays(int days) {
            return new Settings(disabledCategories, logEnabled, days);
        }
    }

    private static final String FILE_NAME = "app_prefs.bin";
    private static final byte[] ASSOCIATED_DATA = "akeeper/app-prefs/v1".getBytes(StandardCharsets.UTF_8);

    private static volatile AppPrefs instance;

    private final SecureFile file;
    private final Set<Consumer<Settings>> listeners = new CopyOnWriteArraySet<>();
    // Instantané immuable : lu sans verrou, remplacé sous le moniteur de update().
    private volatile Settings settings;

    AppPrefs(File file, Aead aead) {
        this.file = new SecureFile(file, aead, ASSOCIATED_DATA);
        this.settings = this.file.read().map(AppPrefs::decode).orElse(Settings.DEFAULT);
    }

    /** Le premier appel peut ouvrir la clé Keystore : à éviter sur un chemin critique de l'UI. */
    public static AppPrefs get(Context context) throws GeneralSecurityException, IOException {
        var current = instance;
        if (current == null) {
            synchronized (AppPrefs.class) {
                current = instance;
                if (current == null) {
                    var app = context.getApplicationContext();
                    current = new AppPrefs(new File(app.getNoBackupFilesDir(), FILE_NAME), SecureStorage.aead(app));
                    instance = current;
                }
            }
        }
        return current;
    }

    public Settings settings() {
        return settings;
    }

    public synchronized void update(UnaryOperator<Settings> change) throws IOException {
        var next = change.apply(settings);
        if (next.equals(settings)) {
            return;
        }
        file.write(encode(next));
        settings = next;
        listeners.forEach(listener -> listener.accept(next));
    }

    /** L'observateur reçoit chaque modification, pas l'état courant : appelant et lecteur d'état sont distincts. */
    public ShieldStatus.Subscription observe(Consumer<Settings> listener) {
        listeners.add(listener);
        return () -> listeners.remove(listener);
    }

    static byte[] encode(Settings settings) throws IOException {
        var properties = new Properties();
        properties.setProperty("disabled", String.join(",", settings.disabledCategories().stream().map(Enum::name).sorted().toList()));
        properties.setProperty("log", Boolean.toString(settings.logEnabled()));
        properties.setProperty("retention", Integer.toString(settings.retentionDays()));
        var out = new ByteArrayOutputStream();
        properties.store(out, null);
        return out.toByteArray();
    }

    static Settings decode(byte[] clear) {
        var properties = new Properties();
        try {
            properties.load(new ByteArrayInputStream(clear));
        } catch (IOException | IllegalArgumentException unreadable) {
            return Settings.DEFAULT;
        }
        var disabled = EnumSet.noneOf(RuleCategory.class);
        for (var name : properties.getProperty("disabled", "").split(",")) {
            for (var category : RuleCategory.values()) {
                if (category.name().equals(name.trim())) {
                    disabled.add(category);
                }
            }
        }
        return new Settings(disabled, !"false".equals(properties.getProperty("log")),
                retention(properties.getProperty("retention")));
    }

    private static int retention(String value) {
        try {
            int days = Integer.parseInt(value == null ? "" : value.trim());
            for (int choice : RETENTION_CHOICES) {
                if (choice == days) {
                    return days;
                }
            }
        } catch (NumberFormatException ignored) {
            // Valeur absente ou corrompue : la durée maximale par défaut s'applique.
        }
        return Settings.DEFAULT.retentionDays();
    }
}
