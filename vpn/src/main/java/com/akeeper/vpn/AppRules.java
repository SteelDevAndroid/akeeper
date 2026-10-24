package com.akeeper.vpn;

import android.content.Context;
import android.content.pm.PackageManager;

import com.google.crypto.tink.Aead;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import java.util.Objects;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Paquets privés d'Internet (pare-feu par app), chiffrés au repos : écriture atomique (fichier temporaire,
 * fsync, rename) + Tink AEAD, clé maîtresse dans le Keystore Android. Partagé par le service et l'UI.
 */
public final class AppRules {

    private static final String FILE_NAME = "app_rules.bin";
    // Lie le chiffré à son usage : un autre fichier chiffré avec la même clé ne peut pas être substitué.
    private static final byte[] ASSOCIATED_DATA = "akeeper/app-rules/v1".getBytes(StandardCharsets.UTF_8);
    private static final Pattern PACKAGE_NAME = Pattern.compile("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z][A-Za-z0-9_]*)+");

    private static volatile AppRules instance;

    private final SecureFile file;
    private final Set<Consumer<Set<String>>> listeners = new CopyOnWriteArraySet<>();
    // Instantané immuable : lu sans verrou, remplacé sous le moniteur de setBlocked().
    private volatile Set<String> blocked;

    AppRules(File file, Aead aead) {
        this.file = new SecureFile(file, aead, ASSOCIATED_DATA);
        this.blocked = load();
    }

    /** Le premier appel crée ou ouvre la clé Keystore : à éviter sur un chemin critique de l'UI. */
    public static AppRules get(Context context) throws GeneralSecurityException, IOException {
        var current = instance;
        if (current == null) {
            synchronized (AppRules.class) {
                current = instance;
                if (current == null) {
                    var app = context.getApplicationContext();
                    current = new AppRules(new File(app.getNoBackupFilesDir(), FILE_NAME), SecureStorage.aead(app));
                    instance = current;
                }
            }
        }
        return current;
    }

    public Set<String> blocked() {
        return blocked;
    }

    public synchronized void setBlocked(Set<String> packages, boolean block) throws IOException {
        var next = new TreeSet<>(blocked);
        if (block) {
            next.addAll(packages);
        } else {
            next.removeAll(packages);
        }
        var snapshot = Set.copyOf(next);
        write(snapshot);
        blocked = snapshot;
        listeners.forEach(listener -> listener.accept(snapshot));
    }

    /** L'observateur reçoit l'ensemble courant, puis chaque modification, sur le thread de l'écrivain. */
    public ShieldStatus.Subscription observe(Consumer<Set<String>> listener) {
        listeners.add(listener);
        listener.accept(blocked);
        return () -> listeners.remove(listener);
    }

    /** UID des paquets donnés ; un paquet désinstallé est ignoré. Les UID partagés sont dédoublonnés. */
    public static int[] uids(PackageManager packageManager, Set<String> packages) {
        return packages.stream()
                .map(name -> {
                    try {
                        return packageManager.getPackageUid(name, 0);
                    } catch (PackageManager.NameNotFoundException uninstalled) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .distinct()
                .mapToInt(Integer::intValue)
                .toArray();
    }

    private Set<String> load() {
        // Fichier absent, illisible ou falsifié : aucune règle plutôt que des règles douteuses ; l'app reste utilisable.
        return file.read().map(AppRules::decode).orElse(Set.of());
    }

    private void write(Set<String> packages) throws IOException {
        file.write(encode(packages));
    }

    static byte[] encode(Set<String> packages) {
        return String.join("\n", new TreeSet<>(packages)).getBytes(StandardCharsets.UTF_8);
    }

    static Set<String> decode(byte[] clear) {
        return Arrays.stream(new String(clear, StandardCharsets.UTF_8).split("\n"))
                .filter(name -> PACKAGE_NAME.matcher(name).matches())
                .collect(Collectors.toUnmodifiableSet());
    }
}
