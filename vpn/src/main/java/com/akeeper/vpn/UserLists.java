package com.akeeper.vpn;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;
import java.util.concurrent.CopyOnWriteArraySet;
import java.util.function.Consumer;

/**
 * Domaines bloqués et exceptions de l'utilisateur (R2), dans {@code filesDir/blocklist.txt} : un domaine par ligne,
 * préfixé de {@code @@} pour une exception, {@code #} commente. Le moteur lit ce fichier tel quel.
 */
public final class UserLists {

    public enum Kind { BLOCKED, ALLOWED }

    public record Lists(Set<String> blocked, Set<String> allowed) {
        public static final Lists EMPTY = new Lists(Set.of(), Set.of());

        public Set<String> of(Kind kind) {
            return kind == Kind.BLOCKED ? blocked : allowed;
        }
    }

    private static final String EXCEPTION_PREFIX = "@@";

    private static volatile UserLists instance;

    private final File file;
    private final Set<Consumer<Lists>> listeners = new CopyOnWriteArraySet<>();
    // Instantané immuable : lu sans verrou, remplacé sous le moniteur des écritures.
    private volatile Lists lists;

    UserLists(File file) {
        this.file = file;
        this.lists = load();
    }

    public static UserLists get(Context context) {
        var current = instance;
        if (current == null) {
            synchronized (UserLists.class) {
                current = instance;
                if (current == null) {
                    current = new UserLists(new File(context.getApplicationContext().getFilesDir(),
                            ShieldVpnService.BLOCKLIST_FILE));
                    instance = current;
                }
            }
        }
        return current;
    }

    public Lists lists() {
        return lists;
    }

    /**
     * Ajoute un domaine à la liste, après validation. Un domaine ajouté d'un côté est retiré de l'autre : il ne peut
     * pas être à la fois bloqué et autorisé.
     *
     * @return la forme canonique ajoutée, vide si le domaine est invalide
     */
    public synchronized Optional<String> add(Kind kind, String input) throws IOException {
        var domain = DomainRules.normalize(input);
        if (domain.isEmpty()) {
            return domain;
        }
        var blocked = new TreeSet<>(lists.blocked());
        var allowed = new TreeSet<>(lists.allowed());
        (kind == Kind.BLOCKED ? blocked : allowed).add(domain.get());
        (kind == Kind.BLOCKED ? allowed : blocked).remove(domain.get());
        replace(new Lists(Set.copyOf(blocked), Set.copyOf(allowed)));
        return domain;
    }

    public synchronized void remove(Kind kind, String domain) throws IOException {
        var blocked = new TreeSet<>(lists.blocked());
        var allowed = new TreeSet<>(lists.allowed());
        (kind == Kind.BLOCKED ? blocked : allowed).remove(domain);
        replace(new Lists(Set.copyOf(blocked), Set.copyOf(allowed)));
    }

    /** L'observateur reçoit chaque modification, pas l'état courant. */
    public ShieldStatus.Subscription observe(Consumer<Lists> listener) {
        listeners.add(listener);
        return () -> listeners.remove(listener);
    }

    private void replace(Lists next) throws IOException {
        if (next.equals(lists)) {
            return;
        }
        AtomicFiles.write(file, encode(next));
        lists = next;
        listeners.forEach(listener -> listener.accept(next));
    }

    private Lists load() {
        if (!file.exists()) {
            return Lists.EMPTY;
        }
        try {
            return decode(new String(Files.readAllBytes(file.toPath()), StandardCharsets.UTF_8));
        } catch (IOException unreadable) {
            return Lists.EMPTY;
        }
    }

    static byte[] encode(Lists lists) {
        var out = new StringBuilder("# Règles personnelles d'aKeeper : un domaine par ligne, @@ devant une exception.\n");
        new TreeSet<>(lists.blocked()).forEach(domain -> out.append(domain).append('\n'));
        new TreeSet<>(lists.allowed()).forEach(domain -> out.append(EXCEPTION_PREFIX).append(domain).append('\n'));
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    static Lists decode(String text) {
        var blocked = new TreeSet<String>();
        var allowed = new TreeSet<String>();
        for (var line : text.split("\n")) {
            var rule = line.split("#", 2)[0].trim();
            var exception = rule.startsWith(EXCEPTION_PREFIX);
            DomainRules.normalize(exception ? rule.substring(EXCEPTION_PREFIX.length()) : rule)
                    .ifPresent((exception ? allowed : blocked)::add);
        }
        return new Lists(Set.copyOf(blocked), Set.copyOf(allowed));
    }
}
