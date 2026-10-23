package com.akeeper.ui;

import java.text.Collator;
import java.util.Comparator;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Filtres de l'écran Apps (docs/ui-ecrans.md, A2). */
final class AppFilter {

    enum Scope { ALL, BLOCKED, SYSTEM }

    private AppFilter() {
    }

    static List<AppEntry> apply(List<AppEntry> apps, String query, Scope scope, Set<String> blocked) {
        var needle = query.trim().toLowerCase(Locale.ROOT);
        var collator = Collator.getInstance(Locale.FRENCH);
        return apps.stream()
                .filter(app -> switch (scope) {
                    case ALL -> !app.system();
                    case BLOCKED -> blocked.contains(app.packageName());
                    case SYSTEM -> app.system();
                })
                .filter(app -> needle.isEmpty()
                        || app.label().toLowerCase(Locale.ROOT).contains(needle)
                        || app.packageName().contains(needle))
                // Bloquées d'abord : ce sont celles que l'utilisateur vient vérifier.
                .sorted(Comparator.comparing((AppEntry app) -> !blocked.contains(app.packageName()))
                        .thenComparing(AppEntry::label, collator))
                .toList();
    }
}
