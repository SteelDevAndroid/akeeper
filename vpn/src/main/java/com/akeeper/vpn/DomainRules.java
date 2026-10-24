package com.akeeper.vpn;

import java.net.IDN;
import java.util.Locale;
import java.util.Optional;

/** Validation des domaines saisis par l'utilisateur (R2). */
public final class DomainRules {

    private static final int MAX_LENGTH = 253;
    private static final int MAX_LABEL = 63;

    private DomainRules() {
    }

    /**
     * Forme canonique d'un domaine saisi, ou vide s'il est invalide. Un préfixe {@code *.} est accepté et équivaut au
     * domaine nu, sous-domaines compris ; tout autre joker, un chemin, un port ou une adresse IP sont refusés.
     */
    public static Optional<String> normalize(String input) {
        if (input == null) {
            return Optional.empty();
        }
        var name = input.trim().toLowerCase(Locale.ROOT);
        if (name.startsWith("*.")) {
            name = name.substring(2);
        }
        if (name.endsWith(".")) {
            name = name.substring(0, name.length() - 1);
        }
        try {
            name = IDN.toASCII(name, IDN.ALLOW_UNASSIGNED);
        } catch (IllegalArgumentException invalid) {
            return Optional.empty();
        }
        if (name.isEmpty() || name.length() > MAX_LENGTH || name.indexOf('.') < 0) {
            return Optional.empty();
        }
        var labels = name.split("\\.", -1);
        for (var label : labels) {
            if (!validLabel(label)) {
                return Optional.empty();
            }
        }
        // Un dernier label numérique est une adresse IP (ou son début) : un filtre DNS ne peut pas la bloquer.
        if (labels[labels.length - 1].chars().allMatch(Character::isDigit)) {
            return Optional.empty();
        }
        return Optional.of(name);
    }

    private static boolean validLabel(String label) {
        if (label.isEmpty() || label.length() > MAX_LABEL || label.startsWith("-") || label.endsWith("-")) {
            return false;
        }
        return label.chars().allMatch(c -> (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_');
    }
}
