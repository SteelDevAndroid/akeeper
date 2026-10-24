package com.akeeper.vpn;

import java.util.Set;

/** Catégories de domaines du bundle que l'utilisateur peut désactiver. L'identifiant est celui de l'enveloppe. */
public enum RuleCategory {
    ADS(1),
    MALWARE(2),
    PHISHING(3);

    public final int id;

    RuleCategory(int id) {
        this.id = id;
    }

    /**
     * Masque donné au moteur : un bit par identifiant de catégorie laissée active. Les catégories inconnues de cette
     * version de l'app (bundle plus récent) restent actives.
     */
    public static int mask(Set<RuleCategory> disabled) {
        int mask = -1;
        for (var category : disabled) {
            mask &= ~(1 << category.id);
        }
        return mask;
    }
}
