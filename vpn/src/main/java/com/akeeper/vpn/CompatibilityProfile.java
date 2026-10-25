package com.akeeper.vpn;

import java.util.Set;

/**
 * Profil de compatibilité d'une app. Il ne crée jamais de bypass VPN : il sert à signaler les actions à risque et
 * à appliquer des garde-fous explicites sans affaiblir le filtrage global.
 */
public enum CompatibilityProfile {
    DEFAULT,
    FINANCE,
    PAYMENT,
    SYSTEM_CONNECTIVITY;

    private static final Set<String> SYSTEM_CONNECTIVITY_PACKAGES = Set.of(
            "com.android.captiveportallogin",
            "com.android.networkstack",
            "com.google.android.networkstack",
            "com.google.android.captiveportallogin",
            "com.android.vending",
            "com.google.android.gms"
    );

    private static final Set<String> PAYMENT_PACKAGES = Set.of(
            "com.google.android.apps.walletnfcrel",
            "com.samsung.android.spay",
            "com.samsung.android.samsungpay.gear",
            "fr.creditagricole.macarteca"
    );

    private static final Set<String> FINANCE_PACKAGES = Set.of(
            "com.socgen.samobile.android",
            "societe.generale.private.ebanking.mc",
            "mobi.societegenerale.mobile.lapplipro",
            "fr.creditagricole.cabourse",
            "fr.banquepopulaire.cyberplus.pro"
    );

    public static CompatibilityProfile classify(String packageName) {
        if (SYSTEM_CONNECTIVITY_PACKAGES.contains(packageName)) {
            return SYSTEM_CONNECTIVITY;
        }
        if (PAYMENT_PACKAGES.contains(packageName)) {
            return PAYMENT;
        }
        if (FINANCE_PACKAGES.contains(packageName)) {
            return FINANCE;
        }
        return DEFAULT;
    }

    public boolean requiresBlockWarning() {
        return this != DEFAULT;
    }
}
