package com.akeeper.ui;

import com.akeeper.vpn.CompatibilityProfile;

/** App installée qui demande l'accès réseau. {@code sharedWith} : nombre d'autres paquets du même UID. */
record AppEntry(String packageName, String label, int uid, boolean system, int sharedWith,
                CompatibilityProfile compatibilityProfile) {

    AppEntry(String packageName, String label, int uid, boolean system, int sharedWith) {
        this(packageName, label, uid, system, sharedWith, CompatibilityProfile.DEFAULT);
    }

    boolean shared() {
        return sharedWith > 0;
    }
}
