package com.akeeper.ui;

/** App installée qui demande l'accès réseau. {@code sharedWith} : nombre d'autres paquets du même UID. */
record AppEntry(String packageName, String label, int uid, boolean system, int sharedWith) {

    boolean shared() {
        return sharedWith > 0;
    }
}
