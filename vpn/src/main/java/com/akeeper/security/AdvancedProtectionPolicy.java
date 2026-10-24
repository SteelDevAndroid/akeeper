package com.akeeper.security;

import android.content.Context;
import android.security.advancedprotection.AdvancedProtectionManager;

import com.akeeper.vpn.ShieldPolicy;

public final class AdvancedProtectionPolicy {

    private final AdvancedProtectionManager manager;

    public AdvancedProtectionPolicy(Context context) {
        this.manager = context.getSystemService(AdvancedProtectionManager.class);
    }

    /** Protection avancée active : l'option réseau local est alors indisponible. */
    public boolean active() {
        return manager != null && manager.isAdvancedProtectionEnabled();
    }

    // Si l'utilisateur a activé Advanced Protection (Android 16), aucune option de relâchement n'est proposée.
    public ShieldPolicy effective(ShieldPolicy userPolicy) {
        if (active()) {
            return ShieldPolicy.hardened();
        }
        return userPolicy;
    }
}
