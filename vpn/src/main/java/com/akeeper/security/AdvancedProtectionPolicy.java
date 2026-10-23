package com.akeeper.security;

import android.content.Context;
import android.security.advancedprotection.AdvancedProtectionManager;

import com.akeeper.vpn.ShieldPolicy;

public final class AdvancedProtectionPolicy {

    private final AdvancedProtectionManager manager;

    public AdvancedProtectionPolicy(Context context) {
        this.manager = context.getSystemService(AdvancedProtectionManager.class);
    }

    // Si l'utilisateur a activé Advanced Protection (Android 16), aucune option de relâchement n'est proposée.
    public ShieldPolicy effective(ShieldPolicy userPolicy) {
        if (manager != null && manager.isAdvancedProtectionEnabled()) {
            return ShieldPolicy.hardened();
        }
        return userPolicy;
    }
}
