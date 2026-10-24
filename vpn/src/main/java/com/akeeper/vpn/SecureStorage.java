package com.akeeper.vpn;

import android.content.Context;

import com.google.crypto.tink.Aead;
import com.google.crypto.tink.KeyTemplates;
import com.google.crypto.tink.RegistryConfiguration;
import com.google.crypto.tink.aead.AeadConfig;
import com.google.crypto.tink.integration.android.AndroidKeysetManager;

import java.io.IOException;
import java.security.GeneralSecurityException;

/** AEAD de l'app : keyset Tink protégé par une clé AES-GCM du Keystore Android. */
final class SecureStorage {

    private static volatile Aead aead;

    private SecureStorage() {
    }

    /** Le premier appel crée ou ouvre la clé Keystore : à éviter sur un chemin critique de l'UI. */
    static Aead aead(Context context) throws GeneralSecurityException, IOException {
        var current = aead;
        if (current == null) {
            synchronized (SecureStorage.class) {
                current = aead;
                if (current == null) {
                    AeadConfig.register();
                    var handle = new AndroidKeysetManager.Builder()
                            .withSharedPref(context.getApplicationContext(), "app_rules_keyset", "akeeper_tink")
                            .withKeyTemplate(KeyTemplates.get("AES256_GCM"))
                            .withMasterKeyUri("android-keystore://akeeper_app_rules")
                            .build()
                            .getKeysetHandle();
                    current = handle.getPrimitive(RegistryConfiguration.get(), Aead.class);
                    aead = current;
                }
            }
        }
        return current;
    }
}
