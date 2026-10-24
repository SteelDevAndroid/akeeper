package com.akeeper.vpn;

import android.content.Context;

import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;

/**
 * Clé de la base du journal : 32 octets aléatoires, chiffrés par la clé Keystore de l'app (AEAD Tink) puis écrits de
 * façon atomique. Perdre ce fichier rend le journal illisible, ce qui est voulu : la base est alors recréée.
 */
final class DatabaseKey {

    private static final String FILE_NAME = "activity.key";
    private static final byte[] ASSOCIATED_DATA = "akeeper/activity-key/v1".getBytes(StandardCharsets.UTF_8);
    static final int LENGTH = 32;

    private DatabaseKey() {
    }

    /** Le premier appel crée la clé ; à éviter sur le thread principal (Keystore). */
    static byte[] load(Context context) throws GeneralSecurityException, IOException {
        var app = context.getApplicationContext();
        var file = new SecureFile(new File(app.getNoBackupFilesDir(), FILE_NAME), SecureStorage.aead(app),
                ASSOCIATED_DATA);
        var existing = file.read();
        if (existing.isPresent() && existing.get().length == LENGTH) {
            return existing.get();
        }
        var key = new byte[LENGTH];
        new SecureRandom().nextBytes(key);
        file.write(key);
        return key;
    }
}
