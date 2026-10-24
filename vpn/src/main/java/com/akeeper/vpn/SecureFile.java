package com.akeeper.vpn;

import com.google.crypto.tink.Aead;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.Optional;

/**
 * Fichier chiffré par Tink AEAD et écrit de façon atomique. Les données associées lient le chiffré à son usage : un
 * autre fichier chiffré avec la même clé ne peut pas être substitué.
 */
final class SecureFile {

    private final File file;
    private final Aead aead;
    private final byte[] associatedData;

    SecureFile(File file, Aead aead, byte[] associatedData) {
        this.file = file;
        this.aead = aead;
        this.associatedData = associatedData;
    }

    /** Vide si le fichier est absent, illisible ou falsifié : l'appelant retombe alors sur ses valeurs par défaut. */
    Optional<byte[]> read() {
        if (!file.exists()) {
            return Optional.empty();
        }
        try {
            return Optional.of(aead.decrypt(Files.readAllBytes(file.toPath()), associatedData));
        } catch (IOException | GeneralSecurityException unreadable) {
            return Optional.empty();
        }
    }

    void write(byte[] clear) throws IOException {
        byte[] cipher;
        try {
            cipher = aead.encrypt(clear, associatedData);
        } catch (GeneralSecurityException e) {
            throw new IOException("chiffrement impossible", e);
        }
        AtomicFiles.write(file, cipher);
    }
}
