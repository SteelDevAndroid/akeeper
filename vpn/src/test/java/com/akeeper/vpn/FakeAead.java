package com.akeeper.vpn;

import com.google.crypto.tink.Aead;

import java.security.GeneralSecurityException;
import java.util.Arrays;

/** AEAD factice : XOR + étiquette liée aux données associées, suffisant pour tester l'intégration. */
final class FakeAead implements Aead {

    @Override
    public byte[] encrypt(byte[] plaintext, byte[] associatedData) {
        var out = Arrays.copyOf(plaintext, plaintext.length + 1);
        for (int i = 0; i < plaintext.length; i++) {
            out[i] ^= 0x5a;
        }
        out[plaintext.length] = (byte) Arrays.hashCode(associatedData);
        return out;
    }

    @Override
    public byte[] decrypt(byte[] ciphertext, byte[] associatedData) throws GeneralSecurityException {
        if (ciphertext.length == 0 || ciphertext[ciphertext.length - 1] != (byte) Arrays.hashCode(associatedData)) {
            throw new GeneralSecurityException("étiquette invalide");
        }
        var out = Arrays.copyOf(ciphertext, ciphertext.length - 1);
        for (int i = 0; i < out.length; i++) {
            out[i] ^= 0x5a;
        }
        return out;
    }
}
