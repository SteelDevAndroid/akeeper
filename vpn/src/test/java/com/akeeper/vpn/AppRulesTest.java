package com.akeeper.vpn;

import com.google.crypto.tink.Aead;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AppRulesTest {

    /** AEAD factice : XOR + étiquette liée aux données associées, suffisant pour tester l'intégration. */
    private static final class FakeAead implements Aead {
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

    @TempDir
    File dir;

    @Test
    void persistsEncryptedAcrossInstances() throws Exception {
        var file = new File(dir, "rules.bin");
        var rules = new AppRules(file, new FakeAead());
        rules.setBlocked(Set.of("com.example.social", "com.example.game"), true);
        rules.setBlocked(Set.of("com.example.game"), false);

        assertThat(new AppRules(file, new FakeAead()).blocked()).containsExactly("com.example.social");
        assertThat(new String(Files.readAllBytes(file.toPath()))).doesNotContain("com.example.social");
        assertThat(new File(dir, "rules.bin.tmp")).doesNotExist();
    }

    @Test
    void tamperedFileYieldsNoRules() throws Exception {
        var file = new File(dir, "rules.bin");
        new AppRules(file, new FakeAead()).setBlocked(Set.of("com.example.social"), true);
        var bytes = Files.readAllBytes(file.toPath());
        bytes[bytes.length - 1] ^= 1;
        Files.write(file.toPath(), bytes);

        assertThat(new AppRules(file, new FakeAead()).blocked()).isEmpty();
    }

    @Test
    void observersGetCurrentStateThenChanges() throws Exception {
        var rules = new AppRules(new File(dir, "rules.bin"), new FakeAead());
        var seen = new ArrayList<Set<String>>();
        try (var ignored = rules.observe(seen::add)) {
            rules.setBlocked(Set.of("com.example.social"), true);
        }
        rules.setBlocked(Set.of("com.example.other"), true);

        assertThat(seen).containsExactly(Set.of(), Set.of("com.example.social"));
    }

    @Test
    void decodeDropsInvalidPackageNames() {
        assertThat(AppRules.decode("com.example.ok\n../etc\n\nsingle\ncom.Example.ok2".getBytes()))
                .containsExactlyInAnyOrder("com.example.ok", "com.Example.ok2");
    }
}
