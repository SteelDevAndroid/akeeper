package com.akeeper.vpn;


import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

class AppRulesTest {

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
