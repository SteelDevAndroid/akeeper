package com.akeeper.vpn;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Set;

class AppPrefsTest {

    @TempDir
    File dir;

    @Test
    void defaultsKeepEveryCategoryActive() {
        var settings = new AppPrefs(new File(dir, "prefs.bin"), new FakeAead()).settings();

        assertThat(settings).isEqualTo(AppPrefs.Settings.DEFAULT);
        assertThat(settings.disabledCategories()).isEmpty();
        assertThat(settings.logEnabled()).isTrue();
        assertThat(settings.retentionDays()).isEqualTo(7);
        assertThat(settings.lanBypass()).as("le réseau local est filtré par défaut").isFalse();
    }

    @Test
    void persistsTheLanOptionAndTreatsGarbageAsOff() throws Exception {
        var file = new File(dir, "prefs.bin");
        new AppPrefs(file, new FakeAead()).update(s -> s.withLanBypass(true));

        assertThat(new AppPrefs(file, new FakeAead()).settings().lanBypass()).isTrue();
        assertThat(AppPrefs.decode("lan=oui\n".getBytes(StandardCharsets.UTF_8)).lanBypass()).isFalse();
    }

    @Test
    void persistsEncryptedAcrossInstances() throws Exception {
        var file = new File(dir, "prefs.bin");
        var prefs = new AppPrefs(file, new FakeAead());
        prefs.update(s -> s.withCategory(RuleCategory.PHISHING, false).withLogEnabled(false).withRetentionDays(3));

        var reloaded = new AppPrefs(file, new FakeAead()).settings();
        assertThat(reloaded.disabledCategories()).containsExactly(RuleCategory.PHISHING);
        assertThat(reloaded.logEnabled()).isFalse();
        assertThat(reloaded.retentionDays()).isEqualTo(3);
        assertThat(new String(Files.readAllBytes(file.toPath()), StandardCharsets.ISO_8859_1)).doesNotContain("PHISHING");
        assertThat(new File(dir, "prefs.bin.tmp")).doesNotExist();
    }

    @Test
    void aTamperedFileFallsBackOnProtectiveDefaults() throws Exception {
        var file = new File(dir, "prefs.bin");
        new AppPrefs(file, new FakeAead()).update(s -> s.withCategory(RuleCategory.ADS, false));
        var bytes = Files.readAllBytes(file.toPath());
        bytes[bytes.length - 1] ^= 1;
        Files.write(file.toPath(), bytes);

        assertThat(new AppPrefs(file, new FakeAead()).settings()).isEqualTo(AppPrefs.Settings.DEFAULT);
    }

    @Test
    void decodeIgnoresUnknownCategoriesAndClampsTheRetention() {
        var clear = "disabled=ADS,NOPE, MALWARE\nlog=maybe\nretention=30\n".getBytes(StandardCharsets.UTF_8);

        var settings = AppPrefs.decode(clear);

        assertThat(settings.disabledCategories()).containsExactlyInAnyOrder(RuleCategory.ADS, RuleCategory.MALWARE);
        assertThat(settings.logEnabled()).as("seule la valeur « false » désactive").isTrue();
        assertThat(settings.retentionDays()).isEqualTo(7);
    }

    @Test
    void notifiesOnRealChangesOnly() throws Exception {
        var prefs = new AppPrefs(new File(dir, "prefs.bin"), new FakeAead());
        var seen = new ArrayList<AppPrefs.Settings>();
        try (var ignored = prefs.observe(seen::add)) {
            prefs.update(s -> s.withLogEnabled(true));
            prefs.update(s -> s.withLogEnabled(false));
        }
        assertThat(seen).hasSize(1);
        assertThat(seen.getFirst().logEnabled()).isFalse();
    }

    @Test
    void theCategoryMaskClearsOnlyTheDisabledBits() {
        assertThat(RuleCategory.mask(Set.of())).isEqualTo(-1);
        int mask = RuleCategory.mask(Set.of(RuleCategory.ADS, RuleCategory.PHISHING));
        assertThat(mask & (1 << RuleCategory.ADS.id)).isZero();
        assertThat(mask & (1 << RuleCategory.PHISHING.id)).isZero();
        assertThat(mask & (1 << RuleCategory.MALWARE.id)).isNotZero();
        assertThat(mask & (1 << 4)).as("DoH et catégories futures restent actives").isNotZero();
        assertThat(mask & (1 << 9)).isNotZero();
    }
}
