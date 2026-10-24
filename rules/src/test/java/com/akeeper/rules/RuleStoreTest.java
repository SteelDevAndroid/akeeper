package com.akeeper.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.google.crypto.tink.subtle.Ed25519Sign;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

class RuleStoreTest {

    @TempDir
    File dir;

    private Ed25519Sign.KeyPair key;
    private RuleStore store;

    @BeforeEach
    void setUp() throws GeneralSecurityException {
        key = Ed25519Sign.KeyPair.newKeyPair();
        store = newStore(0);
    }

    private RuleStore newStore(long embeddedFloor) {
        return new RuleStore(new File(dir, "rules"), new BundleVerifier(List.of(key.getPublicKey())), embeddedFloor,
                RuleStore.Embedded.NONE);
    }

    private RuleBundle install(long version) throws IOException, GeneralSecurityException {
        return store.install(new ByteArrayInputStream(TestBundles.signed(key, 0, version, version * 100)));
    }

    @Test
    void activatesNewerBundlesAndExposesTheFileFromItsStart() throws Exception {
        assertThat(store.openActive()).isEmpty();
        install(4);
        try (var active = store.openActive().orElseThrow()) {
            assertThat(active.bundle().version()).isEqualTo(4);
            assertThat(active.stream().readNBytes(4)).containsExactly(BundleVerifier.MAGIC);
        }
        install(5);
        assertThat(store.active()).map(RuleBundle::version).contains(5L);
        assertThat(new File(dir, "rules").list()).containsExactlyInAnyOrder("bundle.akrb", "floor");
    }

    @Test
    void rejectsReplayAndRollbackEvenAfterTheBundleIsDeleted() throws Exception {
        install(7);
        assertThatThrownBy(() -> install(7)).isInstanceOf(RollbackException.class);
        assertThatThrownBy(() -> install(6)).isInstanceOf(RollbackException.class);
        Files.delete(new File(dir, "rules/bundle.akrb").toPath());
        // Le plancher persiste : un bundle N-1 signé ne redevient pas acceptable.
        assertThatThrownBy(() -> install(6)).isInstanceOf(RollbackException.class);
        assertThat(install(8).version()).isEqualTo(8);
    }

    @Test
    void ignoresAnActiveBundleOlderThanTheFloor() throws Exception {
        install(3);
        assertThat(newStore(10).openActive()).isEmpty();
        assertThatThrownBy(() -> newStore(10).install(
                new ByteArrayInputStream(TestBundles.signed(key, 0, 9, 0)))).isInstanceOf(RollbackException.class);
    }

    @Test
    void neverActivatesAForgedBundle() throws Exception {
        install(2);
        var forged = TestBundles.signed(Ed25519Sign.KeyPair.newKeyPair(), 0, 99, 0);
        assertThatThrownBy(() -> store.install(new ByteArrayInputStream(forged)))
                .isInstanceOf(GeneralSecurityException.class)
                .isNotInstanceOf(RollbackException.class);
        assertThat(store.active()).map(RuleBundle::version).contains(2L);
    }

    @Test
    void ignoresACorruptedActiveFile() throws Exception {
        install(2);
        Files.write(new File(dir, "rules/bundle.akrb").toPath(), new byte[]{'A', 'K', 'R', 'B'});
        assertThat(store.openActive()).isEmpty();
    }

    @Test
    void notifiesObserversAfterActivationOnly() throws Exception {
        var calls = new AtomicInteger();
        try (var ignored = store.observe(calls::incrementAndGet)) {
            install(1);
            assertThatThrownBy(() -> install(1)).isInstanceOf(RollbackException.class);
        }
        install(2);
        assertThat(calls).hasValue(1);
    }

    /** Liste intégrée de test : le fixture partagé avec Rust, dont la signature n'est pas vérifiée ici. */
    private RuleStore storeWithEmbedded(byte[] bytes, long updatedAt, AtomicInteger opened) {
        var embedded = new RuleStore.Embedded() {
            @Override
            public InputStream open() {
                opened.incrementAndGet();
                return new ByteArrayInputStream(bytes);
            }

            @Override
            public long updatedAt() {
                return updatedAt;
            }
        };
        return new RuleStore(new File(dir, "rules"), new BundleVerifier(List.of(key.getPublicKey())), 0, embedded);
    }

    private byte[] fixture() throws IOException {
        try (var in = getClass().getResourceAsStream("fixture-v5.akrb")) {
            return in.readAllBytes();
        }
    }

    @Test
    void fallsBackOnTheEmbeddedListWhenNothingWasDownloaded() throws Exception {
        var store = storeWithEmbedded(fixture(), 0, new AtomicInteger());

        try (var rules = store.openRules().orElseThrow()) {
            assertThat(rules.stream().readNBytes(4)).containsExactly(BundleVerifier.MAGIC);
        }
        assertThat(store.active()).as("« active » ne désigne que le bundle téléchargé").isEmpty();
        assertThat(store.notice()).contains("Listes de test, domaine public.");
    }

    @Test
    void aDownloadedBundleReplacesTheEmbeddedList() throws Exception {
        var store = storeWithEmbedded(fixture(), 0, new AtomicInteger());
        store.install(new ByteArrayInputStream(TestBundles.signed(key, 0, 9, 0)));

        try (var rules = store.openRules().orElseThrow()) {
            assertThat(rules.bundle().version()).isEqualTo(9);
        }
        assertThat(store.notice()).contains("test");
    }

    @Test
    void aCorruptedDownloadFallsBackOnTheEmbeddedList() throws Exception {
        var store = storeWithEmbedded(fixture(), 0, new AtomicInteger());
        store.install(new ByteArrayInputStream(TestBundles.signed(key, 0, 9, 0)));
        Files.write(new File(dir, "rules/bundle.akrb").toPath(), new byte[]{'A', 'K', 'R', 'B'});

        try (var rules = store.openRules().orElseThrow()) {
            assertThat(rules.bundle().version()).isEqualTo(5);
        }
    }

    @Test
    void copiesTheEmbeddedListOnlyWhenTheAppWasUpdated() throws Exception {
        var opened = new AtomicInteger();
        var store = storeWithEmbedded(fixture(), 0, opened);

        store.openRules().orElseThrow().close();
        store.openRules().orElseThrow().close();
        assertThat(opened).as("copiée une seule fois").hasValue(1);

        var updated = storeWithEmbedded(fixture(), System.currentTimeMillis() + 60_000, opened);
        updated.openRules().orElseThrow().close();
        assertThat(opened).as("recopiée après une mise à jour de l'app").hasValue(2);
    }

    @Test
    void ignoresAnUnreadableEmbeddedList() {
        assertThat(storeWithEmbedded(new byte[]{1, 2, 3}, 0, new AtomicInteger()).openRules()).isEmpty();
        assertThat(newStore(0).openRules()).isEmpty();
    }
}
