package com.akeeper.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.google.crypto.tink.subtle.Ed25519Sign;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.util.List;

@ExtendWith(MockitoExtension.class)
class RuleUpdaterTest {

    @TempDir
    File dir;

    @Mock
    HttpURLConnection connection;

    private Ed25519Sign.KeyPair key;
    private RuleStore store;
    private RuleUpdater updater;
    private URL url;

    @BeforeEach
    void setUp() throws Exception {
        key = Ed25519Sign.KeyPair.newKeyPair();
        store = new RuleStore(dir, new BundleVerifier(List.of(key.getPublicKey())), 0, RuleStore.Embedded.NONE);
        updater = new RuleUpdater(store, target -> connection);
        url = URI.create("https://rules.example/bundle.akrb").toURL();
    }

    private void serve(byte[] body) throws IOException {
        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_OK);
        when(connection.getInputStream()).thenReturn(new ByteArrayInputStream(body));
    }

    @Test
    void installsANewerBundleAndAsksConditionallyNextTime() throws Exception {
        serve(TestBundles.signed(key, 0, 2, 1_700_000_000L));
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.UPDATED);
        verify(connection, never()).setIfModifiedSince(anyLong());
        assertThat(store.active()).map(RuleBundle::version).contains(2L);

        when(connection.getResponseCode()).thenReturn(HttpURLConnection.HTTP_NOT_MODIFIED);
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.UP_TO_DATE);
        verify(connection).setIfModifiedSince(1_700_000_000_000L);
        verify(connection, times(2)).disconnect();
    }

    @Test
    void treatsTheSameVersionAsUpToDate() throws Exception {
        store.install(new ByteArrayInputStream(TestBundles.signed(key, 0, 2, 0)));
        serve(TestBundles.signed(key, 0, 2, 0));
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.UP_TO_DATE);
    }

    @Test
    void rejectsAForgedBundle() throws Exception {
        serve(TestBundles.signed(Ed25519Sign.KeyPair.newKeyPair(), 0, 2, 0));
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.REJECTED);
        assertThat(store.active()).isEmpty();
    }

    @Test
    void retriesOnServerOrNetworkErrors() throws Exception {
        when(connection.getResponseCode()).thenReturn(503).thenThrow(new IOException("reset"));
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.RETRY);
        assertThat(updater.update(url)).isEqualTo(RuleUpdater.Outcome.RETRY);
        assertThat(new RuleUpdater(store, target -> {
            throw new IOException("unreachable");
        }).update(url)).isEqualTo(RuleUpdater.Outcome.RETRY);
    }
}
